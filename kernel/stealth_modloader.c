/*
 * stealth_modloader.c - Stealth kernel module loading framework
 *
 * Provides infrastructure to load third-party kernel modules with complete
 * trace elimination. After loading, the module is invisible in:
 * - /proc/modules (lsmod)
 * - /sys/module/<name>/
 * - /proc/kallsyms
 * - dmesg / kernel log
 *
 * Also maintains a "stealth module registry" that other filter modules
 * (proc_hide, klog_sanitize, etc.) query to dynamically extend their
 * filter rules based on which modules are currently stealth-loaded.
 *
 * Usage:
 *   1. Userspace calls supercall STEALTH_LOAD_MODULE(path)
 *   2. Or: after manual insmod, call STEALTH_REGISTER_MODULE(name)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/kobject.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/umh.h>
#include <linux/limits.h>
#include <linux/namei.h>

#include "klog.h" // IWYU pragma: keep
#include "util.h"

/* ---- Stealth Module Registry ---- */

#define MAX_STEALTH_MODULES 32
#define MAX_PREFIXES_PER_MODULE 8
#define MAX_PREFIX_LEN 64
#define MAX_MODULE_NAME_LEN 64

struct stealth_module_entry {
	char name[MAX_MODULE_NAME_LEN];
	char prefixes[MAX_PREFIXES_PER_MODULE][MAX_PREFIX_LEN];
	int prefix_count;
	struct module *mod; /* NULL if unloaded or not tracked */
	bool active;
};

static struct stealth_module_entry registry[MAX_STEALTH_MODULES];
static DEFINE_MUTEX(registry_lock);
static int registry_count;

/*
 * Flat prefix array for fast iteration by filter modules.
 * Rebuilt whenever registry changes. NULL-terminated.
 */
#define PREFIX_CACHE_SIZE (MAX_STEALTH_MODULES * MAX_PREFIXES_PER_MODULE + 1)

/*
 * Double-buffered prefix cache for lock-free reads.
 * Writers (rebuild_prefix_cache, under registry_lock) fill the inactive
 * buffer, issue smp_wmb(), then atomically swap the active index.
 * Readers (ksu_get_stealth_symbol_prefixes, no lock) read the active
 * index after smp_rmb() and iterate the corresponding buffer.
 */
static const char *prefix_buf[2][PREFIX_CACHE_SIZE];
static atomic_t active_prefix_idx = ATOMIC_INIT(0);
static atomic_t prefix_cache_valid = ATOMIC_INIT(0);

static void rebuild_prefix_cache(void)
{
	int i, j, idx = 0;
	int next = !atomic_read(&active_prefix_idx);

	for (i = 0; i < registry_count; i++) {
		if (!registry[i].active)
			continue;
		for (j = 0; j < registry[i].prefix_count; j++) {
			if (idx < PREFIX_CACHE_SIZE - 1)
				prefix_buf[next][idx++] = registry[i].prefixes[j];
		}
		/* Also add module name itself as a prefix */
		if (idx < PREFIX_CACHE_SIZE - 1)
			prefix_buf[next][idx++] = registry[i].name;
	}
	prefix_buf[next][idx] = NULL;
	/* Ensure all writes above are visible before switching the index */
	smp_wmb();
	atomic_set(&active_prefix_idx, next);
	atomic_set(&prefix_cache_valid, 1);
}

static bool name_in_pre_list(const char *name,
			     char pre_names[][MAX_MODULE_NAME_LEN],
			     int pre_count)
{
	int i;

	for (i = 0; i < pre_count; i++) {
		if (!strcmp(pre_names[i], name))
			return true;
	}
	return false;
}

/**
 * ksu_get_stealth_symbol_prefixes() - Get NULL-terminated array of stealth prefixes.
 *
 * Called by proc_hide, klog_sanitize, boot_sanitize to extend their
 * filter rules dynamically.
 *
 * Returns: pointer to static NULL-terminated array, or NULL if empty.
 * The caller must NOT free the returned pointer.
 */
const char **ksu_get_stealth_symbol_prefixes(void)
{
	int cur;

	if (!atomic_read(&prefix_cache_valid) || registry_count == 0)
		return NULL;
	smp_rmb();  /* pair with smp_wmb() in rebuild_prefix_cache */
	cur = atomic_read(&active_prefix_idx);
	return (const char **)prefix_buf[cur];
}

/* ---- Module Hiding Helpers ---- */

static struct mutex *p_module_mutex;
static struct list_head *p_modules_list;

static void resolve_module_mutex(void)
{
	unsigned long addr;

	if (p_module_mutex)
		return;
	if (!ksu_ensure_kallsyms_lookup())
		return;
	addr = ksu_lookup_name("module_mutex");
	p_module_mutex = addr ? (struct mutex *)addr : NULL;
}

static void resolve_modules_list(void)
{
	unsigned long addr;

	if (p_modules_list)
		return;
	if (!ksu_ensure_kallsyms_lookup())
		return;
	addr = ksu_lookup_name("modules");
	p_modules_list = addr ? (struct list_head *)addr : NULL;
}

/**
 * hide_module_sysfs() - Remove sysfs/kallsyms traces from a loaded module.
 * @mod: pointer to the module struct
 *
 * After this call, the module is invisible to lsmod, /proc/modules,
 * /sys/module/<name>/, and /proc/kallsyms.
 * The module remains loaded and functional.
 *
 * NOTE: Caller MUST already hold p_module_mutex for list removal, or
 * must have already removed mod from the list. This function handles
 * sysfs/kallsyms cleanup only.
 */
static void hide_module_sysfs(struct module *mod)
{
	if (!mod)
		return;

	/* Remove sysfs entry (/sys/module/<name>/) */
	kobject_del(&mod->mkobj.kobj);

	/* Clear kallsyms so symbols don't appear in /proc/kallsyms */
	mod->kallsyms = NULL;

	/* Clear section attributes */
#if defined(CONFIG_KALLSYMS) && defined(CONFIG_SYSFS)
	mod->sect_attrs = NULL;
#endif

	/* Zero module name to prevent string matching */
	memset(mod->name, 0, sizeof(mod->name));
}

/* ---- Printk Suppression Window ---- */

static int *p_console_printk;
static int saved_loglevel = -1;
static int printk_suppress_depth;
static DEFINE_MUTEX(printk_lock);

static void ksu_suppress_console(void)
{
	unsigned long addr;

	if (!p_console_printk) {
		addr = ksu_lookup_name("console_printk");
		p_console_printk = addr ? (int *)addr : NULL;
	}

	if (!p_console_printk)
		return;

	mutex_lock(&printk_lock);
	if (printk_suppress_depth == 0) {
		saved_loglevel = p_console_printk[0];
		/* Set console loglevel to 0 (suppress all console output) */
		p_console_printk[0] = 0;
	}
	printk_suppress_depth++;
	mutex_unlock(&printk_lock);
}

static void ksu_restore_console(void)
{
	if (!p_console_printk)
		return;

	mutex_lock(&printk_lock);
	if (printk_suppress_depth > 0)
		printk_suppress_depth--;
	if (printk_suppress_depth == 0 && saved_loglevel >= 0) {
		p_console_printk[0] = saved_loglevel;
		saved_loglevel = -1;
	}
	mutex_unlock(&printk_lock);
}

/* ---- Public API ---- */

#include "stealth.h"

/**
 * ksu_stealth_register_module() - Register a module in the stealth registry.
 * @name: module name (will be copied)
 * @symbol_prefixes: NULL-terminated array of symbol prefix strings to filter,
 *                   or NULL to just filter the module name itself.
 *
 * Used for:
 * 1. Post-insmod registration (module already loaded, just hide it)
 * 2. Internal use after stealth_load_module completes
 *
 * Returns 0 on success, -ENOSPC if registry is full, -EINVAL on bad args.
 */
int ksu_stealth_register_module(const char *name,
				const char **symbol_prefixes)
{
	struct stealth_module_entry *entry;
	struct module *mod;
	int i, slot = -1;

	if (!name || strlen(name) == 0)
		return -EINVAL;

	mutex_lock(&registry_lock);

	/* Check for duplicate and find first free slot */
	for (i = 0; i < registry_count; i++) {
		if (registry[i].active &&
		    strcmp(registry[i].name, name) == 0) {
			mutex_unlock(&registry_lock);
			return 0; /* Already registered */
		}
		if (!registry[i].active && slot < 0)
			slot = i; /* Reuse deactivated slot */
	}

	/* No free slot found in existing entries, try to append */
	if (slot < 0) {
		if (registry_count >= MAX_STEALTH_MODULES) {
			mutex_unlock(&registry_lock);
			return -ENOSPC;
		}
		slot = registry_count;
		registry_count++;
	}

	entry = &registry[slot];
	memset(entry, 0, sizeof(*entry));
	strscpy(entry->name, name, MAX_MODULE_NAME_LEN);
	entry->active = true;

	/* Retry symbol resolution lazily in case init-time lookup failed */
	resolve_module_mutex();

	/* Copy symbol prefixes */
	if (symbol_prefixes) {
		for (i = 0; symbol_prefixes[i] && i < MAX_PREFIXES_PER_MODULE; i++)
			strscpy(entry->prefixes[i], symbol_prefixes[i],
				MAX_PREFIX_LEN);
		entry->prefix_count = i;
	}

	/*
	 * Find the module struct and hide it.
	 * Use the resolved p_module_mutex (via kallsyms) instead of the
	 * direct module_mutex symbol which may not be exported.
	 * Hold the lock across find + hide to prevent TOCTOU race.
	 */
	mod = NULL;
	if (p_module_mutex) {
		mutex_lock(p_module_mutex);
		mod = find_module(name);
		if (mod) {
			entry->mod = mod;
			/* Remove from modules list while holding the lock */
			list_del_init(&mod->list);
		}
		mutex_unlock(p_module_mutex);
	}

	if (mod) {
		/* Suppress printk while performing remaining hiding */
		ksu_suppress_console();

		/* Remove sysfs + kallsyms (list already removed above) */
		hide_module_sysfs(mod);

		/* Scrub ring buffer to remove loading traces */
		ksu_boot_sanitize_scrub();

		ksu_restore_console();
	}

	rebuild_prefix_cache();

	mutex_unlock(&registry_lock);
	return 0;
}

/**
 * ksu_stealth_unload_module() - Unregister a module from stealth registry.
 * @name: module name
 *
 * Note: This does NOT actually unload the module (that's not safely possible
 * after we removed it from the module list). It just removes the registry
 * entry so filters stop hiding its traces.
 */
int ksu_stealth_unload_module(const char *name)
{
	int i;

	if (!name)
		return -EINVAL;

	mutex_lock(&registry_lock);

	for (i = 0; i < registry_count; i++) {
		if (registry[i].active &&
		    strcmp(registry[i].name, name) == 0) {
			registry[i].active = false;
			rebuild_prefix_cache();
			mutex_unlock(&registry_lock);
			return 0;
		}
	}

	mutex_unlock(&registry_lock);
	return -ENOENT;
}

/**
 * ksu_is_stealth_module() - Check if a module name is in the stealth registry.
 */
bool ksu_is_stealth_module(const char *name)
{
	int i;
	bool found = false;

	if (!name)
		return false;

	mutex_lock(&registry_lock);
	for (i = 0; i < registry_count; i++) {
		if (registry[i].active &&
		    strcmp(registry[i].name, name) == 0) {
			found = true;
			break;
		}
	}
	mutex_unlock(&registry_lock);
	return found;
}

/**
 * ksu_stealth_load_module() - Load a kernel module with full trace hiding.
 * @path: userspace path to the .ko file
 * @params: module parameters string (or NULL)
 *
 * This is the all-in-one API:
 * 1. Suppresses printk
 * 2. Loads the module via internal kernel API
 * 3. Hides all traces
 * 4. Scrubs ring buffer
 * 5. Registers in stealth registry
 *
 * For now, module loading is done by having userspace call insmod first,
 * then calling ksu_stealth_register_module(). Direct kernel-internal
 * loading requires resolving unexported load_module() which varies
 * significantly across kernel versions.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ksu_stealth_load_module(const char __user *path,
			    const char __user *params)
{
	(void)params; /* params not used in insmod fallback path */
	char kpath[PATH_MAX];
	long path_len;
	char *argv_insmod[] = { "/system/bin/insmod", kpath, NULL };
	char *argv_vendor[] = { "/vendor/bin/insmod", kpath, NULL };
	char **argv = argv_insmod;
	int ret;
	typedef char mod_name_t[MAX_MODULE_NAME_LEN];
	mod_name_t *pre_names;
	int pre_count = 0;

	if (!path)
		return -EINVAL;

	/* Retry symbol resolution lazily in case init-time lookup failed */
	resolve_module_mutex();
	resolve_modules_list();

	path_len = strncpy_from_user(kpath, path, sizeof(kpath));
	if (path_len <= 0)
		return -EFAULT;
	if (path_len >= (long)sizeof(kpath))
		return -ENAMETOOLONG;
	kpath[sizeof(kpath) - 1] = '\0';
	if (!kpath[0])
		return -EINVAL;
	if (kpath[0] != '/')
		return -EINVAL;

	/* Try /system/bin/insmod first, fallback to /vendor/bin/insmod */
	{
		struct path tmp;
		if (kern_path(argv_insmod[0], LOOKUP_FOLLOW, &tmp)) {
			if (kern_path(argv_vendor[0], LOOKUP_FOLLOW, &tmp))
				return -ENOENT;
			argv = argv_vendor;
		}
		path_put(&tmp);
	}

	/* Sanity check chosen insmod path */
	{
		struct path tmp;
		if (kern_path(argv[0], LOOKUP_FOLLOW, &tmp))
			return -ENOENT;
		path_put(&tmp);
	}

	/* Allocate pre_names on heap to avoid 4KB stack allocation */
	pre_names = kmalloc_array(64, sizeof(mod_name_t), GFP_KERNEL);

	/* Snapshot modules list before load */
	if (pre_names && p_module_mutex && p_modules_list) {
		struct module *m;
		mutex_lock(p_module_mutex);
		list_for_each_entry(m, p_modules_list, list) {
			if (!m->name[0])
				continue;
			if (pre_count >= 64)
				break;
			strscpy(pre_names[pre_count++], m->name,
				MAX_MODULE_NAME_LEN);
		}
		mutex_unlock(p_module_mutex);
	}

	ksu_suppress_console();
	ret = call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_PROC);
	ksu_restore_console();

	if (ret) {
		kfree(pre_names);
		return ret;
	}

	/* Derive module name from filename and hide it */
	{
		const char *base = strrchr(kpath, '/');
		const char *name = base ? base + 1 : kpath;
		char modname_guess[MAX_MODULE_NAME_LEN];
		char modname_real[MAX_MODULE_NAME_LEN] = { 0 };
		struct module *mod;
		ssize_t slen = strscpy(modname_guess, name, sizeof(modname_guess));
		size_t len = slen >= 0 ? (size_t)slen : strlen(modname_guess);
		bool found = false;

		if (len > 3 && !strcmp(modname_guess + len - 3, ".ko"))
			modname_guess[len - 3] = '\0';

		if (p_module_mutex && p_modules_list) {
			/*
			 * Collect candidate names while holding p_module_mutex,
			 * but do NOT call ksu_is_stealth_module() here because
			 * it takes registry_lock, and ksu_stealth_register_module
			 * takes registry_lock -> p_module_mutex.  Calling it here
			 * (p_module_mutex -> registry_lock) would create an ABBA
			 * deadlock.  Instead, collect all new module names and
			 * filter stealth ones after releasing p_module_mutex.
			 */
			char new_names[4][MAX_MODULE_NAME_LEN];
			int new_count = 0;

			mutex_lock(p_module_mutex);
			mod = find_module(modname_guess);
			if (mod) {
				strscpy(modname_real, mod->name,
					sizeof(modname_real));
				found = true;
			} else {
				list_for_each_entry(mod, p_modules_list, list) {
					if (!mod->name[0])
						continue;
					if (!strcmp(mod->name, "kernelsu"))
						continue;
					if (pre_names &&
					    name_in_pre_list(mod->name,
							     pre_names,
							     pre_count))
						continue;
					if (new_count < 4)
						strscpy(new_names[new_count++],
							mod->name,
							MAX_MODULE_NAME_LEN);
				}
			}
			mutex_unlock(p_module_mutex);

			/* Now filter stealth modules without holding p_module_mutex */
			if (!found) {
				int ni;
				for (ni = new_count - 1; ni >= 0; ni--) {
					if (!ksu_is_stealth_module(new_names[ni])) {
						strscpy(modname_real,
							new_names[ni],
							sizeof(modname_real));
						found = true;
						break;
					}
				}
			}
		}

		if (!found)
			strscpy(modname_real, modname_guess,
				sizeof(modname_real));

		ret = ksu_stealth_register_module(modname_real, NULL);
		if (ret) {
			kfree(pre_names);
			return ret;
		}
	}

	kfree(pre_names);
	return 0;
}

/* ---- Printk suppression control (for userspace two-step loading) ---- */

void ksu_stealth_suppress_printk_start(void)
{
	if (!ksu_ensure_kallsyms_lookup())
		return;
	ksu_suppress_console();
}

void ksu_stealth_suppress_printk_stop(void)
{
	ksu_restore_console();
}

/* ---- Init/Exit ---- */

void ksu_stealth_modloader_init(void)
{
	memset(registry, 0, sizeof(registry));
	registry_count = 0;
	memset(prefix_buf, 0, sizeof(prefix_buf));
	printk_suppress_depth = 0;
	saved_loglevel = -1;

	ksu_ensure_kallsyms_lookup();
	resolve_module_mutex();
	resolve_modules_list();
}

void ksu_stealth_modloader_exit(void)
{
	/* Ensure console loglevel is restored even on unmatched start/stop pairs */
	while (printk_suppress_depth > 0)
		ksu_restore_console();
}
