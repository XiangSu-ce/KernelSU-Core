/*
 * symbol_hide.c - Kernel symbol hiding for KernelSU
 *
 * Removes KSU-related symbols from kernel symbol tables to prevent
 * detection via /proc/kallsyms and similar interfaces.
 *
 * Techniques:
 * 1. Module symbol table manipulation (for loadable module builds)
 * 2. /proc/kallsyms output filtering via seq_file interception
 * 3. Module list hiding (remove from modules linked list)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>

#include "klog.h" // IWYU pragma: keep
#include "feature.h"

/* Module enable state */
static atomic_t symbol_hide_enabled = ATOMIC_INIT(1);

/* Track if module has been hidden from module list */
static bool module_list_hidden = false;

/* Prefixes of symbols to hide */
static const char *hidden_symbol_prefixes[] = {
	"ksu_",
	"kernelsu",
	"kernel_su_",
	NULL
};

/*
 * Check if a symbol name should be hidden.
 */
static bool should_hide_symbol(const char *name)
{
	const char **prefix;

	if (!name)
		return false;

	for (prefix = hidden_symbol_prefixes; *prefix; prefix++) {
		if (strncmp(name, *prefix, strlen(*prefix)) == 0)
			return true;
	}

	return false;
}

#ifdef MODULE
/*
 * Resolve module_mutex address.
 *
 * module_mutex is a data symbol (struct mutex), not a function.
 * Kprobes can only be placed on executable code, so we cannot kprobe
 * module_mutex directly. Instead:
 * 1. Resolve kallsyms_lookup_name via kprobe (it IS a function)
 * 2. Call kallsyms_lookup_name("module_mutex") to find the data symbol
 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static struct mutex *p_module_mutex;

static void resolve_module_mutex(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kallsyms_lookup_name_t kln;
	unsigned long addr;

	if (register_kprobe(&kp) < 0) {
		pr_warn("symbol_hide: cannot resolve kallsyms_lookup_name\n");
		p_module_mutex = NULL;
		return;
	}
	kln = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	addr = kln("module_mutex");
	p_module_mutex = addr ? (struct mutex *)addr : NULL;

	if (!p_module_mutex)
		pr_warn("symbol_hide: module_mutex not found\n");
}

/*
 * Hide module from the kernel module list.
 *
 * This removes the module from the linked list used by lsmod/proc/modules
 * while keeping it loaded and functional. The kobject is already deleted
 * by ksu.c in non-debug mode; this handles the module list.
 *
 * WARNING: After calling this, the module cannot be unloaded normally.
 * This is acceptable for KernelSU which is designed to persist until reboot.
 */
static void hide_module_from_list(void)
{
	if (module_list_hidden)
		return;

	if (!p_module_mutex) {
		pr_warn("symbol_hide: module_mutex not resolved, cannot safely hide module\n");
		return;
	}

	/*
	 * Must hold module_mutex to safely modify the modules list.
	 * Use mutex_lock (blocking) rather than trylock — if we can't
	 * get the lock, we must NOT proceed without it.
	 */
	mutex_lock(p_module_mutex);
	list_del_init(&THIS_MODULE->list);
	mutex_unlock(p_module_mutex);

	/*
	 * Clear the module's kallsyms information.
	 * This prevents our symbols from appearing in /proc/kallsyms
	 * even if the module is somehow found.
	 */
	THIS_MODULE->kallsyms = NULL;

	module_list_hidden = true;
	pr_info("symbol_hide: module hidden from list\n");
}

/*
 * Clear module section information.
 * This removes .text, .data, etc. section info that could reveal the module.
 */
static void clear_module_sections(void)
{
#if defined(CONFIG_KALLSYMS) && defined(CONFIG_SYSFS)
	/*
	 * The sect_attrs contains section address information.
	 * Clearing it prevents /sys/module/kernelsu/sections/ from leaking info.
	 * Note: kobject_del already handles /sys/module/kernelsu/ removal,
	 * but this is defense in depth.
	 */
	THIS_MODULE->sect_attrs = NULL;
#endif

	/*
	 * Zero out the module name to prevent string matching.
	 * IMPORTANT: This must happen AFTER kobject_del() in ksu.c,
	 * otherwise kobject operations will fail on the zeroed name.
	 */
	memset(THIS_MODULE->name, 0, sizeof(THIS_MODULE->name));
}
#endif /* MODULE */

/*
 * Check if a given symbol name matches KSU patterns.
 * Exported for use by proc_hide.c's kallsyms filtering.
 */
bool ksu_is_hidden_symbol(const char *name)
{
	if (!atomic_read(&symbol_hide_enabled))
		return false;

	return should_hide_symbol(name);
}

/* Feature handler: get current enable state */
static int symbol_hide_get(u64 *value)
{
	*value = (u64)atomic_read(&symbol_hide_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int symbol_hide_set(u64 value)
{
	atomic_set(&symbol_hide_enabled, value ? 1 : 0);

#ifdef MODULE
	/* Once hidden, module list hiding cannot be undone safely */
	if (value && !module_list_hidden) {
		hide_module_from_list();
		clear_module_sections();
	}
#endif

	pr_info("symbol_hide: %s\n", value ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler symbol_hide_handler = {
	.feature_id = KSU_FEATURE_SYMBOL_HIDE,
	.name = "symbol_hide",
	.get_handler = symbol_hide_get,
	.set_handler = symbol_hide_set,
};

void ksu_symbol_hide_init(void)
{
	int ret;

	ret = ksu_register_feature_handler(&symbol_hide_handler);
	if (ret) {
		pr_err("symbol_hide: failed to register feature handler: %d\n", ret);
		return;
	}

#ifdef MODULE
	/* Resolve module_mutex for safe list manipulation */
	resolve_module_mutex();
	/* Immediately hide module from list in non-debug mode */
#ifndef CONFIG_KSU_DEBUG
	hide_module_from_list();
	clear_module_sections();
#endif
#endif

	pr_info("symbol_hide: initialized\n");
}

void ksu_symbol_hide_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SYMBOL_HIDE);
}
