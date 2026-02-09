/*
 * debug_disable.c - Debug interface disabling for KernelSU
 *
 * Restricts access to debug interfaces that can reveal root/kernel modification.
 * Targets: ptrace, debugfs (kprobes list), dmesg, perf_event_open.
 *
 * This module operates through the KSU feature framework and can be
 * dynamically enabled/disabled via the manager app.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/sysctl.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>

#include "klog.h" // IWYU pragma: keep
#include "feature.h"
#include "allowlist.h"

/* Module enable state */
static atomic_t debug_disable_enabled = ATOMIC_INIT(1);

/* Protects orig_* values and p_* pointers during concurrent access */
static DEFINE_SPINLOCK(debug_lock);

/* Saved original sysctl values for restoration */
static int orig_dmesg_restrict = -1;
static int orig_kptr_restrict = -1;
static int orig_ptrace_scope = -1;

/*
 * Pointers to sysctl variables, resolved at init time.
 * Using pointers instead of extern declarations ensures MODULE compatibility
 * regardless of whether the symbols are exported.
 */
static int *p_dmesg_restrict;
static int *p_kptr_restrict;
static int *p_ptrace_scope;

/*
 * Check if the current process should be blocked from debug access.
 * Root/system/authorized processes are not restricted.
 */
static bool should_restrict_debug(void)
{
	uid_t uid;

	if (!atomic_read(&debug_disable_enabled))
		return false;

	uid = current_uid().val;

	/* Root, system, and shell are unrestricted */
	if (uid == 0 || uid == 1000 || uid == 2000)
		return false;

	/* KSU-authorized apps are unrestricted */
	if (ksu_is_allow_uid(uid))
		return false;

	return true;
}

/*
 * Apply restrictive sysctl values to hide debug information.
 * Called during initialization and when feature is enabled.
 * Must be called with debug_lock held.
 */
static void apply_debug_restrictions_locked(void)
{
	/* dmesg_restrict: blocks non-privileged dmesg reads */
	if (p_dmesg_restrict) {
		if (orig_dmesg_restrict < 0)
			orig_dmesg_restrict = *p_dmesg_restrict;
		*p_dmesg_restrict = 1;
	}

	/* kptr_restrict: hides kernel pointers in /proc/kallsyms */
	if (p_kptr_restrict) {
		if (orig_kptr_restrict < 0)
			orig_kptr_restrict = *p_kptr_restrict;
		*p_kptr_restrict = 2;
	}

	/* ptrace_scope: restricts ptrace attach */
	if (p_ptrace_scope) {
		if (orig_ptrace_scope < 0)
			orig_ptrace_scope = *p_ptrace_scope;
		*p_ptrace_scope = 2;
	}
}

static void apply_debug_restrictions(void)
{
	unsigned long flags;

	spin_lock_irqsave(&debug_lock, flags);
	apply_debug_restrictions_locked();
	spin_unlock_irqrestore(&debug_lock, flags);
	pr_info("debug_disable: restrictions applied\n");
}

/*
 * Restore original sysctl values.
 * Called when feature is disabled or module exits.
 */
static void restore_debug_settings(void)
{
	unsigned long flags;

	spin_lock_irqsave(&debug_lock, flags);
	if (p_dmesg_restrict && orig_dmesg_restrict >= 0) {
		*p_dmesg_restrict = orig_dmesg_restrict;
		orig_dmesg_restrict = -1;
	}

	if (p_kptr_restrict && orig_kptr_restrict >= 0) {
		*p_kptr_restrict = orig_kptr_restrict;
		orig_kptr_restrict = -1;
	}

	if (p_ptrace_scope && orig_ptrace_scope >= 0) {
		*p_ptrace_scope = orig_ptrace_scope;
		orig_ptrace_scope = -1;
	}
	spin_unlock_irqrestore(&debug_lock, flags);

	pr_info("debug_disable: restrictions removed\n");
}

/*
 * Check if ptrace should be blocked for the current process.
 * This is called from the syscall handler to intercept ptrace calls.
 */
bool ksu_should_block_ptrace(void)
{
	return should_restrict_debug();
}

/* Feature handler: get current enable state */
static int debug_disable_get(u64 *value)
{
	*value = (u64)atomic_read(&debug_disable_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int debug_disable_set(u64 value)
{
	bool enable = value ? true : false;
	atomic_set(&debug_disable_enabled, enable ? 1 : 0);

	if (enable)
		apply_debug_restrictions();
	else
		restore_debug_settings();

	pr_info("debug_disable: %s\n", enable ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler debug_disable_handler = {
	.feature_id = KSU_FEATURE_DEBUG_DISABLE,
	.name = "debug_disable",
	.get_handler = debug_disable_get,
	.set_handler = debug_disable_set,
};

/*
 * Resolve any kernel symbol address, including data symbols.
 *
 * Kprobes can ONLY be placed on executable/text symbols (functions).
 * Data symbols (e.g., dmesg_restrict, kptr_restrict) reside in .data/.bss
 * sections and cannot be probed — register_kprobe will fail.
 *
 * Strategy:
 * - Built-in: kallsyms_lookup_name() is directly available
 * - MODULE (kernel >= 5.7): kallsyms_lookup_name is not exported, so we
 *   first resolve IT via kprobe (it IS a function), then call it to
 *   resolve data symbols.
 */
#ifdef MODULE
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_addr;

static bool resolve_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (register_kprobe(&kp) < 0) {
		pr_warn("debug_disable: cannot resolve kallsyms_lookup_name\n");
		return false;
	}
	kln_addr = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return true;
}

static unsigned long ksu_lookup_name(const char *name)
{
	return kln_addr ? kln_addr(name) : 0;
}
#else
#include <linux/kallsyms.h>
static bool resolve_kln(void) { return true; }
static unsigned long ksu_lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

/*
 * Resolve sysctl variable addresses.
 * Must be called before apply_debug_restrictions().
 */
static void resolve_sysctl_symbols(void)
{
	unsigned long addr;

	if (!resolve_kln()) {
		pr_warn("debug_disable: symbol resolution unavailable\n");
		return;
	}

	addr = ksu_lookup_name("dmesg_restrict");
	p_dmesg_restrict = addr ? (int *)addr : NULL;

	addr = ksu_lookup_name("kptr_restrict");
	p_kptr_restrict = addr ? (int *)addr : NULL;

	/*
	 * ptrace_scope only exists when CONFIG_SECURITY_YAMA is enabled.
	 * ksu_lookup_name will return 0 if the symbol doesn't exist.
	 */
	addr = ksu_lookup_name("ptrace_scope");
	p_ptrace_scope = addr ? (int *)addr : NULL;

	pr_info("debug_disable: resolved sysctl symbols: dmesg=%s kptr=%s ptrace=%s\n",
		p_dmesg_restrict ? "yes" : "no",
		p_kptr_restrict ? "yes" : "no",
		p_ptrace_scope ? "yes" : "no");
}

void ksu_debug_disable_init(void)
{
	int ret;

	ret = ksu_register_feature_handler(&debug_disable_handler);
	if (ret) {
		pr_err("debug_disable: failed to register feature handler: %d\n", ret);
		return;
	}

	/* Resolve symbols first, then apply restrictions */
	resolve_sysctl_symbols();
	apply_debug_restrictions();

	pr_info("debug_disable: initialized\n");
}

void ksu_debug_disable_exit(void)
{
	restore_debug_settings();
	ksu_unregister_feature_handler(KSU_FEATURE_DEBUG_DISABLE);
}
