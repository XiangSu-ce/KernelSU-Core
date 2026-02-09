#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#ifdef CONFIG_KSU_SILENT
/* Silent mode: ALL ksu log output becomes no-op.
 * This includes pr_err and pr_alert to prevent any KSU string leakage. */
#define pr_fmt(fmt) "kernel: " fmt

#define ksu_log_noop(fmt, ...) do { } while (0)

#undef pr_info
#define pr_info(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)
#undef pr_warn
#define pr_warn(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)
#undef pr_notice
#define pr_notice(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)
#undef pr_debug
#define pr_debug(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)
#undef pr_err
#define pr_err(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)
#undef pr_alert
#define pr_alert(fmt, ...) ksu_log_noop(fmt, ##__VA_ARGS__)

/*
 * ksu_crit() - Only for truly fatal errors (OOM, etc.) where silence
 * would cause harder-to-debug kernel panics. Uses innocuous prefix.
 */
#define ksu_crit(fmt, ...) \
	printk(KERN_ERR "kernel: " fmt, ##__VA_ARGS__)

#else
#define pr_fmt(fmt) "KernelSU: " fmt

/* In non-silent mode, ksu_crit is just pr_err */
#define ksu_crit(fmt, ...) pr_err(fmt, ##__VA_ARGS__)

#endif /* CONFIG_KSU_SILENT */

#endif
