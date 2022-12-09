#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"
#include "stealth.h"

struct cred *ksu_cred;

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOMEM;
    }

    ksu_feature_init();

    if (ksu_supercalls_init()) {
        pr_err("supercalls_init failed, abort\n");
        ksu_feature_exit();
        put_cred(ksu_cred);
        ksu_cred = NULL;
        return -EINVAL;
    }

    if (ksu_syscall_hook_manager_init()) {
        pr_err("syscall_hook_manager_init failed, abort\n");
        ksu_supercalls_exit();
        ksu_feature_exit();
        put_cred(ksu_cred);
        ksu_cred = NULL;
        return -EINVAL;
    }

    ksu_allowlist_init();

    ksu_throne_tracker_init();

    ksu_ksud_init();

    ksu_file_wrapper_init();

    /* Initialize stealth/hiding modules */
    ksu_prop_spoof_init();
    ksu_debug_disable_init();
    ksu_proc_hide_init();
    ksu_mount_sanitize_init();
    ksu_klog_sanitize_init();

    /* Initialize Phase 2 deep stealth infrastructure */
    ksu_stealth_modloader_init();
    ksu_stealth_exec_init();
    ksu_stealth_fileio_init();
    ksu_stealth_ipc_init();

    /* Pre-resolve symbols and scrub boot-time ring buffer traces */
    ksu_boot_sanitize_init();
    ksu_boot_sanitize_scrub();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    /* kobject_del must happen BEFORE symbol_hide zeroes the module name */
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif

    /*
     * symbol_hide_init MUST be last: it removes the module from the
     * modules list and zeroes the module name. Any kobject/sysfs
     * operations on THIS_MODULE must complete before this point.
     */
    ksu_symbol_hide_init();
    return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
    /*
     * Exit order: reverse of init.
     * symbol_hide MUST be first: it re-exposes the module before
     * any other cleanup touches sysfs/kobject.
     */
    ksu_symbol_hide_exit();

    /* Cleanup Phase 2 deep stealth infrastructure (reverse of init) */
    ksu_boot_sanitize_exit();
    ksu_stealth_ipc_exit();
    ksu_stealth_fileio_exit();
    ksu_stealth_exec_exit();
    ksu_stealth_modloader_exit();

    /* Cleanup stealth/hiding modules (reverse of init) */
    ksu_klog_sanitize_exit();
    ksu_mount_sanitize_exit();
    ksu_proc_hide_exit();
    ksu_debug_disable_exit();
    ksu_prop_spoof_exit();

    /* Core cleanup (reverse of init) */
    ksu_file_wrapper_exit();

    ksu_ksud_exit();

    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    ksu_feature_exit();

    if (ksu_cred) {
        put_cred(ksu_cred);
    }
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_AUTHOR("dawang (KernelSU Core)");
MODULE_DESCRIPTION("KernelSU Core - Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
