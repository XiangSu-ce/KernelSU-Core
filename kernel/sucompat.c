#include <linux/compiler_types.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>
#include <linux/string.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "sucompat.h"
#include "app_profile.h"
#include "util.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
    *value = ksu_su_compat_enabled ? 1 : 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_su_compat_enabled = enable;
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = "/system/bin/sh";

    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
    const char *path = ksu_get_ksud_path();
    return userspace_stack_buffer(path, strlen(path) + 1);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
                         int *__unused_flags)
{
    const char su[] = SU_PATH;
    long path_len;

    if (unlikely(!filename_user || !*filename_user)) {
        return 0;
    }

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    path_len = strncpy_from_user_nofault(path, *filename_user, sizeof(path));
    if (path_len <= 0 || path_len >= (long)sizeof(path))
        return 0;
    path[sizeof(path) - 1] = '\0';

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("faccessat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    // const char sh[] = SH_PATH;
    const char su[] = SU_PATH;
    long path_len;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    if (unlikely(!filename_user || !*filename_user)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    path_len = strncpy_from_user_nofault(path, *filename_user, sizeof(path));
    if (path_len <= 0 || path_len >= (long)sizeof(path))
        return 0;
    path[sizeof(path) - 1] = '\0';

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

int ksu_handle_execve_sucompat(const char __user **filename_user,
                               void *__never_use_argv, void *__never_use_envp,
                               int *__never_use_flags)
{
    const char su[] = SU_PATH;
    const char __user *fn;
    char path[sizeof(su) + 1];
    long ret;
    unsigned long addr;

    if (unlikely(!filename_user))
        return 0;
    if (unlikely(!*filename_user))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, fn, sizeof(path));

    if (ret < 0 && try_set_access_flag(addr)) {
        ret = strncpy_from_user_nofault(path, fn, sizeof(path));
    }

    if (ret < 0 && preempt_count()) {
        /*
         * DANGER: Temporarily drop preempt to allow page-fault handling.
         * This is intentionally unbalanced: we exit atomic context to let
         * the fault handler run, then immediately re-enter it.
         *
         * On PREEMPT_RT kernels this trick is unsafe because spinlocks
         * are sleeping locks and the scheduler state is different.
         * Skip the rescue path entirely in that case.
         */
#ifndef CONFIG_PREEMPT_RT
        pr_info("Access filename failed, try rescue..\n");
        preempt_enable_no_resched_notrace();
        ret = strncpy_from_user(path, fn, sizeof(path));
        preempt_disable_notrace();
#else
        pr_warn("Access filename failed in PREEMPT_RT, cannot rescue\n");
#endif
    }

    if (ret <= 0 || ret >= (long)sizeof(path)) {
        pr_warn("Access filename when execve failed: %ld", ret);
        return 0;
    }
    path[sizeof(path) - 1] = '\0';

    if (likely(memcmp(path, su, sizeof(su))))
        return 0;

    pr_info("sys_execve su found\n");
    fn = ksud_user_path();
    if (unlikely(!fn))
        return 0;
    *filename_user = fn;

    escape_with_root_profile();

    return 0;
}

// sucompat: permitted process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
