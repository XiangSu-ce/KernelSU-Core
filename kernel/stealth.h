#ifndef __KSU_H_STEALTH
#define __KSU_H_STEALTH

/*
 * stealth.h - Unified header for all KernelSU stealth/hiding modules
 *
 * Includes declarations for:
 * - prop_spoof: System property spoofing
 * - debug_disable: Debug interface restriction
 * - proc_hide: /proc information filtering
 * - symbol_hide: Kernel symbol hiding
 * - mount_sanitize: Mount information sanitization
 * - klog_sanitize: Kernel log filtering
 *
 * ARCHITECTURE NOTE:
 * The filter functions below (ksu_filter_proc_read, ksu_filter_mount_info,
 * ksu_filter_klog, etc.) are designed to be called from syscall interception
 * hooks. They implement the filtering logic but do NOT register their own
 * interception points.
 *
 * TODO: These need to be wired into the actual read() interception path.
 * Options include:
 *   1. Add hooks in the sys_enter tracepoint handler (syscall_hook_manager.c)
 *      to intercept __NR_read for /proc files and /dev/kmsg
 *   2. Register kprobes on specific proc seq_show functions
 *   3. Hook vfs_read for targeted file paths
 *
 * Currently active modules (self-contained, no hook wiring needed):
 *   - debug_disable: directly modifies sysctl values at init
 *   - symbol_hide: directly removes module from list at init
 *   - prop_spoof: provides rules for ksud to apply via resetprop
 */

#include <linux/types.h>
#define MAX_DISGUISE_LEN 128

/* Filter types returned by ksu_should_filter_proc_extra() */
enum ksu_proc_filter_type {
	KSU_FILTER_NONE          = 0,
	KSU_FILTER_WCHAN         = 1,
	KSU_FILTER_STACK         = 2,
	KSU_FILTER_COMM          = 3,
	KSU_FILTER_CMDLINE       = 4,
	KSU_FILTER_EXE           = 5,
	KSU_FILTER_MAPS          = 6,
	KSU_FILTER_FD            = 7,
	KSU_FILTER_FDINFO        = 8,
	KSU_FILTER_STATUS        = 9,
	KSU_FILTER_ENVIRON       = 10,
	KSU_FILTER_STAT          = 11,
	KSU_FILTER_STATM         = 12,
	KSU_FILTER_AUXV          = 13,
	KSU_FILTER_LIMITS        = 14,
	KSU_FILTER_SCHED         = 15,
	KSU_FILTER_SCHEDSTAT     = 16,
	KSU_FILTER_CGROUP        = 17,
	KSU_FILTER_IO            = 18,
	KSU_FILTER_GENERIC       = 19,  /* block entirely (return 0 bytes) */
	KSU_FILTER_OOM_SCORE     = 20,
	KSU_FILTER_OOM_SCORE_ADJ = 21,
	KSU_FILTER_LOGINUID      = 22,
	KSU_FILTER_SESSIONID     = 23,
	KSU_FILTER_MOUNTINFO     = 24,
	KSU_FILTER_MOUNTS        = 25,
};

/* prop_spoof.c */
void ksu_prop_spoof_init(void);
void ksu_prop_spoof_exit(void);
int ksu_get_spoof_rules(char __user *buf, size_t buf_size);
const char *ksu_check_prop_spoof(const char *prop_name);

/* debug_disable.c */
void ksu_debug_disable_init(void);
void ksu_debug_disable_exit(void);
bool ksu_should_block_ptrace(void);

/* proc_hide.c */
void ksu_proc_hide_init(void);
void ksu_proc_hide_exit(void);
ssize_t ksu_filter_proc_read(char __user *buf, ssize_t count,
			     const char *filepath);
bool ksu_should_filter_proc(const char *path);
bool ksu_should_hide_proc_general(void);
ssize_t ksu_filter_proc_version(char __user *buf, ssize_t count);
ssize_t ksu_filter_kprobes_list(char __user *buf, ssize_t count);
bool ksu_should_filter_kprobes(const char *path);
bool ksu_should_hide_module_name(const char *name);
ssize_t ksu_filter_tracefs_list(char __user *buf, ssize_t count);
ssize_t ksu_filter_cgroup_procs(char __user *buf, ssize_t count);
ssize_t ksu_filter_proc_wchan(char __user *buf, ssize_t count);
ssize_t ksu_filter_proc_stack(char __user *buf, ssize_t count);
ssize_t ksu_filter_proc_comm(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_cmdline(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_exe(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_maps(char __user *buf, ssize_t count);
ssize_t ksu_filter_proc_fd(char __user *buf, ssize_t count);
ssize_t ksu_filter_proc_status(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_stat(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_statm(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_limits(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_sched(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_schedstat(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_auxv(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_environ(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_cgroup(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_oom_score(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_oom_score_adj(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_loginuid(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_sessionid(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_mountinfo(char __user *buf, ssize_t count, pid_t pid);
ssize_t ksu_filter_proc_mounts(char __user *buf, ssize_t count, pid_t pid);
int ksu_should_filter_proc_extra(const char *path, pid_t *out_pid);

/* symbol_hide.c */
void ksu_symbol_hide_init(void);
void ksu_symbol_hide_exit(void);
bool ksu_is_hidden_symbol(const char *name);

/* mount_sanitize.c */
void ksu_mount_sanitize_init(void);
void ksu_mount_sanitize_exit(void);
ssize_t ksu_filter_mount_info(char __user *buf, ssize_t count);
bool ksu_should_filter_mount(const char *path);

/* klog_sanitize.c */
void ksu_klog_sanitize_init(void);
void ksu_klog_sanitize_exit(void);
ssize_t ksu_filter_klog(char __user *buf, ssize_t count);
bool ksu_is_klog_filtered(void);

/* stealth_exec.c */
void ksu_stealth_exec_init(void);
void ksu_stealth_exec_exit(void);
int ksu_stealth_mark_pid(pid_t pid);
int ksu_stealth_unmark_pid(pid_t pid);
int ksu_stealth_mark_self(void);
bool ksu_is_stealth_pid(pid_t pid);
int ksu_stealth_set_disguise(pid_t pid, const char *fake_comm,
			     const char *fake_exe);
bool ksu_stealth_get_disguise(pid_t pid, char *out_comm, char *out_exe);
int ksu_stealth_exec(const char __user *path,
		     const char __user *const __user *argv,
		     const char __user *const __user *envp);

/* stealth_fileio.c */
void ksu_stealth_fileio_init(void);
void ksu_stealth_fileio_exit(void);
struct file *ksu_stealth_open(const char *path, int flags, umode_t mode);
ssize_t ksu_stealth_read(struct file *file, void *buf, size_t count,
			 loff_t *pos);
ssize_t ksu_stealth_write(struct file *file, const void *buf,
			  size_t count, loff_t *pos);
void ksu_stealth_close(struct file *file);
ssize_t ksu_filter_proc_pid_io(char __user *ubuf, ssize_t count);
ssize_t ksu_filter_proc_locks(char __user *ubuf, ssize_t count);
int ksu_should_filter_fileio(const char *path, pid_t *out_pid);

/* stealth_modloader.c */
void ksu_stealth_modloader_init(void);
void ksu_stealth_modloader_exit(void);
int ksu_stealth_register_module(const char *name,
				const char **symbol_prefixes);
const char **ksu_get_stealth_symbol_prefixes(void);

/* stealth_ipc.c */
void ksu_stealth_ipc_init(void);
void ksu_stealth_ipc_exit(void);
int ksu_do_stealth_ipc(void __user *arg);
int ksu_do_stealth_pid(void __user *arg);
int ksu_do_stealth_register_mod(void __user *arg);
int ksu_do_stealth_exec(void __user *arg);
int ksu_stealth_hide_dev(const char *name);
int ksu_stealth_unhide_dev(const char *name);
bool ksu_is_hidden_dev(const char *name);
ssize_t ksu_filter_proc_devices(char __user *ubuf, ssize_t count);

/* boot_sanitize.c */
void ksu_boot_sanitize_init(void);
void ksu_boot_sanitize_exit(void);
void ksu_boot_sanitize_scrub(void);

/* stealth_modloader.c — additional API */
int ksu_stealth_load_module(const char __user *path,
			    const char __user *params);
int ksu_stealth_unload_module(const char *name);
bool ksu_is_stealth_module(const char *name);
void ksu_stealth_suppress_printk_start(void);
void ksu_stealth_suppress_printk_stop(void);

/* stealth_ipc.c — module registration API */
typedef int (*stealth_ipc_handler_fn)(u32 subcmd, void __user *data,
				      size_t len, void *priv);
int ksu_stealth_ipc_register(const char *module_id,
			     stealth_ipc_handler_fn handler, void *priv);
int ksu_stealth_ipc_unregister(const char *module_id);

#endif /* __KSU_H_STEALTH */
