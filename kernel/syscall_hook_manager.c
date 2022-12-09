#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/printk.h"
#include "linux/kernel.h"
#include "selinux/selinux.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <trace/events/syscalls.h>
#include <linux/errno.h>

#include "allowlist.h"
#include "arch.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "syscall_hook_manager.h"
#include "sucompat.h"
#include "setuid_hook.h"
#include "selinux/selinux.h"
#include "stealth.h"
#include "util.h"
#include "ksud.h"
#include <linux/file.h>
#include <linux/string.h>

#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/limits.h>

// Tracepoint registration count management
// == 1: just us
// >  1: someone else is also using syscall tracepoint e.g. ftrace
static int tracepoint_reg_count = 0;
static DEFINE_SPINLOCK(tracepoint_reg_lock);

void ksu_clear_task_tracepoint_flag_if_needed(struct task_struct *t)
{
    unsigned long flags;
    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    if (tracepoint_reg_count <= 1) {
        ksu_clear_task_tracepoint_flag(t);
    }
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);
}


// Process marking management
static void handle_process_mark(bool mark)
{
    struct task_struct *p, *t;
    read_lock(&tasklist_lock);
    for_each_process_thread (p, t) {
        if (mark)
            ksu_set_task_tracepoint_flag(t);
        else
            ksu_clear_task_tracepoint_flag(t);
    }
    read_unlock(&tasklist_lock);
}

void ksu_mark_all_process(void)
{
    handle_process_mark(true);
    pr_info("hook_manager: mark all user process done!\n");
}

void ksu_unmark_all_process(void)
{
    handle_process_mark(false);
    pr_info("hook_manager: unmark all user process done!\n");
}

static void ksu_mark_running_process_locked()
{
    struct task_struct *p, *t;
    read_lock(&tasklist_lock);
    for_each_process_thread (p, t) {
        if (!t->mm) { // only user processes
            continue;
        }
        int uid = task_uid(t).val;
        const struct cred *cred = get_task_cred(t);
        bool ksu_root_process = uid == 0 && is_task_ksu_domain(cred);
        bool is_zygote_process = is_zygote(cred);
        bool is_shell = uid == 2000;
        // before boot completed, we shall mark init for marking zygote
        bool is_init = t->pid == 1;
        if (ksu_root_process || is_zygote_process || is_shell || is_init ||
            ksu_is_allow_uid(uid)) {
            ksu_set_task_tracepoint_flag(t);
            pr_info("hook_manager: mark process: pid:%d, uid: %d, comm:%s\n",
                    t->pid, uid, t->comm);
        } else {
            ksu_clear_task_tracepoint_flag(t);
            pr_info("hook_manager: unmark process: pid:%d, uid: %d, comm:%s\n",
                    t->pid, uid, t->comm);
        }
        put_cred(cred);
    }
    read_unlock(&tasklist_lock);
}

void ksu_mark_running_process()
{
    unsigned long flags;
    int count;

    /* Snapshot count under spinlock, then release before the
     * potentially expensive thread iteration to avoid holding
     * irqsave spinlock for an extended period. */
    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    count = tracepoint_reg_count;
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);

    if (count <= 1) {
        ksu_mark_running_process_locked();
    } else {
        pr_info(
            "hook_manager: not mark running process since syscall tracepoint is in use\n");
    }
}

// Get task mark status
// Returns: 1 if marked, 0 if not marked, -ESRCH if task not found
int ksu_get_task_mark(pid_t pid)
{
    struct task_struct *task;
    int marked = -ESRCH;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        marked = test_task_syscall_work(task, SYSCALL_TRACEPOINT) ? 1 : 0;
#else
        marked = test_tsk_thread_flag(task, TIF_SYSCALL_TRACEPOINT) ? 1 : 0;
#endif
        put_task_struct(task);
    } else {
        rcu_read_unlock();
    }

    return marked;
}

// Set task mark status
// Returns: 0 on success, -ESRCH if task not found
int ksu_set_task_mark(pid_t pid, bool mark)
{
    struct task_struct *task;
    int ret = -ESRCH;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();
        if (mark) {
            ksu_set_task_tracepoint_flag(task);
            pr_info("hook_manager: marked task pid=%d comm=%s\n", pid,
                    task->comm);
        } else {
            ksu_clear_task_tracepoint_flag(task);
            pr_info("hook_manager: unmarked task pid=%d comm=%s\n", pid,
                    task->comm);
        }
        put_task_struct(task);
        ret = 0;
    } else {
        rcu_read_unlock();
    }

    return ret;
}

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name,
                                        kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri,
                                   struct pt_regs *regs)
{
    unsigned long flags;
    int prev_count;

    /* Update count under lock, then release before the expensive
     * thread iteration to avoid holding irqsave spinlock too long. */
    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    prev_count = tracepoint_reg_count;
    tracepoint_reg_count++;
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);

    if (prev_count < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (prev_count == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    return 0;
}


static int syscall_unregfunc_handler(struct kretprobe_instance *ri,
                                     struct pt_regs *regs)
{
    unsigned long flags;
    int new_count;

    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    tracepoint_reg_count--;
    new_count = tracepoint_reg_count;
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);

    if (new_count <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (new_count == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

/* ---------- Read/pread64 post-filtering (stealth) ---------- */
#ifdef CONFIG_KRETPROBES

struct read_rp_data {
    int fd;
    char __user *buf;
};
struct readlink_rp_data {
    char __user *buf;
    int bufsiz;
    pid_t pid;
    bool match;
    int kind;
    char path[128];
    char ns_type[16];
    int fd_num;
};
struct path_rp_data {
    bool match;
    char path[128];
};
struct pid_rp_data {
    bool match;
    pid_t pid;
};

/* Global toggle: default ON */
static atomic_t stealth_filter_enabled = ATOMIC_INIT(1);

enum tracefs_kind {
	TRACEFS_NONE = 0,
	TRACEFS_TRACE = 1,
	TRACEFS_AVAIL_FUNCS = 2,
	TRACEFS_AVAIL_EVENTS = 3,
};

static bool ksu_match_tracefs_path(const char *path, int *kind_out);
static bool ksu_match_cgroup_pid_path(const char *path);
static bool ksu_match_sys_module_path(const char *path, char *mod,
				      size_t modlen);

static ssize_t ksu_filter_read_common(int fd, char __user *ubuf, ssize_t count)
{
    struct file *file;
    struct path path;
    char *tmp;
    char *res;
    ssize_t new_count = count;
    if (!atomic_read(&stealth_filter_enabled))
        return count;

    if (count <= 0 || !ubuf)
        return count;

    file = fget(fd);
    if (!file)
        return count;

    path = file->f_path;
    path_get(&path);
    fput(file);

    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!tmp) {
        path_put(&path);
        return count;
    }

    res = d_path(&path, tmp, PATH_MAX);
    path_put(&path);
    if (IS_ERR(res)) {
        kfree(tmp);
        return count;
    }

    {
        pid_t pid = 0;
        int extra = ksu_should_filter_proc_extra(res, &pid);
        if (extra != KSU_FILTER_NONE) {
            switch (extra) {
            case KSU_FILTER_WCHAN:
                new_count = ksu_filter_proc_wchan(ubuf, count);
                break;
            case KSU_FILTER_STACK:
                new_count = ksu_filter_proc_stack(ubuf, count);
                break;
            case KSU_FILTER_COMM:
                new_count = ksu_filter_proc_comm(ubuf, count, pid);
                break;
            case KSU_FILTER_CMDLINE:
                new_count = ksu_filter_proc_cmdline(ubuf, count, pid);
                break;
            case KSU_FILTER_EXE:
                new_count = ksu_filter_proc_exe(ubuf, count, pid);
                break;
            case KSU_FILTER_MAPS:
                new_count = ksu_filter_proc_maps(ubuf, count);
                break;
            case KSU_FILTER_FD:
            case KSU_FILTER_FDINFO:
                new_count = ksu_filter_proc_fd(ubuf, count);
                break;
            case KSU_FILTER_IO:
                new_count = ksu_filter_proc_pid_io(ubuf, count);
                break;
            case KSU_FILTER_STATUS:
                new_count = ksu_filter_proc_status(ubuf, count, pid);
                break;
            case KSU_FILTER_ENVIRON:
                new_count = ksu_filter_proc_environ(ubuf, count, pid);
                break;
            case KSU_FILTER_STAT:
                new_count = ksu_filter_proc_stat(ubuf, count, pid);
                break;
            case KSU_FILTER_STATM:
                new_count = ksu_filter_proc_statm(ubuf, count, pid);
                break;
            case KSU_FILTER_AUXV:
                new_count = ksu_filter_proc_auxv(ubuf, count, pid);
                break;
            case KSU_FILTER_LIMITS:
                new_count = ksu_filter_proc_limits(ubuf, count, pid);
                break;
            case KSU_FILTER_SCHED:
                new_count = ksu_filter_proc_sched(ubuf, count, pid);
                break;
            case KSU_FILTER_SCHEDSTAT:
                new_count = ksu_filter_proc_schedstat(ubuf, count, pid);
                break;
            case KSU_FILTER_CGROUP:
                new_count = ksu_filter_proc_cgroup(ubuf, count, pid);
                break;
            case KSU_FILTER_OOM_SCORE:
                new_count = ksu_filter_proc_oom_score(ubuf, count, pid);
                break;
            case KSU_FILTER_OOM_SCORE_ADJ:
                new_count = ksu_filter_proc_oom_score_adj(ubuf, count, pid);
                break;
            case KSU_FILTER_LOGINUID:
                new_count = ksu_filter_proc_loginuid(ubuf, count, pid);
                break;
            case KSU_FILTER_SESSIONID:
                new_count = ksu_filter_proc_sessionid(ubuf, count, pid);
                break;
            case KSU_FILTER_MOUNTINFO:
                new_count = ksu_filter_proc_mountinfo(ubuf, count, pid);
                break;
            case KSU_FILTER_MOUNTS:
                new_count = ksu_filter_proc_mounts(ubuf, count, pid);
                break;
            default:
                if (extra >= KSU_FILTER_GENERIC)
                    new_count = 0;
                break;
            }
        } else if (ksu_should_filter_proc(res)) {
            if (path_tail_eq(res, "/version"))
                new_count = ksu_filter_proc_version(ubuf, count);
            else
                new_count = ksu_filter_proc_read(ubuf, count, res);
        } else if (ksu_should_filter_mount(res)) {
            new_count = ksu_filter_mount_info(ubuf, count);
        } else if (strstr(res, "/dev/kmsg")) {
            new_count = ksu_filter_klog(ubuf, count);
        } else {
            int fio_type = ksu_should_filter_fileio(res, NULL);
            if (fio_type == 1)
                new_count = ksu_filter_proc_pid_io(ubuf, count);
            else if (fio_type == 2)
                new_count = ksu_filter_proc_locks(ubuf, count);
            else if (ksu_should_filter_kprobes(res))
                new_count = ksu_filter_kprobes_list(ubuf, count);
            else if (strcmp(res, "/proc/devices") == 0)
                new_count = ksu_filter_proc_devices(ubuf, count);
            else {
                int trace_kind = TRACEFS_NONE;
                char modname[64];

                if (ksu_match_cgroup_pid_path(res)) {
                    new_count = ksu_filter_cgroup_procs(ubuf, count);
                } else if (ksu_match_tracefs_path(res, &trace_kind)) {
                    if (trace_kind == TRACEFS_TRACE)
                        new_count = 0;
                    else
                        new_count = ksu_filter_tracefs_list(ubuf, count);
                } else if (ksu_match_sys_module_path(res, modname,
                                                     sizeof(modname)) &&
                           ksu_should_hide_module_name(modname)) {
                    new_count = 0;
                }
            }
        }
    }

    kfree(tmp);
    return new_count;
}

static bool ksu_match_stealth_proc_path(const char *path)
{
    const char *p;
    pid_t pid = 0;

    if (!ksu_should_hide_proc_general())
        return false;
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return false;

    p = path + 6;
    if (!strncmp(p, "self", 4) && (p[4] == '/' || p[4] == '\0')) {
        pid = current->tgid;
    } else if (!strncmp(p, "thread-self", 11) &&
               (p[11] == '/' || p[11] == '\0')) {
        pid = current->tgid;
    } else {
        while (*p >= '0' && *p <= '9' && pid < 10000000) {
            pid = pid * 10 + (*p - '0');
            p++;
        }
    }
    if (pid <= 0)
        return false;
    return ksu_is_stealth_pid(pid);
}

static bool ksu_match_tracefs_path(const char *path, int *kind_out)
{
    const char *tail;
    if (!ksu_should_hide_proc_general())
        return false;
    if (!path)
        return false;
    /* Only match files directly under the tracing root, not subdirectories */
    if (strncmp(path, "/sys/kernel/debug/tracing/", 26) == 0)
        tail = path + 26;
    else if (strncmp(path, "/sys/kernel/tracing/", 20) == 0)
        tail = path + 20;
    else
        return false;
    /* Reject paths with further '/' — those are subdirectory files */
    if (strchr(tail, '/'))
        return false;
    if (!strcmp(tail, "trace") || !strcmp(tail, "trace_pipe")) {
        if (kind_out)
            *kind_out = TRACEFS_TRACE;
        return true;
    }
    if (!strcmp(tail, "available_filter_functions")) {
        if (kind_out)
            *kind_out = TRACEFS_AVAIL_FUNCS;
        return true;
    }
    if (!strcmp(tail, "available_events")) {
        if (kind_out)
            *kind_out = TRACEFS_AVAIL_EVENTS;
        return true;
    }
    return false;
}

static bool ksu_match_cgroup_pid_path(const char *path)
{
    const char *base;
    if (!ksu_should_hide_proc_general())
        return false;
    if (!path || strncmp(path, "/sys/fs/cgroup/", 15) != 0)
        return false;
    base = strrchr(path, '/');
    if (!base || !*(base + 1))
        return false;
    base++;
    if (strcmp(base, "cgroup.procs") == 0)
        return true;
    if (strcmp(base, "tasks") == 0)
        return true;
    return false;
}

static bool ksu_match_sys_module_path(const char *path, char *mod,
                                      size_t modlen)
{
    const char *p;
    size_t i = 0;

    if (!ksu_should_hide_proc_general())
        return false;
    if (!path || !mod || modlen < 2 || strncmp(path, "/sys/module/", 12) != 0)
        return false;
    p = path + 12;
    if (!*p)
        return false;
    while (p[i] && p[i] != '/' && i < modlen - 1) {
        mod[i] = p[i];
        i++;
    }
    mod[i] = '\0';
    return i > 0;
}

static int procpath_entry_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    struct path_rp_data *data = (struct path_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user *path = (const char __user *)PT_REGS_PARM2(real_regs);
    long path_len;

    data->match = false;
    if (!path)
        return 1;
    path_len = strncpy_from_user_nofault(data->path, path, sizeof(data->path));
    if (path_len <= 0)
        return 1;
    if (path_len >= (long)sizeof(data->path))
        return 1;
    data->path[sizeof(data->path) - 1] = '\0';
    if (!ksu_match_stealth_proc_path(data->path))
        return 1;
    data->match = true;
    return 0;
}

static int procpath_ret_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct path_rp_data *data = (struct path_rp_data *)ri->data;
    long ret = (long)PT_REGS_RC(regs);

    if (!data || !data->match)
        return 0;
    if (ret >= 0)
        PT_REGS_RC(regs) = -ENOENT;
    return 0;
}

static int pidfd_entry_handler(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    pid_t pid = (pid_t)PT_REGS_PARM1(real_regs);

    data->match = false;
    data->pid = pid;
    if (!ksu_should_hide_proc_general())
        return 1;
    if (pid <= 0)
        return 1;
    if (!ksu_is_stealth_pid(pid))
        return 1;
    data->match = true;
    return 0;
}

static int pidfd_ret_handler(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;
    long ret = (long)PT_REGS_RC(regs);

    if (!data || !data->match)
        return 0;
    if (ret >= 0)
        PT_REGS_RC(regs) = -ESRCH;
    return 0;
}
static int kill_entry_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    pid_t pid = (pid_t)PT_REGS_PARM1(real_regs);

    data->match = false;
    data->pid = pid;
    if (!ksu_should_hide_proc_general())
        return 1;
    if (pid <= 0)
        return 1;
    if (!ksu_is_stealth_pid(pid))
        return 1;
    data->match = true;
    return 0;
}

static int tgkill_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    pid_t tgid = (pid_t)PT_REGS_PARM1(real_regs);
    pid_t tid = (pid_t)PT_REGS_PARM2(real_regs);

    data->match = false;
    data->pid = tid;
    if (!ksu_should_hide_proc_general())
        return 1;
    if ((tid > 0 && ksu_is_stealth_pid(tid)) ||
        (tgid > 0 && ksu_is_stealth_pid(tgid))) {
        data->match = true;
        return 0;
    }
    return 1;
}

static int tkill_entry_handler(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    pid_t tid = (pid_t)PT_REGS_PARM1(real_regs);

    data->match = false;
    data->pid = tid;
    if (!ksu_should_hide_proc_general())
        return 1;
    if (tid <= 0)
        return 1;
    if (!ksu_is_stealth_pid(tid))
        return 1;
    data->match = true;
    return 0;
}

static int pid_exist_ret_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct pid_rp_data *data = (struct pid_rp_data *)ri->data;

    if (!data || !data->match)
        return 0;
    PT_REGS_RC(regs) = -ESRCH;
    return 0;
}

static int read_entry_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct read_rp_data *data = (struct read_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    data->fd = (int)PT_REGS_PARM1(real_regs);
    data->buf = (char __user *)PT_REGS_PARM2(real_regs);
    return 0;
}

static int read_ret_handler(struct kretprobe_instance *ri,
                            struct pt_regs *regs)
{
    struct read_rp_data *data = (struct read_rp_data *)ri->data;
    ssize_t ret = (ssize_t)PT_REGS_RC(regs);
    ssize_t new_ret;

    if (!data || ret <= 0)
        return 0;

    new_ret = ksu_filter_read_common(data->fd, data->buf, ret);
    if (new_ret >= 0 && new_ret != ret)
        PT_REGS_RC(regs) = new_ret;
    return 0;
}

enum proc_link_kind {
    PROC_LINK_EXE = 1,
    PROC_LINK_CWD = 2,
    PROC_LINK_ROOT = 3,
    PROC_LINK_FD = 4,
    PROC_LINK_NS = 5,
};

static bool match_proc_link(const char *path, pid_t *pid_out, int *kind_out)
{
    const char *p;
    pid_t pid = 0;
	pid_t tid = 0;
	const char *tail;
	bool has_pid = false;
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return false;
    p = path + 6;
	if (!strncmp(p, "self", 4) && (p[4] == '/' || p[4] == '\0')) {
		pid = current->tgid;
		p += 4;
		has_pid = true;
	} else if (!strncmp(p, "thread-self", 11) &&
		   (p[11] == '/' || p[11] == '\0')) {
		pid = current->tgid;
		p += 11;
		has_pid = true;
	} else {
		while (*p >= '0' && *p <= '9' && pid < 10000000) {
			pid = pid * 10 + (*p - '0');
			p++;
		}
		if (pid <= 0)
			return false;
		has_pid = true;
	}
	if (!has_pid)
		return false;
	/* Handle /proc/<pid>/task/<tid>/... */
	if (!strncmp(p, "/task/", 6)) {
		p += 6;
		while (*p >= '0' && *p <= '9' && tid < 10000000) {
			tid = tid * 10 + (*p - '0');
			p++;
		}
		if (tid <= 0 || *p != '/')
			return false;
		p++; /* skip '/' */
		tail = p;
	} else if (*p == '/') {
		tail = p + 1;
	} else {
		return false;
	}

	if (strcmp(tail, "exe") == 0) {
        if (kind_out)
            *kind_out = PROC_LINK_EXE;
	} else if (strcmp(tail, "cwd") == 0) {
        if (kind_out)
            *kind_out = PROC_LINK_CWD;
	} else if (strcmp(tail, "root") == 0) {
        if (kind_out)
            *kind_out = PROC_LINK_ROOT;
	} else if (!strncmp(tail, "fd/", 3)) {
        if (kind_out)
            *kind_out = PROC_LINK_FD;
	} else if (!strncmp(tail, "ns/", 3)) {
        if (kind_out)
            *kind_out = PROC_LINK_NS;
    } else {
        return false;
    }
    if (pid_out)
        *pid_out = pid;
    return true;
}

static void fill_ns_type(struct readlink_rp_data *data)
{
    const char *ns;
    size_t i = 0;

    if (!data)
        return;
    data->ns_type[0] = '\0';

    ns = strstr(data->path, "/ns/");
    if (!ns)
        return;
    ns += 4;
    while (ns[i] && ns[i] != '/' && i < sizeof(data->ns_type) - 1) {
        data->ns_type[i] = ns[i];
        i++;
    }
    data->ns_type[i] = '\0';
}

static void fill_fd_num(struct readlink_rp_data *data)
{
    const char *fdp;
    int n = -1;

    if (!data)
        return;
    data->fd_num = -1;

    fdp = strstr(data->path, "/fd/");
    if (!fdp)
        return;
    fdp += 4;
    if (*fdp < '0' || *fdp > '9')
        return;
    n = 0;
    while (*fdp >= '0' && *fdp <= '9' && n < 10000000) {
        n = n * 10 + (*fdp - '0');
        fdp++;
    }
    data->fd_num = n;
}

static u32 ksu_hash_str(const char *s)
{
    u32 h = 0;

    if (!s)
        return 0;
    while (*s) {
        h = (h * 131) + (u32)(*s++);
    }
    return h;
}

static ssize_t write_link_path(char __user *buf, int bufsiz, const char *path)
{
    size_t len;
    if (!buf || bufsiz <= 0)
        return -EINVAL;
    len = strlen(path);
    if (len > (size_t)bufsiz)
        len = bufsiz;
    if (copy_to_user(buf, path, len))
        return -EFAULT;
    return (ssize_t)len;
}

static int readlinkat_entry_handler(struct kretprobe_instance *ri,
                                    struct pt_regs *regs)
{
    struct readlink_rp_data *data = (struct readlink_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user *path = (const char __user *)PT_REGS_PARM2(real_regs);
    long path_len;
    pid_t pid;

    data->match = false;
    data->ns_type[0] = '\0';
    data->fd_num = -1;
    if (!ksu_should_hide_proc_general())
        return 1;
    if (!path)
        return 1;
    path_len = strncpy_from_user_nofault(data->path, path, sizeof(data->path));
    if (path_len <= 0)
        return 1;
    if (path_len >= (long)sizeof(data->path))
        return 1;
    data->path[sizeof(data->path) - 1] = '\0';

    if (!match_proc_link(data->path, &pid, &data->kind))
        return 1;
    if (!ksu_is_stealth_pid(pid))
        return 1;
    if (data->kind == PROC_LINK_NS)
        fill_ns_type(data);
    else if (data->kind == PROC_LINK_FD)
        fill_fd_num(data);
    data->pid = pid;
    data->buf = (char __user *)PT_REGS_PARM3(real_regs);
    data->bufsiz = (int)PT_REGS_SYSCALL_PARM4(real_regs);
    data->match = true;
    return 0;
}

static int readlink_entry_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    struct readlink_rp_data *data = (struct readlink_rp_data *)ri->data;
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user *path = (const char __user *)PT_REGS_PARM1(real_regs);
    long path_len;
    pid_t pid;

    data->match = false;
    data->ns_type[0] = '\0';
    data->fd_num = -1;
    if (!ksu_should_hide_proc_general())
        return 1;
    if (!path)
        return 1;
    path_len = strncpy_from_user_nofault(data->path, path, sizeof(data->path));
    if (path_len <= 0)
        return 1;
    if (path_len >= (long)sizeof(data->path))
        return 1;
    data->path[sizeof(data->path) - 1] = '\0';

    if (!match_proc_link(data->path, &pid, &data->kind))
        return 1;
    if (!ksu_is_stealth_pid(pid))
        return 1;
    if (data->kind == PROC_LINK_NS)
        fill_ns_type(data);
    else if (data->kind == PROC_LINK_FD)
        fill_fd_num(data);

    data->pid = pid;
    data->buf = (char __user *)PT_REGS_PARM2(real_regs);
    data->bufsiz = (int)PT_REGS_PARM3(real_regs);
    data->match = true;
    return 0;
}

static int readlink_ret_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct readlink_rp_data *data = (struct readlink_rp_data *)ri->data;
    ssize_t new_ret;

    if (!data || !data->match)
        return 0;
    if (data->kind == PROC_LINK_EXE) {
        new_ret = ksu_filter_proc_exe(data->buf, data->bufsiz, data->pid);
        if (new_ret >= 0)
            PT_REGS_RC(regs) = new_ret;
    } else if (data->kind == PROC_LINK_CWD || data->kind == PROC_LINK_ROOT) {
        char fake_exe[MAX_DISGUISE_LEN];
        char dir_buf[MAX_DISGUISE_LEN];
        char *slash;

        if (!ksu_stealth_get_disguise(data->pid, NULL, fake_exe) ||
            fake_exe[0] == '\0') {
            strscpy(fake_exe, "/system/bin/logd", sizeof(fake_exe));
        }
        strscpy(dir_buf, fake_exe, sizeof(dir_buf));
        slash = strrchr(dir_buf, '/');
        if (slash && slash != dir_buf)
            *slash = '\0';
        else
            strscpy(dir_buf, "/", sizeof(dir_buf));

        if (data->kind == PROC_LINK_ROOT)
            new_ret = write_link_path(data->buf, data->bufsiz, "/");
        else
            new_ret = write_link_path(data->buf, data->bufsiz, dir_buf);

        if (new_ret >= 0)
            PT_REGS_RC(regs) = new_ret;
    } else if (data->kind == PROC_LINK_FD) {
        char fake_exe[MAX_DISGUISE_LEN];
        char dir_buf[MAX_DISGUISE_LEN];
        char fd_buf[MAX_DISGUISE_LEN];
        char *slash;
        const char *fd_path = NULL;
        u32 h;
        u32 inode;

        if (!ksu_stealth_get_disguise(data->pid, NULL, fake_exe) ||
            fake_exe[0] == '\0') {
            strscpy(fake_exe, "/system/bin/logd", sizeof(fake_exe));
        }
        strscpy(dir_buf, fake_exe, sizeof(dir_buf));
        slash = strrchr(dir_buf, '/');
        if (slash && slash != dir_buf)
            *slash = '\0';
        else
            strscpy(dir_buf, "/", sizeof(dir_buf));

        if (data->fd_num == 0 || data->fd_num == 1 || data->fd_num == 2) {
            fd_path = "/dev/null";
        } else if (data->fd_num >= 0) {
            h = (u32)data->pid * 1315423911u + (u32)data->fd_num * 2654435761u;
            inode = 40000 + (h % 100000);
            switch (h % 4) {
            case 0:
                snprintf(fd_buf, sizeof(fd_buf), "pipe:[%u]", inode);
                fd_path = fd_buf;
                break;
            case 1:
                snprintf(fd_buf, sizeof(fd_buf), "socket:[%u]", inode);
                fd_path = fd_buf;
                break;
            case 2:
                strscpy(fd_buf, "anon_inode:[eventfd]", sizeof(fd_buf));
                fd_path = fd_buf;
                break;
            default:
                if (strcmp(dir_buf, "/") == 0)
                    snprintf(fd_buf, sizeof(fd_buf), "/.fd/%d", data->fd_num);
                else
                    snprintf(fd_buf, sizeof(fd_buf), "%s/.fd/%d", dir_buf,
                             data->fd_num);
                fd_path = fd_buf;
                break;
            }
        } else {
            snprintf(fd_buf, sizeof(fd_buf), "%s/.fd", dir_buf);
            fd_path = fd_buf;
        }
        new_ret = write_link_path(data->buf, data->bufsiz, fd_path);
        if (new_ret >= 0)
            PT_REGS_RC(regs) = new_ret;
    } else if (data->kind == PROC_LINK_NS) {
        char ns_buf[32];
        const char *type = data->ns_type[0] ? data->ns_type : "mnt";
        u32 ino = 4026531840u + (ksu_hash_str(type) % 1024);

        snprintf(ns_buf, sizeof(ns_buf), "%s:[%u]", type, ino);
        new_ret = write_link_path(data->buf, data->bufsiz, ns_buf);
        if (new_ret >= 0)
            PT_REGS_RC(regs) = new_ret;
    }
    return 0;
}

static struct kretprobe read_rp = {
    .kp.symbol_name = SYS_READ_SYMBOL,
    .entry_handler = read_entry_handler,
    .handler = read_ret_handler,
    .data_size = sizeof(struct read_rp_data),
    .maxactive = 64,
};

static struct kretprobe pread_rp = {
    .kp.symbol_name = SYS_PREAD64_SYMBOL,
    .entry_handler = read_entry_handler,
    .handler = read_ret_handler,
    .data_size = sizeof(struct read_rp_data),
    .maxactive = 64,
};

static struct kretprobe newfstatat_rp = {
    .kp.symbol_name = SYS_NEWFSTATAT_SYMBOL,
    .entry_handler = procpath_entry_handler,
    .handler = procpath_ret_handler,
    .data_size = sizeof(struct path_rp_data),
    .maxactive = 64,
};

static struct kretprobe faccessat_rp = {
    .kp.symbol_name = SYS_FACCESSAT_SYMBOL,
    .entry_handler = procpath_entry_handler,
    .handler = procpath_ret_handler,
    .data_size = sizeof(struct path_rp_data),
    .maxactive = 64,
};

static struct kretprobe openat_rp = {
    .kp.symbol_name = SYS_OPENAT_SYMBOL,
    .entry_handler = procpath_entry_handler,
    .handler = procpath_ret_handler,
    .data_size = sizeof(struct path_rp_data),
    .maxactive = 64,
};

static struct kretprobe statx_rp = {
    .kp.symbol_name = SYS_STATX_SYMBOL,
    .entry_handler = procpath_entry_handler,
    .handler = procpath_ret_handler,
    .data_size = sizeof(struct path_rp_data),
    .maxactive = 64,
};

static struct kretprobe openat2_rp = {
    .kp.symbol_name = SYS_OPENAT2_SYMBOL,
    .entry_handler = procpath_entry_handler,
    .handler = procpath_ret_handler,
    .data_size = sizeof(struct path_rp_data),
    .maxactive = 64,
};

static struct kretprobe pidfd_open_rp = {
    .kp.symbol_name = SYS_PIDFD_OPEN_SYMBOL,
    .entry_handler = pidfd_entry_handler,
    .handler = pidfd_ret_handler,
    .data_size = sizeof(struct pid_rp_data),
    .maxactive = 64,
};
static struct kretprobe kill_rp = {
    .kp.symbol_name = SYS_KILL_SYMBOL,
    .entry_handler = kill_entry_handler,
    .handler = pid_exist_ret_handler,
    .data_size = sizeof(struct pid_rp_data),
    .maxactive = 64,
};

static struct kretprobe tgkill_rp = {
    .kp.symbol_name = SYS_TGKILL_SYMBOL,
    .entry_handler = tgkill_entry_handler,
    .handler = pid_exist_ret_handler,
    .data_size = sizeof(struct pid_rp_data),
    .maxactive = 64,
};

static struct kretprobe tkill_rp = {
    .kp.symbol_name = SYS_TKILL_SYMBOL,
    .entry_handler = tkill_entry_handler,
    .handler = pid_exist_ret_handler,
    .data_size = sizeof(struct pid_rp_data),
    .maxactive = 64,
};

static struct kretprobe readlink_rp = {
    .kp.symbol_name = SYS_READLINK_SYMBOL,
    .entry_handler = readlink_entry_handler,
    .handler = readlink_ret_handler,
    .data_size = sizeof(struct readlink_rp_data),
    .maxactive = 32,
};

static struct kretprobe readlinkat_rp = {
    .kp.symbol_name = SYS_READLINKAT_SYMBOL,
    .entry_handler = readlinkat_entry_handler,
    .handler = readlink_ret_handler,
    .data_size = sizeof(struct readlink_rp_data),
    .maxactive = 32,
};

/* Feature handler for global stealth filter enable/disable */
static int stealth_filter_get(u64 *value)
{
    *value = (u64)atomic_read(&stealth_filter_enabled);
    return 0;
}

static int stealth_filter_set(u64 value)
{
    atomic_set(&stealth_filter_enabled, value ? 1 : 0);
    pr_info("stealth_filter_io: %s\n", value ? "enabled" : "disabled");
    return 0;
}

static const struct ksu_feature_handler stealth_filter_handler = {
    .feature_id = KSU_FEATURE_STEALTH_FILTER_IO,
    .name = "stealth_filter_io",
    .get_handler = stealth_filter_get,
    .set_handler = stealth_filter_set,
};
#endif

static inline bool check_syscall_fastpath(int nr)
{
    switch (nr) {
    case __NR_newfstatat:
    case __NR_faccessat:
    case __NR_execve:
    case __NR_setresuid:
        return true;
    default:
        return false;
    }
}

// Unmark init's child that are not zygote, adbd or ksud
int ksu_handle_init_mark_tracker(const char __user **filename_user)
{
    char path[64];
    unsigned long addr;
    const char __user *fn;
    long ret;
    bool truncated = false;

    if (unlikely(!filename_user))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, fn, sizeof(path));
    if (ret < 0 && try_set_access_flag(addr)) {
        ret = strncpy_from_user_nofault(path, fn, sizeof(path));
        pr_info("ksu_handle_init_mark_tracker: %ld\n", ret);
    }
    if (ret <= 0)
        return 0;
    if (ret >= (long)sizeof(path))
        truncated = true;
    path[sizeof(path) - 1] = '\0';
    if (truncated)
        return 0;

    if (unlikely(strcmp(path, ksu_get_ksud_path()) == 0)) {
        pr_info("hook_manager: escape to root for init executing ksud: %d\n",
                current->pid);
        escape_to_root_for_init();
    } else if (likely(strstr(path, "/app_process") == NULL &&
                      strstr(path, "/adbd") == NULL)) {
        pr_info("hook_manager: unmark %d exec %s\n", current->pid, path);
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }

    return 0;
}

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// Generic sys_enter handler that dispatches to specific handlers
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
    if (unlikely(check_syscall_fastpath(id))) {
        if (ksu_su_compat_enabled) {
            // Handle newfstatat
            if (id == __NR_newfstatat) {
                int *dfd = (int *)&PT_REGS_PARM1(regs);
                const char __user **filename_user =
                    (const char __user **)&PT_REGS_PARM2(regs);
                int *flags = (int *)&PT_REGS_SYSCALL_PARM4(regs);
                ksu_handle_stat(dfd, filename_user, flags);
                return;
            }

            // Handle faccessat
            if (id == __NR_faccessat) {
                int *dfd = (int *)&PT_REGS_PARM1(regs);
                const char __user **filename_user =
                    (const char __user **)&PT_REGS_PARM2(regs);
                int *mode = (int *)&PT_REGS_PARM3(regs);
                ksu_handle_faccessat(dfd, filename_user, mode, NULL);
                return;
            }

            // Handle execve
            if (id == __NR_execve) {
                const char __user **filename_user =
                    (const char __user **)&PT_REGS_PARM1(regs);
                if (current->pid != 1 && is_init(get_current_cred())) {
                    ksu_handle_init_mark_tracker(filename_user);
                } else {
                    ksu_handle_execve_sucompat(filename_user, NULL, NULL, NULL);
                }
                return;
            }
        }

        // Handle setresuid
        if (id == __NR_setresuid) {
            uid_t ruid = (uid_t)PT_REGS_PARM1(regs);
            uid_t euid = (uid_t)PT_REGS_PARM2(regs);
            uid_t suid = (uid_t)PT_REGS_PARM3(regs);
            ksu_handle_setresuid(ruid, euid, suid);
            return;
        }
    }
}
#endif

int ksu_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: ksu_hook_manager_init called\n");

#ifdef CONFIG_KRETPROBES
    // Register kretprobe for syscall_regfunc
    syscall_regfunc_rp =
        init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    // Register kretprobe for syscall_unregfunc
    syscall_unregfunc_rp =
        init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);

    // Register kretprobes for read/pread64 post-filtering
    ret = register_kretprobe(&read_rp);
    if (ret)
        pr_err("hook_manager: register read_rp failed: %d\n", ret);
    ret = register_kretprobe(&pread_rp);
    if (ret)
        pr_err("hook_manager: register pread_rp failed: %d\n", ret);
    ret = register_kretprobe(&newfstatat_rp);
    if (ret)
        pr_err("hook_manager: register newfstatat_rp failed: %d\n", ret);
    ret = register_kretprobe(&faccessat_rp);
    if (ret)
        pr_err("hook_manager: register faccessat_rp failed: %d\n", ret);
    ret = register_kretprobe(&openat_rp);
    if (ret)
        pr_err("hook_manager: register openat_rp failed: %d\n", ret);
    ret = register_kretprobe(&statx_rp);
    if (ret)
        pr_err("hook_manager: register statx_rp failed: %d\n", ret);
    ret = register_kretprobe(&openat2_rp);
    if (ret)
        pr_err("hook_manager: register openat2_rp failed: %d\n", ret);
    ret = register_kretprobe(&pidfd_open_rp);
    if (ret)
        pr_err("hook_manager: register pidfd_open_rp failed: %d\n", ret);
    ret = register_kretprobe(&kill_rp);
    if (ret)
        pr_err("hook_manager: register kill_rp failed: %d\n", ret);
    ret = register_kretprobe(&tgkill_rp);
    if (ret)
        pr_err("hook_manager: register tgkill_rp failed: %d\n", ret);
    ret = register_kretprobe(&tkill_rp);
    if (ret)
        pr_err("hook_manager: register tkill_rp failed: %d\n", ret);
    ret = register_kretprobe(&readlink_rp);
    if (ret)
        pr_err("hook_manager: register readlink_rp failed: %d\n", ret);
    ret = register_kretprobe(&readlinkat_rp);
    if (ret)
        pr_err("hook_manager: register readlinkat_rp failed: %d\n", ret);

    ret = ksu_register_feature_handler(&stealth_filter_handler);
    if (ret)
        pr_err("hook_manager: register stealth_filter handler failed: %d\n",
               ret);
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_sys_enter(ksu_sys_enter_handler, NULL);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n",
               ret);
        return ret;
    }
    pr_info("hook_manager: sys_enter tracepoint registered\n");
#endif

    ksu_setuid_hook_init();
    ksu_sucompat_init();
    return 0;
}

void ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
    unregister_kretprobe(&read_rp);
    unregister_kretprobe(&pread_rp);
    unregister_kretprobe(&newfstatat_rp);
    unregister_kretprobe(&faccessat_rp);
    unregister_kretprobe(&openat_rp);
    unregister_kretprobe(&statx_rp);
    unregister_kretprobe(&openat2_rp);
    unregister_kretprobe(&pidfd_open_rp);
    unregister_kretprobe(&kill_rp);
    unregister_kretprobe(&tgkill_rp);
    unregister_kretprobe(&tkill_rp);
    unregister_kretprobe(&readlink_rp);
    unregister_kretprobe(&readlinkat_rp);
    ksu_unregister_feature_handler(KSU_FEATURE_STEALTH_FILTER_IO);
#endif

    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
