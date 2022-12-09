/*
 * stealth_exec.c - Stealth process execution framework for KernelSU
 *
 * Provides infrastructure to execute userspace ELF binaries with complete
 * trace hiding. A "stealth process" is invisible in:
 * - ps / top (hidden from /proc/ directory listing)
 * - /proc/[pid]/exe, cmdline, comm, maps, status (disguised or empty)
 * - SELinux audit logs (execve not logged)
 *
 * Stealth PID set:
 * - Processes can be marked as stealth via supercall
 * - Child processes inherit stealth mark on fork
 * - Stealth mark is automatically removed on process exit
 *
 * The actual /proc filtering is done by proc_hide.c and
 * syscall_hook_manager.c querying ksu_is_stealth_pid().
 */

#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/bitmap.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "stealth.h"

/* ---- Stealth PID Bitmap ---- */

/*
 * We use a bitmap indexed by PID for O(1) lookup.
 * Android PID_MAX_DEFAULT is typically 32768.
 * We support up to 65536 PIDs.
 */
/*
 * Android PID_MAX_DEFAULT is typically 32768, but some kernels
 * allow higher values via /proc/sys/kernel/pid_max.
 * Use 131072 for safety margin.
 */
#define STEALTH_PID_MAX 131072

static DECLARE_BITMAP(stealth_pids, STEALTH_PID_MAX);
static DEFINE_SPINLOCK(stealth_pid_lock);

/* Process disguise information */
#define MAX_DISGUISED_PROCS 64

struct stealth_disguise {
	pid_t pid;
	char fake_comm[MAX_DISGUISE_LEN];
	char fake_exe[MAX_DISGUISE_LEN];
	bool active;
};

static struct stealth_disguise disguise_table[MAX_DISGUISED_PROCS];
static DEFINE_SPINLOCK(disguise_lock);

/* ---- PID Set Operations ---- */

/**
 * ksu_stealth_mark_pid() - Mark a PID as stealth.
 * @pid: process ID to mark
 *
 * Returns 0 on success, -EINVAL if pid out of range.
 */
int ksu_stealth_mark_pid(pid_t pid)
{
	unsigned long flags;
	struct task_struct *task;
	struct task_struct *t;
	struct task_struct *leader;

	if (pid <= 0 || pid >= STEALTH_PID_MAX)
		return -EINVAL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	leader = task->group_leader;
	spin_lock_irqsave(&stealth_pid_lock, flags);
	set_bit(leader->pid, stealth_pids);
	for_each_thread(leader, t)
		set_bit(t->pid, stealth_pids);
	spin_unlock_irqrestore(&stealth_pid_lock, flags);
	rcu_read_unlock();

	return 0;
}

/**
 * ksu_stealth_unmark_pid() - Remove stealth mark from a PID.
 */
int ksu_stealth_unmark_pid(pid_t pid)
{
	unsigned long flags;
	struct task_struct *task;
	struct task_struct *t;
	struct task_struct *leader;

	if (pid <= 0 || pid >= STEALTH_PID_MAX)
		return -EINVAL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	leader = task->group_leader;
	spin_lock_irqsave(&stealth_pid_lock, flags);
	clear_bit(leader->pid, stealth_pids);
	for_each_thread(leader, t)
		clear_bit(t->pid, stealth_pids);
	spin_unlock_irqrestore(&stealth_pid_lock, flags);

	/* Also clear any disguise entries for the whole thread group */
	spin_lock_irqsave(&disguise_lock, flags);
	t = leader;
	do {
		int i;
		for (i = 0; i < MAX_DISGUISED_PROCS; i++) {
			if (disguise_table[i].active &&
			    disguise_table[i].pid == t->pid) {
				disguise_table[i].active = false;
				break;
			}
		}
		t = next_thread(t);
	} while (t != leader);
	spin_unlock_irqrestore(&disguise_lock, flags);
	rcu_read_unlock();

	return 0;
}

/**
 * ksu_stealth_mark_self() - Mark current process as stealth.
 */
int ksu_stealth_mark_self(void)
{
	return ksu_stealth_mark_pid(current->pid);
}

/**
 * ksu_is_stealth_pid() - Check if a PID is marked as stealth.
 *
 * This is the primary query function used by proc_hide.c and
 * syscall_hook_manager.c to determine if a process should be hidden.
 *
 * Must be fast — called on every /proc read and getdents.
 */
bool ksu_is_stealth_pid(pid_t pid)
{
	if (pid <= 0 || pid >= STEALTH_PID_MAX)
		return false;
	return test_bit(pid, stealth_pids);
}

/* ---- Process Disguise ---- */

/**
 * ksu_stealth_set_disguise() - Set fake identity for a stealth process.
 * @pid: process ID
 * @fake_comm: fake process name (shown in /proc/[pid]/comm, status)
 * @fake_exe: fake executable path (shown in /proc/[pid]/exe readlink)
 *
 * If the process is not stealth-marked, this also marks it.
 */
int ksu_stealth_set_disguise(pid_t pid, const char *fake_comm,
			     const char *fake_exe)
{
	unsigned long flags;
	int i, slot = -1;

	if (pid <= 0 || pid >= STEALTH_PID_MAX)
		return -EINVAL;

	/* Ensure process is stealth-marked */
	ksu_stealth_mark_pid(pid);

	spin_lock_irqsave(&disguise_lock, flags);

	/* Find existing or free slot */
	for (i = 0; i < MAX_DISGUISED_PROCS; i++) {
		if (disguise_table[i].active &&
		    disguise_table[i].pid == pid) {
			slot = i;
			break;
		}
		if (!disguise_table[i].active && slot < 0)
			slot = i;
	}

	if (slot < 0) {
		spin_unlock_irqrestore(&disguise_lock, flags);
		return -ENOSPC;
	}

	disguise_table[slot].pid = pid;
	disguise_table[slot].active = true;

	if (fake_comm)
		strscpy(disguise_table[slot].fake_comm, fake_comm,
			MAX_DISGUISE_LEN);
	else
		disguise_table[slot].fake_comm[0] = '\0';

	if (fake_exe)
		strscpy(disguise_table[slot].fake_exe, fake_exe,
			MAX_DISGUISE_LEN);
	else
		disguise_table[slot].fake_exe[0] = '\0';

	spin_unlock_irqrestore(&disguise_lock, flags);
	return 0;
}

/**
 * ksu_stealth_get_disguise() - Get fake identity for a stealth process.
 * @pid: process ID
 * @out_comm: buffer for fake comm (at least MAX_DISGUISE_LEN), or NULL
 * @out_exe: buffer for fake exe (at least MAX_DISGUISE_LEN), or NULL
 *
 * Returns true if disguise exists, false otherwise.
 */
bool ksu_stealth_get_disguise(pid_t pid, char *out_comm, char *out_exe)
{
	unsigned long flags;
	int i;
	bool found = false;

	spin_lock_irqsave(&disguise_lock, flags);
	for (i = 0; i < MAX_DISGUISED_PROCS; i++) {
		if (disguise_table[i].active &&
		    disguise_table[i].pid == pid) {
			if (out_comm)
				strscpy(out_comm,
					disguise_table[i].fake_comm,
					MAX_DISGUISE_LEN);
			if (out_exe)
				strscpy(out_exe,
					disguise_table[i].fake_exe,
					MAX_DISGUISE_LEN);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&disguise_lock, flags);
	return found;
}

/* ---- Fork/Exit Hooks for Stealth Inheritance ---- */

#ifdef CONFIG_KRETPROBES

/*
 * Hook wake_up_new_task() to inherit stealth mark from parent.
 * wake_up_new_task is called after copy_process completes,
 * giving us access to the new task's PID.
 *
 * Uses a plain kprobe (not kretprobe) since we only need the entry
 * point and never need the return value. This avoids kretprobe
 * instance management overhead on the hot fork path.
 *
 * Prototype: void wake_up_new_task(struct task_struct *p)
 */
static int fork_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child =
		(struct task_struct *)PT_REGS_PARM1(regs);

	if (!child)
		return 0;

	/* Check if parent is stealth — child inherits the mark */
	if (ksu_is_stealth_pid(current->pid))
		ksu_stealth_mark_pid(child->pid);

	return 0;
}

static struct kprobe fork_kp = {
	.symbol_name = "wake_up_new_task",
	.pre_handler = fork_handler_pre,
};

/*
 * Hook do_exit() to clean up stealth mark on process exit.
 * Prototype: void __noreturn do_exit(long code)
 *
 * IMPORTANT: Only clear the CURRENT thread's stealth bit, not the
 * entire thread group. ksu_stealth_unmark_pid() clears all threads
 * in the group, which would expose sibling threads that are still
 * running in a multi-threaded stealth process.
 */
static void stealth_unmark_single(pid_t pid)
{
	unsigned long flags;
	int i;

	if (pid <= 0 || pid >= STEALTH_PID_MAX)
		return;

	spin_lock_irqsave(&stealth_pid_lock, flags);
	clear_bit(pid, stealth_pids);
	spin_unlock_irqrestore(&stealth_pid_lock, flags);

	/* Clear disguise entry for this specific thread only */
	spin_lock_irqsave(&disguise_lock, flags);
	for (i = 0; i < MAX_DISGUISED_PROCS; i++) {
		if (disguise_table[i].active &&
		    disguise_table[i].pid == pid) {
			disguise_table[i].active = false;
			break;
		}
	}
	spin_unlock_irqrestore(&disguise_lock, flags);
}

static int exit_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	pid_t pid = current->pid;

	if (ksu_is_stealth_pid(pid))
		stealth_unmark_single(pid);

	return 0;
}

static struct kprobe exit_kp = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	.symbol_name = "make_task_dead",
#else
	.symbol_name = "do_exit",
#endif
	.pre_handler = exit_handler_pre,
};

#endif /* CONFIG_KRETPROBES */

/* ---- Stealth Exec (fork+exec with auto-mark) ---- */

/**
 * ksu_stealth_exec() - Execute a binary in stealth mode.
 *
 * This is a placeholder for the supercall interface.
 * The actual execution flow:
 *   1. Userspace calls supercall STEALTH_EXEC
 *   2. KSU marks the calling process as stealth
 *   3. Userspace does the actual exec (the stealth mark inherits)
 *
 * The two-step approach avoids complex kernel-internal execve calls.
 */
int ksu_stealth_exec(const char __user *path,
		     const char __user *const __user *argv,
		     const char __user *const __user *envp)
{
	/* Mark current process as stealth before exec */
	ksu_stealth_mark_self();

	/*
	 * Actual exec is done by userspace after this supercall returns.
	 * The stealth mark will be inherited by the exec'd process
	 * (same PID after execve).
	 */
	return 0;
}

/* ---- Init/Exit ---- */

void ksu_stealth_exec_init(void)
{
#ifdef CONFIG_KRETPROBES
	int ret;

	bitmap_zero(stealth_pids, STEALTH_PID_MAX);
	memset(disguise_table, 0, sizeof(disguise_table));

	ret = register_kprobe(&fork_kp);
	if (ret)
		pr_err("stealth_exec: fork hook failed: %d\n", ret);

	ret = register_kprobe(&exit_kp);
	if (ret)
		pr_err("stealth_exec: exit hook failed: %d\n", ret);
#endif
}

void ksu_stealth_exec_exit(void)
{
#ifdef CONFIG_KRETPROBES
	unregister_kprobe(&exit_kp);
	unregister_kprobe(&fork_kp);
#endif
	bitmap_zero(stealth_pids, STEALTH_PID_MAX);
}
