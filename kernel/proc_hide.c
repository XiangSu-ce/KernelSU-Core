/*
 * proc_hide.c - /proc filesystem information hiding for KernelSU
 *
 * Filters sensitive entries from /proc files to prevent root/KSU detection:
 * - /proc/kallsyms: hide ksu-related kernel symbols
 * - /proc/version: sanitize kernel version string
 * - /proc/mounts, /proc/self/mountinfo: hide overlay/bind mounts
 * - /proc/self/maps: hide ksu-related memory mappings
 * - /proc/modules: hide KSU module entry
 * - /proc/[pid]/wchan, stack: hide stealth process kernel traces
 * - /sys/kernel/debug/kprobes/list: hide ksu kprobes
 * - /proc/ getdents: hide stealth PID directories
 *
 * Provides filter functions that must be called from a read interception
 * hook (see stealth.h for integration details).
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/sched.h>

/* struct ksu_dirent64 — local definition for kernel portability.
 * We use our own name to avoid conflicts with any kernel-provided
 * linux_dirent64 definition. */
struct ksu_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

#define HIDE_MODE_NONE     0
#define HIDE_MODE_FD_MIN   1
#define HIDE_MODE_EMPTY    2
#define KSU_MAX_MODULE_NAME_LEN 64

static bool path_eq_or_subpath(const char *path, const char *base)
{
	size_t n;

	if (!path || !base)
		return false;
	n = strlen(base);
	return strncmp(path, base, n) == 0 &&
	       (path[n] == '\0' || (path[n] == '/' && path[n + 1] == '\0'));
}

static bool path_component_match(const char *path, const char *component)
{
	size_t n;

	if (!path || !component)
		return false;
	n = strlen(component);
	return strncmp(path, component, n) == 0 &&
	       (path[n] == '\0' || path[n] == '/');
}


static unsigned short ksu_dirent_reclen(const char *name)
{
	size_t len = strlen(name) + 1;
	size_t reclen = sizeof(struct ksu_dirent64) + len;

	return (unsigned short)ALIGN(reclen, sizeof(u64));
}

static ssize_t fill_min_fd_dir(char *kbuf, size_t size)
{
	static const char *names[] = { "0", "1", "2" };
	size_t off = 0;
	int i;

	for (i = 0; i < 3; i++) {
		unsigned short reclen = ksu_dirent_reclen(names[i]);
		struct ksu_dirent64 *de;

		if (off + reclen > size)
			break;
		de = (struct ksu_dirent64 *)(kbuf + off);
		de->d_ino = i + 1;
		de->d_off = 0;
		de->d_reclen = reclen;
		de->d_type = DT_LNK;
		memcpy(de->d_name, names[i], strlen(names[i]) + 1);
		off += reclen;
	}

	return off;
}

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "feature.h"
#include "allowlist.h"
#include "util.h"

/* Module enable state */
static atomic_t proc_hide_enabled = ATOMIC_INIT(1);

/* Strings to filter from /proc/kallsyms */
static const char *kallsyms_filter_strings[] = {
	"ksu_",
	"kernelsu",
	"kernel_su",
	"ksu ",		/* space-separated in kallsyms output */
	NULL
};

/* Strings to filter from /proc/mounts and mountinfo */
static const char *mount_filter_strings[] = {
	"/data/adb",
	"kernelsu",
	NULL
};

/* Strings to filter from /proc/modules */
static const char *module_filter_strings[] = {
	"kernelsu",
	NULL
};

/* Strings to filter from /proc/self/maps */
static const char *maps_filter_strings[] = {
	"kernelsu",
	"ksu_",
	"/data/adb/ksu",
	"/data/adb/modules",
	NULL
};

/* Strings to filter from /sys/kernel/debug/kprobes/list */
static const char *kprobes_filter_strings[] = {
	"ksu_",
	"kernelsu",
	"kernel_su",
	/* stealth module hooks — these symbol names appear in kprobes/list */
	"fsnotify",
	"fsnotify_parent",
	"__fsnotify_parent",
	"vfs_read",
	"vfs_write",
	"wake_up_new_task",
	"do_exit",
	"make_task_dead",
	"task_io_account_read",
	"task_io_account_write",
	/* syscall hook symbols (arch-specific wrappers) */
	"__arm64_sys_read",
	"__arm64_sys_pread64",
	"__arm64_sys_reboot",
	"__arm64_sys_getdents64",
	"__arm64_sys_newfstat",
	"__arm64_sys_newfstatat",
	"__arm64_sys_faccessat",
	"__arm64_sys_openat",
	"__arm64_sys_statx",
	"__arm64_sys_openat2",
	"__arm64_sys_pidfd_open",
	"__arm64_sys_kill",
	"__arm64_sys_tgkill",
	"__arm64_sys_tkill",
	"__arm64_sys_execve",
	"__arm64_sys_readlink",
	"__arm64_sys_readlinkat",
	"__x64_sys_read",
	"__x64_sys_pread64",
	"__x64_sys_reboot",
	"__x64_sys_getdents64",
	"__x64_sys_newfstat",
	"__x64_sys_newfstatat",
	"__x64_sys_faccessat",
	"__x64_sys_openat",
	"__x64_sys_statx",
	"__x64_sys_openat2",
	"__x64_sys_pidfd_open",
	"__x64_sys_kill",
	"__x64_sys_tgkill",
	"__x64_sys_tkill",
	"__x64_sys_execve",
	"__x64_sys_readlink",
	"__x64_sys_readlinkat",
	"ksys_getdents64",
	/* tracepoint management hooks */
	"syscall_regfunc",
	"syscall_unregfunc",
	/* kallsyms resolution hook (self-referential) */
	"kallsyms_lookup_name",
	/* lock source suppression hook */
	"locks_init_lock",
	"posix_lock_file",
	"flock_lock_file",
	"posix_test_lock",
	"locks_insert_lock",
	"locks_insert_block",
	"locks_copy_lock",
	NULL
};

/* Stealth subsystem declarations */
#include "stealth.h"

/*
 * Check if the current process should see filtered /proc data.
 */
static bool should_hide_proc(void)
{
	uid_t uid;

	if (!atomic_read(&proc_hide_enabled))
		return false;

	uid = current_uid().val;

	/* Root, system, shell see real data */
	if (uid == 0 || uid == 1000 || uid == 2000)
		return false;

	/* KSU-authorized apps see real data */
	if (ksu_is_allow_uid(uid))
		return false;

	return true;
}

bool ksu_should_hide_proc_general(void)
{
	return should_hide_proc();
}

/*
 * Check if a line contains any of the filter strings.
 */
static bool line_matches_filter(const char *line, const char **filters)
{
	const char **f;

	if (!line || !filters)
		return false;

	for (f = filters; *f; f++) {
		if (strstr(line, *f))
			return true;
	}

	return false;
}

/*
 * Extended match: check both static filters AND dynamic stealth prefixes.
 * Used for kallsyms and modules filtering.
 */
static bool line_matches_extended(const char *line, const char **static_filters)
{
	const char **dynamic;

	if (line_matches_filter(line, static_filters))
		return true;

	/* Also check stealth module prefixes */
	dynamic = ksu_get_stealth_symbol_prefixes();
	if (dynamic && line_matches_filter(line, dynamic))
		return true;

	return false;
}

/*
 * Filter buffer content line by line, removing lines that match filter strings.
 * Operates in-place on the buffer.
 * Returns new buffer length after filtering.
 */
static ssize_t filter_buffer_lines(char *buf, ssize_t len,
				   const char **filters)
{
	char *src, *dst, *line_start, *line_end;
	ssize_t new_len = 0;
	char *temp;

	if (!buf || len <= 0 || !filters)
		return len;

	/* Work on a temporary copy, +1 for null terminator at end */
	temp = kmalloc(len + 1, GFP_KERNEL);
	if (!temp)
		return len; /* On allocation failure, return unfiltered */

	memcpy(temp, buf, len);
	temp[len] = '\0'; /* Ensure last line is null-terminated for strstr */

	src = temp;
	dst = buf;
	line_start = src;

	while (line_start < src + len) {
		/* Find end of line */
		line_end = memchr(line_start, '\n', (src + len) - line_start);
		if (!line_end)
			line_end = src + len;
		else
			line_end++; /* Include the newline */

		/* Check if this line should be filtered */
		{
			size_t line_len = line_end - line_start;
			/*
			 * Temporarily null-terminate for strstr.
			 * Only safe when line_end is within the buffer.
			 * At buffer end, the line is already bounded by line_len.
			 */
			char saved = 0;
			bool need_restore = (line_end < src + len);
			if (need_restore) {
				saved = *line_end;
				*line_end = '\0';
			}

			if (!line_matches_filter(line_start, filters)) {
				/* Keep this line */
				memcpy(dst, line_start, line_len);
				dst += line_len;
				new_len += line_len;
			}

			if (need_restore)
				*line_end = saved;
		}

		line_start = line_end;
	}

	kfree(temp);
	return new_len;
}

/*
 * Filter /proc read output for the current process.
 * Called after the actual read syscall completes.
 *
 * @buf:      User-space buffer that was read into
 * @count:    Number of bytes actually read
 * @filepath: Path of the file being read
 *
 * Returns: new count after filtering, or original count if no filtering done.
 */
/*
 * Extended filter that checks both static and dynamic prefix lists.
 * Used for kallsyms and modules.
 */
static ssize_t filter_buffer_lines_extended(char *buf, ssize_t len,
					    const char **static_filters)
{
	char *src, *dst, *line_start, *line_end;
	ssize_t new_len = 0;
	char *temp;

	if (!buf || len <= 0)
		return len;

	temp = kmalloc(len + 1, GFP_KERNEL);
	if (!temp)
		return len;

	memcpy(temp, buf, len);
	temp[len] = '\0';

	src = temp;
	dst = buf;
	line_start = src;

	while (line_start < src + len) {
		line_end = memchr(line_start, '\n', (src + len) - line_start);
		if (!line_end)
			line_end = src + len;
		else
			line_end++;

		{
			size_t line_len = line_end - line_start;
			char saved = 0;
			bool need_restore = (line_end < src + len);
			if (need_restore) {
				saved = *line_end;
				*line_end = '\0';
			}

			if (!line_matches_extended(line_start, static_filters)) {
				memcpy(dst, line_start, line_len);
				dst += line_len;
				new_len += line_len;
			}

			if (need_restore)
				*line_end = saved;
		}

		line_start = line_end;
	}

	kfree(temp);
	return new_len;
}

ssize_t ksu_filter_proc_read(char __user *buf, ssize_t count,
			     const char *filepath)
{
	char *kbuf;
	ssize_t new_count;
	const char **filters = NULL;
	bool use_extended = false;

	if (!should_hide_proc() || count <= 0)
		return count;

	/* Determine which filters to apply */
	if (path_tail_eq(filepath, "/kallsyms")) {
		filters = kallsyms_filter_strings;
		use_extended = true;
	} else if (path_tail_eq(filepath, "/modules")) {
		filters = module_filter_strings;
		use_extended = true;
	} else if (path_tail_eq(filepath, "/mountinfo") ||
		   path_tail_eq(filepath, "/mounts")) {
		filters = mount_filter_strings;
	} else if (path_tail_eq(filepath, "/maps")) {
		filters = maps_filter_strings;
	} else {
		return count;
	}

	/* Copy buffer to kernel space for filtering */
	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	/* Apply filtering with optional dynamic prefix extension */
	if (use_extended)
		new_count = filter_buffer_lines_extended(kbuf, count, filters);
	else
		new_count = filter_buffer_lines(kbuf, count, filters);

	/* Copy filtered data back */
	if (new_count != count) {
		if (copy_to_user(buf, kbuf, new_count)) {
			kfree(kbuf);
			return count;
		}
	}

	kfree(kbuf);
	return new_count;
}

/*
 * Check if a file path is a /proc path that needs filtering.
 */
bool ksu_should_filter_proc(const char *path)
{
	if (!should_hide_proc() || !path)
		return false;

	if (strncmp(path, "/proc/", 6) != 0)
		return false;

	return (path_tail_eq(path, "/kallsyms") ||
		path_tail_eq(path, "/modules") ||
		path_tail_eq(path, "/mounts") ||
		path_tail_eq(path, "/mountinfo") ||
		path_tail_eq(path, "/maps") ||
		path_tail_eq(path, "/version"));
}

/* ---- debugfs kprobes/list filtering ---- */

/**
 * ksu_filter_kprobes_list() - Filter /sys/kernel/debug/kprobes/list.
 *
 * Removes lines containing ksu-related kprobe symbols and
 * stealth module kprobe hooks.
 */
ssize_t ksu_filter_kprobes_list(char __user *buf, ssize_t count)
{
	char *kbuf;
	ssize_t new_count;

	/* Root/system/shell see real kprobes data for debugging */
	if (!should_hide_proc() || count <= 0)
		return count;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	new_count = filter_buffer_lines_extended(kbuf, count,
						 kprobes_filter_strings);

	if (new_count != count) {
		if (copy_to_user(buf, kbuf, new_count)) {
			kfree(kbuf);
			return count;
		}
	}

	kfree(kbuf);
	return new_count;
}

/**
 * ksu_should_filter_kprobes() - Check if path is kprobes debug file.
 */
bool ksu_should_filter_kprobes(const char *path)
{
	if (!path)
		return false;
	if (path_tail_eq(path, "/kprobes/list"))
		return true;
	if (path_tail_eq(path, "/kprobe_events"))
		return true;
	if (path_tail_eq(path, "/uprobe_events"))
		return true;
	return false;
}

bool ksu_should_hide_module_name(const char *name)
{
	if (!should_hide_proc())
		return false;
	if (!name || !*name)
		return false;
	if (ksu_is_stealth_module(name))
		return true;
	if (line_matches_extended(name, module_filter_strings))
		return true;
	return false;
}

ssize_t ksu_filter_tracefs_list(char __user *buf, ssize_t count)
{
	char *kbuf;
	ssize_t new_count;

	if (!should_hide_proc() || count <= 0)
		return count;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	new_count = filter_buffer_lines_extended(kbuf, count,
						 kprobes_filter_strings);

	if (new_count != count) {
		if (copy_to_user(buf, kbuf, new_count)) {
			kfree(kbuf);
			return count;
		}
	}

	kfree(kbuf);
	return new_count;
}

static bool parse_pid_line(const char *line, size_t len, pid_t *pid_out)
{
	size_t i = 0;
	pid_t pid = 0;
	bool has = false;

	if (!line || len == 0)
		return false;

	while (i < len && (line[i] == ' ' || line[i] == '\t'))
		i++;
	while (i < len && line[i] >= '0' && line[i] <= '9' &&
	       pid < 10000000) {
		has = true;
		pid = pid * 10 + (line[i] - '0');
		i++;
	}
	if (!has)
		return false;
	if (pid_out)
		*pid_out = pid;
	return true;
}

ssize_t ksu_filter_cgroup_procs(char __user *buf, ssize_t count)
{
	char *kbuf;
	char *src, *dst, *line_start, *line_end;
	ssize_t new_len = 0;
	char *temp;

	if (!should_hide_proc() || count <= 0)
		return count;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	temp = kmalloc(count + 1, GFP_KERNEL);
	if (!temp) {
		kfree(kbuf);
		return count;
	}
	memcpy(temp, kbuf, count);
	temp[count] = '\0';

	src = temp;
	dst = kbuf;
	line_start = src;

	while (line_start < src + count) {
		line_end = memchr(line_start, '\n', (src + count) - line_start);
		if (!line_end)
			line_end = src + count;
		else
			line_end++;

		{
			size_t line_len = line_end - line_start;
			pid_t pid = 0;
			bool skip = false;

			if (parse_pid_line(line_start, line_len, &pid)) {
				if (pid > 0 && ksu_is_stealth_pid(pid))
					skip = true;
			}
			if (!skip) {
				memcpy(dst, line_start, line_len);
				dst += line_len;
				new_len += line_len;
			}
		}

		line_start = line_end;
	}

	if (new_len != count) {
		if (copy_to_user(buf, kbuf, new_len)) {
			kfree(temp);
			kfree(kbuf);
			return count;
		}
	}

	kfree(temp);
	kfree(kbuf);
	return new_len;
}

/* ---- Stealth PID /proc entry hiding ---- */

/**
 * ksu_filter_proc_wchan() - Return fake wchan for stealth PIDs.
 *
 * /proc/[pid]/wchan shows the kernel function where a process sleeps.
 * For stealth PIDs, return "0" to appear as a non-sleeping process.
 */
ssize_t ksu_filter_proc_wchan(char __user *buf, ssize_t count)
{
	if (count <= 0)
		return count;

	if (copy_to_user(buf, "0", 1))
		return count;

	return 1;
}

/**
 * ksu_filter_proc_stack() - Return empty stack for stealth PIDs.
 */
ssize_t ksu_filter_proc_stack(char __user *buf, ssize_t count)
{
	/* Return 0 bytes — empty stack */
	return 0;
}

/* ---- Stealth PID misc (/proc/[pid]/exe,cmdline,comm,maps,fd) ---- */

static const char *default_fake_comm = "logd";
static const char *default_fake_exe = "/system/bin/logd";

static void get_disguise(pid_t pid, char *comm_buf, char *exe_buf)
{
	char comm_tmp[MAX_DISGUISE_LEN] = { 0 };
	char exe_tmp[MAX_DISGUISE_LEN] = { 0 };
	bool ok = ksu_stealth_get_disguise(pid, comm_tmp, exe_tmp);

	if (!ok || comm_tmp[0] == '\0')
		strscpy(comm_tmp, default_fake_comm, MAX_DISGUISE_LEN);
	if (!ok || exe_tmp[0] == '\0')
		strscpy(exe_tmp, default_fake_exe, MAX_DISGUISE_LEN);

	if (comm_buf)
		strscpy(comm_buf, comm_tmp, MAX_DISGUISE_LEN);
	if (exe_buf)
		strscpy(exe_buf, exe_tmp, MAX_DISGUISE_LEN);
}

static ssize_t write_text_buf(char __user *buf, ssize_t count, const char *text)
{
	size_t len;

	if (!buf || count <= 0 || !text)
		return count;

	len = strlen(text);
	if (len > (size_t)count)
		len = count;
	if (copy_to_user(buf, text, len))
		return count;
	return (ssize_t)len;
}

static void sanitize_comm(char *comm)
{
	char *p;

	if (!comm)
		return;
	for (p = comm; *p; p++) {
		if (*p == ')' || *p == '(')
			*p = '_';
	}
}
ssize_t ksu_filter_proc_comm(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_comm[MAX_DISGUISE_LEN];
	char tmp[MAX_DISGUISE_LEN + 2];
	size_t len;

	if (count <= 0)
		return count;

	get_disguise(pid, fake_comm, NULL);

	len = strscpy(tmp, fake_comm, sizeof(tmp));
	if (len < 0)
		len = 0;
	if (len < sizeof(tmp) - 1)
		tmp[len++] = '\n';
	if (len > (size_t)count)
		len = count;
	if (copy_to_user(buf, tmp, len))
		return count;
	return len;
}

ssize_t ksu_filter_proc_cmdline(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_exe[MAX_DISGUISE_LEN];
	size_t len;

	if (count <= 0)
		return count;

	get_disguise(pid, NULL, fake_exe);
	len = strlen(fake_exe);
	if (len + 1 > (size_t)count)
		len = count;
	else
		len += 1; /* include trailing NUL */
	if (copy_to_user(buf, fake_exe, len))
		return count;
	return len;
}

ssize_t ksu_filter_proc_exe(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_exe[MAX_DISGUISE_LEN];
	size_t len;

	if (count <= 0)
		return count;

	get_disguise(pid, NULL, fake_exe);
	len = strlen(fake_exe);
	if (len > count)
		len = count;
	if (copy_to_user(buf, fake_exe, len))
		return count;
	return len;
}

ssize_t ksu_filter_proc_maps(char __user *buf, ssize_t count)
{
	/* Hide all mappings */
	return 0;
}

ssize_t ksu_filter_proc_fd(char __user *buf, ssize_t count)
{
	/* Hide fd/fdinfo contents */
	return 0;
}
ssize_t ksu_filter_proc_status(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_comm[MAX_DISGUISE_LEN];
	char tmp[512];
	int n;
	size_t len;

	if (count <= 0)
		return count;

	get_disguise(pid, fake_comm, NULL);
	sanitize_comm(fake_comm);

	n = snprintf(tmp, sizeof(tmp),
		     "Name:\t%s\n"
		     "State:\tS (sleeping)\n"
		     "Tgid:\t%d\n"
		     "Pid:\t%d\n"
		     "PPid:\t1\n"
		     "Uid:\t0\t0\t0\t0\n"
		     "Gid:\t0\t0\t0\t0\n"
		     "Threads:\t1\n",
		     fake_comm, pid, pid);
	if (n < 0)
		return count;
	if (n >= (int)sizeof(tmp))
		len = sizeof(tmp) - 1;
	else
		len = (size_t)n;
	if (len > (size_t)count)
		len = count;
	if (copy_to_user(buf, tmp, len))
		return count;
	return len;
}

ssize_t ksu_filter_proc_stat(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_comm[MAX_DISGUISE_LEN];
	char tmp[512];
	int n;
	size_t len;

	if (count <= 0)
		return count;

	get_disguise(pid, fake_comm, NULL);
	sanitize_comm(fake_comm);

	n = snprintf(tmp, sizeof(tmp),
		     "%d (%s) S 1 %d %d 0 -1 0 "
		     "0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
		     "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
		     pid, fake_comm, pid, pid);
	if (n < 0)
		return count;
	if (n >= (int)sizeof(tmp))
		len = sizeof(tmp) - 1;
	else
		len = (size_t)n;
	if (len > (size_t)count)
		len = count;
	if (copy_to_user(buf, tmp, len))
		return count;
	return len;
}

ssize_t ksu_filter_proc_statm(char __user *buf, ssize_t count, pid_t pid)
{
	static const char statm[] = "0 0 0 0 0 0 0\n";

	(void)pid;
	return write_text_buf(buf, count, statm);
}

ssize_t ksu_filter_proc_limits(char __user *buf, ssize_t count, pid_t pid)
{
	static const char limits[] =
		"Limit                     Soft Limit           Hard Limit           Units\n"
		"Max open files            1024                 4096                 files\n";

	(void)pid;
	return write_text_buf(buf, count, limits);
}

ssize_t ksu_filter_proc_sched(char __user *buf, ssize_t count, pid_t pid)
{
	static const char sched[] =
		"se.exec_start                             : 0\n"
		"se.vruntime                               : 0\n"
		"se.sum_exec_runtime                       : 0\n"
		"se.nr_migrations                          : 0\n"
		"policy                                    : 0\n"
		"prio                                      : 120\n";

	(void)pid;
	return write_text_buf(buf, count, sched);
}

ssize_t ksu_filter_proc_schedstat(char __user *buf, ssize_t count, pid_t pid)
{
	static const char schedstat[] = "0 0 0\n";

	(void)pid;
	return write_text_buf(buf, count, schedstat);
}

ssize_t ksu_filter_proc_auxv(char __user *buf, ssize_t count, pid_t pid)
{
	static const char auxv[] = "0 0\n";

	(void)pid;
	return write_text_buf(buf, count, auxv);
}

ssize_t ksu_filter_proc_environ(char __user *buf, ssize_t count, pid_t pid)
{
	static const char env[] = "PATH=/system/bin\0";

	(void)pid;
	if (!buf || count <= 0)
		return count;
	if (count > (ssize_t)sizeof(env))
		count = sizeof(env);
	if (copy_to_user(buf, env, count))
		return count;
	return count;
}

ssize_t ksu_filter_proc_cgroup(char __user *buf, ssize_t count, pid_t pid)
{
	static const char cgroup[] = "0::/\n";

	(void)pid;
	return write_text_buf(buf, count, cgroup);
}

ssize_t ksu_filter_proc_oom_score(char __user *buf, ssize_t count, pid_t pid)
{
	static const char oom_score[] = "0\n";

	(void)pid;
	return write_text_buf(buf, count, oom_score);
}

ssize_t ksu_filter_proc_oom_score_adj(char __user *buf, ssize_t count, pid_t pid)
{
	static const char oom_score_adj[] = "0\n";

	(void)pid;
	return write_text_buf(buf, count, oom_score_adj);
}

ssize_t ksu_filter_proc_loginuid(char __user *buf, ssize_t count, pid_t pid)
{
	static const char loginuid[] = "0\n";

	(void)pid;
	return write_text_buf(buf, count, loginuid);
}

ssize_t ksu_filter_proc_sessionid(char __user *buf, ssize_t count, pid_t pid)
{
	static const char sessionid[] = "0\n";

	(void)pid;
	return write_text_buf(buf, count, sessionid);
}

ssize_t ksu_filter_proc_mountinfo(char __user *buf, ssize_t count, pid_t pid)
{
	static const char mountinfo[] = "0 0 0:0 / / ro - rootfs rootfs ro\n";

	(void)pid;
	return write_text_buf(buf, count, mountinfo);
}

ssize_t ksu_filter_proc_mounts(char __user *buf, ssize_t count, pid_t pid)
{
	static const char mounts[] = "rootfs / rootfs ro 0 0\n";

	(void)pid;
	return write_text_buf(buf, count, mounts);
}

/**
 * ksu_should_filter_proc_extra() - Classify /proc/[stealth_pid]/<file> reads.
 * @path: file path being read
 * @out_pid: if non-NULL, receives the parsed PID
 *
 * Returns: enum ksu_proc_filter_type value identifying the filter to apply,
 *          or KSU_FILTER_NONE if the path does not match a stealth PID.
 */
int ksu_should_filter_proc_extra(const char *path, pid_t *out_pid)
{
	const char *p;
	pid_t pid;
	bool is_task = false;
	bool has_pid = false;

	if (!path || strncmp(path, "/proc/", 6) != 0)
		return KSU_FILTER_NONE;

	p = path + 6;
	pid = 0;
	if (!strncmp(p, "self", 4) && (p[4] == '/' || p[4] == '\0')) {
		pid = current->tgid;
		p += 4;
		has_pid = true;
	} else if (!strncmp(p, "thread-self", 11) &&
		   (p[11] == '/' || p[11] == '\0')) {
		pid = current->tgid;
		p += 11;
		is_task = true;
		has_pid = true;
	} else {
		while (*p >= '0' && *p <= '9' && pid < 10000000) {
			pid = pid * 10 + (*p - '0');
			p++;
		}
		if (pid <= 0)
			return KSU_FILTER_NONE;
		has_pid = true;
	}

	if (!has_pid || !ksu_is_stealth_pid(pid))
		return KSU_FILTER_NONE;

	if (out_pid)
		*out_pid = pid;
	/* Support /proc/<pid>/task/<tid>/... */
	if (!strncmp(p, "/task/", 6)) {
		p += 6;
		pid_t tid = 0;
		while (*p >= '0' && *p <= '9' && tid < 10000000) {
			tid = tid * 10 + (*p - '0');
			p++;
		}
		if (tid <= 0 || *p != '/')
			return KSU_FILTER_NONE;
		is_task = true;
		/* p already points at '/' of the tail */
	}

	if (strcmp(p, "/wchan") == 0)
		return KSU_FILTER_WCHAN;
	if (strcmp(p, "/stack") == 0)
		return KSU_FILTER_STACK;
	if (strcmp(p, "/comm") == 0)
		return KSU_FILTER_COMM;
	if (strcmp(p, "/cmdline") == 0)
		return KSU_FILTER_CMDLINE;
	if (strcmp(p, "/exe") == 0)
		return KSU_FILTER_EXE;
	if (strcmp(p, "/maps") == 0 ||
	    strcmp(p, "/smaps") == 0 ||
	    strcmp(p, "/smaps_rollup") == 0)
		return KSU_FILTER_MAPS;
	if (strcmp(p, "/io") == 0)
		return KSU_FILTER_IO;
	if (path_component_match(p, "/fd"))
		return KSU_FILTER_FD;
	if (path_component_match(p, "/fdinfo"))
		return KSU_FILTER_FDINFO;
	if (path_component_match(p, "/map_files"))
		return KSU_FILTER_MAPS;
	if (path_component_match(p, "/task"))
		return KSU_FILTER_FD;
	if (path_component_match(p, "/attr"))
		return KSU_FILTER_GENERIC;
	if (strcmp(p, "/ns") == 0 || strcmp(p, "/ns/") == 0)
		return KSU_FILTER_FD;
	if (strcmp(p, "/status") == 0)
		return KSU_FILTER_STATUS;
	if (strcmp(p, "/environ") == 0)
		return KSU_FILTER_ENVIRON;
	if (strcmp(p, "/stat") == 0)
		return KSU_FILTER_STAT;
	if (strcmp(p, "/statm") == 0)
		return KSU_FILTER_STATM;
	if (strcmp(p, "/auxv") == 0)
		return KSU_FILTER_AUXV;
	if (strcmp(p, "/limits") == 0)
		return KSU_FILTER_LIMITS;
	if (strcmp(p, "/sched") == 0)
		return KSU_FILTER_SCHED;
	if (strcmp(p, "/schedstat") == 0)
		return KSU_FILTER_SCHEDSTAT;
	if (strcmp(p, "/cgroup") == 0)
		return KSU_FILTER_CGROUP;
	if (strcmp(p, "/oom_score") == 0)
		return KSU_FILTER_OOM_SCORE;
	if (strcmp(p, "/oom_score_adj") == 0)
		return KSU_FILTER_OOM_SCORE_ADJ;
	if (strcmp(p, "/loginuid") == 0)
		return KSU_FILTER_LOGINUID;
	if (strcmp(p, "/sessionid") == 0)
		return KSU_FILTER_SESSIONID;
	if (strcmp(p, "/mountinfo") == 0)
		return KSU_FILTER_MOUNTINFO;
	if (strcmp(p, "/mounts") == 0)
		return KSU_FILTER_MOUNTS;
	/* Hide any other /proc/<pid>/task/<tid>/... files by default */
	if (is_task)
		return KSU_FILTER_GENERIC;

	return KSU_FILTER_GENERIC;
}

/* ---- getdents64 hook: hide stealth PID entries from /proc/ ---- */

#ifdef CONFIG_KRETPROBES

/*
 * We hook sys_getdents64 to filter stealth PID directory entries
 * from /proc/ listings. This makes stealth processes completely
 * invisible to `ls /proc/`, `ps`, `top`, etc.
 *
 * Strategy:
 * - On entry: check if fd points to /proc/ directory
 * - On return: scan the dirent buffer and remove entries whose
 *   d_name is a numeric PID that matches a stealth PID
 */

struct getdents_data {
	void __user *dirp;
	bool is_proc_dir;
	bool is_dev_dir;
	bool is_sys_module_dir;
	bool hide_all;
	int hide_mode;
};

static int getdents_entry_handler(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct getdents_data *data = (struct getdents_data *)ri->data;
	/* For __arm64_sys_*, args are in the inner pt_regs */
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int fd = (int)PT_REGS_PARM1(real_regs);
	struct file *file;
	struct path path;
	char *tmp, *res;

	data->is_proc_dir = false;
	data->is_dev_dir = false;
	data->is_sys_module_dir = false;
	data->hide_all = false;
	data->hide_mode = HIDE_MODE_NONE;
	data->dirp = (void __user *)PT_REGS_PARM2(real_regs);

	if (!should_hide_proc())
		return 1; /* skip return handler */

	file = fget(fd);
	if (!file)
		return 1;

	path = file->f_path;
	path_get(&path);
	fput(file);

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		path_put(&path);
		return 1;
	}

	res = d_path(&path, tmp, PATH_MAX);
	path_put(&path);

	if (!IS_ERR(res)) {
		if (path_eq_or_subpath(res, "/proc")) {
			data->is_proc_dir = true;
		} else if (path_eq_or_subpath(res, "/dev")) {
			data->is_dev_dir = true;
		} else if (path_eq_or_subpath(res, "/sys/module")) {
			data->is_sys_module_dir = true;
		} else if (strncmp(res, "/proc/", 6) == 0) {
			const char *q = res + 6;
			pid_t pid = 0;
			if (!strncmp(q, "self", 4) &&
			    (q[4] == '\0' || q[4] == '/')) {
				pid = current->tgid;
				q += 4;
			} else if (!strncmp(q, "thread-self", 11) &&
				   (q[11] == '\0' || q[11] == '/')) {
				pid = current->tgid;
				q += 11;
			} else {
				while (*q >= '0' && *q <= '9' && pid < 10000000) {
					pid = pid * 10 + (*q - '0');
					q++;
				}
			}
			if (pid > 0 && ksu_is_stealth_pid(pid)) {
				/* Hide /proc/<pid>/task/<tid> listings */
				if (!strncmp(q, "/task/", 6) &&
				    q[6] >= '0' && q[6] <= '9') {
					const char *r = q + 6;
					pid_t tid = 0;
					while (*r >= '0' && *r <= '9' && tid < 10000000) {
						tid = tid * 10 + (*r - '0');
						r++;
					}
					if (tid > 0 && (*r == '\0' || *r == '/')) {
						data->hide_all = true;
					}
				}
				if (strcmp(q, "/fd") == 0 ||
				    strcmp(q, "/fd/") == 0 ||
				    strcmp(q, "/fdinfo") == 0 ||
				    strcmp(q, "/fdinfo/") == 0 ||
				    strcmp(q, "/task") == 0 ||
				    strcmp(q, "/task/") == 0 ||
				    strcmp(q, "/map_files") == 0 ||
				    strcmp(q, "/map_files/") == 0 ||
				    strcmp(q, "/ns") == 0 ||
				    strcmp(q, "/ns/") == 0) {
					data->hide_all = true;
					if (strcmp(q, "/fd") == 0 ||
					    strcmp(q, "/fd/") == 0)
						data->hide_mode =
							HIDE_MODE_FD_MIN;
					else
						data->hide_mode =
							HIDE_MODE_EMPTY;
				}
			}
		}
	}

	kfree(tmp);

	if (!data->is_proc_dir && !data->is_dev_dir &&
	    !data->is_sys_module_dir && !data->hide_all)
		return 1; /* skip */

	return 0;
}

static int getdents_ret_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct getdents_data *data = (struct getdents_data *)ri->data;
	ssize_t ret = (ssize_t)PT_REGS_RC(regs);
	char *kbuf, *src, *dst;
	ssize_t new_ret;
	size_t min_reclen = offsetof(struct ksu_dirent64, d_name) + 1;
	bool malformed = false;

	if (data->hide_all) {
		if (data->hide_mode == HIDE_MODE_FD_MIN && ret > 0) {
			kbuf = kmalloc(ret, GFP_KERNEL);
			if (kbuf) {
				new_ret = fill_min_fd_dir(kbuf, ret);
				if (new_ret > 0 &&
				    !copy_to_user(data->dirp, kbuf, new_ret))
					PT_REGS_RC(regs) = new_ret;
				else
					PT_REGS_RC(regs) = 0;
				kfree(kbuf);
				return 0;
			}
		}
		PT_REGS_RC(regs) = 0;
		return 0;
	}

	if ((!data->is_proc_dir && !data->is_dev_dir &&
	     !data->is_sys_module_dir) || ret <= 0)
		return 0;

	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return 0;

	if (copy_from_user(kbuf, data->dirp, ret)) {
		kfree(kbuf);
		return 0;
	}

	/* Walk the dirent64 buffer, removing stealth PID entries */
	src = kbuf;
	dst = kbuf;
	new_ret = 0;

	while (src < kbuf + ret) {
		struct ksu_dirent64 *de =
			(struct ksu_dirent64 *)src;
		unsigned short reclen = de->d_reclen;
		bool skip = false;

		if (reclen < min_reclen || src + reclen > kbuf + ret)
		{
			malformed = true;
			break;
		}

		if (data->is_proc_dir) {
			/* Check if d_name is a numeric PID */
			const char *name = de->d_name;
			pid_t pid = 0;
			bool is_num = (*name != '\0');
			const char *c;

			for (c = name; *c; c++) {
				if (*c < '0' || *c > '9') {
					is_num = false;
					break;
				}
				if (pid >= 10000000) {
					is_num = false;
					break;
				}
				pid = pid * 10 + (*c - '0');
			}

			if (is_num && ksu_is_stealth_pid(pid))
				skip = true;
		} else if (data->is_dev_dir) {
			if (ksu_is_hidden_dev(de->d_name))
				skip = true;
		} else if (data->is_sys_module_dir) {
			if (ksu_should_hide_module_name(de->d_name))
				skip = true;
		}

		if (!skip) {
			if (dst != src)
				memmove(dst, src, reclen);
			dst += reclen;
			new_ret += reclen;
		}

		src += reclen;
	}

	if (!malformed && new_ret != ret) {
		if (copy_to_user(data->dirp, kbuf, new_ret))
			goto out; /* On error, keep original */
		PT_REGS_RC(regs) = new_ret;
	}

out:
	kfree(kbuf);
	return 0;
}

static struct kretprobe getdents_rp = {
#if defined(__aarch64__)
	.kp.symbol_name = "__arm64_sys_getdents64",
#elif defined(__x86_64__)
	.kp.symbol_name = "__x64_sys_getdents64",
#else
	.kp.symbol_name = "sys_getdents64",
#endif
	.entry_handler = getdents_entry_handler,
	.handler = getdents_ret_handler,
	.data_size = sizeof(struct getdents_data),
	.maxactive = 32,
};

/* Fallback symbol name for non-arm64 or older kernels */
static struct kretprobe getdents_rp_alt = {
	.kp.symbol_name = "ksys_getdents64",
	.entry_handler = getdents_entry_handler,
	.handler = getdents_ret_handler,
	.data_size = sizeof(struct getdents_data),
	.maxactive = 32,
};

static bool getdents_hooked;
static bool getdents_alt_hooked;

#endif /* CONFIG_KRETPROBES */

/*
 * Filter /proc/version content.
 * Removes custom kernel identifiers from the version string.
 */
ssize_t ksu_filter_proc_version(char __user *buf, ssize_t count)
{
	char *kbuf;
	char *pos;
	static const char *version_filters[] = {
		"ksu", "kernelsu", "KernelSU", "KSU", NULL
	};

	if (!should_hide_proc() || count <= 0)
		return count;

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}
	kbuf[count] = '\0';

	/* Replace KSU identifiers with spaces */
	{
		const char **f;
		for (f = version_filters; *f; f++) {
			while ((pos = strstr(kbuf, *f)) != NULL) {
				memset(pos, ' ', strlen(*f));
			}
		}
	}

	if (copy_to_user(buf, kbuf, count)) {
		kfree(kbuf);
		return count;
	}

	kfree(kbuf);
	return count;
}

/* Feature handler: get current enable state */
static int proc_hide_get(u64 *value)
{
	*value = (u64)atomic_read(&proc_hide_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int proc_hide_set(u64 value)
{
	atomic_set(&proc_hide_enabled, value ? 1 : 0);
	pr_info("proc_hide: %s\n", value ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler proc_hide_handler = {
	.feature_id = KSU_FEATURE_PROC_HIDE,
	.name = "proc_hide",
	.get_handler = proc_hide_get,
	.set_handler = proc_hide_set,
};

void ksu_proc_hide_init(void)
{
	int ret = ksu_register_feature_handler(&proc_hide_handler);
	if (ret)
		pr_err("proc_hide: failed to register feature handler: %d\n", ret);
	else
		pr_info("proc_hide: initialized\n");

#ifdef CONFIG_KRETPROBES
	/* Register getdents64 hook for stealth PID directory filtering */
	getdents_hooked = false;
	getdents_alt_hooked = false;

	ret = register_kretprobe(&getdents_rp);
	if (ret == 0) {
		getdents_hooked = true;
	} else {
		/* Try alternative symbol */
		ret = register_kretprobe(&getdents_rp_alt);
		if (ret == 0)
			getdents_alt_hooked = true;
		else
			pr_err("proc_hide: getdents64 hook failed: %d\n", ret);
	}
#endif
}

void ksu_proc_hide_exit(void)
{
#ifdef CONFIG_KRETPROBES
	if (getdents_hooked)
		unregister_kretprobe(&getdents_rp);
	if (getdents_alt_hooked)
		unregister_kretprobe(&getdents_rp_alt);
#endif
	ksu_unregister_feature_handler(KSU_FEATURE_PROC_HIDE);
}
