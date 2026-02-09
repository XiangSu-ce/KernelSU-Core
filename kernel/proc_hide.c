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
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/limits.h>

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

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "feature.h"
#include "allowlist.h"

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
	"vfs_read",
	"vfs_write",
	"wake_up_new_task",
	"do_exit",
	"make_task_dead",
	/* syscall hook symbols (arch-specific wrappers) */
	"__arm64_sys_read",
	"__arm64_sys_pread64",
	"__arm64_sys_reboot",
	"__arm64_sys_getdents64",
	"__arm64_sys_newfstat",
	"__arm64_sys_execve",
	"__x64_sys_read",
	"__x64_sys_pread64",
	"__x64_sys_reboot",
	"__x64_sys_getdents64",
	"__x64_sys_newfstat",
	"__x64_sys_execve",
	"ksys_getdents64",
	/* tracepoint management hooks */
	"syscall_regfunc",
	"syscall_unregfunc",
	/* kallsyms resolution hook (self-referential) */
	"kallsyms_lookup_name",
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
	if (strstr(filepath, "kallsyms")) {
		filters = kallsyms_filter_strings;
		use_extended = true;
	} else if (strstr(filepath, "modules")) {
		filters = module_filter_strings;
		use_extended = true;
	} else if (strstr(filepath, "mountinfo") || strstr(filepath, "mounts")) {
		filters = mount_filter_strings;
	} else if (strstr(filepath, "/maps")) {
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

	return (strstr(path, "kallsyms") ||
		strstr(path, "modules") ||
		strstr(path, "mounts") ||
		strstr(path, "mountinfo") ||
		strstr(path, "/maps") ||
		strstr(path, "version"));
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
	return (strstr(path, "/kprobes/list") != NULL);
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
	if (!ksu_stealth_get_disguise(pid, comm_buf, exe_buf)) {
		strscpy(comm_buf, default_fake_comm, MAX_DISGUISE_LEN);
		strscpy(exe_buf, default_fake_exe, MAX_DISGUISE_LEN);
	}
}

ssize_t ksu_filter_proc_comm(char __user *buf, ssize_t count, pid_t pid)
{
	char fake_comm[MAX_DISGUISE_LEN];

	if (count <= 0)
		return count;

	get_disguise(pid, fake_comm, NULL);

	if (copy_to_user(buf, fake_comm, min_t(size_t, strlen(fake_comm), count)))
		return count;
	return min_t(size_t, strlen(fake_comm), count);
}

ssize_t ksu_filter_proc_cmdline(char __user *buf, ssize_t count)
{
	/* Empty cmdline */
	return 0;
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

/**
 * ksu_should_filter_proc_extra() - Check /proc/[stealth_pid]/{wchan,stack,fd}.
 * @path: file path being read
 *
 * Returns: 1 for wchan, 2 for stack, 0 otherwise.
 */
int ksu_should_filter_proc_extra(const char *path, pid_t *out_pid)
{
	const char *p;
	pid_t pid;

	if (!path || strncmp(path, "/proc/", 6) != 0)
		return 0;
	if (out_pid)
		*out_pid = pid;

	p = path + 6;
	pid = 0;
	while (*p >= '0' && *p <= '9') {
		pid = pid * 10 + (*p - '0');
		p++;
	}

	if (pid <= 0 || !ksu_is_stealth_pid(pid))
		return 0;

	if (strcmp(p, "/wchan") == 0)
		return 1;
	if (strcmp(p, "/stack") == 0)
		return 2;
	if (strcmp(p, "/comm") == 0)
		return 3;
	if (strcmp(p, "/cmdline") == 0)
		return 4;
	if (strcmp(p, "/exe") == 0)
		return 5;
	if (strcmp(p, "/maps") == 0)
		return 6;
	if (strncmp(p, "/fd", 3) == 0)
		return 7;
	if (strncmp(p, "/fdinfo", 7) == 0)
		return 8;
	if (strcmp(p, "/status") == 0)
		return 9;
	if (strcmp(p, "/environ") == 0)
		return 10;

	return 0;
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
		if (strcmp(res, "/proc") == 0)
			data->is_proc_dir = true;
		else if (strcmp(res, "/dev") == 0)
			data->is_dev_dir = true;
	}

	kfree(tmp);

	if (!data->is_proc_dir)
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

	if ((!data->is_proc_dir && !data->is_dev_dir) || ret <= 0)
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

		if (reclen == 0)
			break;

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
				pid = pid * 10 + (*c - '0');
			}

			if (is_num && ksu_is_stealth_pid(pid))
				skip = true;
		} else if (data->is_dev_dir) {
			if (ksu_is_hidden_dev(de->d_name))
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

	if (new_ret != ret) {
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
