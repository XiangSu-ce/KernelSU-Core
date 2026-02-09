/*
 * klog_sanitize.c - Kernel log runtime sanitization for KernelSU
 *
 * Provides runtime filtering of kernel log (dmesg) output to remove
 * KSU-related log messages. This complements the compile-time
 * CONFIG_KSU_SILENT option by providing runtime log filtering even
 * when the silent option is not enabled at compile time.
 *
 * The module works by:
 * 1. Registering as a feature handler for dynamic enable/disable
 * 2. Providing filter functions that can be called from dmesg read paths
 * 3. Identifying and suppressing lines containing KSU-related keywords
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/cred.h>

#include "klog.h" // IWYU pragma: keep
#include "feature.h"
#include "allowlist.h"

/* Module enable state */
static atomic_t log_silent_enabled = ATOMIC_INIT(1);

/* Keywords to filter from kernel log output */
static const char *klog_filter_keywords[] = {
	"KernelSU",
	"kernelsu",
	"ksu_",
	"ksu:",
	"[ksu",
	"ksud",
	"KERNEL_SU",
	/* Feature-related logs */
	"prop_spoof",
	"proc_hide",
	"debug_disable",
	"symbol_hide",
	"mount_sanitize",
	"klog_sanitize",
	/* Hook-related logs */
	"hook_manager",
	"throne_tracker",
	"su_compat",
	"sucompat",
	/* SELinux audit traces */
	"system_server_helper",
	"system_misc_file",
	"/data/adb/.svc",
	/* Boot/module loading traces */
	"boot_sanitize",
	"stealth_mod",
	"stealth_exec",
	"stealth_fileio",
	"stealth_ipc",
	NULL
};

/*
 * Check if current process should see filtered kernel logs.
 */
static bool should_filter_klog(void)
{
	uid_t uid;

	if (!atomic_read(&log_silent_enabled))
		return false;

	uid = current_uid().val;

	/* Root and system processes see real logs */
	if (uid == 0 || uid == 1000)
		return false;

	/* Shell sees real logs for debugging */
	if (uid == 2000)
		return false;

	/* KSU-authorized apps see real logs */
	if (ksu_is_allow_uid(uid))
		return false;

	return true;
}

/*
 * Check if a kernel log line contains KSU-related content.
 */
/* Stealth subsystem declarations */
#include "stealth.h"

static bool is_ksu_log_line(const char *line, size_t len)
{
	const char **kw;
	const char **prefixes;

	if (!line || len == 0)
		return false;

	for (kw = klog_filter_keywords; *kw; kw++) {
		if (strnstr(line, *kw, len))
			return true;
	}

	/* Also check dynamic keywords from stealth module registry */
	prefixes = ksu_get_stealth_symbol_prefixes();
	if (prefixes) {
		for (kw = prefixes; *kw; kw++) {
			if (strnstr(line, *kw, len))
				return true;
		}
	}

	/* Combination filter: AVC lines mentioning our domains */
	if (strnstr(line, "avc:", len) || strnstr(line, "audit", len)) {
		if (strnstr(line, "system_server_helper", len) ||
		    strnstr(line, "system_misc_file", len) ||
		    strnstr(line, "/data/adb", len))
			return true;
	}

	return false;
}

/*
 * Filter kernel log buffer in-place.
 * Removes lines containing KSU-related keywords.
 *
 * @kbuf: kernel buffer containing log text
 * @len:  length of data in buffer
 *
 * Returns new length after filtering.
 */
static ssize_t filter_klog_buffer(char *kbuf, ssize_t len)
{
	char *src, *dst, *line_start, *line_end;
	ssize_t new_len = 0;
	char *temp;

	if (!kbuf || len <= 0)
		return len;

	temp = kmalloc(len, GFP_KERNEL);
	if (!temp)
		return len;

	memcpy(temp, kbuf, len);
	src = temp;
	dst = kbuf;
	line_start = src;

	while (line_start < src + len) {
		line_end = memchr(line_start, '\n', (src + len) - line_start);
		if (!line_end)
			line_end = src + len;
		else
			line_end++; /* include newline */

		{
			size_t line_len = line_end - line_start;

			if (!is_ksu_log_line(line_start, line_len)) {
				memcpy(dst, line_start, line_len);
				dst += line_len;
				new_len += line_len;
			}
		}

		line_start = line_end;
	}

	kfree(temp);
	return new_len;
}

/*
 * Filter kernel log output for the current process.
 *
 * @buf:   user-space buffer that dmesg was read into
 * @count: number of bytes actually read
 *
 * Returns new count after filtering.
 */
ssize_t ksu_filter_klog(char __user *buf, ssize_t count)
{
	char *kbuf;
	ssize_t new_count;

	if (!should_filter_klog() || count <= 0)
		return count;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	new_count = filter_klog_buffer(kbuf, count);

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
 * Check if kernel log filtering is currently active.
 * Can be used by other modules to decide whether to log.
 */
bool ksu_is_klog_filtered(void)
{
	return atomic_read(&log_silent_enabled) != 0;
}

/* Feature handler: get current enable state */
static int log_silent_get(u64 *value)
{
	*value = (u64)atomic_read(&log_silent_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int log_silent_set(u64 value)
{
	atomic_set(&log_silent_enabled, value ? 1 : 0);
	pr_info("klog_sanitize: %s\n", value ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler log_silent_handler = {
	.feature_id = KSU_FEATURE_LOG_SILENT,
	.name = "log_silent",
	.get_handler = log_silent_get,
	.set_handler = log_silent_set,
};

void ksu_klog_sanitize_init(void)
{
	int ret = ksu_register_feature_handler(&log_silent_handler);
	if (ret)
		pr_err("klog_sanitize: failed to register feature handler: %d\n", ret);
	else
		pr_info("klog_sanitize: initialized\n");
}

void ksu_klog_sanitize_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_LOG_SILENT);
}
