/*
 * mount_sanitize.c - Mount information sanitization for KernelSU
 *
 * Enhances the existing kernel_umount.c by filtering mount information
 * visible to non-authorized processes. This prevents detection via:
 * - /proc/self/mountinfo
 * - /proc/self/mounts
 * - /proc/mounts
 *
 * KSU modules use overlayfs and bind mounts which leave traces in
 * mount information. This module filters those traces.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/atomic.h>

#include "klog.h" // IWYU pragma: keep
#include "feature.h"
#include "allowlist.h"

/* Module enable state */
static atomic_t mount_sanitize_enabled = ATOMIC_INIT(1);

/* Paths and keywords to filter from mount listings */
static const char *mount_hide_patterns[] = {
	/* KSU data directory */
	"/data/adb/ksu",
	"/data/adb/modules",

	/* Module overlay markers */
	"lowerdir=/data/adb",
	"upperdir=/data/adb",
	"workdir=/data/adb",

	/* KSU-specific mount tags (use prefix to avoid false positives) */
	"kernelsu",

	NULL
};

/*
 * Check if the current process should see sanitized mount info.
 */
static bool should_sanitize_mounts(void)
{
	uid_t uid;

	if (!atomic_read(&mount_sanitize_enabled))
		return false;

	uid = current_uid().val;

	/* Root, system, shell see real mount info */
	if (uid == 0 || uid == 1000 || uid == 2000)
		return false;

	/* KSU-authorized apps see real mount info */
	if (ksu_is_allow_uid(uid))
		return false;

	return true;
}

/*
 * Check if a mount info line should be hidden.
 */
static bool should_hide_mount_line(const char *line, size_t len)
{
	const char **pattern;

	if (!line || len == 0)
		return false;

	for (pattern = mount_hide_patterns; *pattern; pattern++) {
		if (strnstr(line, *pattern, len))
			return true;
	}

	/* Also hide lines with suspicious overlayfs entries */
	if (strnstr(line, "overlay", len) &&
	    strnstr(line, "/data/adb", len))
		return true;

	return false;
}

/*
 * Filter mount information buffer in-place.
 * Removes lines that contain KSU-related mount entries.
 *
 * @kbuf: kernel buffer containing mount info text
 * @len:  length of data in buffer
 *
 * Returns new length after filtering.
 */
static ssize_t filter_mount_buffer(char *kbuf, ssize_t len)
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

			if (!should_hide_mount_line(line_start, line_len)) {
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
 * Filter mount information for the current process.
 * Called from the /proc read path when mountinfo/mounts is being read.
 *
 * @buf:   user-space buffer
 * @count: bytes read
 *
 * Returns new count after filtering.
 */
ssize_t ksu_filter_mount_info(char __user *buf, ssize_t count)
{
	char *kbuf;
	ssize_t new_count;

	if (!should_sanitize_mounts() || count <= 0)
		return count;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return count;
	}

	new_count = filter_mount_buffer(kbuf, count);

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
 * Check if a given path is a mount info path that needs filtering.
 */
bool ksu_should_filter_mount(const char *path)
{
	const char *p;

	if (!should_sanitize_mounts() || !path)
		return false;

	if (strcmp(path, "/proc/mounts") == 0)
		return true;
	if (strncmp(path, "/proc/", 6) != 0)
		return false;

	p = path + 6;
	if (strncmp(p, "self/", 5) == 0)
		return strcmp(p + 5, "mountinfo") == 0 || strcmp(p + 5, "mounts") == 0;
	if (strncmp(p, "thread-self/", 12) == 0)
		return strcmp(p + 12, "mountinfo") == 0 || strcmp(p + 12, "mounts") == 0;

	while (*p >= '0' && *p <= '9')
		p++;
	if (p == path + 6 || *p != '/')
		return false;
	p++;

	return strcmp(p, "mountinfo") == 0 || strcmp(p, "mounts") == 0;
}

/* Feature handler: get current enable state */
static int mount_sanitize_get(u64 *value)
{
	*value = (u64)atomic_read(&mount_sanitize_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int mount_sanitize_set(u64 value)
{
	atomic_set(&mount_sanitize_enabled, value ? 1 : 0);
	pr_info("mount_sanitize: %s\n", value ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler mount_sanitize_handler = {
	.feature_id = KSU_FEATURE_MOUNT_SANITIZE,
	.name = "mount_sanitize",
	.get_handler = mount_sanitize_get,
	.set_handler = mount_sanitize_set,
};

void ksu_mount_sanitize_init(void)
{
	int ret = ksu_register_feature_handler(&mount_sanitize_handler);
	if (ret)
		pr_err("mount_sanitize: failed to register feature handler: %d\n", ret);
	else
		pr_info("mount_sanitize: initialized\n");
}

void ksu_mount_sanitize_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_SANITIZE);
}
