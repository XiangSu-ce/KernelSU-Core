/*
 * prop_spoof.c - System property spoofing for KernelSU
 *
 * Provides a spoofing rule table for system properties that reveal
 * root/bootloader/debug state. The actual property application is done
 * by ksud in userspace via resetprop during post-fs-data.
 *
 * The kernel module provides:
 * - The spoof rule table (accessible via ksu_get_spoof_rules)
 * - Process-level filtering (which processes see spoofed values)
 * - Runtime enable/disable via the KSU feature framework
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
#include "ksud.h"

/* Module enable state */
static atomic_t prop_spoof_enabled = ATOMIC_INIT(1);

/* Property name -> spoofed value mapping */
struct prop_rule {
	const char *name;
	const char *spoof_value;
};

/* Default spoofing rules: hide root, BL unlock, debug state */
static const struct prop_rule spoof_rules[] = {
	/* Debugger detection */
	{ "ro.debuggable",              "0" },
	{ "ro.secure",                  "1" },

	/* Bootloader unlock status */
	{ "ro.boot.flash.locked",       "1" },
	{ "ro.boot.vbmeta.device_state", "locked" },
	{ "ro.boot.verifiedbootstate",  "green" },
	{ "ro.boot.veritymode",         "enforcing" },
	{ "sys.oem_unlock_allowed",     "0" },

	/* Build type fingerprints */
	{ "ro.build.type",              "user" },
	{ "ro.build.tags",              "release-keys" },
	{ "ro.build.selinux",           "1" },

	/* Misc root indicators */
	{ "ro.adb.secure",              "1" },
	{ "service.adb.root",           "0" },

	{ NULL, NULL }  /* sentinel */
};

/*
 * Find spoofed value for a given property name.
 * Returns NULL if the property should not be spoofed.
 */
static const char *find_spoof_value(const char *prop_name)
{
	const struct prop_rule *rule;

	if (!prop_name)
		return NULL;

	for (rule = spoof_rules; rule->name; rule++) {
		if (strcmp(prop_name, rule->name) == 0)
			return rule->spoof_value;
	}

	return NULL;
}

/*
 * Check if the current process should see spoofed properties.
 * Root processes and KSU-authorized processes see real values.
 */
static bool should_spoof_for_current(void)
{
	uid_t uid;

	if (!atomic_read(&prop_spoof_enabled))
		return false;

	uid = current_uid().val;

	/* Root and system processes see real values */
	if (uid == 0 || uid == 1000)
		return false;

	/* Shell (adb) sees real values for debugging */
	if (uid == 2000)
		return false;

	/* KSU-authorized apps see real values */
	if (ksu_is_allow_uid(uid))
		return false;

	return true;
}

/*
 * Android properties are applied by ksud in userspace during post-fs-data
 * using resetprop. The kernel module provides the rule table below.
 */

/*
 * Get the full list of properties to spoof.
 * Used by ksud to apply properties during post-fs-data.
 * Returns number of rules copied, or negative error.
 */
int ksu_get_spoof_rules(char __user *buf, size_t buf_size)
{
	size_t offset = 0;
	const struct prop_rule *rule;
	char line[256];
	int len;

	if (!buf || buf_size == 0)
		return -EINVAL;

	for (rule = spoof_rules; rule->name; rule++) {
		len = snprintf(line, sizeof(line), "%s=%s\n",
			       rule->name, rule->spoof_value);
		if (len < 0)
			return -EFAULT;
		if (len >= (int)sizeof(line))
			len = sizeof(line) - 1;
		/* Use subtraction to avoid integer overflow */
		if ((size_t)len > buf_size - offset)
			break;
		if (copy_to_user(buf + offset, line, len))
			return -EFAULT;
		offset += len;
	}

	return (int)offset;
}

/*
 * Check if a specific property should be spoofed for the calling process.
 * Returns the spoofed value or NULL.
 */
const char *ksu_check_prop_spoof(const char *prop_name)
{
	if (!should_spoof_for_current())
		return NULL;

	return find_spoof_value(prop_name);
}

/* Feature handler: get current enable state */
static int prop_spoof_get(u64 *value)
{
	*value = (u64)atomic_read(&prop_spoof_enabled);
	return 0;
}

/* Feature handler: set enable state */
static int prop_spoof_set(u64 value)
{
	atomic_set(&prop_spoof_enabled, value ? 1 : 0);
	pr_info("prop_spoof: %s\n", value ? "enabled" : "disabled");
	return 0;
}

static const struct ksu_feature_handler prop_spoof_handler = {
	.feature_id = KSU_FEATURE_PROP_SPOOF,
	.name = "prop_spoof",
	.get_handler = prop_spoof_get,
	.set_handler = prop_spoof_set,
};

void ksu_prop_spoof_init(void)
{
	int ret = ksu_register_feature_handler(&prop_spoof_handler);
	if (ret)
		pr_err("prop_spoof: failed to register feature handler: %d\n", ret);
	else
		pr_info("prop_spoof: initialized with %zu rules\n",
			ARRAY_SIZE(spoof_rules) - 1);
}

void ksu_prop_spoof_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_PROP_SPOOF);
}
