#ifndef __KSU_H_FEATURE
#define __KSU_H_FEATURE

#include <linux/types.h>

enum ksu_feature_id {
    KSU_FEATURE_SU_COMPAT = 0,
    KSU_FEATURE_KERNEL_UMOUNT = 1,
    KSU_FEATURE_PROP_SPOOF = 2,
    KSU_FEATURE_PROC_HIDE = 3,
    KSU_FEATURE_DEBUG_DISABLE = 4,
    KSU_FEATURE_LOG_SILENT = 5,
    KSU_FEATURE_SYMBOL_HIDE = 6,
    KSU_FEATURE_MOUNT_SANITIZE = 7,
    KSU_FEATURE_STEALTH_FILTER_IO = 8,
    KSU_FEATURE_STEALTH_MODLOADER = 9,
    KSU_FEATURE_STEALTH_EXEC = 10,
    KSU_FEATURE_STEALTH_FILEIO = 11,
    KSU_FEATURE_STEALTH_IPC = 12,

    KSU_FEATURE_MAX
};

typedef int (*ksu_feature_get_t)(u64 *value);
typedef int (*ksu_feature_set_t)(u64 value);

struct ksu_feature_handler {
    u32 feature_id;
    const char *name;
    ksu_feature_get_t get_handler;
    ksu_feature_set_t set_handler;
};

int ksu_register_feature_handler(const struct ksu_feature_handler *handler);

int ksu_unregister_feature_handler(u32 feature_id);

int ksu_get_feature(u32 feature_id, u64 *value, bool *supported);

int ksu_set_feature(u32 feature_id, u64 value);

void ksu_feature_init(void);

void ksu_feature_exit(void);

#endif // __KSU_H_FEATURE
