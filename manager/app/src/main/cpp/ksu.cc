//
// Created by weishu on 2022/12/9.
//

#include <sys/prctl.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <utility>
#include <android/log.h>
#include <dirent.h>
#include <cstdlib>

#include <unistd.h>
#include <climits>
#include <sys/syscall.h>
#include <cerrno>
#include <mutex>
#include <signal.h>
#include "ksu.h"

static int fd = -1;
static std::mutex fd_mutex;
static constexpr uint32_t KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
static constexpr uint32_t KSU_INSTALL_MAGIC2 = 0xCAFEBABE;

static inline int scan_driver_fd() {
    const char *kName = "[timerfd]";
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        return -1;
    }

    int found = -1;
    struct dirent *de;
    char path[64];
    char target[PATH_MAX];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        char *endptr = NULL;
        long fd_long = strtol(de->d_name, &endptr, 10);
        if (!de->d_name[0] || *endptr != '\0' || fd_long < 0 || fd_long > INT_MAX) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/self/fd/%s", de->d_name);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n < 0) {
            continue;
        }
        target[n] = '\0';

        const char *base = strrchr(target, '/');
        base = base ? base + 1 : target;

        if (strstr(base, kName)) {
            found = (int)fd_long;
            break;
        }
    }

    closedir(dir);
    return found;
}

static volatile sig_atomic_t sigsys_caught = 0;

static void sigsys_handler(int) {
    sigsys_caught = 1;
}

static inline int install_driver_fd() {
    int out_fd = -1;

    /*
     * Protect against SIGSYS from seccomp: on modern Android the reboot
     * syscall may be blocked for unprivileged apps. Install a temporary
     * signal handler so we get a recoverable error instead of a crash.
     */
    struct sigaction sa = {}, old_sa = {};
    sa.sa_handler = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigsys_caught = 0;
    sigaction(SIGSYS, &sa, &old_sa);

    long ret = syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &out_fd);

    sigaction(SIGSYS, &old_sa, nullptr);

    if (sigsys_caught || ret < 0 || out_fd < 0) {
        return -1;
    }
    return out_fd;
}

static inline int init_driver_fd() {
    int scanned = scan_driver_fd();
    if (scanned >= 0) {
        return scanned;
    }
    return install_driver_fd();
}

template<typename... Args>
static int ksuctl(unsigned long op, Args &&... args) {
    std::lock_guard<std::mutex> lock(fd_mutex);

    if (fd < 0) {
        fd = init_driver_fd();
        if (fd < 0) {
            errno = ENODEV;
            return -1;
        }
    }

    static_assert(sizeof...(Args) <= 1, "ioctl expects at most one extra argument");

    int ret = ioctl(fd, op, std::forward<Args>(args)...);
    if (ret < 0 && errno == EBADF) {
        // Driver fd may be stale after process lifecycle changes, reacquire once.
        fd = -1;
        fd = init_driver_fd();
        if (fd >= 0) {
            ret = ioctl(fd, op, std::forward<Args>(args)...);
        }
    }
    return ret;
}

static struct ksu_get_info_cmd g_version {};

struct ksu_get_info_cmd get_info() {
    if (!g_version.version) {
        ksuctl(KSU_IOCTL_GET_INFO, &g_version);
    }
    return g_version;
}

uint32_t get_version() {
    auto info = get_info();
    return info.version;
}

bool get_allow_list(struct ksu_get_allow_list_cmd *cmd) {
    return ksuctl(KSU_IOCTL_GET_ALLOW_LIST, cmd) == 0;
}

bool is_safe_mode() {
    struct ksu_check_safemode_cmd cmd = {};
    ksuctl(KSU_IOCTL_CHECK_SAFEMODE, &cmd);
    return cmd.in_safe_mode;
}

bool is_lkm_mode() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & 0x1) != 0;
    }
    return (legacy_get_info().second & 0x1) != 0;
}

bool is_manager() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & 0x2) != 0;
    }
    return legacy_get_info().first > 0;
}

bool uid_should_umount(int uid) {
    struct ksu_uid_should_umount_cmd cmd = {};
    cmd.uid = uid;
    ksuctl(KSU_IOCTL_UID_SHOULD_UMOUNT, &cmd);
    return cmd.should_umount;
}

bool set_app_profile(const app_profile *profile) {
    struct ksu_set_app_profile_cmd cmd = {};
    cmd.profile = *profile;
    return ksuctl(KSU_IOCTL_SET_APP_PROFILE, &cmd) == 0;
}

int get_app_profile(app_profile *profile) {
    struct ksu_get_app_profile_cmd cmd = {.profile = *profile};
    int ret = ksuctl(KSU_IOCTL_GET_APP_PROFILE, &cmd);
    *profile = cmd.profile;
    return ret;
}

bool set_su_enabled(bool enabled) {
    struct ksu_set_feature_cmd cmd = {};
    cmd.feature_id = KSU_FEATURE_SU_COMPAT;
    cmd.value = enabled ? 1 : 0;
    return ksuctl(KSU_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool is_su_enabled() {
    struct ksu_get_feature_cmd cmd = {};
    cmd.feature_id = KSU_FEATURE_SU_COMPAT;
    if (ksuctl(KSU_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (!cmd.supported) {
        return false;
    }
    return cmd.value != 0;
}

static inline bool get_feature(uint32_t feature_id, uint64_t *out_value, bool *out_supported) {
    struct ksu_get_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    if (ksuctl(KSU_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (out_value) *out_value = cmd.value;
    if (out_supported) *out_supported = cmd.supported;
    return true;
}

static inline bool set_feature(uint32_t feature_id, uint64_t value) {
    struct ksu_set_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    cmd.value = value;
    return ksuctl(KSU_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool set_kernel_umount_enabled(bool enabled) {
    return set_feature(KSU_FEATURE_KERNEL_UMOUNT, enabled ? 1 : 0);
}

bool is_kernel_umount_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(KSU_FEATURE_KERNEL_UMOUNT, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

bool get_feature_enabled(uint32_t feature_id, bool *out_supported) {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(feature_id, &value, &supported)) {
        if (out_supported) *out_supported = false;
        return false;
    }
    if (out_supported) *out_supported = supported;
    return supported && value != 0;
}

bool set_feature_enabled(uint32_t feature_id, bool enabled) {
    return set_feature(feature_id, enabled ? 1 : 0);
}
