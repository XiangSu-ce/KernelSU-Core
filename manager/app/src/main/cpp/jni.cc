#include <jni.h>

#include <sys/prctl.h>
#include <linux/capability.h>
#include <pwd.h>

#include <android/log.h>
#include <cstring>

#include "ksu.h"

#define LOG_TAG "KernelSU"
#ifdef NDEBUG
#define LOGD(...) (void)0
#else
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif

extern "C"
JNIEXPORT jint JNICALL
Java_dawang_KernelSU_Core_Natives_getVersion(JNIEnv *env, jobject) {
    int version = get_version();
    if (version > 0) {
        return version;
    }
    // try legacy method as fallback
    return legacy_get_info().first;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_dawang_KernelSU_Core_Natives_getAllowList(JNIEnv *env, jobject) {
    struct ksu_get_allow_list_cmd cmd = {};
    bool result = get_allow_list(&cmd);
    if (result) {
        int count = cmd.count;
        if (count < 0) {
            count = 0;
        } else if (count > static_cast<int>(sizeof(cmd.uids) / sizeof(cmd.uids[0]))) {
            count = static_cast<int>(sizeof(cmd.uids) / sizeof(cmd.uids[0]));
        }
        auto array = env->NewIntArray(count);
        if (!array) {
            return nullptr;
        }
        env->SetIntArrayRegion(array, 0, count, reinterpret_cast<const jint *>(cmd.uids));
        return array;
    }
    auto empty = env->NewIntArray(0);
    return empty;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isSafeMode(JNIEnv *env, jclass clazz) {
    return is_safe_mode();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isLkmMode(JNIEnv *env, jclass clazz) {
    return is_lkm_mode();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isManager(JNIEnv *env, jclass clazz) {
    return is_manager();
}

static void fillIntArray(JNIEnv *env, jobject list, int *data, int count) {
    auto cls = env->GetObjectClass(list);
    auto add = env->GetMethodID(cls, "add", "(Ljava/lang/Object;)Z");
    auto integerCls = env->FindClass("java/lang/Integer");
    auto constructor = env->GetMethodID(integerCls, "<init>", "(I)V");
    for (int i = 0; i < count; ++i) {
        auto integer = env->NewObject(integerCls, constructor, data[i]);
        env->CallBooleanMethod(list, add, integer);
        env->DeleteLocalRef(integer);
    }
    env->DeleteLocalRef(integerCls);
    env->DeleteLocalRef(cls);
}

static void addIntToList(JNIEnv *env, jobject list, int ele) {
    auto cls = env->GetObjectClass(list);
    auto add = env->GetMethodID(cls, "add", "(Ljava/lang/Object;)Z");
    auto integerCls = env->FindClass("java/lang/Integer");
    auto constructor = env->GetMethodID(integerCls, "<init>", "(I)V");
    auto integer = env->NewObject(integerCls, constructor, ele);
    env->CallBooleanMethod(list, add, integer);
    env->DeleteLocalRef(integer);
    env->DeleteLocalRef(integerCls);
    env->DeleteLocalRef(cls);
}

static uint64_t capListToBits(JNIEnv *env, jobject list) {
    auto cls = env->GetObjectClass(list);
    auto get = env->GetMethodID(cls, "get", "(I)Ljava/lang/Object;");
    auto size = env->GetMethodID(cls, "size", "()I");
    auto listSize = env->CallIntMethod(list, size);
    auto integerCls = env->FindClass("java/lang/Integer");
    auto intValue = env->GetMethodID(integerCls, "intValue", "()I");
    uint64_t result = 0;
    for (int i = 0; i < listSize; ++i) {
        auto integer = env->CallObjectMethod(list, get, i);
        int data = env->CallIntMethod(integer, intValue);
        env->DeleteLocalRef(integer);

        if (cap_valid(data)) {
            result |= (1ULL << data);
        }
    }

    env->DeleteLocalRef(integerCls);
    env->DeleteLocalRef(cls);
    return result;
}

static int getListSize(JNIEnv *env, jobject list) {
    auto cls = env->GetObjectClass(list);
    auto size = env->GetMethodID(cls, "size", "()I");
    int result = env->CallIntMethod(list, size);
    env->DeleteLocalRef(cls);
    return result;
}

static void fillArrayWithList(JNIEnv *env, jobject list, int *data, int count) {
    auto cls = env->GetObjectClass(list);
    auto get = env->GetMethodID(cls, "get", "(I)Ljava/lang/Object;");
    auto integerCls = env->FindClass("java/lang/Integer");
    auto intValue = env->GetMethodID(integerCls, "intValue", "()I");
    for (int i = 0; i < count; ++i) {
        auto integer = env->CallObjectMethod(list, get, i);
        data[i] = env->CallIntMethod(integer, intValue);
        env->DeleteLocalRef(integer);
    }
    env->DeleteLocalRef(integerCls);
    env->DeleteLocalRef(cls);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_dawang_KernelSU_Core_Natives_getAppProfile(JNIEnv *env, jobject, jstring pkg, jint uid) {
    if (!pkg) {
        return nullptr;
    }
    if (env->GetStringLength(pkg) >= KSU_MAX_PACKAGE_NAME) {
        return nullptr;
    }

    p_key_t key = {};
    auto cpkg = env->GetStringUTFChars(pkg, nullptr);
    if (!cpkg) {
        return nullptr;
    }
    strncpy(key, cpkg, sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';
    env->ReleaseStringUTFChars(pkg, cpkg);

    app_profile profile = {};
    profile.version = KSU_APP_PROFILE_VER;

    strncpy(profile.key, key, sizeof(profile.key) - 1);
    profile.key[sizeof(profile.key) - 1] = '\0';
    profile.current_uid = uid;

    bool useDefaultProfile = get_app_profile(&profile) != 0;

    auto cls = env->FindClass("dawang/KernelSU/Core/Natives$Profile");
    if (!cls) {
        return nullptr;
    }
    auto constructor = env->GetMethodID(cls, "<init>", "()V");
    auto obj = env->NewObject(cls, constructor);
    auto keyField = env->GetFieldID(cls, "name", "Ljava/lang/String;");
    auto currentUidField = env->GetFieldID(cls, "currentUid", "I");
    auto allowSuField = env->GetFieldID(cls, "allowSu", "Z");

    auto rootUseDefaultField = env->GetFieldID(cls, "rootUseDefault", "Z");
    auto rootTemplateField = env->GetFieldID(cls, "rootTemplate", "Ljava/lang/String;");

    auto uidField = env->GetFieldID(cls, "uid", "I");
    auto gidField = env->GetFieldID(cls, "gid", "I");
    auto groupsField = env->GetFieldID(cls, "groups", "Ljava/util/List;");
    auto capabilitiesField = env->GetFieldID(cls, "capabilities", "Ljava/util/List;");
    auto domainField = env->GetFieldID(cls, "context", "Ljava/lang/String;");
    auto namespacesField = env->GetFieldID(cls, "namespace", "I");

    auto nonRootUseDefaultField = env->GetFieldID(cls, "nonRootUseDefault", "Z");
    auto umountModulesField = env->GetFieldID(cls, "umountModules", "Z");

    jstring keyStr = env->NewStringUTF(profile.key);
    env->SetObjectField(obj, keyField, keyStr);
    env->DeleteLocalRef(keyStr);
    env->SetIntField(obj, currentUidField, profile.current_uid);

    if (useDefaultProfile) {
        // no profile found, so just use default profile:
        // don't allow root and use default profile!
        LOGD("use default profile for: %s, %d", key, uid);

        // allow_su = false
        // non root use default = true
        env->SetBooleanField(obj, allowSuField, false);
        env->SetBooleanField(obj, nonRootUseDefaultField, true);
        env->DeleteLocalRef(cls);

        return obj;
    }

    auto allowSu = profile.allow_su;

    if (allowSu) {
        env->SetBooleanField(obj, rootUseDefaultField, (jboolean) profile.rp_config.use_default);
        if (strlen(profile.rp_config.template_name) > 0) {
            jstring templateStr = env->NewStringUTF(profile.rp_config.template_name);
            env->SetObjectField(obj, rootTemplateField, templateStr);
            env->DeleteLocalRef(templateStr);
        }

        env->SetIntField(obj, uidField, profile.rp_config.profile.uid);
        env->SetIntField(obj, gidField, profile.rp_config.profile.gid);

        jobject groupList = env->GetObjectField(obj, groupsField);
        int groupCount = profile.rp_config.profile.groups_count;
        if (groupCount > KSU_MAX_GROUPS) {
            LOGD("kernel group count too large: %d???", groupCount);
            groupCount = KSU_MAX_GROUPS;
        }
        fillIntArray(env, groupList, profile.rp_config.profile.groups, groupCount);
        env->DeleteLocalRef(groupList);

        jobject capList = env->GetObjectField(obj, capabilitiesField);
        for (int i = 0; i <= CAP_LAST_CAP; i++) {
            if (profile.rp_config.profile.capabilities.effective & (1ULL << i)) {
                addIntToList(env, capList, i);
            }
        }
        env->DeleteLocalRef(capList);

        jstring domainStr = env->NewStringUTF(profile.rp_config.profile.selinux_domain);
        env->SetObjectField(obj, domainField, domainStr);
        env->DeleteLocalRef(domainStr);
        env->SetIntField(obj, namespacesField, profile.rp_config.profile.namespaces);
        env->SetBooleanField(obj, allowSuField, profile.allow_su);
    } else {
        env->SetBooleanField(obj, nonRootUseDefaultField,
                (jboolean) profile.nrp_config.use_default);
        env->SetBooleanField(obj, umountModulesField, profile.nrp_config.profile.umount_modules);
    }

    env->DeleteLocalRef(cls);
    return obj;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_setAppProfile(JNIEnv *env, jobject clazz, jobject profile) {
    if (!profile) {
        return false;
    }
    auto cls = env->FindClass("dawang/KernelSU/Core/Natives$Profile");
    if (!cls) {
        return false;
    }

    auto keyField = env->GetFieldID(cls, "name", "Ljava/lang/String;");
    auto currentUidField = env->GetFieldID(cls, "currentUid", "I");
    auto allowSuField = env->GetFieldID(cls, "allowSu", "Z");

    auto rootUseDefaultField = env->GetFieldID(cls, "rootUseDefault", "Z");
    auto rootTemplateField = env->GetFieldID(cls, "rootTemplate", "Ljava/lang/String;");

    auto uidField = env->GetFieldID(cls, "uid", "I");
    auto gidField = env->GetFieldID(cls, "gid", "I");
    auto groupsField = env->GetFieldID(cls, "groups", "Ljava/util/List;");
    auto capabilitiesField = env->GetFieldID(cls, "capabilities", "Ljava/util/List;");
    auto domainField = env->GetFieldID(cls, "context", "Ljava/lang/String;");
    auto namespacesField = env->GetFieldID(cls, "namespace", "I");

    auto nonRootUseDefaultField = env->GetFieldID(cls, "nonRootUseDefault", "Z");
    auto umountModulesField = env->GetFieldID(cls, "umountModules", "Z");

    auto key = env->GetObjectField(profile, keyField);
    if (!key) {
        env->DeleteLocalRef(cls);
        return false;
    }
    if (env->GetStringLength((jstring) key) >= KSU_MAX_PACKAGE_NAME) {
        env->DeleteLocalRef(key);
        env->DeleteLocalRef(cls);
        return false;
    }

    auto cpkg = env->GetStringUTFChars((jstring) key, nullptr);
    if (!cpkg) {
        env->DeleteLocalRef(key);
        env->DeleteLocalRef(cls);
        return false;
    }
    p_key_t p_key = {};
    strncpy(p_key, cpkg, sizeof(p_key) - 1);
    p_key[sizeof(p_key) - 1] = '\0';
    env->ReleaseStringUTFChars((jstring) key, cpkg);

    auto currentUid = env->GetIntField(profile, currentUidField);

    auto uid = env->GetIntField(profile, uidField);
    auto gid = env->GetIntField(profile, gidField);
    auto groups = env->GetObjectField(profile, groupsField);
    auto capabilities = env->GetObjectField(profile, capabilitiesField);
    auto domain = env->GetObjectField(profile, domainField);
    auto allowSu = env->GetBooleanField(profile, allowSuField);
    auto umountModules = env->GetBooleanField(profile, umountModulesField);

    app_profile p = {};
    p.version = KSU_APP_PROFILE_VER;

    strncpy(p.key, p_key, sizeof(p.key) - 1);
    p.key[sizeof(p.key) - 1] = '\0';
    p.allow_su = allowSu;
    p.current_uid = currentUid;

    if (allowSu) {
        if (!groups || !capabilities) {
            env->DeleteLocalRef(groups);
            env->DeleteLocalRef(capabilities);
            env->DeleteLocalRef(domain);
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(cls);
            return false;
        }

        p.rp_config.use_default = env->GetBooleanField(profile, rootUseDefaultField);
        auto templateName = env->GetObjectField(profile, rootTemplateField);
        if (templateName) {
            if (env->GetStringLength((jstring) templateName) >=
                (jsize)sizeof(p.rp_config.template_name)) {
                env->DeleteLocalRef(templateName);
                env->DeleteLocalRef(groups);
                env->DeleteLocalRef(capabilities);
                env->DeleteLocalRef(domain);
                env->DeleteLocalRef(key);
                env->DeleteLocalRef(cls);
                return false;
            }
            auto ctemplateName = env->GetStringUTFChars((jstring) templateName, nullptr);
            if (!ctemplateName) {
                env->DeleteLocalRef(templateName);
                env->DeleteLocalRef(groups);
                env->DeleteLocalRef(capabilities);
                env->DeleteLocalRef(domain);
                env->DeleteLocalRef(key);
                env->DeleteLocalRef(cls);
                return false;
            }
            strncpy(p.rp_config.template_name, ctemplateName,
                    sizeof(p.rp_config.template_name) - 1);
            p.rp_config.template_name[sizeof(p.rp_config.template_name) - 1] = '\0';
            env->ReleaseStringUTFChars((jstring) templateName, ctemplateName);
            env->DeleteLocalRef(templateName);
        }

        p.rp_config.profile.uid = uid;
        p.rp_config.profile.gid = gid;

        int groups_count = getListSize(env, groups);
        if (groups_count > KSU_MAX_GROUPS) {
            LOGD("groups count too large: %d", groups_count);
            env->DeleteLocalRef(groups);
            env->DeleteLocalRef(capabilities);
            env->DeleteLocalRef(domain);
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(cls);
            return false;
        }
        p.rp_config.profile.groups_count = groups_count;
        fillArrayWithList(env, groups, p.rp_config.profile.groups, groups_count);

        p.rp_config.profile.capabilities.effective = capListToBits(env, capabilities);

        if (!domain ||
            env->GetStringLength((jstring) domain) >=
                (jsize)sizeof(p.rp_config.profile.selinux_domain)) {
            env->DeleteLocalRef(groups);
            env->DeleteLocalRef(capabilities);
            env->DeleteLocalRef(domain);
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(cls);
            return false;
        }
        auto cdomain = env->GetStringUTFChars((jstring) domain, nullptr);
        if (!cdomain) {
            env->DeleteLocalRef(groups);
            env->DeleteLocalRef(capabilities);
            env->DeleteLocalRef(domain);
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(cls);
            return false;
        }
        strncpy(p.rp_config.profile.selinux_domain, cdomain,
                sizeof(p.rp_config.profile.selinux_domain) - 1);
        p.rp_config.profile.selinux_domain[sizeof(p.rp_config.profile.selinux_domain) - 1] =
            '\0';
        env->ReleaseStringUTFChars((jstring) domain, cdomain);

        p.rp_config.profile.namespaces = env->GetIntField(profile, namespacesField);
    } else {
        p.nrp_config.use_default = env->GetBooleanField(profile, nonRootUseDefaultField);
        p.nrp_config.profile.umount_modules = umountModules;
    }

    env->DeleteLocalRef(groups);
    env->DeleteLocalRef(capabilities);
    env->DeleteLocalRef(domain);
    env->DeleteLocalRef(key);
    env->DeleteLocalRef(cls);
    return set_app_profile(&p);
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_uidShouldUmount(JNIEnv *env, jobject thiz, jint uid) {
    return uid_should_umount(uid);
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isSuEnabled(JNIEnv *env, jobject thiz) {
    return is_su_enabled();
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_setSuEnabled(JNIEnv *env, jobject thiz, jboolean enabled) {
    return set_su_enabled(enabled);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isKernelUmountEnabled(JNIEnv *env, jobject thiz) {
    return is_kernel_umount_enabled();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_setKernelUmountEnabled(JNIEnv *env, jobject thiz, jboolean enabled) {
    return set_kernel_umount_enabled(enabled);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isFeatureEnabled(JNIEnv *env, jobject thiz, jint featureId) {
    bool supported = false;
    bool enabled = get_feature_enabled((uint32_t)featureId, &supported);
    return enabled;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_setFeatureEnabled(JNIEnv *env, jobject thiz, jint featureId, jboolean enabled) {
    return set_feature_enabled((uint32_t)featureId, enabled);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_dawang_KernelSU_Core_Natives_isFeatureSupported(JNIEnv *env, jobject thiz, jint featureId) {
    bool supported = false;
    get_feature_enabled((uint32_t)featureId, &supported);
    return supported;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_dawang_KernelSU_Core_Natives_getUserName(JNIEnv *env, jobject thiz, jint uid) {
    struct passwd *pw = getpwuid((uid_t) uid);
    if (pw && pw->pw_name && pw->pw_name[0] != '\0') {
        return env->NewStringUTF(pw->pw_name);
    }
    return nullptr;
}
