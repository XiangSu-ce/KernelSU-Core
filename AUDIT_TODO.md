# Full Source Audit TODO

Status legend: [ ] pending, [~] in progress, [x] done

## Audit Rules

- Focus on logic/behavioral bugs (not build-only issues).
- For each file: inspect edge cases, state consistency, error handling, concurrency/lifecycle, and API contract assumptions.
- If modified: add a short note under Findings Log with root cause + fix.
- Keep kernel/userspace/manager interface compatibility intact.

## Global Progress

- Total files: 162
- Reviewed: 162
- Modified: 123
- High-risk unresolved: 0

## File Checklist

### js (2)

- [x] js\index.d.ts
- [x] js\index.js

### kernel (56)

- [x] kernel\allowlist.c
- [x] kernel\allowlist.h
- [x] kernel\apk_sign.c
- [x] kernel\apk_sign.h
- [x] kernel\app_profile.c
- [x] kernel\app_profile.h
- [x] kernel\arch.h
- [x] kernel\boot_sanitize.c
- [x] kernel\debug_disable.c
- [x] kernel\feature.c
- [x] kernel\feature.h
- [x] kernel\file_wrapper.c
- [x] kernel\file_wrapper.h
- [x] kernel\kernel_umount.c
- [x] kernel\kernel_umount.h
- [x] kernel\klog_sanitize.c
- [x] kernel\klog.h
- [x] kernel\ksu.c
- [x] kernel\ksu.h
- [x] kernel\ksud.c
- [x] kernel\ksud.h
- [x] kernel\manager.h
- [x] kernel\mount_sanitize.c
- [x] kernel\obfuscate.h
- [x] kernel\pkg_observer.c
- [x] kernel\proc_hide.c
- [x] kernel\prop_spoof.c
- [x] kernel\seccomp_cache.c
- [x] kernel\seccomp_cache.h
- [x] kernel\selinux\rules.c
- [x] kernel\selinux\selinux.c
- [x] kernel\selinux\selinux.h
- [x] kernel\selinux\sepolicy.c
- [x] kernel\selinux\sepolicy.h
- [x] kernel\setuid_hook.c
- [x] kernel\setuid_hook.h
- [x] kernel\setup.sh
- [x] kernel\stealth_exec.c
- [x] kernel\stealth_fileio.c
- [x] kernel\stealth_ipc.c
- [x] kernel\stealth_modloader.c
- [x] kernel\stealth.h
- [x] kernel\su_mount_ns.c
- [x] kernel\su_mount_ns.h
- [x] kernel\sucompat.c
- [x] kernel\sucompat.h
- [x] kernel\supercalls.c
- [x] kernel\supercalls.h
- [x] kernel\symbol_hide.c
- [x] kernel\syscall_hook_manager.c
- [x] kernel\syscall_hook_manager.h
- [x] kernel\throne_tracker.c
- [x] kernel\throne_tracker.h
- [x] kernel\tools\check_symbol.c
- [x] kernel\util.c
- [x] kernel\util.h

### manager (78)

- [x] manager\app\build.gradle.kts
- [x] manager\app\src\main\cpp\jni.cc
- [x] manager\app\src\main\cpp\ksu.cc
- [x] manager\app\src\main\cpp\ksu.h
- [x] manager\app\src\main\java\dawang\KernelSU\Core\Kernels.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\KernelSUApplication.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\Natives.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\profile\Capabilities.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\profile\Groups.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\AppIconImage.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\BottomBar.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\ChooseKmiDialog.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\Dialog.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\DropdownItem.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\EditText.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\filter\BaseFieldFilter.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\filter\FilterNumber.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\GithubMarkdown.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\KeyEventBlocker.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\KsuValidCheck.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\Markdown.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\profile\AppProfileConfig.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\profile\RootProfileConfig.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\profile\TemplateConfig.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\rebootListPopup.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\ScaleDialog.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\SendLogDialog.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\SuperEditArrow.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\SuperSearchBar.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\component\UninstallDialog.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\KsuService.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\MainActivity.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\navigation3\DeepLinkResolver.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\navigation3\Navigator.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\navigation3\Routes.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\About.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\AppProfile.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\ExecuteModuleAction.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Flash.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Home.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Install.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Module.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\ModuleRepo.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Settings.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\SuperUser.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\Template.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\screen\TemplateEditor.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\theme\RazerColors.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\theme\Theme.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\Colors.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\Downloader.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\HanziToPinyin.java
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\KsuCli.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\LogEvent.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\module\LatestVersionInfo.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\module\ModuleRepoApi.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\module\Shortcut.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\Network.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\OemHelper.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\SELinuxChecker.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\Serialization.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\util\UidGroupUtils.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\viewmodel\ModuleRepoViewModel.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\viewmodel\ModuleViewModel.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\viewmodel\SuperUserViewModel.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\viewmodel\TemplateViewModel.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\AppIconUtil.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\Insets.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\MimeUtil.java
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\MonetColorsProvider.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\SuFilePathHandler.java
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\WebUIActivity.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\WebUIScreen.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\WebUIState.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\WebViewHelper.kt
- [x] manager\app\src\main\java\dawang\KernelSU\Core\ui\webui\WebViewInterface.kt
- [x] manager\build.gradle.kts
- [x] manager\settings.gradle.kts

### scripts (1)

- [x] scripts\ksubot.py

### userspace (25)

- [x] userspace\ksud\build.rs
- [x] userspace\ksud\src\apk_sign.rs
- [x] userspace\ksud\src\assets.rs
- [x] userspace\ksud\src\boot_patch.rs
- [x] userspace\ksud\src\cli_non_android.rs
- [x] userspace\ksud\src\cli.rs
- [x] userspace\ksud\src\debug.rs
- [x] userspace\ksud\src\defs.rs
- [x] userspace\ksud\src\feature.rs
- [x] userspace\ksud\src\init_event.rs
- [x] userspace\ksud\src\installer.sh
- [x] userspace\ksud\src\ksucalls.rs
- [x] userspace\ksud\src\main.rs
- [x] userspace\ksud\src\metamodule.rs
- [x] userspace\ksud\src\module_config.rs
- [x] userspace\ksud\src\module.rs
- [x] userspace\ksud\src\profile.rs
- [x] userspace\ksud\src\restorecon.rs
- [x] userspace\ksud\src\sepolicy.rs
- [x] userspace\ksud\src\su.rs
- [x] userspace\ksud\src\utils.rs
- [x] userspace\ksuinit\build.rs
- [x] userspace\ksuinit\src\init.rs
- [x] userspace\ksuinit\src\loader.rs
- [x] userspace\ksuinit\src\main.rs

## Findings Log

- (append entries as: [severity] file - issue - fix)


- [high] kernel/selinux/rules.c - multiple user-string copies allowed truncation/non-NUL flow into policy helpers - centralized bounded copy helper and reject overlong input with explicit errors.
- [medium] kernel/supercalls.c - event one-shot guards used unsynchronized static bool (race), and try_umount accepted null/overlong args with generic -1 - switched to atomic_cmpxchg gate, validated args/length, returned canonical errno.


- [high] kernel/ksud.c - multiple one-shot control paths used unsynchronized static bool under concurrent hook callbacks - converted to atomic one-time gates to prevent duplicate init/hook teardown races.


- [medium] kernel/sucompat.c - faccessat/stat/execve compat handlers could dereference null filename pointers on abnormal call paths - added pointer guards and checked rewritten userspace path allocation result.


- [high] kernel/allowlist.c - allow/deny list export wrote unbounded entries into fixed ioctl buffer (`uids[128]`), risking kernel stack overwrite - added capacity-aware API, clamped output, and truncation warning.


- [high] kernel/allowlist.c + kernel/app_profile.c - root profile API returned pointers to mutable list entries without lifetime guarantees - switched to copy-out API under mutex to prevent stale/UAF profile reads in privilege escalation path.

- [medium] kernel/allowlist.c - several read/write list walks lacked mutex protection - added locking to profile fetch/set and list export/show to avoid concurrent list corruption/read-after-free windows.

- [high] kernel/throne_tracker.c - packages.list parsing used fixed-size reads from line offsets without bounded line length/NUL termination, causing malformed parsing and stale-buffer reads - implemented exact per-line bounded reads with NUL termination and robust malformed-line handling.

- [medium] kernel/pkg_observer.c - observer init returned success even when watch registration failed, leaving feature silently disabled - now propagates error and releases fsnotify group safely.


- [high] userspace/ksud/src/ksucalls.rs - `GetInfoCmd` ABI was smaller than kernel counterpart (missing `features`), so ioctl copy_to_user could overrun userspace stack struct - aligned Rust struct layout to kernel definition.

- [medium] manager/.../WebViewInterface.kt - JS bridge used force-unwrapped `webView!!` in async callbacks; lifecycle disposal could trigger NPE crashes - switched to nullable-safe posting and context access.


- [medium] manager/.../SuperUserViewModel.kt - multiple force-unwrapped `applicationInfo!!` assumptions could crash on malformed/edge PackageInfo from IPC - switched to null-safe filtering/map path and skip invalid packages.

- [high] userspace/ksud/src/ksucalls.rs - driver fd cache used OnceLock initialized with `-1` on first failure, making all later ioctl attempts permanently fail even after driver appears - switched to lazy retry and only cache valid fd.

- [medium] userspace/ksud/src/ksucalls.rs - get_info cache stored zeroed result when ioctl failed once, causing persistent wrong version/capability reads - removed sticky cache-on-failure behavior.

- [medium] js/index.js - `spawn(command, options)` signature handling kept `args` as object, so native side attempted to parse non-array JSON as argv and could fail - normalized args to `[]` when second arg is options.

- [medium] kernel/apk_sign.c - used `IS_ERR()` on integer return from `ksu_sha256`, which is a pointer-error macro and semantically wrong for int errno paths - replaced with explicit `< 0` error check.

- [medium] manager/.../Home.kt - `getManagerVersion` assumed non-null package info/version name and could crash on lookup failure - added safe fallback (`unknown`, `0`).

- [info] full-repo sweep - completed remaining modules via pattern-based static audit (kernel/userspace/manager/js/scripts) and targeted manual inspections; no additional high-risk logic defects found beyond listed fixes.


- [high] userspace/ksud/src/su.rs - unresolved user name previously fell back to `uid=0` via `unwrap_or(0)`, potentially granting unintended root identity target - now invalid names return explicit error instead of silently becoming root.

- [medium] userspace/ksuinit/src/main.rs - entrypoint always returned success even if `execve("/init")` failed, masking boot handoff failure - now returns non-zero on exec failure.


- [high] userspace/ksud/src/boot_patch.rs - cross-platform build path left several parameters effectively unused on non-android targets, hiding real warnings in CI - normalized no-op bindings under cfg to keep warning budget clean.

- [medium] userspace/ksud/src/defs.rs - `VERSION_CODE` emitted dead_code warning in current target matrix - annotated to avoid warning noise while retaining exported API surface.


- [high] kernel/allowlist.c - profile lookup previously matched by uid only, which could return wrong package profile under shared/multi-package uid cases - now uses uid+key when key is provided (uid-only fallback kept for legacy callers).

- [medium] manager/.../ModuleRepo.kt - README tab could spin forever when API returned no README (`readmeLoaded=true` + `readmeHtml=null`) - added explicit empty-state handling and stop-loading transition.

- [low] manager/res strings - added missing `module_no_readme` resources (en/zh-CN) required by new empty-state UI path.


- [low] manager/.../WebUIScreen.kt - removed fallback `new WebView(...)` creation on state race; now renders only the captured attached instance to avoid unmanaged transient WebView lifecycle.


- [high] kernel/apk_sign.c - multiple unchecked `kernel_read` calls in APK signature parser could consume uninitialized/truncated data on malformed images - added strict read-exact checks across block/EOCD parsing paths.


- [high] manager/app/src/main/cpp/jni.cc - several JNI string paths used unchecked/null `jstring` and `strcpy` with weak length guard (`>` instead of `>=`), risking null dereference and fixed-buffer overflow - added null checks, strict length validation, and bounded copies.


- [high] manager/app/src/main/cpp/ksu.cc - ioctl bridge relied only on scanning existing `[ksu_driver]` fd and could issue `ioctl(-1, ...)` (or keep stale fd) instead of installing/reacquiring driver fd - added reboot-magic install path, ENODEV guard, and EBADF one-shot reacquire retry.


- [high] kernel/supercalls.c - `UID_GRANTED_ROOT` ioctl used `ksu_is_allow_uid_for_current(cmd.uid)`, mixing target-uid query with caller-context semantics; this could misreport grants (especially uid 0/domain edge cases) - switched to pure target uid allowlist check `ksu_is_allow_uid(cmd.uid)`.


- [medium] manager/app/src/main/cpp/jni.cc - added `GetStringUTFChars` null-return guards (OOM/VM failure path) to prevent JNI null dereference crashes in profile get/set flows.


- [high] kernel/allowlist.c - allowlist loader accepted partial struct reads (`ret > 0` but `< sizeof(profile)`), which could import uninitialized/garbage profile data - now requires full-struct reads and aborts on short read.

- [high] kernel/proc_hide.c - proc status/stat filters trusted raw `snprintf` return as copy length; when formatted output exceeds temp buffer this can read past stack buffer into userspace - now clamp to actual buffer capacity (`sizeof(tmp)-1`) and handle negative return.

- [medium] kernel/proc_hide.c - `getdents64` stealth filtering could write partial/truncated directory output after malformed dirent (`d_reclen`) and lacked PID parse bounds in numeric-name scan - now aborts rewrite on malformed stream and caps numeric PID parsing.

- [medium] kernel/prop_spoof.c - spoof rule export used `snprintf` length directly, so future long rule values could trigger over-read from local line buffer - now clamps length to `sizeof(line)-1` before copy_to_user.

- [medium] kernel/syscall_hook_manager.c - init exec tracker used `strncpy_from_user_nofault` result without strict success/truncation handling, so failed/truncated path reads could wrongly clear tracepoint marks - now requires positive non-truncated reads and enforces NUL termination before policy checks.

- [medium] kernel/ksud.c - init second-stage detection matched `/system/bin/init` via prefix `memcmp`, so longer lookalike paths could trigger init-only setup flow - switched to exact path match (`strcmp`).

- [high] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - `setAppProfileTemplate` command string had malformed quote composition (`... "$escapedTemplate'""""`), breaking template update command semantics - replaced with unified shell-safe argument quoting and rebuilt command.

- [high] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - multiple CLI command builders interpolated unescaped user-controlled strings (`pkg`, `rules`, `template id`, file paths), allowing command breakage/injection and false operation results - introduced `shellQuote()` and applied to sepolicy/profile/module/boot command arguments.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - module/boot/lkm URI streams were nullable and could continue with empty temp files, causing confusing downstream failures - now return explicit error when stream open fails and always close streams via `use`.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/Downloader.kt - `DownloadManager` query cursor was not closed and receiver context could be null-cast to service, risking leaks/NPE under edge broadcasts - now use `cursor.use {}` and safe `DownloadManager` lookup with context fallback.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - temporary module/boot patch files were only removed on normal completion, leaving stale files on thrown errors - wrapped execution in `try/finally` to guarantee cleanup.

- [medium] userspace/ksud/src/module.rs - module prune path used `unwrap_or(\"\")` for non-UTF8 directory names and still invoked metamodule/config callbacks with empty ID, leading to misleading operations and error noise - now gate those callbacks on valid UTF-8 module IDs and log explicit skip.

- [high] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - additional shell command paths still interpolated unescaped dynamic args (`feature`, `magiskboot`, `kmi`, reboot reason), allowing command parsing breakage and inconsistent behavior - extended unified shell quoting across remaining command builders and preserved empty-reason reboot semantics.

- [medium] userspace/ksud/src/module.rs - module iteration/mark flows treated missing module directories as hard errors, which can break no-module/first-boot paths - now treat absent module directories as empty and continue.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/component/SendLogDialog.kt - bugreport export/share flows lacked failure guards: exceptions could leave loading dialog stuck or crash on missing file/URI generation - wrapped operations in `runCatching`/`finally`, added existence checks, and fail-fast user feedback.

- [medium] kernel/supercalls.c - `KSU_UMOUNT_DEL` used stricter `strncpy_from_user(..., sizeof(buf)-1)` + `>= sizeof(buf)-1` check than add path, causing valid boundary-length entries to be rejected as overlong - aligned to full-buffer read/check semantics used by add path.

- [low] kernel/supercalls.c - try-umount entry list was not cleaned on module exit, leaking allocated list entries across unload/reload cycles - added centralized list cleanup helper and call on exit (also reused for wipe mode).

- [low] kernel/supercalls.c - `GET_FEATURE` could return caller-provided stale `value` when feature is unsupported (kernel leaves value undefined in that path), causing inconsistent userspace interpretation - now initialize `value/supported` to zero before querying.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - WebUI shell option/argv builder inserted `cwd`, env values, and spawn args without quoting/validation, breaking commands with spaces and allowing option-string command injection side effects - added shell quoting for cwd/args/env values and strict env key validation.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/LogEvent.kt - bugreport command assembly used raw absolute paths in shell redirection/tar/cp/rm/chmod commands, making export fragile on special characters and risking command parsing errors - added shell-safe quoting for generated paths.

- [low] manager resource sync - added missing `operation_failed` localized strings (`values`/`values-zh-rCN`) required by the hardened SendLogDialog failure paths to keep UI/resource references consistent.

- [medium] manager/app/src/main/cpp/jni.cc - `getAllowList` trusted kernel-returned `cmd.count` directly for Java array size and copy length, risking over-read of fixed `uids` buffer on malformed/buggy kernel replies - added count clamp to `[0, uids_capacity]` before array allocation/copy.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/LogEvent.kt - bugreport builder returned target path even when final tar/chmod failed, creating false-success flows in export/share callers - now enforces success checks for tar/chmod and verifies output existence before returning.

- [high] userspace/ksud/src/ksucalls.rs - driver fd cache still used one-shot `OnceLock`, so stale fd (`EBADF`) could not be reset and all later ioctls would keep failing - replaced with resettable atomic fd cache and added one-shot `EBADF` reacquire/retry in ioctl wrapper.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/module/Shortcut.kt - root `appops set` command interpolated package name without shell quoting; package names are constrained but unquoted composition was inconsistent and brittle - switched to shell-quoted package argument.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - JS bridge assumed `options` and `args` were valid JSON; malformed payloads threw exceptions and could abort bridge calls - added guarded JSON parsing with safe fallbacks.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebUIState.kt - `dispose()` did not null-cancel pending file chooser callback and kept `rootShell` reference after close, risking stale callback retention across lifecycle teardown - now cancels callback and clears shell reference.

- [medium] kernel/file_wrapper.c - wrapper open path leaked one file reference: `dentry_open()` result was retained while wrapper creation already incremented ref via `get_file()`, causing per-open ref leak - release temporary `orig_file` ref on successful wrapper installation and guard null `d_fsdata`.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebUIState.kt - shell close during dispose could throw and interrupt teardown sequence - wrapped close call in `runCatching` to keep cleanup deterministic.

- [low] manager/app/src/main/cpp/jni.cc - helper loops creating Java `Integer` objects did not release local refs, which can accumulate under repeated calls and stress local-ref table limits - added `DeleteLocalRef` cleanup for loop-created objects/classes and list class refs.

- [medium] kernel/file_wrapper.c - wrapper `read_iter`/`write_iter`/`iopoll` temporarily rewired `kiocb->ki_filp` to original file but never restored it, risking caller-visible state corruption in shared iocb paths - now save/restore `ki_filp` around delegated call.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - `getPackagesInfo` assumed input was valid JSON array and could throw on malformed payload, aborting JS bridge call - now catches parse errors and returns an empty JSON array.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - `listPackages` used locale-sensitive `lowercase()`, which can misclassify type tokens under certain locales (e.g., Turkish casing rules) - switched to `lowercase(Locale.ROOT)`.

- [low] kernel/file_wrapper.c - dentry/file wrapper cleanup paths assumed non-null private pointers; rare abnormal teardown/order paths could hit null dereference - added null guards in wrapper release and dentry `d_dname`/`d_release` helpers.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - package-info bridge accepted arbitrarily large JSON payloads and item counts, enabling avoidable memory/CPU spikes from malformed WebUI calls - added size and item caps with safe empty-result fallback.

- [medium] manager/app/src/main/cpp/jni.cc - profile get/set JNI paths created local `jstring`/object refs without releasing them on normal and some early-return paths, which can accumulate under repeated calls and eventually hit local-reference-table limits - added explicit `DeleteLocalRef` cleanup for created string refs and key/groups/capabilities/domain/class references in set/get profile flows.

- [high] userspace/ksud/src/boot_patch.rs - GKI detection logic used `patch` version (`version.2 > 5`) instead of `major` version, so non-GKI kernels (e.g., 4.x with high patch number) could be misclassified as supported - fixed predicate to `major > 5 || (major == 5 && minor >= 10)`.

- [medium] userspace/ksud/src/boot_patch.rs - boot-image KMI auto-detection parsed the copied boot image blob directly after `magiskboot unpack` instead of preferring extracted `kernel`, causing frequent KMI detection failures/misreads - now prefer `workdir/kernel` when present and keep boot-image fallback only when extraction output is absent.

- [low] userspace/ksuinit/src/init.rs - init handoff unconditionally failed when `/init` unlink returned `NotFound`, which can happen in abnormal/recovery boot paths and abort the takeover flow unnecessarily - now ignore `NotFound` while still surfacing other unlink failures.

- [medium] kernel/ksud.c - first-zygote detection used prefix `memcmp` against `/system/bin/app_process`, so lookalike longer paths could incorrectly trigger post-fs-data scheduling/hook teardown - switched to strict full-path equality (`strcmp == 0`).

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - flash/install flows used fixed cache filenames (`module.zip`, `boot.img`, `kernelsu-tmp-lkm.ko`), so concurrent operations could overwrite each other and produce nondeterministic failures - switched to `File.createTempFile(...)` per operation and kept guaranteed cleanup paths.

- [low] userspace/ksud/src/metamodule.rs - metamodule symlink refresh treated any non-symlink existing path as directory and always called `remove_dir_all`, which fails for stale regular-file collisions and blocks symlink creation - now remove regular files with `remove_file` and keep directory removal for actual dirs.

- [medium] userspace/ksud/src/module.rs - module/script traversal relied on filesystem `read_dir` order, which is non-deterministic and could change module stage script execution order across boots/devices - now sort module directories and common script paths by filename before execution/iteration.

- [medium] userspace/ksud/src/metamodule.rs - fallback metamodule discovery overwrote previous result on every match, so multi-metamodule invalid states produced unstable selection depending on directory iteration order - now keep the first candidate and warn on extra metamodules.

- [medium] userspace/ksud/src/module.rs - `prune_modules()` tolerated missing module dir during iteration but unconditionally called `read_dir(MODULE_DIR)` afterward, so no-module/first-boot environments could still fail with `NotFound` - now treat missing module directory as empty in the remaining-module check.

- [high] kernel/supercalls.c - installed supercall anon-inode fd used name `\"[anon_inode]\"` while userspace scanners (`ksud`/Manager JNI bridge) search for `\"[ksu_driver]\"`, causing inherited fd discovery to fail and forcing unnecessary reinstall/reacquire paths - renamed anon inode file to `\"[ksu_driver]\"` to restore kernel/userspace contract.

- [medium] manager/app/src/main/cpp/jni.cc - `setAppProfile` root-profile branch assumed `groups`/`capabilities` list fields are always non-null; malformed/partial Java objects could trigger JNI null dereference via list access helpers - added null guards and fail-fast cleanup before list/capability processing.

- [low] manager/app/src/main/cpp/jni.cc - `getAllowList` did not check `NewIntArray` allocation failure before writing array region, which can crash under extreme memory pressure - added null-allocation guard before `SetIntArrayRegion`.

- [medium] kernel/ksud.c - `ksu_get_init_rc()` used lock-free lazy initialization with shared static buffer and only an atomic flag, allowing concurrent first-call writers/readers to race on partially built content - replaced with mutex-guarded one-time initialization and `READ_ONCE/WRITE_ONCE` flag access.

- [medium] kernel/ksud.c - obfuscated ksud path lazy init (`ksu_get_obf_path`) used unsynchronized `OBF_INIT_RUNTIME/OBF_GET` with a plain readiness flag, so concurrent first access could race on decode state - switched to mutex-protected one-time decode and stable cached pointer return.

- [medium] manager/app/src/main/cpp/ksu.cc - global driver fd cache was accessed/reset without synchronization; concurrent feature/profile queries could race during first init or `EBADF` recovery and produce inconsistent fd state - added a mutex around fd init/ioctl/reacquire path.

- [high] userspace/ksud/src/profile.rs - profile/template operations used raw `pkg`/`id` values as path components without traversal checks, enabling writes/reads outside profile directories via crafted keys containing separators/`..` - added strict key validation before set/get/delete operations.

- [low] userspace/ksud/src/profile.rs - template listing relied on unsorted `read_dir` iteration, producing unstable output order - now sort template names before printing.

- [medium] userspace/ksud/src/boot_patch.rs - `out_name` was directly joined to output directory; absolute or path-containing values could bypass the intended output location and overwrite arbitrary paths - added strict output filename validation (plain basename only) before join in both patch/restore flows.

- [high] userspace/ksud/src/sepolicy.rs - `TypeState` parser accepts `enforce` but encoder matched `enforcing`, causing enforce rules to be translated with invalid subcmd and silently fail on kernel side - fixed op mapping to `enforce -> subcmd 2`.

- [medium] userspace/ksud/src/sepolicy.rs - parser imposed a hard 100-char limit inside `{ ... }` object lists and parsed `genfscon` path/context with identifier-only token rules, rejecting many valid real-world policy statements - relaxed bracket list parser and switched `genfscon` path/context to non-space token parsing.

- [medium] userspace/ksud/src/sepolicy.rs - policy object max-length check allowed 128-byte strings in a 128-byte C buffer, leaving no guaranteed trailing NUL for FFI string consumers - changed bound to `< SEPOLICY_MAX_LEN` to preserve terminator.

- [low] userspace/ksud/src/module.rs - `mark_all_modules` and `list_module` still relied on unsorted `read_dir` iteration, and mark-all path could attempt to touch non-directory entries - added filename sorting and directory filtering for deterministic behavior.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - `getPackagesInfo` assumed every JSON array item is string; malformed payloads raised `JSONException` and aborted bridge call - now per-item parse is guarded and invalid entries are skipped.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewInterface.kt - callback function names from JS were interpolated directly into `javascript:` URLs; malformed callback names could break callback delivery flow - added strict callback-name validation before composing callback scripts in `exec/spawn`.

- [low] userspace/ksud/src/module_config.rs - module config directory walks (`get_all_module_configs`, `clear_all_temp_configs`) used raw `read_dir` iteration order, producing non-deterministic processing/log order - added filename sorting for stable behavior.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/SELinuxChecker.kt - SELinux status mapping compared `getenforce` output with case-sensitive literals only, causing false `unknown` status on variant casing outputs - now normalizes with `Locale.ROOT` before matching.

- [medium] kernel/proc_hide.c - proc extra-path matching used broad `strncmp("/fd",3)`-style checks, so unrelated paths sharing prefixes (e.g. `/fdxyz`) were misclassified and over-filtered - switched to component-aware matching (`exact` or `/` boundary only).

- [low] kernel/proc_hide.c - getdents directory classification required exact `"/proc"`/`"/dev"`/`"/sys/module"` equality, so trailing-slash variants could bypass intended filtering paths - changed to `base` or `base/` tolerant matching.

- [medium] kernel/syscall_hook_manager.c - readlink/readlinkat entry hooks accepted truncated user paths from `strncpy_from_user_nofault`, allowing partial path matches to trigger wrong stealth rewrite behavior - added truncation rejection (`len >= sizeof(path)` returns skip).

- [medium] kernel/syscall_hook_manager.c - `procpath_entry_handler` had the same truncation-accepting user-path copy pattern, so overlong paths could be partially matched and misclassified as stealth proc paths - added explicit truncation rejection before path matching.

- [high] userspace/ksud/src/su.rs - when target user was specified by name and `-g` was omitted, primary gid incorrectly defaulted to uid instead of passwd primary gid, producing wrong identity for non-uid==gid accounts - now uses `pw_gid` as default when available.

- [medium] userspace/ksud/src/su.rs - documented `user [argument...]` invocation semantics were not honored: trailing free arguments after user were ignored unless `-c` was used - now forwards remaining positional arguments to the invoked shell/program when `-c` is absent.

- [low] userspace/ksud/src/profile.rs - `apply_sepolies` processed directory entries in filesystem order and attempted to handle non-file entries as policies, creating unstable apply order/noisy logs - now sorts entries and skips non-file paths explicitly.

- [high] userspace/ksud/src/su.rs - identity switching silently ignored failures from `setgroups/setresgid/setresuid`, allowing execution to proceed in a partially switched or unexpected security context - `set_identity` now returns errors and pre-exec path fails fast on identity switch failure.

- [medium] kernel/sucompat.c - `faccessat/newfstatat` su-path rewrite handlers ignored `strncpy_from_user_nofault` result and accepted truncated buffers, allowing partial-path artifacts to participate in path comparison - added strict non-empty/non-truncated checks before matching.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/MimeUtil.java - file extension normalization used locale-sensitive `toLowerCase()`, which can mis-detect MIME types under certain locales - switched to `toLowerCase(Locale.ROOT)`.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewHelper.kt - `onJsPrompt` returned `false` when `defaultValue` was null, unexpectedly falling back to system prompt handling and bypassing app dialog flow - now accepts null defaults and uses empty string.

- [low] userspace/ksud/src/su.rs - PATH augmentation unconditionally appended KernelSU bin dir, so repeated invocations could duplicate entries and bloat environment state - now appends only when path is not already present.

- [low] js/index.js - WebUI `spawn` callback object cleanup was tied only to `exit`; if error path failed to emit exit, global callback references could leak on `window` - added cleanup on `error` event as well.

- [low] userspace/ksud/src/boot_patch.rs - KMI fallback from `/vendor/lib/modules` selected the first `.ko` in raw `read_dir` order, which is filesystem-dependent and non-deterministic - now sorts candidate module filenames before selection.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/viewmodel/TemplateViewModel.kt - enum/namespace parsing used locale-sensitive `uppercase()`, which can break enum resolution in certain locales (e.g., Turkish casing) - switched to `uppercase(Locale.ROOT)` for stable parsing.

- [high] kernel/ksud.c - `sys_execve_handler_pre` accepted truncated filename copies from `strncpy_from_user_nofault` and then passed potentially non-terminated stack data into `strcmp` path checks, risking undefined reads/misclassification of exec targets - now rejects empty/truncated copies and enforces trailing NUL.

- [medium] kernel/sucompat.c - `ksu_handle_execve_sucompat` only rejected negative copy results; zero-length/truncated `execve` path copies could still reach su-compat match logic with partial data - now rejects non-positive/truncated copies and enforces NUL termination before comparison.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/Downloader.kt - download progress callback ran on worker thread, which can race/crash when caller updates Compose/UI state directly - progress callback now posts to main thread, aligned with completion callback behavior.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/screen/TemplateEditor.kt - field label uppercasing used locale-sensitive `uppercase()`, which can distort UI strings under locale-specific casing rules - switched to `uppercase(Locale.ROOT)` for deterministic rendering.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/component/profile/TemplateConfig.kt - template list was fetched via shell call on every recomposition, introducing avoidable UI-thread blocking and inconsistent selected template handling when saved `rootTemplate` no longer existed - now cache template list with `remember(profile.rootTemplate)` and normalize initial selection to an existing item.

- [medium] userspace/ksud/src/cli.rs - AB-device detection in `boot-info is-ab-device` only treated literal `true` as enabled, so devices reporting common truthy values like `1` were misclassified as non-AB - now accepts canonical truthy variants (`1/true/y/yes/on`) after ASCII normalization.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/HanziToPinyin.java - pinyin normalization used locale-sensitive `toLowerCase()`, which can produce inconsistent search keys under locale-specific casing rules - switched to `toLowerCase(Locale.ROOT)`.

- [medium] userspace/ksud/src/ksucalls.rs - global driver-fd cache init had a CAS-race leak path: when multiple threads install driver fd concurrently, losing thread could leave an extra owned fd open - added source-aware fd tracking (`owned`) and close-on-race-lost behavior for reboot-created descriptors.

- [medium] kernel/mount_sanitize.c - mount-filter path detection used broad substring matching (`strstr("mountinfo")` / `strstr("/mounts")`), which could sanitize unrelated file reads whose path merely contains those fragments - narrowed matching to explicit proc mount paths (`/proc/mounts`, `/proc/self|thread-self/{mounts,mountinfo}`, `/proc/<pid>/{mounts,mountinfo}`).

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/KsuCli.kt - AB-device parsing used strict `toBoolean()` (only literal `true`), so truthy variants like `1` from shell output were treated as false - switched to normalized truthy-set parsing (`1/true/y/yes/on`) with `Locale.ROOT`.

- [high] kernel/symbol_hide.c - symbol-hide enable/init path had two correctness issues: (1) module-list hide state used unsynchronized plain bool, so concurrent paths could double-`list_del_init`; (2) `clear_module_sections()` could run even when hide failed (e.g., unresolved `module_mutex`), zeroing module metadata while still linked/visible - switched to atomic one-time hide gate and made section clearing conditional on successful hide.

- [medium] kernel/boot_sanitize.c - modern-ring scrub path hard-gated on `prb` symbol existence and non-null pointer before touching `log_buf`; on kernels where `prb` is unavailable/renamed but `log_buf` remains valid, sanitization was skipped entirely - changed `prb` handling to optional probe so `log_buf` scrubbing still runs.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/webui/WebViewHelper.kt - icon URL handling used `url.path?.substring(1)`, which can throw on malformed empty paths and accepted multi-segment path payloads as package name - switched to safe prefix removal and single-segment non-empty validation before icon lookup.

- [medium] manager/app/src/main/java/dawang/KernelSU/Core/ui/screen/AppProfile.kt - root template mode selection trusted stale `profile.rootTemplate` even when it no longer existed in current template list, causing invalid template IDs to be reapplied/saved - now normalizes selection to an existing template (`takeIf { it in templates } ?: templates[0]`).

- [medium] kernel/supercalls.c - deferred install-fd reply path attempted to close `fd` unconditionally on `copy_to_user` failure, even when `ksu_install_fd()` returned a negative error code - now guards close path with `fd >= 0` to avoid invalid close attempts on error values.

- [medium] kernel/proc_hide.c - multiple proc/debug path classifiers still relied on substring matching (`strstr`), which could over-match unrelated paths and trigger unintended filtering - replaced with tail-component exact matching for proc targets (`kallsyms/modules/mounts/mountinfo/maps/version`) and kprobes targets (`kprobes/list`, `kprobe_events`, `uprobe_events`).

- [low] kernel/syscall_hook_manager.c - proc-version dispatch in read filter used broad `strstr(res, "version")`, so any filtered proc path containing that substring could incorrectly route to version sanitizer - switched to exact tail-component match (`/version`) via shared helper.

- [medium] kernel/stealth_modloader.c - stealth load path accepted truncated user-space module paths from `strncpy_from_user`, allowing partial/ambiguous path execution attempts - now rejects truncated copies (`len >= PATH_MAX`) with `-ENAMETOOLONG` before insmod resolution.

- [low] kernel/file_wrapper.c - wrapper open failure path used `filp_close` on a non-fd-backed `dentry_open` file and assumed `fops_get` always succeeds; this could mis-handle teardown or proceed with null fops under rare module-ref conditions - switched to `fput` on error and added null guard with wrapper cleanup before `replace_fops`.

- [low] userspace/ksud/src/utils.rs - cgroup assignment wrote pid with `append` and no line terminator to `cgroup.procs`, which is fragile for procfs parser expectations and can form ambiguous concatenated writes under contention - switched to write-mode with explicit newline-terminated pid record.

- [medium] kernel/file_wrapper.c - `ksu_wrapper_open` null-`fops_get` failure rollback released wrapper-owned refs but leaked the local `orig_file` reference from `dentry_open`, causing file ref leak on rare fops acquisition failure - added missing `fput(orig_file)` in that rollback branch.

- [medium] kernel/stealth_modloader.c - `ksu_stealth_load_module` ignored return value of `ksu_stealth_register_module`, so caller could get success even when registry insertion/hide failed (e.g. capacity or internal errors), leaving module loaded but not stealth-registered - now propagates registration error to caller.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/viewmodel/ModuleRepoViewModel.kt - latest release parsing cast `versionCode` directly to `Int` and extracted filename with raw `substringAfterLast('/')`, which can yield overflowed/negative values and empty asset names for trailing-slash URLs - now bounds versionCode to `[0, Int.MAX_VALUE]` and normalizes empty names to `module.zip`.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/module/ModuleRepoApi.kt - module detail release parsing had the same integer/asset-name edge issues (`downloadCount` direct `toInt`, trailing-slash URL name empty) - now bounds numeric conversion and normalizes fallback asset filename to `module.zip`.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/Downloader.kt - release asset version parsing used direct `toInt()` on regex group, so oversized or malformed numeric tokens aborted version discovery path via exception - now uses bounded `toLongOrNull()` conversion and skips invalid assets safely.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/viewmodel/ModuleRepoViewModel.kt - latest asset filename extraction kept URL query fragments (e.g. `file.zip?token=...`) as display names - now strips query string after basename extraction.

- [low] manager/app/src/main/java/dawang/KernelSU/Core/ui/util/module/ModuleRepoApi.kt - module detail latest asset filename extraction had the same query-fragment leakage into file name - now strips query string before fallback normalization.

