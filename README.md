# KernelSU Core

A kernel-based root solution for Android, enhanced with advanced stealth features and a custom UI.

> **This project is a derivative work based on [KernelSU](https://github.com/tiann/KernelSU) by [@tiann](https://github.com/tiann), licensed under GPL-3.0 / GPL-2.0.**

## About

**KernelSU Core** is a secondary development project based on the open-source [KernelSU](https://github.com/tiann/KernelSU). We build upon the excellent foundation of the original KernelSU project and extend it with additional features and improvements.

We sincerely thank the original KernelSU developers for their outstanding work.

## Changes from Upstream KernelSU

### Kernel Enhancements
- **Syscall Hook Manager** (`kernel/syscall_hook_manager.c`) — Advanced syscall tracepoint management with kretprobes, process mark/unmark system, and read/pread64 post-filtering for stealth operations.
- **Feature Management Framework** (`kernel/feature.h`) — Pluggable feature toggle system supporting 12+ features including stealth filtering, property spoofing, process hiding, debug disabling, log silencing, symbol hiding, mount sanitization, and more.
- **Enhanced Logging** (`kernel/klog.h`) — Improved kernel logging system.
- **Extended Supercalls** (`kernel/supercalls.c/h`) — Expanded supercall interface for new features.
- **Additional SELinux Rules** (`kernel/selinux/rules.c`, `selinux.h`) — Extended SELinux policy support.

### Manager App
- **Rebranded UI** — Custom app icon and branding as "KernelSU Core".
- **Package Rename** — `me.weishu.kernelsu` → `dawang.KernelSU.Core`.
- **UI Restructuring** — Significant UI refactoring with a modernized interface.

## Upstream Repository

- **Original Project**: [KernelSU](https://github.com/tiann/KernelSU) by [@tiann](https://github.com/tiann)
- **Original Website**: [kernelsu.org](https://kernelsu.org)
- **Original License**: GPL-3.0-or-later (GPL-2.0-only for the `kernel` directory)

## License

This project inherits the same license structure as the original KernelSU:

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `kernel` directory are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

See [LICENSE](LICENSE) for the full license text.

## Credits

- [KernelSU](https://github.com/tiann/KernelSU) by [@tiann](https://github.com/tiann) — The upstream project this work is based on.
- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/) — The KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk) — The powerful root tool.
- [genuine](https://github.com/brevent/genuine/) — APK v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine) — Some rootkit skills.
