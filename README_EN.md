**English** | [简体中文](README.md)

# KernelSU Core

An enhanced derivative of [KernelSU](https://github.com/tiann/KernelSU) with extended kernel-level security and privacy protection.

[![Latest release](https://img.shields.io/github/v/release/XiangSu-ce/KernelSU-Core?label=Release&logo=github)](https://github.com/XiangSu-ce/KernelSU-Core/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Channel](https://img.shields.io/badge/QQ%20Group-325900535-blue.svg?logo=tencentqq)](https://qm.qq.com/q/sPZCNpQTNS)

## Features

1. Kernel-based `su` and root access management (inherited from KernelSU)
2. Module system based on metamodules (inherited from KernelSU)
3. App Profile (inherited from KernelSU)
4. Runtime feature toggle system with dynamic enable/disable for all extensions
5. System property correction for unlock-related property values
6. Debug interface access control
7. /proc sensitive information filtering and access control
8. Kernel symbol table cleanup and mount information sanitization
9. Kernel log filtering and boot trace cleanup
10. Stealth kernel module loading framework
11. Process-level privacy protection and file I/O trace protection
12. Inter-process communication protection
13. Compile-time string obfuscation and enhanced silent mode
14. Extended control interface and SELinux policy optimization
15. Fully redesigned manager app with independent branding and UI

## Compatibility

KernelSU Core supports Android GKI 2.0 devices (kernel 5.10+). Older kernels (4.14+) are also supported, but the kernel will need to be built manually.

WSA, ChromeOS, and container-based Android are all supported. Currently only `arm64-v8a` and `x86_64` architectures are supported.

## Usage

- [Installation](https://kernelsu.org/guide/installation.html)
- [How to build](https://kernelsu.org/guide/how-to-build.html)
- [KernelSU Official Docs](https://kernelsu.org/)

## Community

- QQ Group: [325900535](https://qm.qq.com/q/sPZCNpQTNS)

## Security

For information on reporting security vulnerabilities, see [SECURITY.md](/SECURITY.md).

## License

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits

- [KernelSU](https://github.com/tiann/KernelSU): The upstream project. Thanks to [weishu](https://github.com/tiann).
- [Magisk](https://github.com/topjohnwu/Magisk): The powerful root tool.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some kernel techniques.
