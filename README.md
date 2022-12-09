**简体中文** | [English](README_EN.md)

# KernelSU Core

基于 [KernelSU](https://github.com/tiann/KernelSU) 的增强衍生版，扩展了内核级的安全防护与隐私保护能力。

[![Latest release](https://img.shields.io/github/v/release/XiangSu-ce/KernelSU-Core?label=Release&logo=github)](https://github.com/XiangSu-ce/KernelSU-Core/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Channel](https://img.shields.io/badge/QQ群-325900535-blue.svg?logo=tencentqq)](https://qm.qq.com/q/sPZCNpQTNS)

## 功能特性

1. 基于内核的 `su` 与 root 权限管理（继承自 KernelSU）
2. 基于 metamodule 的模块系统（继承自 KernelSU）
3. App Profile 应用配置（继承自 KernelSU）
4. 运行时功能开关系统，所有扩展能力均可动态启用或关闭
5. 系统属性校正，自动修正与解锁相关的属性值
6. 调试接口访问控制
7. /proc 敏感信息过滤与访问控制
8. 内核符号表清理与挂载信息净化
9. 内核日志过滤与启动痕迹清理
10. 内核模块隐匿加载框架
11. 进程级隐私保护与文件 I/O 痕迹保护
12. 进程间通信保护
13. 编译期字符串混淆与增强静默模式
14. 扩展控制接口与 SELinux 策略优化
15. 管理器应用全面改造，独立品牌与界面

## 兼容性

KernelSU Core 支持 Android GKI 2.0 设备（内核 5.10+），同时也支持较旧内核（4.14+），但需要手动编译内核。

支持 WSA、ChromeOS 以及基于容器的 Android 环境。目前支持 `arm64-v8a` 和 `x86_64` 架构。

## 使用说明

- [安装教程](https://kernelsu.org/guide/installation.html)
- [编译指南](https://kernelsu.org/guide/how-to-build.html)
- [KernelSU 官方文档](https://kernelsu.org/)

## 社区

- QQ 群：[325900535](https://qm.qq.com/q/sPZCNpQTNS)

## 安全

如需报告安全漏洞，请参阅 [SECURITY.md](/SECURITY.md)。

## 许可证

- `kernel` 目录下的文件遵循 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
- 其他部分遵循 [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)

## 致谢

- [KernelSU](https://github.com/tiann/KernelSU)：本项目的上游项目，感谢原作者 [weishu](https://github.com/tiann)。
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具。
- [Diamorphine](https://github.com/m0nad/Diamorphine)：部分内核技术参考。
