**简体中文** | [English](README_EN.md)

# KernelSU Core

一个 Android 上基于内核的 root 方案，增强了高级隐身功能。

> **本项目是基于 [@tiann](https://github.com/tiann) 的 [KernelSU](https://github.com/tiann/KernelSU) 开源项目二次开发的衍生作品。**

[![Latest release](https://img.shields.io/github/v/release/XiangSu-ce/KernelSU-Core?label=Release&logo=github)](https://github.com/XiangSu-ce/KernelSU-Core/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/XiangSu-ce/KernelSU-Core?logo=gnu)](/LICENSE)

## 特性

- 基于内核的 `su` 和权限管理。
- 基于 [metamodules](https://kernelsu.org/zh_CN/guide/metamodule.html) 的模块系统：可插拔的模块架构。
- [App Profile](https://kernelsu.org/zh_CN/guide/app-profile.html)：把 Root 权限关进笼子里。
- 高级隐身特性管理框架。
- Syscall Hook 管理器，支持 kretprobes 和进程标记。

## 社区

- QQ群：**325900535**
- GitHub：[XiangSu-ce/KernelSU-Core](https://github.com/XiangSu-ce/KernelSU-Core)

## 上游项目

本项目基于 [@tiann](https://github.com/tiann) 的 [KernelSU](https://github.com/tiann/KernelSU)。详见 [NOTICE](NOTICE)。

## 许可证

- 目录 `kernel` 下所有文件为 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 `kernel` 目录的其他部分均为 [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)。

## 鸣谢

- [KernelSU](https://github.com/tiann/KernelSU) by [@tiann](https://github.com/tiann)：上游项目。
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)：KernelSU 的灵感。
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具箱。
- [genuine](https://github.com/brevent/genuine/)：apk v2 签名验证。
- [Diamorphine](https://github.com/m0nad/Diamorphine)：一些 rootkit 技巧。
