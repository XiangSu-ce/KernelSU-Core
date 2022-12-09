---
layout: home
title: Home

hero:
  name: KernelSU Core
  text: 基于内核的 Android Root 方案
  tagline: "基于 KernelSU 二次开发，增强隐身功能"
  image:
    src: /logo.png
    alt: KernelSU Core
  actions:
    - theme: brand
      text: 开始使用
      link: /guide/what-is-kernelsu
    - theme: alt
      text: GitHub 仓库
      link: https://github.com/XiangSu-ce/KernelSU-Core

features:
  - title: Kernel-based
    details: As the name suggests, KernelSU runs inside the Linux kernel, giving it more control over userspace apps.
  - title: Root access control
    details: Only permitted apps can access or see su; all other apps remain unaware of it.
  - title: Customizable root privileges
    details: KernelSU allows customization of su's uid, gid, groups, capabilities, and SELinux rules, hardening root privileges.
  - title: Metamodule system
    details: Pluggable module infrastructure allows systemless /system modifications. Install a metamodule like meta-overlayfs to enable module mounting.
