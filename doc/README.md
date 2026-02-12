# RustNmap 设计文档

> **版本**: 1.0.0
> **日期**: 2026-02-11
> **状态**: 设计阶段
> **目标平台**: Linux x86_64 (AMD64)

---

## 文档导航

本文档已按模块拆分，请从以下链接选择所需内容：

### 第一部分：项目概述与架构

| 文档 | 描述 | 文件 |
|------|------|------|
| 项目概述 | 项目背景、目标、用户 | [overview.md](overview.md) |
| 系统架构 | 整体架构图、模块依赖 | [architecture.md](architecture.md) |

### 第二部分：核心功能模块

| 模块 | 描述 | 文件 |
|------|------|------|
| 主机发现 | ICMP/TCP/UDP 主机发现技术 | [modules/host-discovery.md](modules/host-discovery.md) |
| 端口扫描 | TCP SYN/CONNECT/UDP/扫描技术 | [modules/port-scanning.md](modules/port-scanning.md) |
| 服务探测 | 服务版本识别与指纹匹配 | [modules/service-detection.md](modules/service-detection.md) |
| OS 检测 | 操作系统指纹识别 | [modules/os-detection.md](modules/os-detection.md) |
| NSE 引擎 | Lua 脚本引擎核心设计 | [modules/nse-engine.md](modules/nse-engine.md) |
| Traceroute | 网络路由追踪 | [modules/traceroute.md](modules/traceroute.md) |
| 规避技术 | 防火墙/IDS 规避 | [modules/evasion.md](modules/evasion.md) |
| 输出模块 | 多格式输出设计 | [modules/output.md](modules/output.md) |
| 目标解析 | 目标规格解析 | [modules/target-parsing.md](modules/target-parsing.md) |
| 原始数据包 | Linux x86_64 数据包引擎 | [modules/raw-packet.md](modules/raw-packet.md) |

### 第三部分：数据库与项目结构

| 文档 | 描述 | 文件 |
|------|------|------|
| 数据库设计 | 服务探测与 OS 指纹数据库 | [database.md](database.md) |
| 项目结构 | Cargo Workspace 结构 | [structure.md](structure.md) |

### 第四部分：开发与实施

| 文档 | 描述 | 文件 |
|------|------|------|
| 开发路线图 | Phase 1-4 开发计划 | [roadmap.md](roadmap.md) |

### 附录

| 文档 | 描述 | 文件 |
|------|------|------|
| Nmap 命令对照 | Nmap 命令参数对照 | [appendix/nmap-commands.md](appendix/nmap-commands.md) |
| 参考资料 | 相关技术文档链接 | [appendix/references.md](appendix/references.md) |
| 部署指南 | Linux x86_64 部署指南 | [appendix/deployment.md](appendix/deployment.md) |

---

## 项目概述

### 1.1 项目背景

Nmap ("Network Mapper") 是网络安全领域最著名的开源工具之一，自1997年发布以来已成为行业标准。然而，Nmap存在以下局限性：

| 局限性 | 描述 |
|--------|------|
| 单线程核心 | 虽然有并行扫描，但核心架构受限于C语言的历史包袱 |
| 性能瓶颈 | 全端口扫描仍需数分钟 |
| 内存安全 | C语言存在潜在的内存安全问题 |
| 现代化不足 | 配置和扩展方式相对传统 |

### 1.2 项目目标

开发一个用 **Rust** 编写的现代化漏洞扫描工具，实现：

1. **100% 功能对等** - 覆盖 Nmap 所有核心功能
2. **性能飞跃** - 利用 Rust 的异步特性实现更高并发
3. **内存安全** - 无 GC 的内存安全保障
4. **现代架构** - 模块化、可扩展的设计
5. **脚本兼容** - 保持 Lua 脚本引擎的完整兼容性

### 1.3 目标用户

- 渗透测试人员
- 安全研究人员
- 系统管理员
- DevSecOps 工程师
- 企业安全团队

