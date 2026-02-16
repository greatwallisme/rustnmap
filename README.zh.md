# RustNmap - Rust 网络扫描器

> **版本**: 1.0.0
> **状态**: 生产就绪
> **平台**: Linux x86_64 (AMD64)
> **语言**: Rust 1.90+

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/greatwallisme/rust-nmap)
[![Tests](https://img.shields.io/badge/tests-970%2B%20passing-brightgreen)](https://github.com/greatwallisme/rust-nmap)
[![Coverage](https://img.shields.io/badge/coverage-63.77%25-yellow)](https://github.com/greatwallisme/rust-nmap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**[English Documentation](README.md)** | [用户手册](doc/manual/) | [用户指南](doc/user-guide.md)

---

## 概述

RustNmap 是一个使用 Rust 编写的现代高性能网络扫描工具，在利用 Rust 的内存安全和异步能力的同时，提供与 Nmap 100% 的功能对等。

**主要特性:**
- **12 种扫描类型**: SYN、Connect、UDP、FIN、NULL、XMAS、ACK、Maimon、Window、IP 协议、Idle、FTP Bounce
- **服务和操作系统检测**: 6000+ 服务探针，5000+ 操作系统签名
- **NSE 脚本**: 完整的 Lua 5.4 引擎，兼容 Nmap 库
- **5 种输出格式**: Normal、XML、JSON、Grepable、Script Kiddie
- **高级规避**: 分片、诱饵、欺骗、时间控制

---

## 快速开始

### 安装

```bash
git clone https://github.com/greatwallisme/rust-nmap.git
cd rust-nmap
cargo build --release
sudo ./target/release/rustnmap --help
```

### 基本用法

```bash
# TCP SYN 扫描 (需要 root)
sudo rustnmap -sS 192.168.1.1

# TCP Connect 扫描 (不需要 root)
rustnmap -sT 192.168.1.1

# 扫描特定端口
sudo rustnmap -p 22,80,443 192.168.1.1

# 服务检测
sudo rustnmap -sV 192.168.1.1

# 操作系统检测
sudo rustnmap -O 192.168.1.1

# 完整激进扫描
sudo rustnmap -A 192.168.1.1
```

---

## 文档

| 文档 | 说明 |
|----------|-------------|
| [用户手册](doc/manual/) | 完整的命令参考和使用指南 |
| [用户指南](doc/user-guide.md) | 综合扫描教程 |
| [架构](doc/architecture.md) | 系统设计和 crate 结构 |

### 手册内容

- [快速参考](doc/manual/quick-reference.md) - 单页命令速查表
- [选项参考](doc/manual/options.md) - 完整 CLI 选项
- [扫描类型](doc/manual/scan-types.md) - 详细扫描文档
- [输出格式](doc/manual/output-formats.md) - 格式规范
- [NSE 脚本](doc/manual/nse-scripts.md) - 脚本指南
- [退出代码](doc/manual/exit-codes.md) - 错误处理参考
- [环境变量](doc/manual/environment.md) - 通过环境变量配置
- [配置文件](doc/manual/configuration.md) - 配置文件格式

---

## 示例

### 目标指定

```bash
# 单个 IP、CIDR、范围、主机名
rustnmap 192.168.1.1
rustnmap 192.168.1.0/24
rustnmap 192.168.1.1-100
rustnmap example.com

# 从文件
rustnmap -iL targets.txt
```

### 扫描类型

```bash
sudo rustnmap -sS 192.168.1.1    # TCP SYN (隐秘)
rustnmap -sT 192.168.1.1          # TCP Connect (无需 root)
sudo rustnmap -sU 192.168.1.1    # UDP
sudo rustnmap -sF 192.168.1.1    # FIN 扫描
sudo rustnmap -sA 192.168.1.1    # ACK (防火墙映射)
```

### 输出格式

```bash
sudo rustnmap -oN results.nmap 192.168.1.1    # Normal
sudo rustnmap -oX results.xml 192.168.1.1     # XML
sudo rustnmap -oJ results.json 192.168.1.1    # JSON
sudo rustnmap -oG results.gnmap 192.168.1.1   # Grepable
sudo rustnmap -oA results 192.168.1.1         # 所有格式
```

### NSE 脚本

```bash
sudo rustnmap -sC 192.168.1.1                           # 默认脚本
sudo rustnmap --script http-title 192.168.1.1           # 特定脚本
sudo rustnmap --script "vuln" 192.168.1.1               # 类别
sudo rustnmap --script "http-*" 192.168.1.1             # 模式
```

---

## 开发

```bash
# 运行测试
just test

# 运行 clippy
just clippy

# 构建发布版本
just release

# 生成文档
just doc
```

---

## 安全

- **内存安全**: Rust 所有权防止缓冲区溢出
- **安全并发**: 编译时数据竞争预防
- **安全等级**: A-
- 仅 7 个 unsafe 块 (全部为带 SAFETY 注释的 FFI)

---

## 与 Nmap 对比

| 特性 | RustNmap | Nmap |
|---------|----------|------|
| 扫描类型 | 12 | 12 |
| 服务检测 | 6000+ 探针 | 6000+ 探针 |
| 操作系统检测 | 5000+ 签名 | 5000+ 签名 |
| NSE 脚本 | 完整 Lua 5.4 | 完整 Lua 5.4 |
| 输出格式 | 5 | 5 |
| 内存安全 | 保证 | 否 |
| 并发 | Async/await | 事件驱动 |

---

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。

---

**免责声明**: 本工具仅用于授权的安全测试。在扫描您不拥有的网络之前，请确保获得适当的授权。
