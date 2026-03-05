# RustNmap User Manual

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的功能。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。
> **Last Updated**: 2026-02-16

---

## Manual Overview / 手册概述

Welcome to the RustNmap User Manual. This manual provides comprehensive documentation for the RustNmap network scanner.

欢迎查阅 RustNmap 用户手册。本手册提供了 RustNmap 网络扫描器的完整文档。

---

## Contents / 目录

| File | Description | 描述 |
|------|-------------|------|
| [quick-reference.md](quick-reference.md) | Quick reference card for common tasks | 常用任务快速参考卡 |
| [options.md](options.md) | Complete command-line options reference | 完整命令行选项参考 |
| [scan-types.md](scan-types.md) | Detailed scan type documentation | 扫描类型详细说明 |
| [output-formats.md](output-formats.md) | Output format specifications | 输出格式规范 |
| [nse-scripts.md](nse-scripts.md) | NSE scripting engine guide | NSE 脚本引擎指南 |
| [exit-codes.md](exit-codes.md) | Exit codes and error handling | 退出代码和错误处理 |
| [environment.md](environment.md) | Environment variables | 环境变量 |
| [configuration.md](configuration.md) | Configuration file format | 配置文件格式 |

---

## Quick Start / 快速开始

### Installation / 安装

```bash
# Build from source
cargo build --release

# Install to system
sudo cp target/release/rustnmap /usr/local/bin/
```

### Basic Usage / 基本用法

```bash
# TCP SYN scan (requires root)
sudo rustnmap -sS 192.168.1.1

# TCP Connect scan (no root required)
rustnmap -sT 192.168.1.1

# Scan specific ports
sudo rustnmap -p 22,80,443 192.168.1.1

# Service detection
sudo rustnmap -sV 192.168.1.1

# OS detection
sudo rustnmap -O 192.168.1.1

# Full aggressive scan
sudo rustnmap -A 192.168.1.1
```

---

## Documentation Conventions / 文档约定

### Syntax Notation / 语法标记

- `<arg>` - Required argument / 必需参数
- `[arg]` - Optional argument / 可选参数
- `a|b` - Alternative options / 可选值
- `-opt` - Short option / 短选项
- `--option` - Long option / 长选项

### Examples / 示例

All examples use `sudo` for scans requiring root privileges.
所有示例中，需要 root 权限的扫描使用 `sudo`。

---

## Related Documentation / 相关文档

- [README](../../README.md) - Project overview / 项目概览
- [Architecture](../architecture.md) - System architecture / 系统架构
- [Manual](../rustnmap.1) - Unix man page / Unix 手册页

---

## Support / 支持

- GitHub Issues: https://github.com/greatwallisme/rust-nmap/issues
- GitHub Discussions: https://github.com/greatwallisme/rust-nmap/discussions

---

**Disclaimer / 免责声明**: This tool is for authorized security testing only. Always obtain proper authorization before scanning networks you do not own.

本工具仅用于授权的安全测试。在扫描您不拥有的网络之前，请确保获得适当的授权。
