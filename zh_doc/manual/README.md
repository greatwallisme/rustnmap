# RustNmap 用户手册

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的功能。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。
> **最后更新**: 2026-02-16

---

## 手册概述

欢迎使用 RustNmap 用户手册。本手册提供了 RustNmap 网络扫描器的完整文档。

---

## 目录

| 文件 | 描述 |
|------|------|
| [quick-reference.md](quick-reference.md) | 常用任务快速参考卡 |
| [options.md](options.md) | 完整命令行选项参考 |
| [scan-types.md](scan-types.md) | 扫描类型详细说明 |
| [output-formats.md](output-formats.md) | 输出格式规范 |
| [nse-scripts.md](nse-scripts.md) | NSE 脚本引擎指南 |
| [exit-codes.md](exit-codes.md) | 退出代码和错误处理 |
| [environment.md](environment.md) | 环境变量 |
| [configuration.md](configuration.md) | 配置文件格式 |

---

## 快速开始

### 安装

```bash
# 从源码构建
cargo build --release

# 安装到系统
sudo cp target/release/rustnmap /usr/local/bin/
```

### 基本用法

```bash
# TCP SYN 扫描（需要 root）
sudo rustnmap -sS 192.168.1.1

# TCP Connect 扫描（无需 root）
rustnmap -sT 192.168.1.1

# 扫描指定端口
sudo rustnmap -p 22,80,443 192.168.1.1

# 服务检测
sudo rustnmap -sV 192.168.1.1

# 操作系统检测
sudo rustnmap -O 192.168.1.1

# 完整激进扫描
sudo rustnmap -A 192.168.1.1
```

---

## 文档约定

### 语法标记

- `<arg>` - 必需参数
- `[arg]` - 可选参数
- `a|b` - 可选值
- `-opt` - 短选项
- `--option` - 长选项

### 示例

所有示例中，需要 root 权限的扫描使用 `sudo`。

---

## 相关文档

- [README](../../README.md) - 项目概览
- [架构](../architecture.md) - 系统架构
- [手册](../README.md) - 手册概览

---

## 支持

- GitHub Issues: https://github.com/greatwallisme/rust-nmap/issues
- GitHub Discussions: https://github.com/greatwallisme/rust-nmap/discussions

---

**免责声明**: 本工具仅用于授权的安全测试。在扫描您不拥有的网络之前，请确保获得适当的授权。
