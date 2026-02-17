# RustNmap Quick Reference / 快速参考

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的快速参考。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> **One-page reference for common RustNmap tasks** / 常见 RustNmap 任务单页参考

---

## Target Specification / 目标指定

```bash
# Single IP / 单个 IP
rustnmap 192.168.1.1

# Multiple IPs / 多个 IP
rustnmap 192.168.1.1 192.168.1.2

# CIDR notation / CIDR 表示法
rustnmap 192.168.1.0/24

# IP range / IP 范围
rustnmap 192.168.1.1-100

# Hostname / 主机名
rustnmap example.com

# From file / 从文件
rustnmap -iL targets.txt

# Exclude hosts / 排除主机
rustnmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

---

## Port Specification / 端口指定

```bash
# Single port / 单个端口
rustnmap -p 22 192.168.1.1

# Multiple ports / 多个端口
rustnmap -p 22,80,443 192.168.1.1

# Port range / 端口范围
rustnmap -p 1-1000 192.168.1.1

# All ports / 所有端口
rustnmap -p- 192.168.1.1

# Fast scan (top 100) / 快速扫描 (前 100)
rustnmap -F 192.168.1.1

# Top N ports / 前 N 个端口
rustnmap --top-ports 100 192.168.1.1

# Protocol specific / 特定协议
rustnmap -p T:80,U:53 192.168.1.1
```

---

## Scan Types / 扫描类型

| Flag | Scan Type | Requires Root | Use Case |
|------|-----------|---------------|----------|
| `-sS` | TCP SYN | Yes | Stealth scan / 隐秘扫描 |
| `-sT` | TCP Connect | No | Standard scan / 标准扫描 |
| `-sU` | UDP | Yes | UDP ports / UDP 端口 |
| `-sF` | TCP FIN | Yes | Stealth (UNIX) / 隐秘 (UNIX) |
| `-sN` | TCP NULL | Yes | Stealth (UNIX) / 隐秘 (UNIX) |
| `-sX` | TCP XMAS | Yes | Stealth (UNIX) / 隐秘 (UNIX) |
| `-sA` | TCP ACK | Yes | Firewall check / 防火墙检测 |
| `-sM` | TCP Maimon | Yes | Stealth variant / 隐秘变体 |
| `-sW` | TCP Window | Yes | Advanced scan / 高级扫描 |
| `-sO` | IP Protocol | Yes | Protocol scan / 协议扫描 |
| `-sI` | Idle (Zombie) | Yes | Highly stealthy / 高度隐秘 |
| `-b` | FTP Bounce | No | FTP proxy scan / FTP 代理扫描 |

---

## Host Discovery / 主机发现

```bash
# Ping scan only / 仅 Ping 扫描
sudo rustnmap -sn 192.168.1.0/24

# ICMP echo / ICMP 回显
sudo rustnmap -PE 192.168.1.0/24

# TCP SYN ping / TCP SYN Ping
sudo rustnmap -PS22,80,443 192.168.1.0/24

# TCP ACK ping / TCP ACK Ping
sudo rustnmap -PA80 192.168.1.0/24

# UDP ping / UDP Ping
sudo rustnmap -PU53 192.168.1.0/24

# ARP ping (local) / ARP Ping (本地)
sudo rustnmap -PR 192.168.1.0/24

# Skip discovery / 跳过发现
sudo rustnmap -Pn 192.168.1.0/24
```

---

## Service Detection / 服务检测

```bash
# Basic service detection / 基本服务检测
sudo rustnmap -sV 192.168.1.1

# Version intensity 0-9 / 版本强度 0-9
sudo rustnmap -sV --version-intensity 5 192.168.1.1

# Light version scan / 轻量版本扫描
sudo rustnmap -sV --version-light 192.168.1.1

# All probes / 所有探针
sudo rustnmap -sV --version-all 192.168.1.1
```

---

## OS Detection / 操作系统检测

```bash
# OS detection / 操作系统检测
sudo rustnmap -O 192.168.1.1

# Limit matches / 限制匹配数
sudo rustnmap -O --osscan-limit 192.168.1.1

# Aggressive guess / 激进猜测
sudo rustnmap -O --osscan-guess 192.168.1.1

# Combined scan / 组合扫描
sudo rustnmap -A 192.168.1.1  # -sV -sC -O --traceroute
```

---

## Timing Templates / 时间模板

| Template | Flag | Delay | Use Case |
|----------|------|-------|----------|
| Paranoid | `-T0` | 5 min | IDS evasion / IDS 规避 |
| Sneaky | `-T1` | 15 sec | IDS evasion / IDS 规避 |
| Polite | `-T2` | 0.4 sec | Slow network / 慢速网络 |
| Normal | `-T3` | Default | General use / 一般用途 |
| Aggressive | `-T4` | Faster | Fast network / 快速网络 |
| Insane | `-T5` | Very fast | Local network / 本地网络 |

```bash
# Examples / 示例
sudo rustnmap -T0 192.168.1.1   # Paranoid / 偏执
sudo rustnmap -T4 192.168.1.1   # Aggressive / 激进
```

---

## Output Formats / 输出格式

```bash
# Normal output / 普通输出
sudo rustnmap -oN results.nmap 192.168.1.1

# XML output / XML 输出
sudo rustnmap -oX results.xml 192.168.1.1

# JSON output / JSON 输出
sudo rustnmap -oJ results.json 192.168.1.1

# Grepable output / Grepable 输出
sudo rustnmap -oG results.gnmap 192.168.1.1

# Script kiddie / Script kiddie 格式
sudo rustnmap -oS results.txt 192.168.1.1

# All formats / 所有格式
sudo rustnmap -oA results 192.168.1.1

# Append output / 追加输出
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

---

## NSE Scripts / NSE 脚本

```bash
# Default scripts / 默认脚本
sudo rustnmap -sC 192.168.1.1

# Specific script / 特定脚本
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts / 多个脚本
sudo rustnmap --script http-title,http-headers 192.168.1.1

# Script category / 脚本类别
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1

# Script with arguments / 带参数的脚本
sudo rustnmap --script http-title --script-args "http.useragent=Mozilla" 192.168.1.1

# List scripts / 列出脚本
rustnmap --script-help
```

---

## Evasion Techniques / 规避技术

```bash
# Fragment packets / 分片数据包
sudo rustnmap -f 192.168.1.1
sudo rustnmap --mtu 8 192.168.1.1

# Decoy scan / 诱饵扫描
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1
sudo rustnmap -D RND:10 192.168.1.1

# Source IP spoofing / 源 IP 欺骗
sudo rustnmap -S 192.168.1.100 192.168.1.1

# Source port / 源端口
sudo rustnmap -g 53 192.168.1.1

# Custom data / 自定义数据
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1
sudo rustnmap --data-string "Hello" 192.168.1.1
sudo rustnmap --data-length 100 192.168.1.1

# MAC spoofing / MAC 欺骗
sudo rustnmap --spoof-mac 00:11:22:33:44:55 192.168.1.1
```

---

## Verbosity / 详细程度

```bash
# Verbose / 详细
sudo rustnmap -v 192.168.1.1
sudo rustnmap -vv 192.168.1.1

# Debug / 调试
sudo rustnmap -d 192.168.1.1
sudo rustnmap -dd 192.168.1.1

# Quiet / 安静
sudo rustnmap -q 192.168.1.1

# Show reasons / 显示原因
sudo rustnmap --reason 192.168.1.1

# Packet trace / 数据包跟踪
sudo rustnmap --packet-trace 192.168.1.1
```

---

## Common Scenarios / 常见场景

### Network Audit / 网络审计

```bash
# Full network scan / 完整网络扫描
sudo rustnmap -A -T4 -oA network-audit 192.168.1.0/24
```

### Web Server Scan / Web 服务器扫描

```bash
sudo rustnmap -sV -p 80,443,8080,8443 --script http-* 192.168.1.1
```

### Database Discovery / 数据库发现

```bash
sudo rustnmap -sV -p 3306,5432,1433,27017,6379,9200 192.168.1.0/24
```

### Vulnerability Scan / 漏洞扫描

```bash
sudo rustnmap -sV --script vuln 192.168.1.1
```

### Stealth Scan / 隐秘扫描

```bash
sudo rustnmap -sS -T0 -f -D RND:10 --data-length 20 192.168.1.1
```

---

## Exit Codes / 退出代码

| Code | Meaning |
|------|---------|
| `0` | Success / 成功 |
| `1` | General error / 一般错误 |
| `2` | Invalid arguments / 无效参数 |
| `3` | No targets specified / 未指定目标 |
| `4` | Network error / 网络错误 |
| `5` | Permission denied / 权限被拒绝 |

---

## Help / 帮助

```bash
# General help / 一般帮助
rustnmap --help

# Manual pages / 手册页
man rustnmap
```
