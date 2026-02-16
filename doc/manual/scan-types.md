# RustNmap Scan Types / 扫描类型

> **Detailed documentation for each scan type** / 每种扫描类型的详细文档

---

## Overview / 概述

RustNmap supports 12 different scan types, each designed for specific scenarios. Understanding how each scan works helps you choose the right technique for your target environment.

RustNmap 支持 12 种不同的扫描类型，每种都为特定场景设计。了解每种扫描的工作原理有助于您为目标环境选择正确的技术。

---

## TCP SYN Scan (`-sS`)

**TCP SYN 扫描 (`-sS`)**

### Description / 描述

TCP SYN scan is the default and most popular scan type. It performs a "half-open" scan by sending SYN packets and analyzing responses without completing the TCP 3-way handshake.

TCP SYN 扫描是默认且最受欢迎的扫描类型。它通过发送 SYN 数据包并分析响应来执行"半开"扫描，而不完成 TCP 三次握手。

### How It Works / 工作原理

```
Scanner          Target
   |    SYN      |
   | ----------> |
   |  SYN-ACK    |  <- Port is OPEN
   | <---------- |
   |    RST      |  <- RST sent instead of ACK
   | ----------> |

   |    SYN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |

   |    SYN      |
   | ----------> |
   |   (timeout) |  <- Port is FILTERED
   |             |
```

### Usage / 用法

```bash
# Default scan / 默认扫描
sudo rustnmap -sS 192.168.1.1

# With port specification / 指定端口
sudo rustnmap -sS -p 22,80,443 192.168.1.1

# With service detection / 带服务检测
sudo rustnmap -sS -sV 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Speed | Fast | 快 |
| Reliability | High | 高 |
| Firewall friendly | Moderate | 中等 |

### Advantages / 优点

1. **Stealthy / 隐秘**: Does not complete TCP connection, less likely to be logged
2. **Fast / 快速**: No need to complete 3-way handshake
3. **Reliable / 可靠**: Works against most TCP stacks

### Disadvantages / 缺点

1. Requires root/administrator privileges
2. May still be detected by modern IDS/IPS systems

---

## TCP Connect Scan (`-sT`)

**TCP Connect 扫描 (`-sT`)**

### Description / 描述

TCP Connect scan performs a full 3-way TCP handshake. This is the default when SYN scan is not available (no root privileges).

TCP Connect 扫描执行完整的三次 TCP 握手。当 SYN 扫描不可用时（无 root 权限），这是默认选项。

### How It Works / 工作原理

```
Scanner          Target
   |    SYN      |
   | ----------> |
   |  SYN-ACK    |  <- Port is OPEN
   | <---------- |
   |    ACK      |  <- Complete handshake
   | ----------> |
   |   (data)    |
   | <---------> |
   |  RST/FIN    |  <- Close connection
   | ----------> |

   |    SYN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage / 用法

```bash
# Without root / 无 root 权限
rustnmap -sT 192.168.1.1

# Full port scan / 全端口扫描
rustnmap -sT -p- 192.168.1.1

# With OS detection / 带操作系统检测
rustnmap -sT -O 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | No | 否 |
| Stealthy | No | 否 |
| Speed | Moderate | 中等 |
| Reliability | High | 高 |
| Logged | Yes | 是 |

### Advantages / 优点

1. **No root required / 无需 root**: Works with standard user privileges
2. **Reliable / 可靠**: Standard TCP connection
3. **Universal / 通用**: Works on all systems

### Disadvantages / 缺点

1. **Logged / 记录**: Full connection is logged by target
2. **Slower / 较慢**: Must complete full handshake
3. **Resource intensive / 资源密集**: Uses more resources on target

---

## UDP Scan (`-sU`)

**UDP 扫描 (`-sU`)**

### Description / 描述

UDP scan detects open UDP ports by sending UDP packets and analyzing responses (or lack thereof). UDP scanning is generally slower than TCP scanning due to the connectionless nature of UDP.

UDP 扫描通过发送 UDP 数据包并分析响应（或缺乏响应）来检测开放的 UDP 端口。由于 UDP 的无连接特性，UDP 扫描通常比 TCP 扫描慢。

### How It Works / 工作原理

```
Scanner          Target
   |   UDP       |
   | ----------> |
   |   UDP       |  <- Port is OPEN (application response)
   | <---------- |

   |   UDP       |
   | ----------> |
   |   ICMP      |  <- Port is CLOSED (ICMP port unreachable)
   | <---------- |
   |  Unreachable|

   |   UDP       |
   | ----------> |
   |  (timeout)  |  <- Port is OPEN or FILTERED
   |             |
```

### Usage / 用法

```bash
# UDP scan / UDP 扫描
sudo rustnmap -sU 192.168.1.1

# Common UDP ports / 常见 UDP 端口
sudo rustnmap -sU -p 53,67,68,123,161,162 192.168.1.1

# With version detection / 带版本检测
sudo rustnmap -sU -sV 192.168.1.1

# Combine with TCP / 与 TCP 结合
sudo rustnmap -sS -sU 192.168.1.1
```

### Common UDP Ports / 常见 UDP 端口

| Port | Service | Description |
|------|---------|-------------|
| 53 | DNS | Domain Name System |
| 67/68 | DHCP | Dynamic Host Configuration |
| 69 | TFTP | Trivial File Transfer |
| 123 | NTP | Network Time Protocol |
| 161/162 | SNMP | Simple Network Management |
| 500 | ISAKMP | VPN Key Exchange |
| 514 | Syslog | System Logging |
| 520 | RIP | Routing Information |

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Moderate | 中等 |
| Speed | Slow | 慢 |
| Reliability | Moderate | 中等 |
| Firewall friendly | Low | 低 |

### Advantages / 优点

1. **Finds UDP services / 发现 UDP 服务**: Detects services TCP scans miss
2. **Standard method / 标准方法**: Well-established technique

### Disadvantages / 缺点

1. **Slow / 慢**: Many timeouts due to no response
2. **Ambiguous results / 模糊结果**: Difficult to distinguish open from filtered
3. **Resource intensive / 资源密集**: Requires sending many packets

---

## TCP FIN Scan (`-sF`)

**TCP FIN 扫描 (`-sF`)**

### Description / 描述

FIN scan sends packets with only the FIN flag set. According to RFC 793, closed ports should respond with RST, while open ports should ignore the packet.

FIN 扫描发送仅设置 FIN 标志的数据包。根据 RFC 793，关闭的端口应该回复 RST，而开放的端口应该忽略该数据包。

### How It Works / 工作原理

```
Scanner          Target
   |    FIN      |
   | ----------> |
   |   (nothing) |  <- Port is OPEN (per RFC 793)
   |             |

   |    FIN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |

   |    FIN      |
   | ----------> |
   |   RST       |  <- Port is OPEN (non-RFC compliant, e.g., Windows)
   | <---------- |     or CLOSED/FILTERED
```

### Usage / 用法

```bash
# FIN scan / FIN 扫描
sudo rustnmap -sF 192.168.1.1

# Specific ports / 特定端口
sudo rustnmap -sF -p 22,80,443 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Speed | Fast | 快 |
| Best for | UNIX systems | UNIX 系统 |
| Windows response | All closed | 全部关闭 |

### Platform Differences / 平台差异

| OS | Behavior | 行为 |
|----|----------|------|
| UNIX/Linux | Follows RFC 793 | 遵循 RFC 793 |
| Windows | Sends RST for all | 对所有端口发送 RST |
| Cisco | Follows RFC 793 | 遵循 RFC 793 |
| BSD | Follows RFC 793 | 遵循 RFC 793 |

---

## TCP NULL Scan (`-sN`)

**TCP NULL 扫描 (`-sN`)**

### Description / 描述

NULL scan sends packets with no TCP flags set. Like FIN scan, RFC 793 specifies that closed ports should respond with RST while open ports ignore the packet.

NULL 扫描发送没有设置任何 TCP 标志的数据包。与 FIN 扫描类似，RFC 793 规定关闭的端口应该回复 RST，而开放的端口忽略该数据包。

### How It Works / 工作原理

```
Scanner          Target
   |   (no flags)|
   | ----------> |
   |   (nothing) |  <- Port is OPEN
   |             |

   |   (no flags)|
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage / 用法

```bash
# NULL scan / NULL 扫描
sudo rustnmap -sN 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Speed | Fast | 快 |
| Best for | UNIX systems | UNIX 系统 |

---

## TCP XMAS Scan (`-sX`)

**TCP XMAS 扫描 (`-sX`)**

### Description / 描述

XMAS scan sends packets with FIN, PSH, and URG flags set, "lighting up the packet like a Christmas tree." Like other stealth scans, it relies on RFC 793 behavior.

XMAS 扫描发送设置了 FIN、PSH 和 URG 标志的数据包，"像圣诞树一样点亮数据包"。与其他隐秘扫描类似，它依赖于 RFC 793 的行为。

### How It Works / 工作原理

```
Scanner          Target
   | FIN+PSH+URG |
   | ----------> |
   |   (nothing) |  <- Port is OPEN
   |             |

   | FIN+PSH+URG |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage / 用法

```bash
# XMAS scan / XMAS 扫描
sudo rustnmap -sX 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Speed | Fast | 快 |
| Best for | UNIX systems | UNIX 系统 |
| Packet appearance | Unusual | 异常 |

---

## TCP ACK Scan (`-sA`)

**TCP ACK 扫描 (`-sA`)**

### Description / 描述

ACK scan is used to map firewall rulesets, not to determine open ports. It sends ACK packets and analyzes whether ports are filtered or unfiltered.

ACK 扫描用于映射防火墙规则集，而非确定开放端口。它发送 ACK 数据包并分析端口是被过滤还是未被过滤。

### How It Works / 工作原理

```
Scanner          Target
   |    ACK      |
   | ----------> |
   |    RST      |  <- Port is UNFILTERED (regardless of state)
   | <---------- |

   |    ACK      |
   | ----------> |
   |   (timeout) |  <- Port is FILTERED
   |             |
   |   or ICMP   |
   |  admin-proh |
```

### Usage / 用法

```bash
# ACK scan for firewall mapping / ACK 扫描用于防火墙映射
sudo rustnmap -sA 192.168.1.1

# Determine firewall rules / 确定防火墙规则
sudo rustnmap -sA -p 1-65535 192.168.1.1
```

### Port States / 端口状态

| Response | State | Meaning |
|----------|-------|---------|
| RST | unfiltered | Port is not filtered by firewall |
| Timeout/ICMP | filtered | Port is filtered by firewall |

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Best for | Firewall mapping | 防火墙映射 |
| Determines | Filtered status | 过滤状态 |

---

## TCP Window Scan (`-sW`)

**TCP Window 扫描 (`-sW`)**

### Description / 描述

Window scan is similar to ACK scan but examines the TCP Window field of RST responses to determine if ports are open or closed.

Window 扫描类似于 ACK 扫描，但检查 RST 响应的 TCP Window 字段来确定端口是开放还是关闭。

### How It Works / 工作原理

```
Scanner          Target
   |    ACK      |
   | ----------> |
   | RST(Window) |  <- Window > 0: OPEN
   | <---------- |     Window = 0: CLOSED
```

### Usage / 用法

```bash
# Window scan / Window 扫描
sudo rustnmap -sW 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Reliability | Low (system dependent) | 低（依赖系统） |
| Best for | Specific systems | 特定系统 |

---

## TCP Maimon Scan (`-sM`)

**TCP Maimon 扫描 (`-sM`)**

### Description / 描述

Maimon scan (named after Uriel Maimon) sends packets with FIN and ACK flags. Some BSD systems drop the packet if port is open (revealing it).

Maimon 扫描（以 Uriel Maimon 命名）发送带有 FIN 和 ACK 标志的数据包。某些 BSD 系统在端口开放时会丢弃该数据包（从而暴露端口状态）。

### How It Works / 工作原理

```
Scanner          Target
   |  FIN+ACK    |
   | ----------> |
   |   (nothing) |  <- Port is OPEN (on some BSD)
   |             |

   |  FIN+ACK    |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage / 用法

```bash
# Maimon scan / Maimon 扫描
sudo rustnmap -sM 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Yes | 是 |
| Best for | BSD systems | BSD 系统 |

---

## IP Protocol Scan (`-sO`)

**IP Protocol 扫描 (`-sO`)**

### Description / 描述

IP protocol scan determines which IP protocols (TCP, ICMP, IGMP, etc.) are supported by the target. It sends raw IP packets with different protocol numbers.

IP 协议扫描确定目标支持哪些 IP 协议（TCP、ICMP、IGMP 等）。它发送带有不同协议号的原始 IP 数据包。

### How It Works / 工作原理

```
Scanner          Target
   | IP(proto=1)|  <- ICMP
   | ----------> |
   |  Response   |  <- Protocol supported
   | <---------- |

   | IP(proto=2)|  <- IGMP
   | ----------> |
   |   ICMP      |  <- Protocol not supported (protocol unreachable)
   | <---------- |
```

### Common Protocols / 常见协议

| Number | Protocol | Description |
|--------|----------|-------------|
| 0 | HOPOPT | IPv6 Hop-by-Hop Option |
| 1 | ICMP | Internet Control Message |
| 2 | IGMP | Internet Group Management |
| 6 | TCP | Transmission Control |
| 17 | UDP | User Datagram |
| 47 | GRE | Generic Routing Encapsulation |
| 50 | ESP | Encapsulating Security Payload |
| 51 | AH | Authentication Header |

### Usage / 用法

```bash
# Protocol scan / 协议扫描
sudo rustnmap -sO 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Layer | Layer 3 (IP) | 第 3 层 (IP) |
| Best for | Protocol enumeration | 协议枚举 |

---

## Idle (Zombie) Scan (`-sI`)

**Idle（僵尸）扫描 (`-sI`)**

### Description / 描述

Idle scan is the stealthiest scan technique. It uses a "zombie" host to bounce scan packets off, making the scan appear to come from the zombie host. Requires a zombie with predictable IP ID sequence.

Idle 扫描是最隐秘的扫描技术。它使用"僵尸"主机反弹扫描数据包，使扫描看起来来自僵尸主机。需要具有可预测 IP ID 序列的僵尸主机。

### How It Works / 工作原理

```
Attacker      Zombie        Target
   |   SYN/ACK  |            |
   | ---------> |            |  <- Probe zombie's IP ID
   |  RST(ID=X) |            |
   | <--------- |            |
   |            |   SYN      |
   |            | ---------> |  <- Spoofed packet to target
   |            |            |
   |            |   SYN/ACK  |  <- If port open
   |            | <--------- |
   |            |    RST     |
   |            | ---------> |  <- Zombie replies, IP ID+1
   |   SYN/ACK  |            |
   | ---------> |            |  <- Probe zombie's IP ID again
   |  RST(ID=Y) |            |
   | <--------- |            |

   If Y = X + 2: Port is OPEN
   If Y = X + 1: Port is CLOSED
```

### Usage / 用法

```bash
# Idle scan / Idle 扫描
sudo rustnmap -sI zombie.example.com 192.168.1.1

# With specific zombie port / 指定僵尸端口
sudo rustnmap -sI zombie.example.com:113 192.168.1.1
```

### Finding Zombies / 寻找僵尸主机

```bash
# Scan for potential zombies / 扫描潜在僵尸主机
sudo rustnmap -O -v 192.168.1.0/24
# Look for hosts with: / 寻找具有以下特征的主机：
# - Predictable IP ID sequence / 可预测的 IP ID 序列
# - Low traffic / 低流量
# - Idle / 空闲
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | Yes | 是 |
| Stealthy | Extremely | 极高 |
| Complexity | High | 高 |
| Requirements | Predictable zombie | 可预测的僵尸主机 |

### Advantages / 优点

1. **Ultimate stealth / 终极隐秘**: Target never sees your IP
2. **Bypasses logging / 绕过记录**: Logs show zombie's IP

### Disadvantages / 缺点

1. **Complex setup / 复杂设置**: Requires finding suitable zombie
2. **Slow / 慢**: Sequential probing required
3. **Unreliable / 不可靠**: Zombie must remain idle

---

## FTP Bounce Scan (`-b`)

**FTP Bounce 扫描 (`-b`)**

### Description / 描述

FTP bounce attack exploits FTP servers with proxy capabilities to bounce scans through them. The FTP server acts as a proxy, making the scan appear to originate from the FTP server.

FTP Bounce 攻击利用具有代理功能的 FTP 服务器来反弹扫描。FTP 服务器充当代理，使扫描看起来源自 FTP 服务器。

### How It Works / 工作原理

```
Scanner        FTP Server      Target
   |   Connect  |              |
   | ---------> |              |
   |   Login    |              |
   | ---------> |              |
   |   PORT     |              |
   | ---------> |              |
   |   PASV     |              |
   | ---------> |              |
   |            |   Connect    |
   |            | ---------->  |  <- FTP server connects to target
   |            |   Response   |
   |            | <----------  |
   |  Response  |              |
   | <--------- |              |
```

### Usage / 用法

```bash
# FTP bounce scan / FTP Bounce 扫描
rustnmap -b ftp.example.com 192.168.1.1

# With username/password / 使用用户名/密码
rustnmap -b user:pass@ftp.example.com:21 192.168.1.1
```

### Characteristics / 特性

| Feature | Value | 值 |
|---------|-------|-----|
| Requires root | No | 否 |
| Stealthy | Yes | 是 |
| Requires | Vulnerable FTP server | 易受攻击的 FTP 服务器 |
| Modern usage | Rare | 罕见 |

### Advantages / 优点

1. **No root required / 无需 root**
2. **Hides source / 隐藏源地址**

### Disadvantages / 缺点

1. **Rare today / 现今罕见**: Modern FTP servers don't allow this
2. **Slow / 慢**: Requires FTP protocol overhead
3. **Limited ports / 有限端口**: Can only scan ports FTP server can reach

---

## Scan Type Comparison / 扫描类型对比

| Scan Type | Root | Stealth | Speed | Reliability | Best For |
|-----------|------|---------|-------|-------------|----------|
| `-sS` SYN | Yes | High | Fast | High | General use |
| `-sT` Connect | No | Low | Medium | High | No root |
| `-sU` UDP | Yes | Medium | Slow | Medium | UDP services |
| `-sF` FIN | Yes | High | Fast | Low | UNIX stealth |
| `-sN` NULL | Yes | High | Fast | Low | UNIX stealth |
| `-sX` XMAS | Yes | High | Fast | Low | UNIX stealth |
| `-sA` ACK | Yes | High | Fast | Medium | Firewall mapping |
| `-sW` Window | Yes | High | Fast | Low | Advanced |
| `-sM` Maimon | Yes | High | Fast | Low | BSD systems |
| `-sO` Protocol | Yes | Medium | Medium | Medium | Protocol enum |
| `-sI` Idle | Yes | Extreme | Slow | Low | Maximum stealth |
| `-b` FTP Bounce | No | High | Slow | Low | Legacy systems |

---

## Choosing the Right Scan / 选择正确的扫描

### Quick Decision Guide / 快速决策指南

```
Do you have root/admin? / 你有 root/管理员权限吗？
├── No → Use -sT (Connect scan) / 使用 -sT (Connect 扫描)
└── Yes → What is your goal? / 你的目标是什么？
    ├── General port scanning → -sS (SYN scan) / -sS (SYN 扫描)
    ├── UDP services → -sU (UDP scan) / -sU (UDP 扫描)
    ├── Firewall rule mapping → -sA (ACK scan) / -sA (ACK 扫描)
    ├── Maximum stealth → -sI (Idle scan) / -sI (Idle 扫描)
    └── IDS evasion on UNIX → -sF/-sN/-sX / -sF/-sN/-sX
```

### Scenario Examples / 场景示例

#### Internal Network Audit / 内部网络审计

```bash
# Fast SYN scan with service detection / 快速 SYN 扫描带服务检测
sudo rustnmap -sS -sV -T4 -p- 192.168.1.0/24
```

#### External Penetration Test / 外部渗透测试

```bash
# Stealthy scan with decoys / 带诱饵的隐秘扫描
sudo rustnmap -sS -T2 -f -D RND:10 10.0.0.1
```

#### Firewall Assessment / 防火墙评估

```bash
# ACK scan to map rules / ACK 扫描映射规则
sudo rustnmap -sA -p- 192.168.1.1
```

#### No Root Access / 无 Root 权限

```bash
# Connect scan / Connect 扫描
rustnmap -sT -p 22,80,443,8080 target.example.com
```

---

## Port State Definitions / 端口状态定义

| State | Meaning | 含义 |
|-------|---------|------|
| `open` | Service is listening | 服务正在监听 |
| `closed` | Port accessible, no service | 端口可访问，无服务 |
| `filtered` | Cannot determine state (firewall) | 无法确定状态（防火墙） |
| `unfiltered` | Port accessible (ACK scan) | 端口可访问（ACK 扫描） |
| `open|filtered` | Cannot determine if open or filtered | 无法确定开放或过滤 |
| `closed|filtered` | Cannot determine if closed or filtered | 无法确定关闭或过滤 |

---

## References / 参考

- [RFC 793](https://tools.ietf.org/html/rfc793) - TCP Specification
- Nmap Scan Types Documentation
- Targeted Cyber Intrusion Detection: The Xmas Scan
