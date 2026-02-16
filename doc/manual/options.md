# RustNmap Command-Line Options / 命令行选项

> **Complete reference for all RustNmap command-line options** / RustNmap 所有命令行选项的完整参考

---

## Overview / 概述

RustNmap uses a command-line interface compatible with Nmap. Options can be combined in most cases.

RustNmap 使用与 Nmap 兼容的命令行界面。选项在大多数情况下可以组合使用。

**Basic Syntax / 基本语法:**
```bash
rustnmap [Scan Type(s)] [Options] {target specification}
```

---

## Target Specification / 目标指定

### `<TARGET>` (Required / 必需)

One or more target hosts to scan.

一个或多个要扫描的目标主机。

```bash
# Single IP address / 单个 IP 地址
rustnmap 192.168.1.1

# Multiple IP addresses / 多个 IP 地址
rustnmap 192.168.1.1 192.168.1.2 192.168.1.3

# CIDR notation / CIDR 表示法
rustnmap 192.168.1.0/24

# IP range / IP 范围
rustnmap 192.168.1.1-100
rustnmap 192.168.1-10.1-50

# Hostname / 主机名
rustnmap example.com

# Mixed targets / 混合目标
rustnmap 192.168.1.1 example.com 10.0.0.0/8
```

### `-iL <FILE>`, `--input-file <FILE>`

Read target specifications from file.

从文件读取目标规格。

```bash
rustnmap -iL targets.txt
```

**File format / 文件格式:**
- One target per line / 每行一个目标
- Lines starting with `#` are comments / 以 `#` 开头的行是注释
- Empty lines are ignored / 空行被忽略

```
# targets.txt
192.168.1.1
192.168.1.0/24
example.com
10.0.0.1-50
```

### `--exclude <HOST1>[,<HOST2>[,...]]>`

Exclude specified hosts from scan.

从扫描中排除指定的主机。

```bash
rustnmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

### `--excludefile <FILE>`

Exclude targets from file.

从文件排除目标。

```bash
rustnmap 192.168.1.0/24 --excludefile exclude.txt
```

---

## Scan Types / 扫描类型

### `-sS`, `--scan-syn`

**TCP SYN Scan / TCP SYN 扫描** (Default with root / root 默认)

Half-open scan that sends SYN packets without completing the handshake.

发送 SYN 数据包而不完成握手的半开扫描。

```bash
sudo rustnmap -sS 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Best for | General scanning |

### `-sT`, `--scan-connect`

**TCP Connect Scan / TCP Connect 扫描** (Default without root / 非 root 默认)

Full TCP 3-way handshake scan.

完整 TCP 三次握手扫描。

```bash
rustnmap -sT 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | No |
| Stealthy | No |
| Speed | Slower |
| Best for | No root access |

### `-sU`, `--scan-udp`

**UDP Scan / UDP 扫描**

Scan UDP ports by sending UDP packets.

通过发送 UDP 数据包扫描 UDP 端口。

```bash
sudo rustnmap -sU 192.168.1.1
sudo rustnmap -sU -p 53,161,162 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Speed | Slow (timeouts common) / 慢（常超时） |
| Best for | DNS, SNMP, DHCP services |

### `-sF`, `--scan-fin`

**TCP FIN Scan / TCP FIN 扫描**

Send packets with FIN flag only.

仅发送带有 FIN 标志的数据包。

```bash
sudo rustnmap -sF 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Works against | UNIX systems |
| Windows response | Usually all closed |

### `-sN`, `--scan-null`

**TCP NULL Scan / TCP NULL 扫描**

Send packets with no flags set.

发送没有设置任何标志的数据包。

```bash
sudo rustnmap -sN 192.168.1.1
```

### `-sX`, `--scan-xmas`

**TCP XMAS Scan / TCP XMAS 扫描**

Send packets with FIN, PSH, and URG flags (lights up like a Christmas tree).

发送带有 FIN、PSH 和 URG 标志的数据包（像圣诞树一样点亮）。

```bash
sudo rustnmap -sX 192.168.1.1
```

### `-sM`, `--scan-maimon`

**TCP Maimon Scan / TCP Maimon 扫描**

Send packets with FIN/ACK flags (named after Uriel Maimon).

发送带有 FIN/ACK 标志的数据包（以 Uriel Maimon 命名）。

```bash
sudo rustnmap -sM 192.168.1.1
```

---

## Port Specification / 端口指定

### `-p <PORTS>`, `--ports <PORTS>`

Specify ports to scan.

指定要扫描的端口。

```bash
# Single port / 单个端口
rustnmap -p 22 192.168.1.1

# Multiple ports / 多个端口
rustnmap -p 22,80,443 192.168.1.1

# Port range / 端口范围
rustnmap -p 1-1000 192.168.1.1
rustnmap -p 1-65535 192.168.1.1

# Protocol specific / 特定协议
rustnmap -p T:22,80,U:53 192.168.1.1
```

### `-p-`, `--port-range-all`

Scan all 65535 ports.

扫描所有 65535 个端口。

```bash
sudo rustnmap -p- 192.168.1.1
```

### `-F`, `--fast-scan`

Fast scan (top 100 ports).

快速扫描（前 100 个端口）。

```bash
rustnmap -F 192.168.1.1
```

### `--top-ports <N>`

Scan top N most common ports.

扫描前 N 个最常见的端口。

```bash
rustnmap --top-ports 100 192.168.1.1
rustnmap --top-ports 1000 192.168.1.1
```

---

## Host Discovery / 主机发现

### `-sn`

**Ping Scan Only / 仅 Ping 扫描**

Disable port scanning, only host discovery.

禁用端口扫描，仅进行主机发现。

```bash
sudo rustnmap -sn 192.168.1.0/24
```

### `-Pn`, `--disable-ping`

**Skip Host Discovery / 跳过主机发现**

Treat all hosts as up (scan all targets).

将所有主机视为在线（扫描所有目标）。

```bash
sudo rustnmap -Pn 192.168.1.0/24
```

### `-PE`

**ICMP Echo Ping / ICMP 回显 Ping**

Use ICMP echo request (Type 8) for discovery.

使用 ICMP 回显请求（类型 8）进行发现。

```bash
sudo rustnmap -PE 192.168.1.0/24
```

### `-PP`

**ICMP Timestamp Ping / ICMP 时间戳 Ping**

Use ICMP timestamp request (Type 13) for discovery.

使用 ICMP 时间戳请求（类型 13）进行发现。

```bash
sudo rustnmap -PP 192.168.1.0/24
```

### `-PM`

**ICMP Netmask Ping / ICMP 网络掩码 Ping**

Use ICMP netmask request (Type 17) for discovery.

使用 ICMP 网络掩码请求（类型 17）进行发现。

```bash
sudo rustnmap -PM 192.168.1.0/24
```

### `-PS<PORTLIST>`, `--ping-type syn`

**TCP SYN Ping / TCP SYN Ping**

Send SYN packets to ports for discovery.

发送 SYN 数据包到端口进行发现。

```bash
sudo rustnmap -PS 192.168.1.0/24          # Default port 80
sudo rustnmap -PS22,80,443 192.168.1.0/24  # Specific ports
```

### `-PA<PORTLIST>`

**TCP ACK Ping / TCP ACK Ping**

Send ACK packets to ports for discovery.

发送 ACK 数据包到端口进行发现。

```bash
sudo rustnmap -PA 192.168.1.0/24          # Default port 80
sudo rustnmap -PA80,443 192.168.1.0/24    # Specific ports
```

### `-PU<PORTLIST>`

**UDP Ping / UDP Ping**

Send UDP packets to ports for discovery.

发送 UDP 数据包到端口进行发现。

```bash
sudo rustnmap -PU 192.168.1.0/24          # Default port 40125
sudo rustnmap -PU53,161 192.168.1.0/24    # Specific ports
```

### `-PR`

**ARP Ping / ARP Ping**

Use ARP requests for local network discovery (most reliable).

使用 ARP 请求进行本地网络发现（最可靠）。

```bash
sudo rustnmap -PR 192.168.1.0/24
```

---

## Service Detection / 服务检测

### `-sV`, `--service-detection`

**Service Version Detection / 服务版本检测**

Probe open ports to determine service/version information.

探测开放端口以确定服务/版本信息。

```bash
sudo rustnmap -sV 192.168.1.1
sudo rustnmap -sS -sV 192.168.1.1
```

### `--version-intensity <0-9>`

Set intensity of version detection (0 = light, 9 = all probes).

设置版本检测强度（0 = 轻量，9 = 所有探针）。

```bash
sudo rustnmap -sV --version-intensity 0 192.168.1.1   # Light
sudo rustnmap -sV --version-intensity 5 192.168.1.1   # Default
sudo rustnmap -sV --version-intensity 9 192.168.1.1   # All probes
```

### `--version-light`

Light mode (intensity 2).

轻量模式（强度 2）。

```bash
sudo rustnmap -sV --version-light 192.168.1.1
```

### `--version-all`

Try all probes (intensity 9).

尝试所有探针（强度 9）。

```bash
sudo rustnmap -sV --version-all 192.168.1.1
```

---

## OS Detection / 操作系统检测

### `-O`, `--os-detection`

**OS Detection / 操作系统检测**

Enable operating system detection using TCP/IP fingerprinting.

使用 TCP/IP 指纹识别启用操作系统检测。

```bash
sudo rustnmap -O 192.168.1.1
sudo rustnmap -sS -O 192.168.1.1
```

### `--osscan-limit`

Limit OS detection to promising targets.

将操作系统检测限制在有希望的目标上。

```bash
sudo rustnmap -O --osscan-limit 192.168.1.1
```

### `--osscan-guess`, `--fuzzy`

Guess OS more aggressively.

更激进地猜测操作系统。

```bash
sudo rustnmap -O --osscan-guess 192.168.1.1
```

---

## Timing and Performance / 时间和性能

### `-T<0-5>`, `--timing <0-5>`

Set timing template (higher is faster).

设置时间模板（数值越高越快）。

| Level | Name | Description |
|-------|------|-------------|
| 0 | Paranoid | 5 min between probes / 探针间 5 分钟 |
| 1 | Sneaky | 15 sec between probes / 探针间 15 秒 |
| 2 | Polite | 0.4 sec between probes / 探针间 0.4 秒 |
| 3 | Normal | Default / 默认 |
| 4 | Aggressive | Faster / 更快 |
| 5 | Insane | Very fast / 非常快 |

```bash
sudo rustnmap -T0 192.168.1.1   # Paranoid
sudo rustnmap -T1 192.168.1.1   # Sneaky
sudo rustnmap -T2 192.168.1.1   # Polite
sudo rustnmap -T3 192.168.1.1   # Normal (default)
sudo rustnmap -T4 192.168.1.1   # Aggressive
sudo rustnmap -T5 192.168.1.1   # Insane
```

### `--min-parallelism <NUM>`

Minimum number of parallel probes.

最小并行探针数。

```bash
sudo rustnmap --min-parallelism 100 192.168.1.1
```

### `--max-parallelism <NUM>`

Maximum number of parallel probes.

最大并行探针数。

```bash
sudo rustnmap --max-parallelism 500 192.168.1.1
```

### `--scan-delay <MS>`

Delay between probes (milliseconds).

探针之间的延迟（毫秒）。

```bash
sudo rustnmap --scan-delay 1000 192.168.1.1   # 1 second delay
```

### `--host-timeout <MS>`

Timeout for host scan (milliseconds).

主机扫描超时（毫秒）。

```bash
sudo rustnmap --host-timeout 30000 192.168.1.0/24   # 30 seconds
```

### `--min-rate <NUM>`

Minimum packet rate (packets per second).

最小数据包速率（每秒数据包数）。

```bash
sudo rustnmap --min-rate 1000 192.168.1.1
```

### `--max-rate <NUM>`

Maximum packet rate (packets per second).

最大数据包速率（每秒数据包数）。

```bash
sudo rustnmap --max-rate 100 192.168.1.1
```

---

## Firewall/IDS Evasion / 防火墙/IDS 规避

### `-f`, `--fragment-mtu <MTU>`

Fragment packets (default 8 bytes after IP header).

分片数据包（IP 头后默认 8 字节）。

```bash
sudo rustnmap -f 192.168.1.1
sudo rustnmap --mtu 8 192.168.1.1
sudo rustnmap --mtu 16 192.168.1.1
```

### `-D <DECOYS>`, `--decoys <DECOYS>`

Use decoy scans to hide source.

使用诱饵扫描隐藏源地址。

```bash
# Specific decoys / 特定诱饵
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1

# Random decoys / 随机诱饵
sudo rustnmap -D RND:10 192.168.1.1

# Position yourself / 指定自己位置
sudo rustnmap -D ME,192.168.1.2,192.168.1.3 192.168.1.1
```

### `-S <IP>`, `--spoof-ip <IP>`

Spoof source address.

欺骗源地址。

```bash
sudo rustnmap -S 192.168.1.100 192.168.1.1
```

**Note / 注意:** Requires ability to receive responses.
需要能够接收响应。

### `-g <PORT>`, `--source-port <PORT>`

Use specific source port.

使用特定源端口。

```bash
sudo rustnmap -g 53 192.168.1.1     # DNS port
sudo rustnmap -g 20 192.168.1.1     # FTP data port
```

### `-e <IFACE>`, `--interface <IFACE>`

Use specified network interface.

使用指定的网络接口。

```bash
sudo rustnmap -e eth0 192.168.1.1
sudo rustnmap -e wlan0 192.168.1.1
```

### `--data-length <LEN>`

Append random data to packets.

向数据包追加随机数据。

```bash
sudo rustnmap --data-length 100 192.168.1.1
```

### `--data-hex <HEX>`

Append custom hex data to packets.

向数据包追加自定义十六进制数据。

```bash
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1   # "Hello"
```

### `--data-string <STRING>`

Append custom string to packets.

向数据包追加自定义字符串。

```bash
sudo rustnmap --data-string "Hello" 192.168.1.1
```

### `--spoof-mac <MAC>`

Spoof MAC address.

欺骗 MAC 地址。

```bash
sudo rustnmap --spoof-mac 00:11:22:33:44:55 192.168.1.1
sudo rustnmap --spoof-mac 0 192.168.1.1           # Random
sudo rustnmap --spoof-mac Apple 192.168.1.1       # Vendor prefix
```

---

## Output Options / 输出选项

### `-oN <FILE>`, `--output-normal <FILE>`

Normal output to file.

普通输出到文件。

```bash
sudo rustnmap -oN results.nmap 192.168.1.1
```

### `-oX <FILE>`, `--output-xml <FILE>`

XML output to file.

XML 输出到文件。

```bash
sudo rustnmap -oX results.xml 192.168.1.1
```

### `-oJ <FILE>`, `--output-json <FILE>`

JSON output to file.

JSON 输出到文件。

```bash
sudo rustnmap -oJ results.json 192.168.1.1
```

### `-oG <FILE>`, `--output-grepable <FILE>`

Grepable output to file.

Grepable 输出到文件。

```bash
sudo rustnmap -oG results.gnmap 192.168.1.1
```

### `-oS <FILE>`, `--output-script-kiddie`

Script kiddie output.

Script kiddie 输出。

```bash
sudo rustnmap -oS results.txt 192.168.1.1
```

### `-oA <BASENAME>`, `--output-all <BASENAME>`

Output to all formats.

输出到所有格式。

```bash
sudo rustnmap -oA results 192.168.1.1
# Creates: results.nmap, results.xml, results.json, results.gnmap
```

### `--append-output`

Append to output files instead of overwriting.

追加到输出文件而不是覆盖。

```bash
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

### `-v`, `--verbose`

Increase verbosity level (use multiple times).

增加详细程度（可多次使用）。

```bash
sudo rustnmap -v 192.168.1.1      # Verbose
sudo rustnmap -vv 192.168.1.1     # More verbose
sudo rustnmap -vvv 192.168.1.1    # Maximum verbose
```

### `-q`, `--quiet`

Quiet mode (only errors).

安静模式（仅错误）。

```bash
sudo rustnmap -q 192.168.1.1
```

### `-d`, `--debug`

Increase debugging level.

增加调试级别。

```bash
sudo rustnmap -d 192.168.1.1      # Debug
sudo rustnmap -dd 192.168.1.1     # More debug
```

### `--reason`

Display reason for port state.

显示端口状态的原因。

```bash
sudo rustnmap --reason 192.168.1.1
# Shows: syn-ack, reset, no-response, etc.
```

### `--packet-trace`

Show packet trace of scan.

显示扫描的数据包跟踪。

```bash
sudo rustnmap --packet-trace 192.168.1.1
```

### `--open`

Show only open ports.

仅显示开放端口。

```bash
sudo rustnmap --open 192.168.1.1
```

### `--if-list`

Show interface list and routes.

显示接口列表和路由。

```bash
rustnmap --if-list
```

### `--no-output`

Suppress output.

禁止输出。

```bash
sudo rustnmap --no-output 192.168.1.1
```

---

## NSE Scripting / NSE 脚本

### `-sC`

Run default scripts (equivalent to `--script=default`).

运行默认脚本（等同于 `--script=default`）。

```bash
sudo rustnmap -sC 192.168.1.1
```

### `--script <SCRIPTS>`, `-sC`

Run specified scripts.

运行指定的脚本。

```bash
# Single script / 单个脚本
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts / 多个脚本
sudo rustnmap --script http-title,http-headers 192.168.1.1

# Script categories / 脚本类别
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "intrusive" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "version" 192.168.1.1

# Pattern matching / 模式匹配
sudo rustnmap --script "http-*" 192.168.1.1
sudo rustnmap --script "smb-*" 192.168.1.1
```

**Categories / 类别:**
- `auth` - Authentication related / 认证相关
- `broadcast` - Broadcast discovery / 广播发现
- `brute` - Brute force attacks / 暴力破解
- `default` - Default scripts / 默认脚本
- `discovery` - Service discovery / 服务发现
- `dos` - Denial of service / 拒绝服务
- `exploit` - Exploits / 漏洞利用
- `external` - External resources / 外部资源
- `fuzzer` - Fuzzing tests / 模糊测试
- `intrusive` - Intrusive scripts / 侵入性脚本
- `malware` - Malware detection / 恶意软件检测
- `safe` - Safe scripts / 安全脚本
- `version` - Version detection / 版本检测
- `vuln` - Vulnerability detection / 漏洞检测

### `--script-args <ARGS>`

Provide arguments to scripts.

向脚本提供参数。

```bash
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# Multiple arguments / 多个参数
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1
```

### `--script-help <SCRIPT>`

Show help for scripts.

显示脚本帮助。

```bash
# List all scripts / 列出所有脚本
rustnmap --script-help

# Help for specific script / 特定脚本帮助
rustnmap --script-help http-title
```

### `--script-updatedb`

Update script database.

更新脚本数据库。

```bash
rustnmap --script-updatedb
```

---

## Miscellaneous / 其他

### `--traceroute`

Trace hop path to target.

跟踪到目标的跳数路径。

```bash
sudo rustnmap --traceroute 192.168.1.1
```

### `--traceroute-hops <NUM>`

Maximum traceroute hops.

最大 traceroute 跳数。

```bash
sudo rustnmap --traceroute --traceroute-hops 20 192.168.1.1
```

### `--randomize-hosts`

Randomize target host order.

随机化目标主机顺序。

```bash
sudo rustnmap --randomize-hosts 192.168.1.0/24
```

### `--host-group-size <NUM>`

Host group size for parallel scanning.

并行扫描的主机组大小。

```bash
sudo rustnmap --host-group-size 10 192.168.1.0/24
```

### `--print-urls`

Print interacted URLs.

打印交互的 URL。

```bash
rustnmap --print-urls 192.168.1.1
```

### `-A`

**Aggressive Scan / 激进扫描**

Enable OS detection, version detection, script scanning, and traceroute.

启用操作系统检测、版本检测、脚本扫描和 traceroute。

```bash
sudo rustnmap -A 192.168.1.1
# Equivalent to: -sV -sC -O --traceroute
```

### `-h`, `--help`

Show help message.

显示帮助信息。

```bash
rustnmap --help
```

### `-V`, `--version`

Show version information.

显示版本信息。

```bash
rustnmap --version
```

---

## Option Combinations / 选项组合

### Common Combinations / 常见组合

```bash
# Comprehensive scan / 综合扫描
sudo rustnmap -A -T4 -oA full-scan 192.168.1.1

# Stealth web scan / 隐秘 Web 扫描
sudo rustnmap -sS -T2 -p 80,443 --script http-* 192.168.1.1

# Fast network discovery / 快速网络发现
sudo rustnmap -sn -T4 192.168.1.0/24

# Full port scan with service detection / 全端口扫描带服务检测
sudo rustnmap -p- -sV -T4 192.168.1.1

# IDS evasion scan / IDS 规避扫描
sudo rustnmap -sS -T0 -f -D RND:10 192.168.1.1
```

### Conflicting Options / 冲突选项

The following options conflict with each other:

以下选项相互冲突：

- Only one scan type: `-sS`, `-sT`, `-sU`, `-sF`, `-sN`, `-sX`, `-sM`
- Only one port specification: `-p`, `-F`, `--top-ports`, `-p-`
- Only one output format group: `-oN`, `-oX`, `-oJ`, `-oG`, `-oA`

---

## Summary Tables / 汇总表

### Scan Types Summary / 扫描类型汇总

| Flag | Name | Root | Description |
|------|------|------|-------------|
| `-sS` | SYN | Yes | Half-open scan |
| `-sT` | Connect | No | Full handshake |
| `-sU` | UDP | Yes | UDP scan |
| `-sF` | FIN | Yes | FIN flag only |
| `-sN` | NULL | Yes | No flags |
| `-sX` | XMAS | Yes | FIN/PSH/URG |
| `-sA` | ACK | Yes | ACK flag |
| `-sM` | Maimon | Yes | FIN/ACK |

### Output Formats Summary / 输出格式汇总

| Flag | Extension | Description |
|------|-----------|-------------|
| `-oN` | .nmap | Human-readable |
| `-oX` | .xml | Machine-parseable |
| `-oJ` | .json | Structured JSON |
| `-oG` | .gnmap | Grepable |
| `-oS` | .txt | Script kiddie |
| `-oA` | Multiple | All formats |

### Timing Templates Summary / 时间模板汇总

| Flag | Name | Speed | Use Case |
|------|------|-------|----------|
| `-T0` | Paranoid | Very slow | IDS evasion |
| `-T1` | Sneaky | Slow | IDS evasion |
| `-T2` | Polite | Moderate | Slow network |
| `-T3` | Normal | Default | General use |
| `-T4` | Aggressive | Fast | Fast network |
| `-T5` | Insane | Very fast | Local network |
