# RustNmap Configuration File / 配置文件

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的配置文件。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> **Configuration file format and options** / 配置文件格式和选项

---

## Overview / 概述

RustNmap supports configuration files for persistent settings. Configuration files use a simple key-value format similar to INI files.

RustNmap 支持配置文件用于持久化设置。配置文件使用类似于 INI 文件的简单键值格式。

---

## Configuration File Locations / 配置文件位置

RustNmap searches for configuration files in the following order:

RustNmap 按以下顺序搜索配置文件：

| Order | Location | Description |
|-------|----------|-------------|
| 1 | `./rustnmap.conf` | Current directory / 当前目录 |
| 2 | `~/.rustnmap/rustnmap.conf` | User home directory / 用户主目录 |
| 3 | `~/.rustnmap.conf` | User home (alternate) / 用户主目录（备用） |
| 4 | `/etc/rustnmap/rustnmap.conf` | System-wide / 系统范围 |
| 5 | `/etc/rustnmap.conf` | System-wide (alternate) / 系统范围（备用） |

---

## Configuration File Format / 配置文件格式

### Basic Syntax / 基本语法

```ini
# This is a comment / 这是注释
key = value

# Boolean values / 布尔值
debug = true
verbose = yes
quiet = no

# Numeric values / 数值
timing = 4
max-retries = 3

# String values / 字符串值
output-format = xml
log-file = /var/log/rustnmap.log

# Lists (comma-separated) / 列表（逗号分隔）
default-ports = 22,80,443
exclude-ports = 25,110,143

# Multiple values per key / 每键多个值
exclude = 192.168.1.1
exclude = 192.168.1.254
```

### Sections / 节

Configuration files support sections for organizing options:

配置文件支持节用于组织选项：

```ini
[default]
timing = 4
verbose = true

[output]
format = xml
directory = /var/log/scans

[network]
interface = eth0
source-ip = 192.168.1.100

[scripts]
timeout = 120
args = http.useragent=Mozilla/5.0
```

---

## Configuration Options / 配置选项

### Scan Options / 扫描选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `scan-type` | string | Default scan type (`syn`, `connect`, `udp`, etc.) | `syn` |
| `timing` | integer | Timing template (0-5) | `3` |
| `max-retries` | integer | Maximum retry attempts | `10` |
| `host-timeout` | integer | Host timeout in seconds | `0` (no timeout) |
| `scan-delay` | integer | Delay between probes in ms | `0` |
| `min-rate` | integer | Minimum packets per second | `0` |
| `max-rate` | integer | Maximum packets per second | `0` |

**Example / 示例:**

```ini
[scan]
scan-type = syn
timing = 4
max-retries = 3
host-timeout = 300
```

---

### Port Options / 端口选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `default-ports` | list | Default ports to scan | `top-1000` |
| `exclude-ports` | list | Ports to exclude | (none) |
| `fast-scan` | boolean | Use fast scan (top 100) | `false` |
| `all-ports` | boolean | Scan all 65535 ports | `false` |

**Example / 示例:**

```ini
[ports]
default-ports = 22,80,443,8080,8443
exclude-ports = 25,110,143
fast-scan = false
```

---

### Host Discovery / 主机发现

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `skip-ping` | boolean | Skip host discovery | `false` |
| `ping-type` | string | Ping type (`icmp`, `tcp`, `udp`, `arp`) | `auto` |
| `tcp-ping-ports` | list | TCP ping ports | `80,443` |
| `udp-ping-ports` | list | UDP ping ports | `53,161` |

**Example / 示例:**

```ini
[discovery]
skip-ping = false
ping-type = tcp
tcp-ping-ports = 22,80,443,3389
udp-ping-ports = 53,161,162
```

---

### Service Detection / 服务检测

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `service-detection` | boolean | Enable service detection | `false` |
| `version-intensity` | integer | Version detection intensity (0-9) | `7` |
| `version-light` | boolean | Use light version detection | `false` |
| `version-all` | boolean | Use all version probes | `false` |

**Example / 示例:**

```ini
[service]
service-detection = true
version-intensity = 5
version-light = false
```

---

### OS Detection / 操作系统检测

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `os-detection` | boolean | Enable OS detection | `false` |
| `oscan-limit` | boolean | Limit OS detection | `false` |
| `oscan-guess` | boolean | Aggressive OS guessing | `false` |

**Example / 示例:**

```ini
[os]
os-detection = true
oscan-limit = false
oscan-guess = true
```

---

### Output Options / 输出选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `output-format` | string | Output format (`normal`, `xml`, `json`, `grepable`) | `normal` |
| `output-directory` | string | Default output directory | `.` |
| `append-output` | boolean | Append to output files | `false` |
| `show-reason` | boolean | Show port state reasons | `false` |
| `open-only` | boolean | Show only open ports | `false` |
| `packet-trace` | boolean | Show packet trace | `false` |

**Example / 示例:**

```ini
[output]
output-format = xml
output-directory = /var/log/scans
append-output = false
show-reason = true
open-only = false
```

---

### NSE Scripts / NSE 脚本

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `default-scripts` | boolean | Run default scripts | `false` |
| `script-timeout` | integer | Script timeout in seconds | `120` |
| `script-args` | string | Default script arguments | (none) |
| `script-categories` | list | Script categories to run | (none) |

**Example / 示例:**

```ini
[scripts]
default-scripts = true
script-timeout = 180
script-args = http.useragent=Mozilla/5.0
script-categories = safe,discovery
```

---

### Evasion Options / 规避选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `fragment-mtu` | integer | Fragment MTU size | (none) |
| `decoys` | list | Decoy IP addresses | (none) |
| `source-ip` | string | Spoofed source IP | (none) |
| `source-port` | integer | Fixed source port | (none) |
| `data-length` | integer | Random data length | `0` |
| `randomize-hosts` | boolean | Randomize target order | `false` |

**Example / 示例:**

```ini
[evasion]
fragment-mtu = 8
source-port = 53
randomize-hosts = true
```

---

### Network Options / 网络选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `interface` | string | Network interface | (auto) |
| `source-ip` | string | Source IP address | (auto) |
| `dns-servers` | list | Custom DNS servers | (system) |
| `system-dns` | boolean | Use system DNS | `true` |

**Example / 示例:**

```ini
[network]
interface = eth0
source-ip = 192.168.1.100
dns-servers = 8.8.8.8,8.8.4.4
system-dns = false
```

---

### Logging Options / 日志选项

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `verbose` | integer | Verbosity level (0-3) | `0` |
| `debug` | integer | Debug level (0-3) | `0` |
| `quiet` | boolean | Quiet mode | `false` |
| `log-file` | string | Log file path | (none) |

**Example / 示例:**

```ini
[logging]
verbose = 1
debug = 0
quiet = false
log-file = /var/log/rustnmap.log
```

---

## Complete Configuration Example / 完整配置示例

### Basic Configuration / 基本配置

```ini
# ~/.rustnmap/rustnmap.conf
# Basic RustNmap configuration

[default]
# Scan options / 扫描选项
timing = 3
max-retries = 3

# Output options / 输出选项
verbose = 1
show-reason = true

# Service detection / 服务检测
service-detection = true
version-intensity = 5
```

### Security Analyst / 安全分析师

```ini
# ~/.rustnmap/rustnmap.conf
# Security analyst configuration

[default]
timing = 4
max-retries = 2
verbose = 2
show-reason = true
randomize-hosts = true

[output]
output-format = xml
output-directory = ~/security-audits
append-output = false

[service]
service-detection = true
version-intensity = 7

[os]
os-detection = true
oscan-guess = true

[scripts]
default-scripts = true
script-timeout = 180
script-args = http.useragent=Mozilla/5.0

[logging]
log-file = ~/.rustnmap/scans.log
verbose = 2
```

### Stealth Scanning / 隐秘扫描

```ini
# ~/.rustnmap/rustnmap.conf
# Stealth scanning configuration

[default]
timing = 1
max-retries = 1
scan-delay = 15000
randomize-hosts = true

[evasion]
fragment-mtu = 8
source-port = 53
randomize-hosts = true

[network]
# Use specific interface / 使用特定接口
interface = eth0

[output]
# Minimal output / 最小输出
quiet = true
show-reason = false
```

### Network Administrator / 网络管理员

```ini
# /etc/rustnmap/rustnmap.conf
# System-wide configuration

[default]
timing = 4
max-retries = 3

[ports]
default-ports = 22,23,25,53,80,110,143,443,445,993,995,3389

[discovery]
ping-type = icmp
tcp-ping-ports = 22,80,443

[output]
output-directory = /var/log/network-scans

[logging]
log-file = /var/log/rustnmap.log
verbose = 1
```

---

## Configuration with Environment Variables / 使用环境变量配置

Configuration files can reference environment variables:

配置文件可以引用环境变量：

```ini
[default]
# Use environment variable / 使用环境变量
output-directory = ${HOME}/scans

# With default value / 带默认值
log-file = ${RUSTNMAP_LOG_FILE:-/tmp/rustnmap.log}

[scripts]
# Script directory from env / 从环境变量获取脚本目录
script-directory = ${RUSTNMAP_SCRIPTS}
```

---

## Loading Configuration / 加载配置

### Automatic Loading / 自动加载

RustNmap automatically loads configuration from the locations listed above.

RustNmap 自动从上面列出的位置加载配置。

---

## Configuration Precedence / 配置优先级

Options are applied in the following order (later overrides earlier):

选项按以下顺序应用（后面的覆盖前面的）：

1. Built-in defaults / 内置默认值
2. System-wide configuration (`/etc/rustnmap.conf`) / 系统范围配置
3. User configuration (`~/.rustnmap.conf`) / 用户配置
4. Local configuration (`./rustnmap.conf`) / 本地配置
5. Environment variables / 环境变量
6. Command-line options / 命令行选项

---

## Troubleshooting / 故障排除

### Configuration Not Loading / 配置未加载

```bash
# Check file permissions / 检查文件权限
ls -la ~/.rustnmap/rustnmap.conf

# Check file location / 检查文件位置
find ~ -name "rustnmap.conf" 2>/dev/null

# Verify syntax / 验证语法
cat ~/.rustnmap/rustnmap.conf | grep -v "^#" | grep -v "^$"
```

### Invalid Option / 无效选项

```bash
# Error: Invalid option 'timingg'
# Check spelling / 检查拼写
# timingg -> timing

# Check available options / 检查可用选项
rustnmap --help
```

---

## Configuration Templates / 配置模板

### Quick Templates / 快速模板

Save these as starting points:

保存这些作为起点：

**fast-scan.conf:**
```ini
[default]
timing = 5
max-retries = 2
fast-scan = true
```

**stealth-scan.conf:**
```ini
[default]
timing = 1
max-retries = 1
scan-delay = 5000
randomize-hosts = true

[evasion]
fragment-mtu = 8
```

**comprehensive-scan.conf:**
```ini
[default]
timing = 3

[service]
service-detection = true
version-intensity = 9

[os]
os-detection = true

[scripts]
default-scripts = true

[output]
output-format = xml
```

---

## Related Documentation / 相关文档

- [Environment Variables](environment.md) - Environment configuration / 环境配置
- [Options Reference](options.md) - Command-line options / 命令行选项
