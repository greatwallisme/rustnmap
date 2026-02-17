# RustNmap Environment Variables / 环境变量

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的环境变量。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> **Environment variables reference for RustNmap** / RustNmap 环境变量参考

---

## Overview / 概述

RustNmap supports several environment variables that control various aspects of its behavior. These can be set in your shell or in configuration files.

RustNmap 支持多个环境变量来控制其行为的各种方面。这些可以在 shell 或配置文件中设置。

---

## Environment Variables Reference / 环境变量参考

| Variable | Description | Default |
|----------|-------------|---------|
| `RUSTNMAP_HOME` | RustNmap home directory | `~/.rustnmap` |
| `RUSTNMAP_SCRIPTS` | Scripts directory | `/usr/share/rustnmap/scripts` |
| `RUSTNMAP_DATA` | Data directory | `/usr/share/rustnmap` |
| `RUSTNMAP_OUTPUT` | Default output directory | Current directory |
| `RUSTNMAP_OPTIONS` | Default command-line options | None |
| `RUSTNMAP_TARGETS` | Default target list | None |

---

## Path Variables / 路径变量

### RUSTNMAP_HOME

**Description / 描述**

Sets the RustNmap home directory for user-specific files.

设置 RustNmap 主目录用于用户特定文件。

**Default / 默认值**

```
~/.rustnmap
```

**Usage / 用法**

```bash
# Set custom home directory / 设置自定义主目录
export RUSTNMAP_HOME=/opt/rustnmap

# Files stored in: / 文件存储在：
# $RUSTNMAP_HOME/scripts/     # User scripts / 用户脚本
# $RUSTNMAP_HOME/data/        # User data / 用户数据
# $RUSTNMAP_HOME/config/      # User config / 用户配置
```

---

### RUSTNMAP_SCRIPTS

**Description / 描述**

Sets the directory containing NSE scripts.

设置包含 NSE 脚本的目录。

**Default / 默认值**

```
/usr/share/rustnmap/scripts
```

**Usage / 用法**

```bash
# Use custom scripts directory / 使用自定义脚本目录
export RUSTNMAP_SCRIPTS=/path/to/custom/scripts

# Run with custom scripts / 使用自定义脚本运行
rustnmap --script my-script 192.168.1.1
```

---

### RUSTNMAP_DATA

**Description / 描述**

Sets the data directory for fingerprint databases and other data files.

设置指纹数据库和其他数据文件的数据目录。

**Default / 默认值**

```
/usr/share/rustnmap
```

**Contents / 内容**

```
$RUSTNMAP_DATA/
├── nmap-service-probes      # Service detection probes
├── nmap-os-db               # OS fingerprints
├── nmap-mac-prefixes        # MAC vendor database
└── scripts/                 # NSE scripts
```

**Usage / 用法**

```bash
# Use custom data directory / 使用自定义数据目录
export RUSTNMAP_DATA=/var/lib/rustnmap

# Update databases in custom location / 在自定义位置更新数据库
rustnmap --script-updatedb
```

---

## Default Options / 默认选项

### RUSTNMAP_OPTIONS

**Description / 描述**

Sets default command-line options that are automatically added to every scan.

设置自动添加到每次扫描的默认命令行选项。

**Default / 默认值**

```
(none)
```

**Usage / 用法**

```bash
# Always use verbose output / 始终使用详细输出
export RUSTNMAP_OPTIONS="-v"

# Always use specific timing / 始终使用特定时间
export RUSTNMAP_OPTIONS="-T4 --reason"

# Multiple options / 多个选项
export RUSTNMAP_OPTIONS="-v -T4 --open"

# Now 'rustnmap 192.168.1.1' is equivalent to:
# rustnmap -v -T4 --open 192.168.1.1
```

**Note / 注意**

Options specified on the command line override environment variable options.

命令行上指定的选项会覆盖环境变量选项。

---

### RUSTNMAP_TARGETS

**Description / 描述**

Sets default target hosts if none are specified on the command line.

如果命令行上未指定，则设置默认目标主机。

**Default / 默认值**

```
(none)
```

**Usage / 用法**

```bash
# Set default network to scan / 设置默认扫描网络
export RUSTNMAP_TARGETS="192.168.1.0/24"

# Run scan without specifying targets / 运行扫描而不指定目标
rustnmap -sS  # Scans 192.168.1.0/24

# Override with command-line target / 用命令行目标覆盖
rustnmap -sS 10.0.0.1  # Scans 10.0.0.1, not default
```

---

## Network Configuration / 网络配置

### RUSTNMAP_INTERFACE

**Description / 描述**

Sets the default network interface to use for scanning.

设置扫描使用的默认网络接口。

**Default / 默认值**

```
(auto-detected)
```

**Usage / 用法**

```bash
# Always use eth0 / 始终使用 eth0
export RUSTNMAP_INTERFACE=eth0

# Override per-scan / 每次扫描覆盖
rustnmap -e wlan0 192.168.1.1
```

---

### RUSTNMAP_SOURCE_IP

**Description / 描述**

Sets the default source IP address for packets.

设置数据包的默认源 IP 地址。

**Default / 默认值**

```
(auto-detected)
```

**Usage / 用法**

```bash
# Set default source IP / 设置默认源 IP
export RUSTNMAP_SOURCE_IP=192.168.1.100

# Override per-scan / 每次扫描覆盖
rustnmap -S 10.0.0.100 192.168.1.1
```

---

## Output Configuration / 输出配置

### RUSTNMAP_OUTPUT_DIR

**Description / 描述**

Sets the default directory for output files.

设置输出文件的默认目录。

**Default / 默认值**

```
(current working directory)
```

**Usage / 用法**

```bash
# Set default output directory / 设置默认输出目录
export RUSTNMAP_OUTPUT_DIR=/var/log/scans

# Results saved to / 结果保存到：
# /var/log/scans/scan_results.nmap
rustnmap -oN scan_results.nmap 192.168.1.1
```

---

### RUSTNMAP_OUTPUT_FORMAT

**Description / 描述**

Sets the default output format.

设置默认输出格式。

**Default / 默认值**

```
normal
```

**Values / 值**

- `normal` - Human-readable text
- `xml` - XML format
- `json` - JSON format
- `grepable` - Grepable format

**Usage / 用法**

```bash
# Always output XML / 始终输出 XML
export RUSTNMAP_OUTPUT_FORMAT=xml

# Override per-scan / 每次扫描覆盖
rustnmap -oN normal.txt 192.168.1.1
```

---

## Script Configuration / 脚本配置

### RUSTNMAP_SCRIPT_ARGS

**Description / 描述**

Sets default arguments for NSE scripts.

设置 NSE 脚本的默认参数。

**Default / 默认值**

```
(none)
```

**Usage / 用法**

```bash
# Set default User-Agent for HTTP scripts / 为 HTTP 脚本设置默认 User-Agent
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"

# Multiple default arguments / 多个默认参数
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla,smb.domain=WORKGROUP"
```

---

### RUSTNMAP_SCRIPT_TIMEOUT

**Description / 描述**

Sets the default timeout for script execution (in seconds).

设置脚本执行的默认超时（以秒为单位）。

**Default / 默认值**

```
120
```

**Usage / 用法**

```bash
# Increase default script timeout / 增加默认脚本超时
export RUSTNMAP_SCRIPT_TIMEOUT=300

# Decrease for faster scans / 减少以加快扫描速度
export RUSTNMAP_SCRIPT_TIMEOUT=60
```

---

## Performance Configuration / 性能配置

### RUSTNMAP_TIMING

**Description / 描述**

Sets the default timing template.

设置默认时间模板。

**Default / 默认值**

```
3 (Normal)
```

**Values / 值**

| Value | Template | Description |
|-------|----------|-------------|
| `0` | Paranoid | Very slow, IDS evasion |
| `1` | Sneaky | Slow, IDS evasion |
| `2` | Polite | Moderate speed |
| `3` | Normal | Default |
| `4` | Aggressive | Fast |
| `5` | Insane | Very fast |

**Usage / 用法**

```bash
# Always use aggressive timing / 始终使用激进时间
export RUSTNMAP_TIMING=4

# Override per-scan / 每次扫描覆盖
rustnmap -T2 192.168.1.1
```

---

### RUSTNMAP_MIN_RATE

**Description / 描述**

Sets the minimum packet rate (packets per second).

设置最小数据包速率（每秒数据包数）。

**Default / 默认值**

```
(auto)
```

**Usage / 用法**

```bash
# Ensure minimum rate / 确保最小速率
export RUSTNMAP_MIN_RATE=100

rustnmap 192.168.1.1  # Uses --min-rate 100
```

---

### RUSTNMAP_MAX_RETRIES

**Description / 描述**

Sets the maximum number of port scan probe retransmissions.

设置端口扫描探针重传的最大次数。

**Default / 默认值**

```
10
```

**Usage / 用法**

```bash
# Reduce retries for faster scans / 减少重试以加快扫描速度
export RUSTNMAP_MAX_RETRIES=2

# Increase for unreliable networks / 为不可靠网络增加
export RUSTNMAP_MAX_RETRIES=20
```

---

## Security Configuration / 安全配置

### RUSTNMAP_NO_PING

**Description / 描述**

Disables host discovery by default.

默认禁用主机发现。

**Default / 默认值**

```
false
```

**Usage / 用法**

```bash
# Always skip ping scan / 始终跳过 Ping 扫描
export RUSTNMAP_NO_PING=1

# Equivalent to always using -Pn / 等同于始终使用 -Pn
rustnmap 192.168.1.1  # Scans all targets without ping
```

---

### RUSTNMAP_RANDOMIZE

**Description / 描述**

Randomizes target order by default.

默认随机化目标顺序。

**Default / 默认值**

```
false
```

**Usage / 用法**

```bash
# Always randomize targets / 始终随机化目标
export RUSTNMAP_RANDOMIZE=1

# Equivalent to always using --randomize-hosts
rustnmap 192.168.1.0/24  # Random order
```

---

## Logging Configuration / 日志配置

### RUSTNMAP_LOG_LEVEL

**Description / 描述**

Sets the default logging level.

设置默认日志级别。

**Default / 默认值**

```
warn
```

**Values / 值**

- `error` - Error messages only
- `warn` - Warnings and errors
- `info` - Informational messages
- `debug` - Debug messages
- `trace` - All messages

**Usage / 用法**

```bash
# Enable debug logging / 启用调试日志
export RUSTNMAP_LOG_LEVEL=debug

# Minimal logging / 最小日志
export RUSTNMAP_LOG_LEVEL=error
```

---

### RUSTNMAP_LOG_FILE

**Description / 描述**

Sets the log file path.

设置日志文件路径。

**Default / 默认值**

```
(stderr)
```

**Usage / 用法**

```bash
# Log to file / 记录到文件
export RUSTNMAP_LOG_FILE=/var/log/rustnmap.log

# Disable file logging / 禁用文件日志
unset RUSTNMAP_LOG_FILE
```

---

## Setting Environment Variables / 设置环境变量

### Temporary (Current Session) / 临时（当前会话）

```bash
# Set for current session only / 仅为当前会话设置
export RUSTNMAP_OPTIONS="-v -T4"

# Unset / 取消设置
unset RUSTNMAP_OPTIONS
```

### Permanent (Bash) / 永久（Bash）

Add to `~/.bashrc` or `~/.bash_profile`:

```bash
# RustNmap configuration / RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=180
```

Then reload:

```bash
source ~/.bashrc
```

### Permanent (Zsh) / 永久（Zsh）

Add to `~/.zshrc`:

```bash
# RustNmap configuration / RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
```

### System-wide / 系统范围

Add to `/etc/environment` or `/etc/profile.d/rustnmap.sh`:

```bash
# /etc/profile.d/rustnmap.sh
export RUSTNMAP_DATA="/usr/share/rustnmap"
export RUSTNMAP_SCRIPTS="/usr/share/rustnmap/scripts"
```

---

## Viewing Environment Variables / 查看环境变量

### List All RustNmap Variables / 列出所有 RustNmap 变量

```bash
# Show all RustNmap environment variables / 显示所有 RustNmap 环境变量
env | grep RUSTNMAP

# Show with values / 显示值
env | grep RUSTNMAP | sort
```

### Check Specific Variable / 检查特定变量

```bash
# Check specific variable / 检查特定变量
echo $RUSTNMAP_OPTIONS
echo $RUSTNMAP_HOME
echo $RUSTNMAP_TIMING
```

### In Scripts / 在脚本中

```bash
#!/bin/bash

# Check if variable is set / 检查变量是否设置
if [ -n "$RUSTNMAP_OPTIONS" ]; then
    echo "Default options: $RUSTNMAP_OPTIONS"
else
    echo "No default options set"
fi

# Use with default fallback / 使用默认回退
OPTIONS="${RUSTNMAP_OPTIONS:--T3}"
rustnmap $OPTIONS 192.168.1.1
```

---

## Complete Configuration Example / 完整配置示例

### Scanning Workstation / 扫描工作站

```bash
# ~/.bashrc

# RustNmap configuration
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason --open"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=120
export RUSTNMAP_LOG_LEVEL=info
export RUSTNMAP_OUTPUT_DIR="$HOME/scans"

# Create directories if they don't exist
mkdir -p "$RUSTNMAP_HOME/scripts"
mkdir -p "$RUSTNMAP_OUTPUT_DIR"
```

### Security Analyst / 安全分析师

```bash
# ~/.bashrc

# RustNmap configuration for security work
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T3 --reason --traceroute"
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"
export RUSTNMAP_OUTPUT_DIR="$HOME/security-audits"
export RUSTNMAP_LOG_LEVEL=debug
export RUSTNMAP_LOG_FILE="$HOME/logs/rustnmap.log"
```

### Stealth Scanning / 隐秘扫描

```bash
# ~/.bashrc

# RustNmap configuration for stealth scanning
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T1 --randomize-hosts"
export RUSTNMAP_TIMING=1
export RUSTNMAP_MIN_RATE=1
export RUSTNMAP_MAX_RETRIES=1
export RUSTNMAP_RANDOMIZE=1
```

---

## Environment Variable Precedence / 环境变量优先级

Options are applied in the following order (later overrides earlier):

选项按以下顺序应用（后面的覆盖前面的）：

1. Default values / 默认值
2. Environment variables / 环境变量
3. Configuration file settings / 配置文件设置
4. Command-line options / 命令行选项

Example / 示例:

```bash
# Environment sets default timing / 环境设置默认时间
export RUSTNMAP_TIMING=3

# Config file overrides to aggressive / 配置文件覆盖为激进
# (in rustnmap.conf: timing = 4)

# Command line overrides everything / 命令行覆盖所有
rustnmap -T5 192.168.1.1  # Uses -T5 (Insane)
```

---

## Related Documentation / 相关文档

- [Configuration](configuration.md) - Configuration file options / 配置文件选项
- [Options Reference](options.md) - Command-line options / 命令行选项
