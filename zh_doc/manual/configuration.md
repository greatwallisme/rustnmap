# RustNmap 配置文件

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的配置文件。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> 配置文件格式和选项

---

## 概述

RustNmap 支持配置文件用于持久化设置。配置文件使用类似于 INI 文件的简单键值格式。

---

## 配置文件位置

RustNmap 按以下顺序搜索配置文件：

| 顺序 | 位置 | 描述 |
|------|------|------|
| 1 | `./rustnmap.conf` | 当前目录 |
| 2 | `~/.rustnmap/rustnmap.conf` | 用户主目录 |
| 3 | `~/.rustnmap.conf` | 用户主目录（备用） |
| 4 | `/etc/rustnmap/rustnmap.conf` | 系统范围 |
| 5 | `/etc/rustnmap.conf` | 系统范围（备用） |

---

## 配置文件格式

### 基本语法

```ini
# 这是注释
key = value

# 布尔值
debug = true
verbose = yes
quiet = no

# 数值
timing = 4
max-retries = 3

# 字符串值
output-format = xml
log-file = /var/log/rustnmap.log

# 列表（逗号分隔）
default-ports = 22,80,443
exclude-ports = 25,110,143

# 每键多个值
exclude = 192.168.1.1
exclude = 192.168.1.254
```

### 节

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

## 配置选项

### 扫描选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `scan-type` | string | 默认扫描类型（`syn`、`connect`、`udp` 等） | `syn` |
| `timing` | integer | 时间模板（0-5） | `3` |
| `max-retries` | integer | 最大重试次数 | `10` |
| `host-timeout` | integer | 主机超时（秒） | `0`（无超时） |
| `scan-delay` | integer | 探针间延迟（毫秒） | `0` |
| `min-rate` | integer | 最小每秒数据包数 | `0` |
| `max-rate` | integer | 最大每秒数据包数 | `0` |

**示例：**

```ini
[scan]
scan-type = syn
timing = 4
max-retries = 3
host-timeout = 300
```

---

### 端口选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `default-ports` | list | 默认扫描端口 | `top-1000` |
| `exclude-ports` | list | 排除端口 | （无） |
| `fast-scan` | boolean | 使用快速扫描（前 100） | `false` |
| `all-ports` | boolean | 扫描所有 65535 个端口 | `false` |

**示例：**

```ini
[ports]
default-ports = 22,80,443,8080,8443
exclude-ports = 25,110,143
fast-scan = false
```

---

### 主机发现

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `skip-ping` | boolean | 跳过主机发现 | `false` |
| `ping-type` | string | Ping 类型（`icmp`、`tcp`、`udp`、`arp`） | `auto` |
| `tcp-ping-ports` | list | TCP Ping 端口 | `80,443` |
| `udp-ping-ports` | list | UDP Ping 端口 | `53,161` |

**示例：**

```ini
[discovery]
skip-ping = false
ping-type = tcp
tcp-ping-ports = 22,80,443,3389
udp-ping-ports = 53,161,162
```

---

### 服务检测

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `service-detection` | boolean | 启用服务检测 | `false` |
| `version-intensity` | integer | 版本检测强度（0-9） | `7` |
| `version-light` | boolean | 使用轻量版本检测 | `false` |
| `version-all` | boolean | 使用所有版本探针 | `false` |

**示例：**

```ini
[service]
service-detection = true
version-intensity = 5
version-light = false
```

---

### 操作系统检测

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `os-detection` | boolean | 启用操作系统检测 | `false` |
| `oscan-limit` | boolean | 限制操作系统检测 | `false` |
| `oscan-guess` | boolean | 激进猜测操作系统 | `false` |

**示例：**

```ini
[os]
os-detection = true
oscan-limit = false
oscan-guess = true
```

---

### 输出选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `output-format` | string | 输出格式（`normal`、`xml`、`json`、`grepable`） | `normal` |
| `output-directory` | string | 默认输出目录 | `.` |
| `append-output` | boolean | 追加到输出文件 | `false` |
| `show-reason` | boolean | 显示端口状态原因 | `false` |
| `open-only` | boolean | 仅显示开放端口 | `false` |
| `packet-trace` | boolean | 显示数据包跟踪 | `false` |

**示例：**

```ini
[output]
output-format = xml
output-directory = /var/log/scans
append-output = false
show-reason = true
open-only = false
```

---

### NSE 脚本

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `default-scripts` | boolean | 运行默认脚本 | `false` |
| `script-timeout` | integer | 脚本超时（秒） | `120` |
| `script-args` | string | 默认脚本参数 | （无） |
| `script-categories` | list | 要运行的脚本类别 | （无） |

**示例：**

```ini
[scripts]
default-scripts = true
script-timeout = 180
script-args = http.useragent=Mozilla/5.0
script-categories = safe,discovery
```

---

### 规避选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `fragment-mtu` | integer | 分片 MTU 大小 | （无） |
| `decoys` | list | 诱饵 IP 地址 | （无） |
| `source-ip` | string | 欺骗源 IP | （无） |
| `source-port` | integer | 固定源端口 | （无） |
| `data-length` | integer | 随机数据长度 | `0` |
| `randomize-hosts` | boolean | 随机化目标顺序 | `false` |

**示例：**

```ini
[evasion]
fragment-mtu = 8
source-port = 53
randomize-hosts = true
```

---

### 网络选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `interface` | string | 网络接口 | （自动） |
| `source-ip` | string | 源 IP 地址 | （自动） |
| `dns-servers` | list | 自定义 DNS 服务器 | （系统） |
| `system-dns` | boolean | 使用系统 DNS | `true` |

**示例：**

```ini
[network]
interface = eth0
source-ip = 192.168.1.100
dns-servers = 8.8.8.8,8.8.4.4
system-dns = false
```

---

### 日志选项

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `verbose` | integer | 详细级别（0-3） | `0` |
| `debug` | integer | 调试级别（0-3） | `0` |
| `quiet` | boolean | 安静模式 | `false` |
| `log-file` | string | 日志文件路径 | （无） |

**示例：**

```ini
[logging]
verbose = 1
debug = 0
quiet = false
log-file = /var/log/rustnmap.log
```

---

## 完整配置示例

### 基本配置

```ini
# ~/.rustnmap/rustnmap.conf
# RustNmap 基本配置

[default]
# 扫描选项
timing = 3
max-retries = 3

# 输出选项
verbose = 1
show-reason = true

# 服务检测
service-detection = true
version-intensity = 5
```

### 安全分析师

```ini
# ~/.rustnmap/rustnmap.conf
# 安全分析师配置

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

### 隐秘扫描

```ini
# ~/.rustnmap/rustnmap.conf
# 隐秘扫描配置

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
# 使用特定接口
interface = eth0

[output]
# 最小输出
quiet = true
show-reason = false
```

### 网络管理员

```ini
# /etc/rustnmap/rustnmap.conf
# 系统范围配置

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

## 使用环境变量配置

配置文件可以引用环境变量：

```ini
[default]
# 使用环境变量
output-directory = ${HOME}/scans

# 带默认值
log-file = ${RUSTNMAP_LOG_FILE:-/tmp/rustnmap.log}

[scripts]
# 从环境变量获取脚本目录
script-directory = ${RUSTNMAP_SCRIPTS}
```

---

## 加载配置

### 自动加载

RustNmap 自动从上面列出的位置加载配置。

---

## 配置优先级

选项按以下顺序应用（后面的覆盖前面的）：

1. 内置默认值
2. 系统范围配置（`/etc/rustnmap.conf`）
3. 用户配置（`~/.rustnmap.conf`）
4. 本地配置（`./rustnmap.conf`）
5. 环境变量
6. 命令行选项

---

## 故障排除

### 配置未加载

```bash
# 检查文件权限
ls -la ~/.rustnmap/rustnmap.conf

# 检查文件位置
find ~ -name "rustnmap.conf" 2>/dev/null

# 验证语法
cat ~/.rustnmap/rustnmap.conf | grep -v "^#" | grep -v "^$"
```

### 无效选项

```bash
# 错误：无效选项 'timingg'
# 检查拼写
# timingg -> timing

# 检查可用选项
rustnmap --help
```

---

## 配置模板

### 快速模板

保存这些作为起点：

**fast-scan.conf：**
```ini
[default]
timing = 5
max-retries = 2
fast-scan = true
```

**stealth-scan.conf：**
```ini
[default]
timing = 1
max-retries = 1
scan-delay = 5000
randomize-hosts = true

[evasion]
fragment-mtu = 8
```

**comprehensive-scan.conf：**
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

## 相关文档

- [环境变量](environment.md) - 环境配置
- [选项参考](options.md) - 命令行选项
