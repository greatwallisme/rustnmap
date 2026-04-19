# RustNmap 环境变量

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的环境变量。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> RustNmap 环境变量参考

---

## 概述

RustNmap 支持多个环境变量来控制其行为的各种方面。这些可以在 shell 或配置文件中设置。

---

## 环境变量参考

| 变量 | 描述 | 默认值 |
|------|------|--------|
| `RUSTNMAP_HOME` | RustNmap 主目录 | `~/.rustnmap` |
| `RUSTNMAP_SCRIPTS` | 脚本目录 | `/usr/share/rustnmap/scripts` |
| `RUSTNMAP_DATA` | 数据目录 | `/usr/share/rustnmap` |
| `RUSTNMAP_OUTPUT` | 默认输出目录 | 当前目录 |
| `RUSTNMAP_OPTIONS` | 默认命令行选项 | 无 |
| `RUSTNMAP_TARGETS` | 默认目标列表 | 无 |

---

## 路径变量

### RUSTNMAP_HOME

**描述**

设置 RustNmap 主目录用于用户特定文件。

**默认值**

```
~/.rustnmap
```

**用法**

```bash
# 设置自定义主目录
export RUSTNMAP_HOME=/opt/rustnmap

# 文件存储在：
# $RUSTNMAP_HOME/scripts/     # 用户脚本
# $RUSTNMAP_HOME/data/        # 用户数据
# $RUSTNMAP_HOME/config/      # 用户配置
```

---

### RUSTNMAP_SCRIPTS

**描述**

设置包含 NSE 脚本的目录。

**默认值**

```
/usr/share/rustnmap/scripts
```

**用法**

```bash
# 使用自定义脚本目录
export RUSTNMAP_SCRIPTS=/path/to/custom/scripts

# 使用自定义脚本运行
rustnmap --script my-script 192.168.1.1
```

---

### RUSTNMAP_DATA

**描述**

设置指纹数据库和其他数据文件的数据目录。

**默认值**

```
/usr/share/rustnmap
```

**内容**

```
$RUSTNMAP_DATA/
├── nmap-service-probes      # 服务检测探针
├── nmap-os-db               # 操作系统指纹
├── nmap-mac-prefixes        # MAC 厂商数据库
└── scripts/                 # NSE 脚本
```

**用法**

```bash
# 使用自定义数据目录
export RUSTNMAP_DATA=/var/lib/rustnmap

# 在自定义位置更新数据库
rustnmap --script-updatedb
```

---

## 默认选项

### RUSTNMAP_OPTIONS

**描述**

设置自动添加到每次扫描的默认命令行选项。

**默认值**

```
（无）
```

**用法**

```bash
# 始终使用详细输出
export RUSTNMAP_OPTIONS="-v"

# 始终使用特定时间模板
export RUSTNMAP_OPTIONS="-T4 --reason"

# 多个选项
export RUSTNMAP_OPTIONS="-v -T4 --open"

# 现在 'rustnmap 192.168.1.1' 等同于：
# rustnmap -v -T4 --open 192.168.1.1
```

**注意**

命令行上指定的选项会覆盖环境变量选项。

---

### RUSTNMAP_TARGETS

**描述**

如果命令行上未指定，则设置默认目标主机。

**默认值**

```
（无）
```

**用法**

```bash
# 设置默认扫描网络
export RUSTNMAP_TARGETS="192.168.1.0/24"

# 运行扫描而不指定目标
rustnmap -sS  # 扫描 192.168.1.0/24

# 用命令行目标覆盖
rustnmap -sS 10.0.0.1  # 扫描 10.0.0.1，而非默认值
```

---

## 网络配置

### RUSTNMAP_INTERFACE

**描述**

设置扫描使用的默认网络接口。

**默认值**

```
（自动检测）
```

**用法**

```bash
# 始终使用 eth0
export RUSTNMAP_INTERFACE=eth0

# 每次扫描覆盖
rustnmap -e wlan0 192.168.1.1
```

---

### RUSTNMAP_SOURCE_IP

**描述**

设置数据包的默认源 IP 地址。

**默认值**

```
（自动检测）
```

**用法**

```bash
# 设置默认源 IP
export RUSTNMAP_SOURCE_IP=192.168.1.100

# 每次扫描覆盖
rustnmap -S 10.0.0.100 192.168.1.1
```

---

## 输出配置

### RUSTNMAP_OUTPUT_DIR

**描述**

设置输出文件的默认目录。

**默认值**

```
（当前工作目录）
```

**用法**

```bash
# 设置默认输出目录
export RUSTNMAP_OUTPUT_DIR=/var/log/scans

# 结果保存到：
# /var/log/scans/scan_results.nmap
rustnmap -oN scan_results.nmap 192.168.1.1
```

---

### RUSTNMAP_OUTPUT_FORMAT

**描述**

设置默认输出格式。

**默认值**

```
normal
```

**值**

- `normal` - 人类可读文本
- `xml` - XML 格式
- `json` - JSON 格式
- `grepable` - Grepable 格式

**用法**

```bash
# 始终输出 XML
export RUSTNMAP_OUTPUT_FORMAT=xml

# 每次扫描覆盖
rustnmap -oN normal.txt 192.168.1.1
```

---

## 脚本配置

### RUSTNMAP_SCRIPT_ARGS

**描述**

设置 NSE 脚本的默认参数。

**默认值**

```
（无）
```

**用法**

```bash
# 为 HTTP 脚本设置默认 User-Agent
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"

# 多个默认参数
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla,smb.domain=WORKGROUP"
```

---

### RUSTNMAP_SCRIPT_TIMEOUT

**描述**

设置脚本执行的默认超时（以秒为单位）。

**默认值**

```
120
```

**用法**

```bash
# 增加默认脚本超时
export RUSTNMAP_SCRIPT_TIMEOUT=300

# 减少以加快扫描速度
export RUSTNMAP_SCRIPT_TIMEOUT=60
```

---

## 性能配置

### RUSTNMAP_TIMING

**描述**

设置默认时间模板。

**默认值**

```
3（正常）
```

**值**

| 值 | 模板 | 描述 |
|----|------|------|
| `0` | 偏执 | 非常慢，IDS 规避 |
| `1` | 鬼祟 | 慢，IDS 规避 |
| `2` | 礼貌 | 中等速度 |
| `3` | 正常 | 默认 |
| `4` | 激进 | 快 |
| `5` | 疯狂 | 非常快 |

**用法**

```bash
# 始终使用激进时间
export RUSTNMAP_TIMING=4

# 每次扫描覆盖
rustnmap -T2 192.168.1.1
```

---

### RUSTNMAP_MIN_RATE

**描述**

设置最小数据包速率（每秒数据包数）。

**默认值**

```
（自动）
```

**用法**

```bash
# 确保最小速率
export RUSTNMAP_MIN_RATE=100

rustnmap 192.168.1.1  # 使用 --min-rate 100
```

---

### RUSTNMAP_MAX_RETRIES

**描述**

设置端口扫描探针重传的最大次数。

**默认值**

```
10
```

**用法**

```bash
# 减少重试以加快扫描速度
export RUSTNMAP_MAX_RETRIES=2

# 为不可靠网络增加
export RUSTNMAP_MAX_RETRIES=20
```

---

## 安全配置

### RUSTNMAP_NO_PING

**描述**

默认禁用主机发现。

**默认值**

```
false
```

**用法**

```bash
# 始终跳过 Ping 扫描
export RUSTNMAP_NO_PING=1

# 等同于始终使用 -Pn
rustnmap 192.168.1.1  # 不经 Ping 直接扫描所有目标
```

---

### RUSTNMAP_RANDOMIZE

**描述**

默认随机化目标顺序。

**默认值**

```
false
```

**用法**

```bash
# 始终随机化目标
export RUSTNMAP_RANDOMIZE=1

# 等同于始终使用 --randomize-hosts
rustnmap 192.168.1.0/24  # 随机顺序
```

---

## 日志配置

### RUSTNMAP_LOG_LEVEL

**描述**

设置默认日志级别。

**默认值**

```
warn
```

**值**

- `error` - 仅错误消息
- `warn` - 警告和错误
- `info` - 信息性消息
- `debug` - 调试消息
- `trace` - 所有消息

**用法**

```bash
# 启用调试日志
export RUSTNMAP_LOG_LEVEL=debug

# 最小日志
export RUSTNMAP_LOG_LEVEL=error
```

---

### RUSTNMAP_LOG_FILE

**描述**

设置日志文件路径。

**默认值**

```
（stderr）
```

**用法**

```bash
# 记录到文件
export RUSTNMAP_LOG_FILE=/var/log/rustnmap.log

# 禁用文件日志
unset RUSTNMAP_LOG_FILE
```

---

## 设置环境变量

### 临时（当前会话）

```bash
# 仅为当前会话设置
export RUSTNMAP_OPTIONS="-v -T4"

# 取消设置
unset RUSTNMAP_OPTIONS
```

### 永久（Bash）

添加到 `~/.bashrc` 或 `~/.bash_profile`：

```bash
# RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=180
```

然后重新加载：

```bash
source ~/.bashrc
```

### 永久（Zsh）

添加到 `~/.zshrc`：

```bash
# RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
```

### 系统范围

添加到 `/etc/environment` 或 `/etc/profile.d/rustnmap.sh`：

```bash
# /etc/profile.d/rustnmap.sh
export RUSTNMAP_DATA="/usr/share/rustnmap"
export RUSTNMAP_SCRIPTS="/usr/share/rustnmap/scripts"
```

---

## 查看环境变量

### 列出所有 RustNmap 变量

```bash
# 显示所有 RustNmap 环境变量
env | grep RUSTNMAP

# 显示值
env | grep RUSTNMAP | sort
```

### 检查特定变量

```bash
# 检查特定变量
echo $RUSTNMAP_OPTIONS
echo $RUSTNMAP_HOME
echo $RUSTNMAP_TIMING
```

### 在脚本中

```bash
#!/bin/bash

# 检查变量是否设置
if [ -n "$RUSTNMAP_OPTIONS" ]; then
    echo "默认选项: $RUSTNMAP_OPTIONS"
else
    echo "未设置默认选项"
fi

# 使用默认回退
OPTIONS="${RUSTNMAP_OPTIONS:--T3}"
rustnmap $OPTIONS 192.168.1.1
```

---

## 完整配置示例

### 扫描工作站

```bash
# ~/.bashrc

# RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason --open"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=120
export RUSTNMAP_LOG_LEVEL=info
export RUSTNMAP_OUTPUT_DIR="$HOME/scans"

# 如果目录不存在则创建
mkdir -p "$RUSTNMAP_HOME/scripts"
mkdir -p "$RUSTNMAP_OUTPUT_DIR"
```

### 安全分析师

```bash
# ~/.bashrc

# 安全工作 RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T3 --reason --traceroute"
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"
export RUSTNMAP_OUTPUT_DIR="$HOME/security-audits"
export RUSTNMAP_LOG_LEVEL=debug
export RUSTNMAP_LOG_FILE="$HOME/logs/rustnmap.log"
```

### 隐秘扫描

```bash
# ~/.bashrc

# 隐秘扫描 RustNmap 配置
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T1 --randomize-hosts"
export RUSTNMAP_TIMING=1
export RUSTNMAP_MIN_RATE=1
export RUSTNMAP_MAX_RETRIES=1
export RUSTNMAP_RANDOMIZE=1
```

---

## 环境变量优先级

选项按以下顺序应用（后面的覆盖前面的）：

1. 默认值
2. 环境变量
3. 配置文件设置
4. 命令行选项

示例：

```bash
# 环境设置默认时间
export RUSTNMAP_TIMING=3

# 配置文件覆盖为激进
# （在 rustnmap.conf 中：timing = 4）

# 命令行覆盖所有
rustnmap -T5 192.168.1.1  # 使用 -T5（疯狂）
```

---

## 相关文档

- [配置文件](configuration.md) - 配置文件选项
- [选项参考](options.md) - 命令行选项
