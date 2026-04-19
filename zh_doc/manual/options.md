# RustNmap 命令行选项

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的命令行选项。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> RustNmap 所有命令行选项的完整参考

---

## 概述

RustNmap 使用与 Nmap 兼容的命令行界面。选项在大多数情况下可以组合使用。

**基本语法：**
```bash
rustnmap [Scan Type(s)] [Options] {target specification}
```

---

## 目标指定

### `<TARGET>`（必需）

一个或多个要扫描的目标主机。

```bash
# 单个 IP 地址
rustnmap 192.168.1.1

# 多个 IP 地址
rustnmap 192.168.1.1 192.168.1.2 192.168.1.3

# CIDR 表示法
rustnmap 192.168.1.0/24

# IP 范围
rustnmap 192.168.1.1-100
rustnmap 192.168.1-10.1-50

# 主机名
rustnmap example.com

# 混合目标
rustnmap 192.168.1.1 example.com 10.0.0.0/8
```

### `-i <FILE>`，`--input-file <FILE>`

从文件读取目标规格。

```bash
rustnmap -i targets.txt
```

**文件格式：**
- 每行一个目标
- 以 `#` 开头的行是注释
- 空行被忽略

```
# targets.txt
192.168.1.1
192.168.1.0/24
example.com
10.0.0.1-50
```

---

## 扫描类型

### `-sS`

**TCP SYN 扫描**（root 默认）

发送 SYN 数据包而不完成握手的半开扫描。

```bash
sudo rustnmap -sS 192.168.1.1
```

| 特性 | 值 |
|------|-----|
| 需要 root | 是 |
| 隐秘 | 是 |
| 速度 | 快 |
| 最佳用途 | 通用扫描 |

### `-sT`

**TCP Connect 扫描**（非 root 默认）

完整 TCP 三次握手扫描。

```bash
rustnmap -sT 192.168.1.1
```

| 特性 | 值 |
|------|-----|
| 需要 root | 否 |
| 隐秘 | 否 |
| 速度 | 较慢 |
| 最佳用途 | 无 root 权限 |

### `-sU`

**UDP 扫描**

通过发送 UDP 数据包扫描 UDP 端口。

```bash
sudo rustnmap -sU 192.168.1.1
sudo rustnmap -sU -p 53,161,162 192.168.1.1
```

| 特性 | 值 |
|------|-----|
| 需要 root | 是 |
| 速度 | 慢（常超时） |
| 最佳用途 | DNS、SNMP、DHCP 服务 |

### `-sF`

**TCP FIN 扫描**

仅发送带有 FIN 标志的数据包。

```bash
sudo rustnmap -sF 192.168.1.1
```

| 特性 | 值 |
|------|-----|
| 需要 root | 是 |
| 适用于 | UNIX 系统 |
| Windows 响应 | 通常全部关闭 |

### `-sN`

**TCP NULL 扫描**

发送没有设置任何标志的数据包。

```bash
sudo rustnmap -sN 192.168.1.1
```

### `-sX`

**TCP XMAS 扫描**

发送带有 FIN、PSH 和 URG 标志的数据包（像圣诞树一样点亮）。

```bash
sudo rustnmap -sX 192.168.1.1
```

### `-sM`

**TCP Maimon 扫描**

发送带有 FIN/ACK 标志的数据包（以 Uriel Maimon 命名）。

```bash
sudo rustnmap -sM 192.168.1.1
```

---

## 端口指定

### `-p <PORTS>`，`--ports <PORTS>`（`-p-` 扫描所有端口）

指定要扫描的端口。

```bash
# 单个端口
rustnmap -p 22 192.168.1.1

# 多个端口
rustnmap -p 22,80,443 192.168.1.1

# 端口范围
rustnmap -p 1-1000 192.168.1.1
rustnmap -p 1-65535 192.168.1.1

# 特定协议
rustnmap -p T:22,80,U:53 192.168.1.1
```

### `-p-`

扫描所有 65535 个端口（等同于 `-p 1-65535`）。

```bash
sudo rustnmap -p- 192.168.1.1
```

### `-F`，`--fast-scan`

快速扫描（前 100 个端口）。

```bash
rustnmap -F 192.168.1.1
```

### `--top-ports <N>`

扫描前 N 个最常见的端口。

```bash
rustnmap --top-ports 100 192.168.1.1
rustnmap --top-ports 1000 192.168.1.1
```

---

## 主机发现

### `-sn`

**仅 Ping 扫描**

禁用端口扫描，仅进行主机发现。

```bash
sudo rustnmap -sn 192.168.1.0/24
```

### `-Pn`，`--disable-ping`

**跳过主机发现**

将所有主机视为在线（扫描所有目标）。

```bash
sudo rustnmap -Pn 192.168.1.0/24
```

### `-PE`

**ICMP 回显 Ping**

使用 ICMP 回显请求（类型 8）进行发现。

```bash
sudo rustnmap -PE 192.168.1.0/24
```

### `-PP`

**ICMP 时间戳 Ping**

使用 ICMP 时间戳请求（类型 13）进行发现。

```bash
sudo rustnmap -PP 192.168.1.0/24
```

### `-PM`

**ICMP 网络掩码 Ping**

使用 ICMP 网络掩码请求（类型 17）进行发现。

```bash
sudo rustnmap -PM 192.168.1.0/24
```

### `-PS<PORTLIST>`，`--ping-type syn`

**TCP SYN Ping**

发送 SYN 数据包到端口进行发现。

```bash
sudo rustnmap -PS 192.168.1.0/24          # 默认端口 80
sudo rustnmap -PS22,80,443 192.168.1.0/24  # 指定端口
```

### `-PA<PORTLIST>`

**TCP ACK Ping**

发送 ACK 数据包到端口进行发现。

```bash
sudo rustnmap -PA 192.168.1.0/24          # 默认端口 80
sudo rustnmap -PA80,443 192.168.1.0/24    # 指定端口
```

### `-PU<PORTLIST>`

**UDP Ping**

发送 UDP 数据包到端口进行发现。

```bash
sudo rustnmap -PU 192.168.1.0/24          # 默认端口 40125
sudo rustnmap -PU53,161 192.168.1.0/24    # 指定端口
```

---

## 服务检测

### `-sV`，`--service-detection`

**服务版本检测**

探测开放端口以确定服务/版本信息。

```bash
sudo rustnmap -sV 192.168.1.1
sudo rustnmap -sS -sV 192.168.1.1
```

### `--version-intensity <0-9>`

设置版本检测强度（0 = 轻量，9 = 所有探针）。

```bash
sudo rustnmap -sV --version-intensity 0 192.168.1.1   # 轻量
sudo rustnmap -sV --version-intensity 5 192.168.1.1   # 默认
sudo rustnmap -sV --version-intensity 9 192.168.1.1   # 所有探针
```

---

## 操作系统检测

### `-O`

**操作系统检测**

使用 TCP/IP 指纹识别启用操作系统检测。

```bash
sudo rustnmap -O 192.168.1.1
sudo rustnmap -sS -O 192.168.1.1
```

### `--osscan-limit`

将操作系统检测限制在有希望的目标上。

```bash
sudo rustnmap -O --osscan-limit 192.168.1.1
```

### `--osscan-guess`，`--fuzzy`

更激进地猜测操作系统。

```bash
sudo rustnmap -O --osscan-guess 192.168.1.1
```

---

## 时间和性能

### `-T<0-5>`，`--timing <0-5>`

设置时间模板（数值越高越快）。

| 级别 | 名称 | 描述 |
|------|------|------|
| 0 | 偏执 | 探针间 5 分钟 |
| 1 | 鬼祟 | 探针间 15 秒 |
| 2 | 礼貌 | 探针间 0.4 秒 |
| 3 | 正常 | 默认 |
| 4 | 激进 | 更快 |
| 5 | 疯狂 | 非常快 |

```bash
sudo rustnmap -T0 192.168.1.1   # 偏执
sudo rustnmap -T1 192.168.1.1   # 鬼祟
sudo rustnmap -T2 192.168.1.1   # 礼貌
sudo rustnmap -T3 192.168.1.1   # 正常（默认）
sudo rustnmap -T4 192.168.1.1   # 激进
sudo rustnmap -T5 192.168.1.1   # 疯狂
```

### `--min-parallelism <NUM>`

最小并行探针数。

```bash
sudo rustnmap --min-parallelism 100 192.168.1.1
```

### `--max-parallelism <NUM>`

最大并行探针数。

```bash
sudo rustnmap --max-parallelism 500 192.168.1.1
```

### `--scan-delay <MS>`

探针之间的延迟（毫秒）。

```bash
sudo rustnmap --scan-delay 1000 192.168.1.1   # 1 秒延迟
```

### `--host-timeout <MS>`

主机扫描超时（毫秒）。

```bash
sudo rustnmap --host-timeout 30000 192.168.1.0/24   # 30 秒
```

### `--min-rate <NUM>`

最小数据包速率（每秒数据包数）。

```bash
sudo rustnmap --min-rate 1000 192.168.1.1
```

### `--max-rate <NUM>`

最大数据包速率（每秒数据包数）。

```bash
sudo rustnmap --max-rate 100 192.168.1.1
```

---

## 防火墙/IDS 规避

### `-f`，`--fragment-mtu <MTU>`

分片数据包（IP 头后默认 16 字节）。单独 `-f` 使用默认 MTU；`-f16` 或 `--mtu 16` 指定自定义值。

```bash
sudo rustnmap -f 192.168.1.1
sudo rustnmap -f8 192.168.1.1
sudo rustnmap --mtu 16 192.168.1.1
```

### `-D <DECOYS>`，`--decoys <DECOYS>`

使用诱饵扫描隐藏源地址。

```bash
# 特定诱饵
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1

# 随机诱饵
sudo rustnmap -D RND:10 192.168.1.1

# 指定自己位置
sudo rustnmap -D ME,192.168.1.2,192.168.1.3 192.168.1.1
```

### `-S <IP>`，`--spoof-ip <IP>`

欺骗源地址。

```bash
sudo rustnmap -S 192.168.1.100 192.168.1.1
```

**注意：** 需要能够接收响应。

### `-g <PORT>`，`--source-port <PORT>`

使用特定源端口。

```bash
sudo rustnmap -g 53 192.168.1.1     # DNS 端口
sudo rustnmap -g 20 192.168.1.1     # FTP 数据端口
```

### `-e <IFACE>`，`--interface <IFACE>`

使用指定的网络接口。

```bash
sudo rustnmap -e eth0 192.168.1.1
sudo rustnmap -e wlan0 192.168.1.1
```

### `--data-length <LEN>`

向数据包追加随机数据。

```bash
sudo rustnmap --data-length 100 192.168.1.1
```

### `--data-hex <HEX>`

向数据包追加自定义十六进制数据。

```bash
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1   # "Hello"
```

### `--data-string <STRING>`

向数据包追加自定义字符串。

```bash
sudo rustnmap --data-string "Hello" 192.168.1.1
```

---

## 输出选项

### `-oN <FILE>`

普通输出到文件。

```bash
sudo rustnmap -oN results.nmap 192.168.1.1
```

### `-oX <FILE>`

XML 输出到文件。

```bash
sudo rustnmap -oX results.xml 192.168.1.1
```

### `-oJ <FILE>`，`--output-json <FILE>`

JSON 输出到文件。

```bash
sudo rustnmap -oJ results.json 192.168.1.1
```

### `--output-ndjson <FILE>`

NDJSON（换行分隔 JSON）输出到文件。

```bash
sudo rustnmap --output-ndjson results.ndjson 192.168.1.1
```

### `--output-markdown <FILE>`

Markdown 输出到文件。

```bash
sudo rustnmap --output-markdown results.md 192.168.1.1
```

### `-oG <FILE>`

Grepable 输出到文件。

```bash
sudo rustnmap -oG results.gnmap 192.168.1.1
```

### `--output-script-kiddie`

Script Kiddie 输出（仅控制台）。

```bash
sudo rustnmap --output-script-kiddie 192.168.1.1
```

### `-oA <BASENAME>`

输出到所有格式（普通、XML、JSON、Grepable）。

```bash
sudo rustnmap -oA results 192.168.1.1
# 创建：results.nmap, results.xml, results.json, results.gnmap
```

### `--append-output`

追加到输出文件而不是覆盖。

```bash
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

### `-v`，`--verbose`

增加详细程度（可多次使用）。

```bash
sudo rustnmap -v 192.168.1.1      # 详细
sudo rustnmap -vv 192.168.1.1     # 更详细
sudo rustnmap -vvv 192.168.1.1    # 最大详细
```

### `-q`，`--quiet`

安静模式（仅错误）。

```bash
sudo rustnmap -q 192.168.1.1
```

### `-d`，`--debug`

增加调试级别。

```bash
sudo rustnmap -d 192.168.1.1      # 调试
sudo rustnmap -dd 192.168.1.1     # 更多调试
```

### `--reason`

显示端口状态的原因。

```bash
sudo rustnmap --reason 192.168.1.1
# 显示：syn-ack, reset, no-response 等
```

### `--packet-trace`

显示扫描的数据包跟踪。

```bash
sudo rustnmap --packet-trace 192.168.1.1
```

### `--open`

仅显示开放端口。

```bash
sudo rustnmap --open 192.168.1.1
```

### `--iflist`

显示接口列表和路由。

```bash
rustnmap --iflist
```

### `--no-output`

禁止输出。

```bash
sudo rustnmap --no-output 192.168.1.1
```

---

## NSE 脚本

### `-sC`

运行默认脚本（等同于 `--script=default`）。

```bash
sudo rustnmap -sC 192.168.1.1
```

### `--script <SCRIPTS>`，`-sC`

运行指定的脚本。

```bash
# 单个脚本
sudo rustnmap --script http-title 192.168.1.1

# 多个脚本
sudo rustnmap --script http-title,http-headers 192.168.1.1

# 脚本类别
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "intrusive" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "version" 192.168.1.1

# 模式匹配
sudo rustnmap --script "http-*" 192.168.1.1
sudo rustnmap --script "smb-*" 192.168.1.1
```

**类别：**
- `auth` - 认证相关
- `broadcast` - 广播发现
- `brute` - 暴力破解
- `default` - 默认脚本
- `discovery` - 服务发现
- `dos` - 拒绝服务
- `exploit` - 漏洞利用
- `external` - 外部资源
- `fuzzer` - 模糊测试
- `intrusive` - 侵入性脚本
- `malware` - 恶意软件检测
- `safe` - 安全脚本
- `version` - 版本检测
- `vuln` - 漏洞检测

### `--script-args <ARGS>`

向脚本提供参数。

```bash
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# 多个参数
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1
```

### `--script-help <SCRIPT>`

显示特定脚本的帮助。

```bash
# 特定脚本帮助
rustnmap --script-help http-title
```

### `--script-updatedb`

更新脚本数据库。

```bash
rustnmap --script-updatedb
```

---

## 其他

### `--traceroute`

跟踪到目标的跳数路径。

```bash
sudo rustnmap --traceroute 192.168.1.1
```

### `--traceroute-hops <NUM>`

最大 traceroute 跳数。

```bash
sudo rustnmap --traceroute --traceroute-hops 20 192.168.1.1
```

### `--randomize-hosts`

随机化目标主机顺序。

```bash
sudo rustnmap --randomize-hosts 192.168.1.0/24
```

### `--host-group-size <NUM>`

并行扫描的主机组大小。

```bash
sudo rustnmap --host-group-size 10 192.168.1.0/24
```

### `--print-urls`

打印交互的 URL。

```bash
rustnmap --print-urls 192.168.1.1
```

### `-A`

**激进扫描**

启用操作系统检测、版本检测、脚本扫描和 traceroute。

```bash
sudo rustnmap -A 192.168.1.1
# 等同于：-sV -sC -O --traceroute
```

### `-h`，`--help`

显示帮助信息。

```bash
rustnmap --help
```

### `-V`，`--version`

显示版本信息。

```bash
rustnmap --version
```

---

## 选项组合

### 常见组合

```bash
# 综合扫描
sudo rustnmap -A -T4 -oA full-scan 192.168.1.1

# 隐秘 Web 扫描
sudo rustnmap -sS -T2 -p 80,443 --script http-* 192.168.1.1

# 快速网络发现
sudo rustnmap -sn -T4 192.168.1.0/24

# 全端口扫描带服务检测
sudo rustnmap -p- -sV -T4 192.168.1.1

# IDS 规避扫描
sudo rustnmap -sS -T0 -f -D RND:10 192.168.1.1
```

### 冲突选项

以下选项相互冲突：

- 只能选择一种扫描类型：`-sS`、`-sT`、`-sU`、`-sF`、`-sN`、`-sX`、`-sM`
- 只能选择一种端口指定：`-p`、`-F`、`--top-ports`、`-p-`
- 只能选择一组输出格式：`-oN`、`-oX`、`-oJ`、`-oG`、`-oA`

---

## 汇总表

### 扫描类型汇总

| 标志 | 名称 | Root | 描述 |
|------|------|------|------|
| `-sS` | SYN | 是 | 半开扫描 |
| `-sT` | Connect | 否 | 完整握手 |
| `-sU` | UDP | 是 | UDP 扫描 |
| `-sF` | FIN | 是 | 仅 FIN 标志 |
| `-sN` | NULL | 是 | 无标志 |
| `-sX` | XMAS | 是 | FIN/PSH/URG |
| `-sA` | ACK | 是 | ACK 标志 |
| `-sW` | Window | 是 | Window 扫描 |
| `-sM` | Maimon | 是 | FIN/ACK |
| `-b` | FTP Bounce | 否 | FTP 代理扫描 |

### 输出格式汇总

| 标志 | 扩展名 | 描述 |
|------|--------|------|
| `-oN` | .nmap | 人类可读 |
| `-oX` | .xml | 机器可解析 |
| `-oJ` | .json | 结构化 JSON |
| `-oG` | .gnmap | Grepable |
| `--output-script-kiddie` | （控制台） | Script Kiddie |
| `--output-ndjson` | .ndjson | 换行分隔 JSON |
| `--output-markdown` | .md | Markdown 格式 |
| `-oA` | 多个 | 所有格式 |

### 时间模板汇总

| 标志 | 名称 | 速度 | 用途 |
|------|------|------|------|
| `-T0` | 偏执 | 非常慢 | IDS 规避 |
| `-T1` | 鬼祟 | 慢 | IDS 规避 |
| `-T2` | 礼貌 | 中等 | 慢速网络 |
| `-T3` | 正常 | 默认 | 通用 |
| `-T4` | 激进 | 快 | 快速网络 |
| `-T5` | 疯狂 | 非常快 | 本地网络 |
