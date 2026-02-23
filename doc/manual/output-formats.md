# RustNmap Output Formats / 输出格式

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的输出格式。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> **Complete documentation for all output formats** / 所有输出格式的完整文档

---

## Overview / 概述

RustNmap supports 5 output formats, each designed for different use cases:

RustNmap 支持 5 种输出格式，每种都为不同的用例设计：

| Format | Extension | Flag | Use Case |
|--------|-----------|------|----------|
| Normal | `.nmap` | `-oN` | Human-readable output / 人类可读输出 |
| XML | `.xml` | `-oX` | Machine parsing / 机器解析 |
| JSON | `.json` | `-oJ` | Structured data / 结构化数据 |
| Grepable | `.gnmap` | `-oG` | Grep/AWK processing / Grep/AWK 处理 |
| Script Kiddie | `.txt` | `-oS` | Fun format / 趣味格式 |

---

## Normal Output / 普通输出

### Flag / 标志

`-oN <FILE>`, `--output-normal <FILE>`

### Description / 描述

Normal output is the default console output format. It provides human-readable scan results with formatting that is easy to read and interpret.

普通输出是默认的控制台输出格式。它提供人类可读的扫描结果，格式易于阅读和解释。

### Example Output / 示例输出

```
# RustNmap 1.0.0 scan initiated Mon Feb 16 10:30:00 2026
# rustnmap -sS 192.168.1.1

RustNmap scan report for 192.168.1.1
Host is up (0.0005s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

RustNmap done: 1 IP address (1 host up) scanned in 2.34 seconds
```

### With Service Detection / 带服务检测

```
# RustNmap 1.0.0 scan initiated Mon Feb 16 10:30:00 2026
# rustnmap -sS -sV 192.168.1.1

RustNmap scan report for 192.168.1.1
Host is up (0.0005s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp  open  http    Apache httpd 2.4.41
443/tcp open  https   Apache httpd 2.4.41

RustNmap done: 1 IP address (1 host up) scanned in 8.76 seconds
```

### With OS Detection / 带操作系统检测

```
# RustNmap 1.0.0 scan initiated Mon Feb 16 10:30:00 2026
# rustnmap -sS -O 192.168.1.1

RustNmap scan report for 192.168.1.1
Host is up (0.0005s latency).
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http

MAC Address: 00:11:22:33:44:55 (Cisco Systems)
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.4 - 5.10
Network Distance: 1 hop

RustNmap done: 1 IP address (1 host up) scanned in 12.45 seconds
```

### Usage Examples / 用法示例

```bash
# Save normal output / 保存普通输出
sudo rustnmap -sS -oN scan_results.nmap 192.168.1.1

# Append to existing file / 追加到现有文件
sudo rustnmap -sS -oN scan_results.nmap --append-output 192.168.1.2

# Multiple hosts / 多个主机
sudo rustnmap -sS -oN network_scan.nmap 192.168.1.0/24
```

### Format Characteristics / 格式特性

| Feature | Description |
|---------|-------------|
| Human readable | Yes |
| Machine parsable | Difficult |
| File size | Medium |
| Verbosity levels | Supported |
| Color output | Console only |

---

## XML Output / XML 输出

### Flag / 标志

`-oX <FILE>`, `--output-xml <FILE>`

### Description / 描述

XML output provides structured, machine-parseable results. It follows the Nmap XML output format specification and is ideal for importing into other tools or automated processing.

XML 输出提供结构化、机器可解析的结果。它遵循 Nmap XML 输出格式规范，非常适合导入到其他工具或自动化处理。

### XML Schema / XML 模式

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="rustnmap" version="1.0.0" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>

  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco"/>

    <hostnames>
      <hostname name="router.example.com" type="PTR"/>
    </hostnames>

    <ports>
      <extraports state="closed" count="65532">
        <extrareasons reason="reset" count="65532"/>
      </extraports>

      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"
                 extrainfo="Ubuntu 4ubuntu0.5" method="probed"/>
      </port>

      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>

    <os>
      <osmatch name="Linux 5.4" accuracy="95" line="12345">
        </cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
      </osmatch>
    </os>
  </host>

  <runstats>
    <finished time="1739706600" timestr="Mon Feb 16 10:30:00 2026"
             elapsed="12.45"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

### Usage Examples / 用法示例

```bash
# Save XML output / 保存 XML 输出
sudo rustnmap -sS -sV -oX results.xml 192.168.1.1

# Process with Python / 使用 Python 处理
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('results.xml')
root = tree.getroot()
for host in root.findall('host'):
    addr = host.find('address').get('addr')
    print(f'Host: {addr}')
    for port in host.findall('.//port'):
        portid = port.get('portid')
        state = port.find('state').get('state')
        print(f'  Port {portid}: {state}')
"
```

### XML Elements Reference / XML 元素参考

| Element | Description | 描述 |
|---------|-------------|------|
| `nmaprun` | Root element with scan metadata | 根元素，包含扫描元数据 |
| `scaninfo` | Scan type and protocol information | 扫描类型和协议信息 |
| `host` | Individual host results | 单个主机结果 |
| `status` | Host state (up/down) | 主机状态 |
| `address` | IP/MAC address | IP/MAC 地址 |
| `hostnames` | Discovered hostnames | 发现的主机名 |
| `ports` | Port scan results container | 端口扫描结果容器 |
| `port` | Individual port information | 单个端口信息 |
| `state` | Port state (open/closed/filtered) | 端口状态 |
| `service` | Service detection results | 服务检测结果 |
| `os` | OS detection results | 操作系统检测结果 |
| `runstats` | Scan statistics | 扫描统计 |

### Format Characteristics / 格式特性

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Excellent |
| File size | Large |
| Schema defined | Yes |
| XPath support | Yes |

---

## JSON Output / JSON 输出

### Flag / 标志

`-oJ <FILE>`, `--output-json <FILE>`

### Description / 描述

JSON output provides structured data that is easy to parse with modern programming languages. It's more compact than XML while maintaining full scan information.

JSON 输出提供结构化数据，易于使用现代编程语言解析。它比 XML 更紧凑，同时保持完整的扫描信息。

### JSON Schema / JSON 模式

```json
{
  "scanner": "rustnmap",
  "version": "1.0.0",
  "start_time": "2026-02-16T10:30:00Z",
  "scan_info": {
    "type": "syn",
    "protocol": "tcp",
    "services": "22,80,443"
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "status": "up",
      "reason": "syn-ack",
      "mac": "00:11:22:33:44:55",
      "vendor": "Cisco Systems",
      "hostname": "router.example.com",
      "latency_ms": 0.5,
      "ports": [
        {
          "number": 22,
          "protocol": "tcp",
          "state": "open",
          "reason": "syn-ack",
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "extrainfo": "Ubuntu 4ubuntu0.5"
          }
        },
        {
          "number": 80,
          "protocol": "tcp",
          "state": "open",
          "reason": "syn-ack",
          "service": {
            "name": "http",
            "product": "Apache httpd",
            "version": "2.4.41"
          }
        }
      ],
      "os_matches": [
        {
          "name": "Linux 5.4",
          "accuracy": 95,
          "cpe": ["cpe:/o:linux:linux_kernel:5.4"]
        }
      ]
    }
  ],
  "statistics": {
    "total_hosts": 1,
    "hosts_up": 1,
    "hosts_down": 0,
    "elapsed_seconds": 12.45
  }
}
```

### Usage Examples / 用法示例

```bash
# Save JSON output / 保存 JSON 输出
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1

# Pretty print JSON / 美化打印 JSON
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1
jq '.' results.json

# Process with Python / 使用 Python 处理
python3 -c "
import json
with open('results.json') as f:
    data = json.load(f)
    for host in data['hosts']:
        print(f\"Host: {host['ip']}\")
        for port in host['ports']:
            print(f\"  {port['number']}/{port['protocol']}: {port['state']}\")
"

# Process with jq / 使用 jq 处理
jq '.hosts[].ports[] | select(.state == "open") | .number' results.json
jq '.hosts[] | {ip: .ip, open_ports: [.ports[] | select(.state == "open") | .number]}' results.json
```

### JSON Schema Reference / JSON 模式参考

| Field | Type | Description |
|-------|------|-------------|
| `scanner` | string | Scanner name |
| `version` | string | Scanner version |
| `start_time` | string | ISO 8601 timestamp |
| `scan_info` | object | Scan configuration |
| `hosts` | array | Host results array |
| `hosts[].ip` | string | IP address |
| `hosts[].status` | string | Host status |
| `hosts[].ports` | array | Port results |
| `hosts[].os_matches` | array | OS detection results |
| `statistics` | object | Scan statistics |

### Format Characteristics / 格式特性

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Excellent |
| File size | Medium |
| Native support | All modern languages |
| Query support | jq, JSONPath |

---

## Grepable Output / Grepable 输出

### Flag / 标志

`-oG <FILE>`, `--output-grepable <FILE>`

### Description / 描述

Grepable format provides a single-line format for each host that is easy to parse with grep, awk, sed, and other Unix command-line tools. It's designed for quick filtering and extraction.

Grepable 格式为每个主机提供单行格式，易于使用 grep、awk、sed 和其他 Unix 命令行工具解析。它专为快速过滤和提取而设计。

### Format Specification / 格式规范

```
Host: <IP> (<hostname>)	Status: <status>
Host: <IP> (<hostname>)	Ports: <port_list>
```

### Example Output / 示例输出

```
# RustNmap 1.0.0 Grepable Output
# Scan initiated: Mon Feb 16 10:30:00 2026

Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache httpd 2.4.41/

Host: 192.168.1.2 (server.example.com)	Status: Up
Host: 192.168.1.2 (server.example.com)	Ports: 443/open/tcp//https///

Host: 192.168.1.3 ()	Status: Down
```

### Port Format / 端口格式

```
<port>/<state>/<protocol>//<service>//<version>/
```

Examples / 示例:
- `22/open/tcp//ssh//OpenSSH 8.2p1/`
- `80/open/tcp//http//Apache httpd 2.4.41/`
- `443/filtered/tcp//https///`

### Usage Examples / 用法示例

```bash
# Save grepable output / 保存 Grepable 输出
sudo rustnmap -sS -sV -oG results.gnmap 192.168.1.0/24

# Find all open SSH ports / 查找所有开放的 SSH 端口
grep -i "ssh" results.gnmap

# Extract IPs with open port 80 / 提取开放 80 端口的 IP
grep "80/open" results.gnmap | awk '{print $2}'

# Find all open ports on specific host / 查找特定主机的所有开放端口
grep "192.168.1.1" results.gnmap | grep "Ports:" | cut -f3

# Count hosts that are up / 统计在线主机数
grep "Status: Up" results.gnmap | wc -l

# Find all web servers (port 80 or 443) / 查找所有 Web 服务器
awk '/Ports:.*(80|443)\/open/' results.gnmap

# Extract IP list / 提取 IP 列表
awk '/Status: Up/{print $2}' results.gnmap | sed 's/()//'
```

### awk Scripting / awk 脚本

```bash
# Comprehensive parsing with awk / 使用 awk 综合解析
awk -F'\t' '
/Host:/ {
    host = $2
    gsub(/[()]/, "", host)
}
/Ports:/ {
    ports = $2
    gsub(/Ports: /, "", ports)
    split(ports, portlist, ", ")
    for (i in portlist) {
        split(portlist[i], p, "//")
        split(p[1], info, "/")
        print host, info[1], info[2], p[3]
    }
}
' results.gnmap
```

### Format Characteristics / 格式特性

| Feature | Description |
|---------|-------------|
| Human readable | Low |
| Machine parsable | Good (text tools) |
| File size | Small |
| Line-oriented | Yes |
| Unix-friendly | Excellent |

---

## Script Kiddie Output / Script Kiddie 输出

### Flag / 标志

`-oS <FILE>`, `--output-script-kiddie`

### Description / 描述

Script Kiddie format is a fun, "l33t speak" style output format. It replaces letters with numbers and uses irregular capitalization for entertainment value.

Script Kiddie 格式是一种有趣的"l33t speak"风格输出格式。它将字母替换为数字并使用不规则的大小写，具有娱乐价值。

### Example Output / 示例输出

```
RuStNmAp 1.0.0 ScAn InItIaTeD

== HoSt: 192.168.1.1 ==
  [+] PoRt 22 iS oPeN!
  [+] PoRt 80 iS oPeN!
  [+] PoRt 443 iS oPeN!

== HoSt: 192.168.1.2 ==
  [+] PoRt 3389 iS oPeN!

ScAn CoMpLeTe! 2 HoStS fOuNd
```

### Usage Examples / 用法示例

```bash
# Save script kiddie output / 保存 Script Kiddie 输出
sudo rustnmap -sS -oS results.txt 192.168.1.1

# Console output only / 仅控制台输出
sudo rustnmap -sS --output-script-kiddie 192.168.1.1
```

### Format Characteristics / 格式特性

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Poor |
| File size | Small |
| Purpose | Entertainment |
| Professional use | Not recommended |

---

## All Formats / 所有格式

### Flag / 标志

`-oA <BASENAME>`, `--output-all <BASENAME>`

### Description / 描述

Outputs to all four major formats at once using the specified basename.

使用指定的基本名称同时输出到所有四种主要格式。

### Generated Files / 生成文件

```bash
sudo rustnmap -sS -sV -oA scan_results 192.168.1.1

# Creates: / 创建：
# - scan_results.nmap  (Normal / 普通)
# - scan_results.xml   (XML / XML)
# - scan_results.json  (JSON / JSON)
# - scan_results.gnmap (Grepable / Grepable)
```

### Usage Examples / 用法示例

```bash
# Comprehensive scan with all outputs / 全面扫描带所有输出
sudo rustnmap -A -T4 -oA comprehensive-scan 192.168.1.0/24

# Daily scan automation / 每日扫描自动化
date_str=$(date +%Y-%m-%d)
sudo rustnmap -sS -oA "daily-scan-${date_str}" 192.168.1.0/24
```

---

## Output Options / 输出选项

### Append Output / 追加输出

```bash
# Append to existing files / 追加到现有文件
sudo rustnmap -sS -oN results.nmap --append-output 192.168.1.2
```

### Suppress Output / 禁止输出

```bash
# Quiet mode / 安静模式
sudo rustnmap -sS -q 192.168.1.1

# No output / 无输出
sudo rustnmap -sS --no-output 192.168.1.1
```

### Verbosity Levels / 详细级别

```bash
# Verbose / 详细
sudo rustnmap -sS -v 192.168.1.1

# More verbose / 更详细
sudo rustnmap -sS -vv 192.168.1.1

# Debug / 调试
sudo rustnmap -sS -d 192.168.1.1

# Packet trace / 数据包跟踪
sudo rustnmap -sS --packet-trace 192.168.1.1
```

### Show Reasons / 显示原因

```bash
# Show reason for port state / 显示端口状态原因
sudo rustnmap -sS --reason 192.168.1.1
```

Output / 输出:
```
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp closed https   reset
```

---

## Format Comparison / 格式对比

| Feature | Normal | XML | JSON | Grepable | Kiddie |
|---------|--------|-----|------|----------|--------|
| Human readable | Excellent | Poor | Good | Poor | Moderate |
| Machine parsing | Difficult | Excellent | Excellent | Good | Poor |
| File size | Medium | Large | Medium | Small | Small |
| Schema defined | No | Yes | Yes | Yes | No |
| Use case | Review | Import | API | Filter | Fun |

---

## Best Practices / 最佳实践

### Recommended Format Selection / 推荐格式选择

```bash
# For manual review / 手动审查
sudo rustnmap -sS -oN results.nmap 192.168.1.1

# For automation / 自动化
sudo rustnmap -sS -oJ results.json 192.168.1.1

# For integration with other tools / 与其他工具集成
sudo rustnmap -sS -oX results.xml 192.168.1.1

# For command-line processing / 命令行处理
sudo rustnmap -sS -oG results.gnmap 192.168.1.1

# For comprehensive documentation / 全面文档
sudo rustnmap -A -oA full-report 192.168.1.1
```

### Automation Examples / 自动化示例

```bash
# Daily security scan / 每日安全扫描
#!/bin/bash
DATE=$(date +%Y%m%d)
sudo rustnmap -sS -sV -T4 -oX "scan-${DATE}.xml" 192.168.1.0/24

# Parse and alert on new open ports / 解析并告警新开放端口
python3 parse_and_alert.py "scan-${DATE}.xml"

# Weekly comprehensive report / 每周综合报告
sudo rustnmap -A -T4 -oA "weekly-${DATE}" 10.0.0.0/24
```

---

## Troubleshooting Output / 输出故障排除

### No Output / 无输出

```bash
# Check if quiet mode is enabled / 检查是否启用了安静模式
rustnmap 192.168.1.1  # Should show output
rustnmap -q 192.168.1.1  # Suppresses most output
```

### File Not Created / 文件未创建

```bash
# Check directory permissions / 检查目录权限
ls -ld $(dirname output.nmap)

# Use absolute path / 使用绝对路径
sudo rustnmap -sS -oN /tmp/results.nmap 192.168.1.1
```

### Corrupted Output / 输出损坏

```bash
# Validate XML / 验证 XML
xmllint --noout results.xml

# Validate JSON / 验证 JSON
jq '.' results.json > /dev/null
```
