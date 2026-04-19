# RustNmap 输出格式

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的输出格式。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> 所有输出格式的完整文档

---

## 概述

RustNmap 支持 5 种输出格式，每种都为不同的用例设计：

| 格式 | 扩展名 | 标志 | 用途 |
|------|--------|------|------|
| Normal | `.nmap` | `-oN` | 人类可读输出 |
| XML | `.xml` | `-oX` | 机器解析 |
| JSON | `.json` | `-oJ` | 结构化数据 |
| NDJSON | `.ndjson` | `--output-ndjson` | 流式 JSON |
| Markdown | `.md` | `--output-markdown` | 文档 |
| Grepable | `.gnmap` | `-oG` | Grep/AWK 处理 |
| Script Kiddie | （控制台） | `--output-script-kiddie` | 趣味格式 |

---

## 普通输出

### 标志

`-oN <FILE>`，`--output-normal <FILE>`

### 描述

普通输出是默认的控制台输出格式。它提供人类可读的扫描结果，格式易于阅读和解释。

### 示例输出

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

### 带服务检测

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

### 带操作系统检测

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

### 用法示例

```bash
# 保存普通输出
sudo rustnmap -sS -oN scan_results.nmap 192.168.1.1

# 追加到现有文件
sudo rustnmap -sS -oN scan_results.nmap --append-output 192.168.1.2

# 多个主机
sudo rustnmap -sS -oN network_scan.nmap 192.168.1.0/24
```

### 格式特性

| 特性 | 描述 |
|------|------|
| 人类可读 | 是 |
| 机器可解析 | 困难 |
| 文件大小 | 中等 |
| 详细级别 | 支持 |
| 彩色输出 | 仅控制台 |

---

## XML 输出

### 标志

`-oX <FILE>`，`--output-xml <FILE>`

### 描述

XML 输出提供结构化、机器可解析的结果。它遵循 Nmap XML 输出格式规范，非常适合导入到其他工具或自动化处理。

### XML 模式

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

### 用法示例

```bash
# 保存 XML 输出
sudo rustnmap -sS -sV -oX results.xml 192.168.1.1

# 使用 Python 处理
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

### XML 元素参考

| 元素 | 描述 |
|------|------|
| `nmaprun` | 根元素，包含扫描元数据 |
| `scaninfo` | 扫描类型和协议信息 |
| `host` | 单个主机结果 |
| `status` | 主机状态 |
| `address` | IP/MAC 地址 |
| `hostnames` | 发现的主机名 |
| `ports` | 端口扫描结果容器 |
| `port` | 单个端口信息 |
| `state` | 端口状态（open/closed/filtered） |
| `service` | 服务检测结果 |
| `os` | 操作系统检测结果 |
| `runstats` | 扫描统计 |

### 格式特性

| 特性 | 描述 |
|------|------|
| 人类可读 | 中等 |
| 机器可解析 | 优秀 |
| 文件大小 | 大 |
| 模式定义 | 是 |
| XPath 支持 | 是 |

---

## JSON 输出

### 标志

`-oJ <FILE>`，`--output-json <FILE>`

### 描述

JSON 输出提供结构化数据，易于使用现代编程语言解析。它比 XML 更紧凑，同时保持完整的扫描信息。

### JSON 模式

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

### 用法示例

```bash
# 保存 JSON 输出
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1

# 美化打印 JSON
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1
jq '.' results.json

# 使用 Python 处理
python3 -c "
import json
with open('results.json') as f:
    data = json.load(f)
    for host in data['hosts']:
        print(f\"Host: {host['ip']}\")
        for port in host['ports']:
            print(f\"  {port['number']}/{port['protocol']}: {port['state']}\")
"

# 使用 jq 处理
jq '.hosts[].ports[] | select(.state == "open") | .number' results.json
jq '.hosts[] | {ip: .ip, open_ports: [.ports[] | select(.state == "open") | .number]}' results.json
```

### JSON 模式参考

| 字段 | 类型 | 描述 |
|------|------|------|
| `scanner` | string | 扫描器名称 |
| `version` | string | 扫描器版本 |
| `start_time` | string | ISO 8601 时间戳 |
| `scan_info` | object | 扫描配置 |
| `hosts` | array | 主机结果数组 |
| `hosts[].ip` | string | IP 地址 |
| `hosts[].status` | string | 主机状态 |
| `hosts[].ports` | array | 端口结果 |
| `hosts[].os_matches` | array | 操作系统检测结果 |
| `statistics` | object | 扫描统计 |

### 格式特性

| 特性 | 描述 |
|------|------|
| 人类可读 | 中等 |
| 机器可解析 | 优秀 |
| 文件大小 | 中等 |
| 原生支持 | 所有现代语言 |
| 查询支持 | jq、JSONPath |

---

## Grepable 输出

### 标志

`-oG <FILE>`，`--output-grepable <FILE>`

### 描述

Grepable 格式为每个主机提供单行格式，易于使用 grep、awk、sed 和其他 Unix 命令行工具解析。它专为快速过滤和提取而设计。

### 格式规范

```
Host: <IP> (<hostname>)	Status: <status>
Host: <IP> (<hostname>)	Ports: <port_list>
```

### 示例输出

```
# RustNmap 1.0.0 Grepable Output
# Scan initiated: Mon Feb 16 10:30:00 2026

Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache httpd 2.4.41/

Host: 192.168.1.2 (server.example.com)	Status: Up
Host: 192.168.1.2 (server.example.com)	Ports: 443/open/tcp//https///

Host: 192.168.1.3 ()	Status: Down
```

### 端口格式

```
<port>/<state>/<protocol>//<service>//<version>/
```

示例：
- `22/open/tcp//ssh//OpenSSH 8.2p1/`
- `80/open/tcp//http//Apache httpd 2.4.41/`
- `443/filtered/tcp//https///`

### 用法示例

```bash
# 保存 Grepable 输出
sudo rustnmap -sS -sV -oG results.gnmap 192.168.1.0/24

# 查找所有开放的 SSH 端口
grep -i "ssh" results.gnmap

# 提取开放 80 端口的 IP
grep "80/open" results.gnmap | awk '{print $2}'

# 查找特定主机的所有开放端口
grep "192.168.1.1" results.gnmap | grep "Ports:" | cut -f3

# 统计在线主机数
grep "Status: Up" results.gnmap | wc -l

# 查找所有 Web 服务器
awk '/Ports:.*(80|443)\/open/' results.gnmap

# 提取 IP 列表
awk '/Status: Up/{print $2}' results.gnmap | sed 's/()//'
```

### awk 脚本

```bash
# 使用 awk 综合解析
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

### 格式特性

| 特性 | 描述 |
|------|------|
| 人类可读 | 低 |
| 机器可解析 | 好（文本工具） |
| 文件大小 | 小 |
| 面向行 | 是 |
| Unix 友好 | 优秀 |

---

## Script Kiddie 输出

### 标志

`--output-script-kiddie`

### 描述

Script Kiddie 格式是一种有趣的"l33t speak"风格输出格式。它将字母替换为数字并使用不规则的大小写，具有娱乐价值。

### 示例输出

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

### 用法示例

```bash
# 控制台输出
sudo rustnmap -sS --output-script-kiddie 192.168.1.1
```

### 格式特性

| 特性 | 描述 |
|------|------|
| 人类可读 | 中等 |
| 机器可解析 | 差 |
| 文件大小 | 小 |
| 用途 | 娱乐 |
| 专业使用 | 不推荐 |

---

## 所有格式

### 标志

`-oA <BASENAME>`，`--output-all <BASENAME>`

### 描述

使用指定的基本名称同时输出到所有四种主要格式。

### 生成文件

```bash
sudo rustnmap -sS -sV -oA scan_results 192.168.1.1

# 创建：
# - scan_results.nmap  （普通）
# - scan_results.xml   （XML）
# - scan_results.json  （JSON）
# - scan_results.gnmap （Grepable）
```

### 用法示例

```bash
# 全面扫描带所有输出
sudo rustnmap -A -T4 -oA comprehensive-scan 192.168.1.0/24

# 每日扫描自动化
date_str=$(date +%Y-%m-%d)
sudo rustnmap -sS -oA "daily-scan-${date_str}" 192.168.1.0/24
```

---

## 输出选项

### 追加输出

```bash
# 追加到现有文件
sudo rustnmap -sS -oN results.nmap --append-output 192.168.1.2
```

### 禁止输出

```bash
# 安静模式
sudo rustnmap -sS -q 192.168.1.1

# 无输出
sudo rustnmap -sS --no-output 192.168.1.1
```

### 详细级别

```bash
# 详细
sudo rustnmap -sS -v 192.168.1.1

# 更详细
sudo rustnmap -sS -vv 192.168.1.1

# 调试
sudo rustnmap -sS -d 192.168.1.1

# 数据包跟踪
sudo rustnmap -sS --packet-trace 192.168.1.1
```

### 显示原因

```bash
# 显示端口状态原因
sudo rustnmap -sS --reason 192.168.1.1
```

输出：
```
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp closed https   reset
```

---

## 格式对比

| 特性 | Normal | XML | JSON | NDJSON | Markdown | Grepable | Kiddie |
|------|--------|-----|------|--------|----------|----------|--------|
| 人类可读 | 优秀 | 差 | 好 | 好 | 优秀 | 差 | 中等 |
| 机器解析 | 困难 | 优秀 | 优秀 | 优秀 | 中等 | 好 | 差 |
| 文件大小 | 中等 | 大 | 中等 | 中等 | 中等 | 小 | 小 |
| 模式定义 | 否 | 是 | 是 | 是 | 否 | 是 | 否 |
| 用途 | 审查 | 导入 | API | 流式 | 文档 | 过滤 | 娱乐 |

---

## 最佳实践

### 推荐格式选择

```bash
# 手动审查
sudo rustnmap -sS -oN results.nmap 192.168.1.1

# 自动化
sudo rustnmap -sS -oJ results.json 192.168.1.1

# 与其他工具集成
sudo rustnmap -sS -oX results.xml 192.168.1.1

# 命令行处理
sudo rustnmap -sS -oG results.gnmap 192.168.1.1

# 全面文档
sudo rustnmap -A -oA full-report 192.168.1.1
```

### 自动化示例

```bash
# 每日安全扫描
#!/bin/bash
DATE=$(date +%Y%m%d)
sudo rustnmap -sS -sV -T4 -oX "scan-${DATE}.xml" 192.168.1.0/24

# 解析并告警新开放端口
python3 parse_and_alert.py "scan-${DATE}.xml"

# 每周综合报告
sudo rustnmap -A -T4 -oA "weekly-${DATE}" 10.0.0.0/24
```

---

## 输出故障排除

### 无输出

```bash
# 检查是否启用了安静模式
rustnmap 192.168.1.1  # 应该显示输出
rustnmap -q 192.168.1.1  # 禁止大部分输出
```

### 文件未创建

```bash
# 检查目录权限
ls -ld $(dirname output.nmap)

# 使用绝对路径
sudo rustnmap -sS -oN /tmp/results.nmap 192.168.1.1
```

### 输出损坏

```bash
# 验证 XML
xmllint --noout results.xml

# 验证 JSON
jq '.' results.json > /dev/null
```
