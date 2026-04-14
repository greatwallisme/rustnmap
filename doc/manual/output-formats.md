# RustNmap Output Formats

> **Version**: 1.0.0
> **Status**: This document describes the output formats of RustNmap 1.0.0. Version 2.0 is under development, see [CHANGELOG.md](../CHANGELOG.md).

> **Complete documentation for all output formats**

---

## Overview

RustNmap supports 5 output formats, each designed for different use cases:

| Format | Extension | Flag | Use Case |
|--------|-----------|------|----------|
| Normal | `.nmap` | `-oN` | Human-readable output |
| XML | `.xml` | `-oX` | Machine parsing |
| JSON | `.json` | `-oJ` | Structured data |
| NDJSON | `.ndjson` | `--output-ndjson` | Streaming JSON |
| Markdown | `.md` | `--output-markdown` | Documentation |
| Grepable | `.gnmap` | `-oG` | Grep/AWK processing |
| Script Kiddie | (console) | `--output-script-kiddie` | Fun format |

---

## Normal Output

### Flag

`-oN <FILE>`, `--output-normal <FILE>`

### Description

Normal output is the default console output format. It provides human-readable scan results with formatting that is easy to read and interpret.

### Example Output

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

### With Service Detection

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

### With OS Detection

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

### Usage Examples

```bash
# Save normal output
sudo rustnmap -sS -oN scan_results.nmap 192.168.1.1

# Append to existing file
sudo rustnmap -sS -oN scan_results.nmap --append-output 192.168.1.2

# Multiple hosts
sudo rustnmap -sS -oN network_scan.nmap 192.168.1.0/24
```

### Format Characteristics

| Feature | Description |
|---------|-------------|
| Human readable | Yes |
| Machine parsable | Difficult |
| File size | Medium |
| Verbosity levels | Supported |
| Color output | Console only |

---

## XML Output

### Flag

`-oX <FILE>`, `--output-xml <FILE>`

### Description

XML output provides structured, machine-parseable results. It follows the Nmap XML output format specification and is ideal for importing into other tools or automated processing.

### XML Schema

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

### Usage Examples

```bash
# Save XML output
sudo rustnmap -sS -sV -oX results.xml 192.168.1.1

# Process with Python
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

### XML Elements Reference

| Element | Description |
|---------|-------------|
| `nmaprun` | Root element with scan metadata |
| `scaninfo` | Scan type and protocol information |
| `host` | Individual host results |
| `status` | Host state (up/down) |
| `address` | IP/MAC address |
| `hostnames` | Discovered hostnames |
| `ports` | Port scan results container |
| `port` | Individual port information |
| `state` | Port state (open/closed/filtered) |
| `service` | Service detection results |
| `os` | OS detection results |
| `runstats` | Scan statistics |

### Format Characteristics

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Excellent |
| File size | Large |
| Schema defined | Yes |
| XPath support | Yes |

---

## JSON Output

### Flag

`-oJ <FILE>`, `--output-json <FILE>`

### Description

JSON output provides structured data that is easy to parse with modern programming languages. It's more compact than XML while maintaining full scan information.

### JSON Schema

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

### Usage Examples

```bash
# Save JSON output
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1

# Pretty print JSON
sudo rustnmap -sS -sV -oJ results.json 192.168.1.1
jq '.' results.json

# Process with Python
python3 -c "
import json
with open('results.json') as f:
    data = json.load(f)
    for host in data['hosts']:
        print(f\"Host: {host['ip']}\")
        for port in host['ports']:
            print(f\"  {port['number']}/{port['protocol']}: {port['state']}\")
"

# Process with jq
jq '.hosts[].ports[] | select(.state == "open") | .number' results.json
jq '.hosts[] | {ip: .ip, open_ports: [.ports[] | select(.state == "open") | .number]}' results.json
```

### JSON Schema Reference

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

### Format Characteristics

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Excellent |
| File size | Medium |
| Native support | All modern languages |
| Query support | jq, JSONPath |

---

## Grepable Output

### Flag

`-oG <FILE>`, `--output-grepable <FILE>`

### Description

Grepable format provides a single-line format for each host that is easy to parse with grep, awk, sed, and other Unix command-line tools. It's designed for quick filtering and extraction.

### Format Specification

```
Host: <IP> (<hostname>)	Status: <status>
Host: <IP> (<hostname>)	Ports: <port_list>
```

### Example Output

```
# RustNmap 1.0.0 Grepable Output
# Scan initiated: Mon Feb 16 10:30:00 2026

Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache httpd 2.4.41/

Host: 192.168.1.2 (server.example.com)	Status: Up
Host: 192.168.1.2 (server.example.com)	Ports: 443/open/tcp//https///

Host: 192.168.1.3 ()	Status: Down
```

### Port Format

```
<port>/<state>/<protocol>//<service>//<version>/
```

Examples:
- `22/open/tcp//ssh//OpenSSH 8.2p1/`
- `80/open/tcp//http//Apache httpd 2.4.41/`
- `443/filtered/tcp//https///`

### Usage Examples

```bash
# Save grepable output
sudo rustnmap -sS -sV -oG results.gnmap 192.168.1.0/24

# Find all open SSH ports
grep -i "ssh" results.gnmap

# Extract IPs with open port 80
grep "80/open" results.gnmap | awk '{print $2}'

# Find all open ports on specific host
grep "192.168.1.1" results.gnmap | grep "Ports:" | cut -f3

# Count hosts that are up
grep "Status: Up" results.gnmap | wc -l

# Find all web servers (port 80 or 443)
awk '/Ports:.*(80|443)\/open/' results.gnmap

# Extract IP list
awk '/Status: Up/{print $2}' results.gnmap | sed 's/()//'
```

### awk Scripting

```bash
# Comprehensive parsing with awk
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

### Format Characteristics

| Feature | Description |
|---------|-------------|
| Human readable | Low |
| Machine parsable | Good (text tools) |
| File size | Small |
| Line-oriented | Yes |
| Unix-friendly | Excellent |

---

## Script Kiddie Output

### Flag

`--output-script-kiddie`

### Description

Script Kiddie format is a fun, "l33t speak" style output format. It replaces letters with numbers and uses irregular capitalization for entertainment value.

### Example Output

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

### Usage Examples

```bash
# Console output
sudo rustnmap -sS --output-script-kiddie 192.168.1.1
```

### Format Characteristics

| Feature | Description |
|---------|-------------|
| Human readable | Moderate |
| Machine parsable | Poor |
| File size | Small |
| Purpose | Entertainment |
| Professional use | Not recommended |

---

## All Formats

### Flag

`-oA <BASENAME>`, `--output-all <BASENAME>`

### Description

Outputs to all four major formats at once using the specified basename.

### Generated Files

```bash
sudo rustnmap -sS -sV -oA scan_results 192.168.1.1

# Creates:
# - scan_results.nmap  (Normal)
# - scan_results.xml   (XML)
# - scan_results.json  (JSON)
# - scan_results.gnmap (Grepable)
```

### Usage Examples

```bash
# Comprehensive scan with all outputs
sudo rustnmap -A -T4 -oA comprehensive-scan 192.168.1.0/24

# Daily scan automation
date_str=$(date +%Y-%m-%d)
sudo rustnmap -sS -oA "daily-scan-${date_str}" 192.168.1.0/24
```

---

## Output Options

### Append Output

```bash
# Append to existing files
sudo rustnmap -sS -oN results.nmap --append-output 192.168.1.2
```

### Suppress Output

```bash
# Quiet mode
sudo rustnmap -sS -q 192.168.1.1

# No output
sudo rustnmap -sS --no-output 192.168.1.1
```

### Verbosity Levels

```bash
# Verbose
sudo rustnmap -sS -v 192.168.1.1

# More verbose
sudo rustnmap -sS -vv 192.168.1.1

# Debug
sudo rustnmap -sS -d 192.168.1.1

# Packet trace
sudo rustnmap -sS --packet-trace 192.168.1.1
```

### Show Reasons

```bash
# Show reason for port state
sudo rustnmap -sS --reason 192.168.1.1
```

Output:
```
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp closed https   reset
```

---

## Format Comparison

| Feature | Normal | XML | JSON | NDJSON | Markdown | Grepable | Kiddie |
|---------|--------|-----|------|--------|----------|----------|--------|
| Human readable | Excellent | Poor | Good | Good | Excellent | Poor | Moderate |
| Machine parsing | Difficult | Excellent | Excellent | Excellent | Moderate | Good | Poor |
| File size | Medium | Large | Medium | Medium | Medium | Small | Small |
| Schema defined | No | Yes | Yes | Yes | No | Yes | No |
| Use case | Review | Import | API | Stream | Docs | Filter | Fun |

---

## Best Practices

### Recommended Format Selection

```bash
# For manual review
sudo rustnmap -sS -oN results.nmap 192.168.1.1

# For automation
sudo rustnmap -sS -oJ results.json 192.168.1.1

# For integration with other tools
sudo rustnmap -sS -oX results.xml 192.168.1.1

# For command-line processing
sudo rustnmap -sS -oG results.gnmap 192.168.1.1

# For comprehensive documentation
sudo rustnmap -A -oA full-report 192.168.1.1
```

### Automation Examples

```bash
# Daily security scan
#!/bin/bash
DATE=$(date +%Y%m%d)
sudo rustnmap -sS -sV -T4 -oX "scan-${DATE}.xml" 192.168.1.0/24

# Parse and alert on new open ports
python3 parse_and_alert.py "scan-${DATE}.xml"

# Weekly comprehensive report
sudo rustnmap -A -T4 -oA "weekly-${DATE}" 10.0.0.0/24
```

---

## Troubleshooting Output

### No Output

```bash
# Check if quiet mode is enabled
rustnmap 192.168.1.1  # Should show output
rustnmap -q 192.168.1.1  # Suppresses most output
```

### File Not Created

```bash
# Check directory permissions
ls -ld $(dirname output.nmap)

# Use absolute path
sudo rustnmap -sS -oN /tmp/results.nmap 192.168.1.1
```

### Corrupted Output

```bash
# Validate XML
xmllint --noout results.xml

# Validate JSON
jq '.' results.json > /dev/null
```
