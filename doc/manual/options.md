# RustNmap Command-Line Options

> **Version**: 1.0.0
> **Status**: This document describes the command-line options for RustNmap 1.0.0. Version 2.0 is under development; see [CHANGELOG.md](../CHANGELOG.md).

> **Complete reference for all RustNmap command-line options**

---

## Overview

RustNmap uses a command-line interface compatible with Nmap. Options can be combined in most cases.

**Basic Syntax:**
```bash
rustnmap [Scan Type(s)] [Options] {target specification}
```

---

## Target Specification

### `<TARGET>` (Required)

One or more target hosts to scan.

```bash
# Single IP address
rustnmap 192.168.1.1

# Multiple IP addresses
rustnmap 192.168.1.1 192.168.1.2 192.168.1.3

# CIDR notation
rustnmap 192.168.1.0/24

# IP range
rustnmap 192.168.1.1-100
rustnmap 192.168.1-10.1-50

# Hostname
rustnmap example.com

# Mixed targets
rustnmap 192.168.1.1 example.com 10.0.0.0/8
```

### `-i <FILE>`, `--input-file <FILE>`

Read target specifications from file.

```bash
rustnmap -i targets.txt
```

**File format:**
- One target per line
- Lines starting with `#` are comments
- Empty lines are ignored

```
# targets.txt
192.168.1.1
192.168.1.0/24
example.com
10.0.0.1-50
```

---

## Scan Types

### `-sS`

**TCP SYN Scan** (Default with root)

Half-open scan that sends SYN packets without completing the handshake.

```bash
sudo rustnmap -sS 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Best for | General scanning |

### `-sT`

**TCP Connect Scan** (Default without root)

Full TCP 3-way handshake scan.

```bash
rustnmap -sT 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | No |
| Stealthy | No |
| Speed | Slower |
| Best for | No root access |

### `-sU`

**UDP Scan**

Scan UDP ports by sending UDP packets.

```bash
sudo rustnmap -sU 192.168.1.1
sudo rustnmap -sU -p 53,161,162 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Speed | Slow (timeouts common) |
| Best for | DNS, SNMP, DHCP services |

### `-sF`

**TCP FIN Scan**

Send packets with FIN flag only.

```bash
sudo rustnmap -sF 192.168.1.1
```

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Works against | UNIX systems |
| Windows response | Usually all closed |

### `-sN`

**TCP NULL Scan**

Send packets with no flags set.

```bash
sudo rustnmap -sN 192.168.1.1
```

### `-sX`

**TCP XMAS Scan**

Send packets with FIN, PSH, and URG flags (lights up like a Christmas tree).

```bash
sudo rustnmap -sX 192.168.1.1
```

### `-sM`

**TCP Maimon Scan**

Send packets with FIN/ACK flags (named after Uriel Maimon).

```bash
sudo rustnmap -sM 192.168.1.1
```

---

## Port Specification

### `-p <PORTS>`, `--ports <PORTS>` (also `-p-` for all ports)

Specify ports to scan.

```bash
# Single port
rustnmap -p 22 192.168.1.1

# Multiple ports
rustnmap -p 22,80,443 192.168.1.1

# Port range
rustnmap -p 1-1000 192.168.1.1
rustnmap -p 1-65535 192.168.1.1

# Protocol specific
rustnmap -p T:22,80,U:53 192.168.1.1
```

### `-p-`

Scan all 65535 ports (equivalent to `-p 1-65535`).

```bash
sudo rustnmap -p- 192.168.1.1
```

### `-F`, `--fast-scan`

Fast scan (top 100 ports).

```bash
rustnmap -F 192.168.1.1
```

### `--top-ports <N>`

Scan top N most common ports.

```bash
rustnmap --top-ports 100 192.168.1.1
rustnmap --top-ports 1000 192.168.1.1
```

---

## Host Discovery

### `-sn`

**Ping Scan Only**

Disable port scanning, only host discovery.

```bash
sudo rustnmap -sn 192.168.1.0/24
```

### `-Pn`, `--disable-ping`

**Skip Host Discovery**

Treat all hosts as up (scan all targets).

```bash
sudo rustnmap -Pn 192.168.1.0/24
```

### `-PE`

**ICMP Echo Ping**

Use ICMP echo request (Type 8) for discovery.

```bash
sudo rustnmap -PE 192.168.1.0/24
```

### `-PP`

**ICMP Timestamp Ping**

Use ICMP timestamp request (Type 13) for discovery.

```bash
sudo rustnmap -PP 192.168.1.0/24
```

### `-PM`

**ICMP Netmask Ping**

Use ICMP netmask request (Type 17) for discovery.

```bash
sudo rustnmap -PM 192.168.1.0/24
```

### `-PS<PORTLIST>`, `--ping-type syn`

**TCP SYN Ping**

Send SYN packets to ports for discovery.

```bash
sudo rustnmap -PS 192.168.1.0/24          # Default port 80
sudo rustnmap -PS22,80,443 192.168.1.0/24  # Specific ports
```

### `-PA<PORTLIST>`

**TCP ACK Ping**

Send ACK packets to ports for discovery.

```bash
sudo rustnmap -PA 192.168.1.0/24          # Default port 80
sudo rustnmap -PA80,443 192.168.1.0/24    # Specific ports
```

### `-PU<PORTLIST>`

**UDP Ping**

Send UDP packets to ports for discovery.

```bash
sudo rustnmap -PU 192.168.1.0/24          # Default port 40125
sudo rustnmap -PU53,161 192.168.1.0/24    # Specific ports
```

---

## Service Detection

### `-sV`, `--service-detection`

**Service Version Detection**

Probe open ports to determine service/version information.

```bash
sudo rustnmap -sV 192.168.1.1
sudo rustnmap -sS -sV 192.168.1.1
```

### `--version-intensity <0-9>`

Set intensity of version detection (0 = light, 9 = all probes).

```bash
sudo rustnmap -sV --version-intensity 0 192.168.1.1   # Light
sudo rustnmap -sV --version-intensity 5 192.168.1.1   # Default
sudo rustnmap -sV --version-intensity 9 192.168.1.1   # All probes
```

---

## OS Detection

### `-O`

**OS Detection**

Enable operating system detection using TCP/IP fingerprinting.

```bash
sudo rustnmap -O 192.168.1.1
sudo rustnmap -sS -O 192.168.1.1
```

### `--osscan-limit`

Limit OS detection to promising targets.

```bash
sudo rustnmap -O --osscan-limit 192.168.1.1
```

### `--osscan-guess`, `--fuzzy`

Guess OS more aggressively.

```bash
sudo rustnmap -O --osscan-guess 192.168.1.1
```

---

## Timing and Performance

### `-T<0-5>`, `--timing <0-5>`

Set timing template (higher is faster).

| Level | Name | Description |
|-------|------|-------------|
| 0 | Paranoid | 5 min between probes |
| 1 | Sneaky | 15 sec between probes |
| 2 | Polite | 0.4 sec between probes |
| 3 | Normal | Default |
| 4 | Aggressive | Faster |
| 5 | Insane | Very fast |

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

```bash
sudo rustnmap --min-parallelism 100 192.168.1.1
```

### `--max-parallelism <NUM>`

Maximum number of parallel probes.

```bash
sudo rustnmap --max-parallelism 500 192.168.1.1
```

### `--scan-delay <MS>`

Delay between probes (milliseconds).

```bash
sudo rustnmap --scan-delay 1000 192.168.1.1   # 1 second delay
```

### `--host-timeout <MS>`

Timeout for host scan (milliseconds).

```bash
sudo rustnmap --host-timeout 30000 192.168.1.0/24   # 30 seconds
```

### `--min-rate <NUM>`

Minimum packet rate (packets per second).

```bash
sudo rustnmap --min-rate 1000 192.168.1.1
```

### `--max-rate <NUM>`

Maximum packet rate (packets per second).

```bash
sudo rustnmap --max-rate 100 192.168.1.1
```

---

## Firewall/IDS Evasion

### `-f`, `--fragment-mtu <MTU>`

Fragment packets (default 16 bytes after IP header). `-f` alone uses default MTU; `-f16` or `--mtu 16` specifies custom.

```bash
sudo rustnmap -f 192.168.1.1
sudo rustnmap -f8 192.168.1.1
sudo rustnmap --mtu 16 192.168.1.1
```

### `-D <DECOYS>`, `--decoys <DECOYS>`

Use decoy scans to hide source.

```bash
# Specific decoys
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1

# Random decoys
sudo rustnmap -D RND:10 192.168.1.1

# Position yourself
sudo rustnmap -D ME,192.168.1.2,192.168.1.3 192.168.1.1
```

### `-S <IP>`, `--spoof-ip <IP>`

Spoof source address.

```bash
sudo rustnmap -S 192.168.1.100 192.168.1.1
```

**Note:** Requires ability to receive responses.

### `-g <PORT>`, `--source-port <PORT>`

Use specific source port.

```bash
sudo rustnmap -g 53 192.168.1.1     # DNS port
sudo rustnmap -g 20 192.168.1.1     # FTP data port
```

### `-e <IFACE>`, `--interface <IFACE>`

Use specified network interface.

```bash
sudo rustnmap -e eth0 192.168.1.1
sudo rustnmap -e wlan0 192.168.1.1
```

### `--data-length <LEN>`

Append random data to packets.

```bash
sudo rustnmap --data-length 100 192.168.1.1
```

### `--data-hex <HEX>`

Append custom hex data to packets.

```bash
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1   # "Hello"
```

### `--data-string <STRING>`

Append custom string to packets.

```bash
sudo rustnmap --data-string "Hello" 192.168.1.1
```

---

## Output Options

### `-oN <FILE>`

Normal output to file.

```bash
sudo rustnmap -oN results.nmap 192.168.1.1
```

### `-oX <FILE>`

XML output to file.

```bash
sudo rustnmap -oX results.xml 192.168.1.1
```

### `-oJ <FILE>`, `--output-json <FILE>`

JSON output to file.

```bash
sudo rustnmap -oJ results.json 192.168.1.1
```

### `--output-ndjson <FILE>`

NDJSON (newline-delimited JSON) output to file.

```bash
sudo rustnmap --output-ndjson results.ndjson 192.168.1.1
```

### `--output-markdown <FILE>`

Markdown output to file.

```bash
sudo rustnmap --output-markdown results.md 192.168.1.1
```

### `-oG <FILE>`

Grepable output to file.

```bash
sudo rustnmap -oG results.gnmap 192.168.1.1
```

### `--output-script-kiddie`

Script kiddie output (console only).

```bash
sudo rustnmap --output-script-kiddie 192.168.1.1
```

### `-oA <BASENAME>`

Output to all formats (Normal, XML, JSON, Grepable).

```bash
sudo rustnmap -oA results 192.168.1.1
# Creates: results.nmap, results.xml, results.json, results.gnmap
```

### `--append-output`

Append to output files instead of overwriting.

```bash
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

### `-v`, `--verbose`

Increase verbosity level (use multiple times).

```bash
sudo rustnmap -v 192.168.1.1      # Verbose
sudo rustnmap -vv 192.168.1.1     # More verbose
sudo rustnmap -vvv 192.168.1.1    # Maximum verbose
```

### `-q`, `--quiet`

Quiet mode (only errors).

```bash
sudo rustnmap -q 192.168.1.1
```

### `-d`, `--debug`

Increase debugging level.

```bash
sudo rustnmap -d 192.168.1.1      # Debug
sudo rustnmap -dd 192.168.1.1     # More debug
```

### `--reason`

Display reason for port state.

```bash
sudo rustnmap --reason 192.168.1.1
# Shows: syn-ack, reset, no-response, etc.
```

### `--packet-trace`

Show packet trace of scan.

```bash
sudo rustnmap --packet-trace 192.168.1.1
```

### `--open`

Show only open ports.

```bash
sudo rustnmap --open 192.168.1.1
```

### `--iflist`

Show interface list and routes.

```bash
rustnmap --iflist
```

### `--no-output`

Suppress output.

```bash
sudo rustnmap --no-output 192.168.1.1
```

---

## NSE Scripting

### `-sC`

Run default scripts (equivalent to `--script=default`).

```bash
sudo rustnmap -sC 192.168.1.1
```

### `--script <SCRIPTS>`, `-sC`

Run specified scripts.

```bash
# Single script
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts
sudo rustnmap --script http-title,http-headers 192.168.1.1

# Script categories
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "intrusive" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "version" 192.168.1.1

# Pattern matching
sudo rustnmap --script "http-*" 192.168.1.1
sudo rustnmap --script "smb-*" 192.168.1.1
```

**Categories:**
- `auth` - Authentication related
- `broadcast` - Broadcast discovery
- `brute` - Brute force attacks
- `default` - Default scripts
- `discovery` - Service discovery
- `dos` - Denial of service
- `exploit` - Exploits
- `external` - External resources
- `fuzzer` - Fuzzing tests
- `intrusive` - Intrusive scripts
- `malware` - Malware detection
- `safe` - Safe scripts
- `version` - Version detection
- `vuln` - Vulnerability detection

### `--script-args <ARGS>`

Provide arguments to scripts.

```bash
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# Multiple arguments
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1
```

### `--script-help <SCRIPT>`

Show help for a specific script.

```bash
# Help for specific script
rustnmap --script-help http-title
```

### `--script-updatedb`

Update script database.

```bash
rustnmap --script-updatedb
```

---

## Miscellaneous

### `--traceroute`

Trace hop path to target.

```bash
sudo rustnmap --traceroute 192.168.1.1
```

### `--traceroute-hops <NUM>`

Maximum traceroute hops.

```bash
sudo rustnmap --traceroute --traceroute-hops 20 192.168.1.1
```

### `--randomize-hosts`

Randomize target host order.

```bash
sudo rustnmap --randomize-hosts 192.168.1.0/24
```

### `--host-group-size <NUM>`

Host group size for parallel scanning.

```bash
sudo rustnmap --host-group-size 10 192.168.1.0/24
```

### `--print-urls`

Print interacted URLs.

```bash
rustnmap --print-urls 192.168.1.1
```

### `-A`

**Aggressive Scan**

Enable OS detection, version detection, script scanning, and traceroute.

```bash
sudo rustnmap -A 192.168.1.1
# Equivalent to: -sV -sC -O --traceroute
```

### `-h`, `--help`

Show help message.

```bash
rustnmap --help
```

### `-V`, `--version`

Show version information.

```bash
rustnmap --version
```

---

## Option Combinations

### Common Combinations

```bash
# Comprehensive scan
sudo rustnmap -A -T4 -oA full-scan 192.168.1.1

# Stealth web scan
sudo rustnmap -sS -T2 -p 80,443 --script http-* 192.168.1.1

# Fast network discovery
sudo rustnmap -sn -T4 192.168.1.0/24

# Full port scan with service detection
sudo rustnmap -p- -sV -T4 192.168.1.1

# IDS evasion scan
sudo rustnmap -sS -T0 -f -D RND:10 192.168.1.1
```

### Conflicting Options

The following options conflict with each other:

- Only one scan type: `-sS`, `-sT`, `-sU`, `-sF`, `-sN`, `-sX`, `-sM`
- Only one port specification: `-p`, `-F`, `--top-ports`, `-p-`
- Only one output format group: `-oN`, `-oX`, `-oJ`, `-oG`, `-oA`

---

## Summary Tables

### Scan Types Summary

| Flag | Name | Root | Description |
|------|------|------|-------------|
| `-sS` | SYN | Yes | Half-open scan |
| `-sT` | Connect | No | Full handshake |
| `-sU` | UDP | Yes | UDP scan |
| `-sF` | FIN | Yes | FIN flag only |
| `-sN` | NULL | Yes | No flags |
| `-sX` | XMAS | Yes | FIN/PSH/URG |
| `-sA` | ACK | Yes | ACK flag |
| `-sW` | Window | Yes | Window scan |
| `-sM` | Maimon | Yes | FIN/ACK |
| `-b` | FTP Bounce | No | FTP proxy scan |

### Output Formats Summary

| Flag | Extension | Description |
|------|-----------|-------------|
| `-oN` | .nmap | Human-readable |
| `-oX` | .xml | Machine-parseable |
| `-oJ` | .json | Structured JSON |
| `-oG` | .gnmap | Grepable |
| `--output-script-kiddie` | (console) | Script kiddie |
| `--output-ndjson` | .ndjson | Newline-delimited JSON |
| `--output-markdown` | .md | Markdown format |
| `-oA` | Multiple | All formats |

### Timing Templates Summary

| Flag | Name | Speed | Use Case |
|------|------|-------|----------|
| `-T0` | Paranoid | Very slow | IDS evasion |
| `-T1` | Sneaky | Slow | IDS evasion |
| `-T2` | Polite | Moderate | Slow network |
| `-T3` | Normal | Default | General use |
| `-T4` | Aggressive | Fast | Fast network |
| `-T5` | Insane | Very fast | Local network |
