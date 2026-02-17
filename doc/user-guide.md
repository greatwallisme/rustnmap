# RustNmap User Guide

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的功能。2.0 版本开发中，详见 [CHANGELOG.md](CHANGELOG.md)。
> **Last Updated**: 2026-02-15

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Basic Scanning](#basic-scanning)
4. [Host Discovery](#host-discovery)
5. [Port Scanning Techniques](#port-scanning-techniques)
6. [Service Detection](#service-detection)
7. [OS Detection](#os-detection)
8. [NSE Scripts](#nse-scripts)
9. [Output Formats](#output-formats)
10. [Evasion Techniques](#evasion-techniques)
11. [Timing and Performance](#timing-and-performance)
12. [IPv6 Scanning](#ipv6-scanning)
13. [Troubleshooting](#troubleshooting)

---

## Introduction

RustNmap is a high-performance network scanning tool designed for security professionals and network administrators. It provides comprehensive network discovery and security auditing capabilities.

### Key Capabilities

- **Port Scanning**: 12 different scan types for various scenarios
- **Host Discovery**: Identify live hosts on networks
- **Service Detection**: Identify services and their versions
- **OS Detection**: Determine operating systems of targets
- **Scripting Engine**: Automate scans with Lua scripts
- **Multiple Output Formats**: Text, XML, JSON, grepable

---

## Getting Started

### Installation

```bash
# Clone repository
git clone https://github.com/greatwallisme/rust-nmap.git
cd rust-nmap

# Build release binary
cargo build --release

# Install to system (optional)
sudo cp target/release/rustnmap /usr/local/bin/
```

### Basic Syntax

```bash
rustnmap [Scan Type(s)] [Options] {target specification}
```

### First Scan

```bash
# Simple ping scan
sudo rustnmap -sn 192.168.1.0/24

# Scan a single host
sudo rustnmap 192.168.1.1

# Scan specific ports
sudo rustnmap -p 22,80,443 192.168.1.1
```

---

## Basic Scanning

### Target Specification

**Single Targets:**
```bash
rustnmap 192.168.1.1
rustnmap example.com
```

**Multiple Targets:**
```bash
rustnmap 192.168.1.1 192.168.1.2 192.168.1.3
rustnmap example.com scanme.nmap.org
```

**CIDR Notation:**
```bash
# Scan entire /24 network
rustnmap 192.168.1.0/24

# Scan larger networks
rustnmap 10.0.0.0/8
```

**IP Ranges:**
```bash
# Range notation
rustnmap 192.168.1.1-100
rustnmap 192.168.1-2.1-50
```

**From File:**
```bash
# targets.txt contains one target per line
rustnmap -iL targets.txt
```

**Exclude Targets:**
```bash
# Exclude specific hosts
rustnmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254

# Exclude from file
rustnmap 192.168.1.0/24 --excludefile exclude.txt
```

### Port Specification

**Single Port:**
```bash
rustnmap -p 22 192.168.1.1
```

**Multiple Ports:**
```bash
rustnmap -p 22,80,443 192.168.1.1
```

**Port Ranges:**
```bash
rustnmap -p 1-1000 192.168.1.1
rustnmap -p 1-65535 192.168.1.1
```

**Protocol-Specific:**
```bash
# TCP only
rustnmap -p T:22,80,443 192.168.1.1

# UDP only
rustnmap -p U:53,161 192.168.1.1

# Both
rustnmap -p T:80,U:53 192.168.1.1
```

**Fast Scan (Common Ports):**
```bash
rustnmap -F 192.168.1.1
```

**Top Ports:**
```bash
# Top 100 ports
rustnmap --top-ports 100 192.168.1.1

# Top 1000 ports (default)
rustnmap --top-ports 1000 192.168.1.1
```

---

## Host Discovery

### Ping Scan (No Port Scan)

```bash
# Find live hosts
sudo rustnmap -sn 192.168.1.0/24
```

### ICMP Discovery

```bash
# ICMP echo (standard ping)
sudo rustnmap -PE 192.168.1.0/24

# ICMP timestamp
sudo rustnmap -PP 192.168.1.0/24

# ICMP netmask
sudo rustnmap -PM 192.168.1.0/24
```

### TCP Discovery

```bash
# TCP SYN to default ports (80)
sudo rustnmap -PS 192.168.1.0/24

# TCP SYN to specific ports
sudo rustnmap -PS22,80,443 192.168.1.0/24

# TCP ACK
sudo rustnmap -PA80 192.168.1.0/24
```

### UDP Discovery

```bash
# UDP to default port (40125)
sudo rustnmap -PU 192.168.1.0/24

# UDP to specific ports
sudo rustnmap -PU53,161 192.168.1.0/24
```

### ARP Discovery (Local Network)

```bash
# ARP ping (most reliable on local network)
sudo rustnmap -PR 192.168.1.0/24
```

### Skip Discovery

```bash
# Treat all hosts as up (scan everything)
sudo rustnmap -Pn 192.168.1.0/24
```

### Combined Discovery

```bash
# Use multiple methods
sudo rustnmap -PE -PS22,80 -PA443 -PU53 192.168.1.0/24
```

---

## Port Scanning Techniques

### TCP SYN Scan (Default)

```bash
# Half-open scan (stealthy, requires root)
sudo rustnmap -sS 192.168.1.1

# Most popular scan type
# - Fast and efficient
# - Doesn't complete handshake
# - Less likely to be logged
```

### TCP Connect Scan

```bash
# Full TCP handshake (no root required)
rustnmap -sT 192.168.1.1

# Use when:
# - You don't have root access
# - SYN scan fails
# - Scanning IPv6 targets
```

### UDP Scan

```bash
# UDP port scan
sudo rustnmap -sU 192.168.1.1

# Often slow due to timeouts
# Combine with version detection
sudo rustnmap -sU -sV 192.168.1.1
```

### Stealth Scans

**FIN Scan:**
```bash
# Send FIN packet
sudo rustnmap -sF 192.168.1.1
```

**NULL Scan:**
```bash
# No flags set
sudo rustnmap -sN 192.168.1.1
```

**XMAS Scan:**
```bash
# FIN, PSH, URG flags
sudo rustnmap -sX 192.168.1.1
```

**Note:** Stealth scans work best against UNIX systems. Windows systems often return all ports as closed.

### ACK Scan

```bash
# Firewall/rule mapping
sudo rustnmap -sA 192.168.1.1

# Determines if ports are:
# - Filtered (no response)
# - Unfiltered (RST received)
```

### Window Scan

```bash
# Similar to ACK but uses window size
sudo rustnmap -sW 192.168.1.1
```

### Maimon Scan

```bash
# FIN/ACK probe
sudo rustnmap -sM 192.168.1.1
```

### IP Protocol Scan

```bash
# Scan IP protocols (ICMP, TCP, UDP, etc.)
sudo rustnmap -sO 192.168.1.1
```

### SCTP Scans

```bash
# SCTP INIT scan
sudo rustnmap -sY 192.168.1.1

# SCTP COOKIE ECHO scan
sudo rustnmap -sZ 192.168.1.1
```

### Idle Scan

```bash
# Zombie scan (highly stealthy)
sudo rustnmap -sI zombie.example.com 192.168.1.1

# Requires zombie host with:
# - Predictable IP ID sequence
# - Not communicating with target
```

### FTP Bounce Scan

```bash
# Use FTP server as proxy
rustnmap -b ftp.example.com:21 192.168.1.1
```

---

## Service Detection

### Basic Service Detection

```bash
# Detect services and versions
sudo rustnmap -sV 192.168.1.1
```

### Intensity Levels

```bash
# Light (0) - Fast but less accurate
sudo rustnmap -sV --version-intensity 0 192.168.1.1

# Medium (5) - Default
sudo rustnmap -sV --version-intensity 5 192.168.1.1

# Heavy (9) - All probes, slowest
sudo rustnmap -sV --version-intensity 9 192.168.1.1

# All probes
sudo rustnmap -sV --version-all 192.168.1.1

# Light only
sudo rustnmap -sV --version-light 192.168.1.1
```

### With Default NSE Scripts

```bash
# Service detection + default scripts
sudo rustnmap -sV -sC 192.168.1.1

# Equivalent to -A (without OS detection)
```

---

## OS Detection

### Basic OS Detection

```bash
# Enable OS detection
sudo rustnmap -O 192.168.1.1
```

### Limit Matches

```bash
# Limit to most likely matches
sudo rustnmap -O --osscan-limit 192.168.1.1
```

### Aggressive Guess

```bash
# Guess even with insufficient info
sudo rustnmap -O --osscan-guess 192.168.1.1
```

### Combined Scan

```bash
# Everything: OS, version, scripts, traceroute
sudo rustnmap -A 192.168.1.1

# Equivalent to:
# -sV -sC -O --traceroute
```

---

## NSE Scripts

### Running Scripts

**Default Scripts:**
```bash
# Run default safe scripts
sudo rustnmap -sC 192.168.1.1
```

**Specific Scripts:**
```bash
# Single script
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts
sudo rustnmap --script http-title,http-headers 192.168.1.1
```

**Script Categories:**
```bash
# Safe scripts only
sudo rustnmap --script "safe" 192.168.1.1

# Intrusive scripts
sudo rustnmap --script "intrusive" 192.168.1.1

# Discovery scripts
sudo rustnmap --script "discovery" 192.168.1.1

# Version scripts
sudo rustnmap --script "version" 192.168.1.1

# Multiple categories
sudo rustnmap --script "safe,discovery" 192.168.1.1
```

**Script by Pattern:**
```bash
# All HTTP scripts
sudo rustnmap --script "http-*" 192.168.1.1

# All SMB scripts
sudo rustnmap --script "smb-*" 192.168.1.1
```

### Script Arguments

```bash
# Pass arguments to scripts
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# Multiple arguments
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1
```

### Script Help

```bash
# List all scripts
rustnmap --script-help

# Help for specific script
rustnmap --script-help http-title
```

---

## Output Formats

### Normal Output

```bash
# Human-readable text
sudo rustnmap -oN results.nmap 192.168.1.1

# Append to existing file
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

### XML Output

```bash
# Machine-parseable XML
sudo rustnmap -oX results.xml 192.168.1.1
```

### JSON Output

```bash
# Structured JSON
sudo rustnmap -oJ results.json 192.168.1.1
```

### Grepable Output

```bash
# Line-based format for grep/awk
sudo rustnmap -oG results.gnmap 192.168.1.1

# Example parsing
grep "22/open" results.gnmap
awk '/Host:/{print $2}' results.gnmap
```

### Script Kiddie Output

```bash
# Fun pipe-delimited format
sudo rustnmap -oS results.txt 192.168.1.1
```

### All Formats

```bash
# Generate all formats at once
sudo rustnmap -oA results 192.168.1.1

# Creates:
# - results.nmap
# - results.xml
# - results.json
# - results.gnmap
```

### Verbosity Levels

```bash
# Verbose
sudo rustnmap -v 192.168.1.1

# More verbose
sudo rustnmap -vv 192.168.1.1

# Debug
sudo rustnmap -d 192.168.1.1

# Maximum debug
sudo rustnmap -dd 192.168.1.1

# Quiet (errors only)
sudo rustnmap -q 192.168.1.1
```

### Reason Display

```bash
# Show reason for port state
sudo rustnmap --reason 192.168.1.1

# Shows:
# - syn-ack (for open ports)
# - reset (for closed ports)
# - no-response (for filtered)
```

---

## Evasion Techniques

### Packet Fragmentation

```bash
# Fragment packets
sudo rustnmap -f 192.168.1.1

# Specific MTU size
sudo rustnmap --mtu 8 192.168.1.1
sudo rustnmap --mtu 16 192.168.1.1

# Fragment after 8 bytes
sudo rustnmap -ff 192.168.1.1
```

### Decoy Scanning

```bash
# Use decoys (your real IP is mixed in)
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1

# Random decoys
sudo rustnmap -D RND:10 192.168.1.1

# Use "ME" to specify your position
sudo rustnmap -D ME,192.168.1.2,192.168.1.3 192.168.1.1
```

### Source IP Spoofing

```bash
# Spoof source IP
sudo rustnmap -S 192.168.1.100 192.168.1.1

# Note: Requires ability to receive responses
# Usually only works on local network
```

### Source Port Manipulation

```bash
# Use specific source port
sudo rustnmap -g 53 192.168.1.1
sudo rustnmap -g 20 192.168.1.1
```

### Custom Data Payload

```bash
# Hex payload
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1

# String payload
sudo rustnmap --data-string "Hello" 192.168.1.1

# Random data length
sudo rustnmap --data-length 100 192.168.1.1
```

### MAC Address Spoofing

```bash
# Spoof MAC address
sudo rustnmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Random MAC
sudo rustnmap --spoof-mac 0 192.168.1.1

# Vendor-specific random
sudo rustnmap --spoof-mac Apple 192.168.1.1
```

---

## Timing and Performance

### Timing Templates

| Template | Flag | Use Case |
|----------|------|----------|
| Paranoid | `-T0` | IDS evasion, very slow |
| Sneaky | `-T1` | IDS evasion, slow |
| Polite | `-T2` | Low bandwidth, slow |
| Normal | `-T3` | Default, balanced |
| Aggressive | `-T4` | Fast, reliable network |
| Insane | `-T5` | Very fast, local network |

```bash
# Paranoid - 5 minutes between probes
sudo rustnmap -T0 192.168.1.1

# Sneaky - 15 seconds between probes
sudo rustnmap -T1 192.168.1.1

# Polite - 0.4 seconds between probes
sudo rustnmap -T2 192.168.1.1

# Normal - default
sudo rustnmap -T3 192.168.1.1

# Aggressive - faster
sudo rustnmap -T4 192.168.1.1

# Insane - very fast, may miss ports
sudo rustnmap -T5 192.168.1.1
```

### Custom Timing

```bash
# Parallelism
sudo rustnmap --min-parallelism 100 192.168.1.1
sudo rustnmap --max-parallelism 500 192.168.1.1

# Host group sizes
sudo rustnmap --min-hostgroup 10 192.168.1.0/24
sudo rustnmap --max-hostgroup 100 192.168.1.0/24

# RTT timeout
sudo rustnmap --initial-rtt-timeout 500ms 192.168.1.1
sudo rustnmap --max-rtt-timeout 2s 192.168.1.1
sudo rustnmap --min-rtt-timeout 100ms 192.168.1.1

# Host timeout
sudo rustnmap --host-timeout 30m 192.168.1.0/24

# Scan delay
sudo rustnmap --scan-delay 1s 192.168.1.1
sudo rustnmap --max-scan-delay 5s 192.168.1.1

# Retries
sudo rustnmap --max-retries 2 192.168.1.1
```

### Rate Limiting

```bash
# Minimum rate
sudo rustnmap --min-rate 1000 192.168.1.1

# Maximum rate
sudo rustnmap --max-rate 100 192.168.1.1
```

---

## IPv6 Scanning

### Basic IPv6 Scans

```bash
# Single IPv6 target
sudo rustnmap -sS 2001:db8::1

# IPv6 with CIDR
sudo rustnmap -sS 2001:db8::/64

# IPv6 localhost
sudo rustnmap -sS ::1
```

### IPv6 Host Discovery

```bash
# ICMPv6 ping
sudo rustnmap -PE 2001:db8::/64

# Neighbor Discovery Protocol
sudo rustnmap -PR 2001:db8::/64

# TCP SYN ping
sudo rustnmap -PS80 2001:db8::/64
```

### IPv6 with Options

```bash
# IPv6 with service detection
sudo rustnmap -sS -sV 2001:db8::1

# IPv6 with OS detection
sudo rustnmap -sS -O 2001:db8::1

# IPv6 full scan
sudo rustnmap -A 2001:db8::1
```

---

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Raw socket operations require root
sudo rustnmap -sS 192.168.1.1
```

**All Ports Filtered:**
- Check firewall rules
- Try different scan types
- Use timing template -T4
- Check if target is responsive with -sn

**Slow Scans:**
```bash
# Use faster timing
sudo rustnmap -T4 192.168.1.1

# Reduce retries
sudo rustnmap --max-retries 1 192.168.1.1

# Top ports only
sudo rustnmap --top-ports 100 192.168.1.1
```

**No Responses:**
```bash
# Skip host discovery
sudo rustnmap -Pn 192.168.1.1

# Check connectivity first
ping 192.168.1.1
sudo rustnmap -sn 192.168.1.1
```

### Debug Options

```bash
# Show packet trace
sudo rustnmap --packet-trace 192.168.1.1

# Verbose output
sudo rustnmap -vv 192.168.1.1

# Debug level
sudo rustnmap -d 192.168.1.1
```

### Getting Help

```bash
# General help
rustnmap --help

# Scan types help
rustnmap -h scan-types

# Timing help
rustnmap -h timing

# All options
rustnmap --help-all
```

---

## Examples by Use Case

### Network Audit

```bash
# Full network scan with all checks
sudo rustnmap -A -T4 -oA network-audit 192.168.1.0/24
```

### Web Server Scan

```bash
# Scan web servers
sudo rustnmap -sV -p 80,443,8080,8443 --script http-* 192.168.1.1
```

### Database Discovery

```bash
# Find database servers
sudo rustnmap -sV -p 3306,5432,1433,27017,6379,9200 192.168.1.0/24
```

### Vulnerability Scan

```bash
# Run vulnerability scripts
sudo rustnmap -sV --script vuln 192.168.1.1
```

### Stealth Scan

```bash
# Slow, fragmented, decoy scan
sudo rustnmap -sS -T0 -f -D RND:10 --data-length 20 192.168.1.1
```

### Compliance Check

```bash
# Check for common compliance issues
sudo rustnmap -sV -sC --script ssl-enum-ciphers,ssl-cert 192.168.1.1
```

---

## Best Practices

1. **Start with Host Discovery**
   ```bash
   sudo rustnmap -sn 192.168.1.0/24
   ```

2. **Scan Top Ports First**
   ```bash
   sudo rustnmap --top-ports 1000 targets.txt
   ```

3. **Use Appropriate Timing**
   - Internal networks: -T4
   - External/wan: -T3 or -T2
   - IDS evasion: -T1 or -T0

4. **Save All Output Formats**
   ```bash
   sudo rustnmap -oA scan-results 192.168.1.1
   ```

5. **Get Permission First**
   - Always obtain authorization
   - Document your scans
   - Respect scope limitations

---

**Disclaimer**: Only use RustNmap on networks you own or have explicit permission to scan. Unauthorized scanning may be illegal in your jurisdiction.
