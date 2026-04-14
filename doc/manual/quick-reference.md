# RustNmap Quick Reference

> **Version**: 1.0.0
> **Status**: This document describes RustNmap 1.0.0 quick reference. Version 2.0 is in development, see [CHANGELOG.md](../CHANGELOG.md).

> **One-page reference for common RustNmap tasks**

---

## Target Specification

```bash
# Single IP
rustnmap 192.168.1.1

# Multiple IPs
rustnmap 192.168.1.1 192.168.1.2

# CIDR notation
rustnmap 192.168.1.0/24

# IP range
rustnmap 192.168.1.1-100

# Hostname
rustnmap example.com

# From file
rustnmap -iL targets.txt

# Exclude hosts
rustnmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

---

## Port Specification

```bash
# Single port
rustnmap -p 22 192.168.1.1

# Multiple ports
rustnmap -p 22,80,443 192.168.1.1

# Port range
rustnmap -p 1-1000 192.168.1.1

# All ports
rustnmap -p- 192.168.1.1

# Fast scan (top 100)
rustnmap -F 192.168.1.1

# Top N ports
rustnmap --top-ports 100 192.168.1.1

# Protocol specific
rustnmap -p T:80,U:53 192.168.1.1
```

---

## Scan Types

| Flag | Scan Type | Requires Root | Use Case |
|------|-----------|---------------|----------|
| `-sS` | TCP SYN | Yes | Stealth scan |
| `-sT` | TCP Connect | No | Standard scan |
| `-sU` | UDP | Yes | UDP ports |
| `-sF` | TCP FIN | Yes | Stealth (UNIX) |
| `-sN` | TCP NULL | Yes | Stealth (UNIX) |
| `-sX` | TCP XMAS | Yes | Stealth (UNIX) |
| `-sA` | TCP ACK | Yes | Firewall check |
| `-sM` | TCP Maimon | Yes | Stealth variant |
| `-sW` | TCP Window | Yes | Advanced scan |
| `-b` | FTP Bounce | No | FTP proxy scan |

---

## Host Discovery

```bash
# Ping scan only
sudo rustnmap -sn 192.168.1.0/24

# ICMP echo
sudo rustnmap -PE 192.168.1.0/24

# TCP SYN ping
sudo rustnmap -PS22,80,443 192.168.1.0/24

# TCP ACK ping
sudo rustnmap -PA80 192.168.1.0/24

# UDP ping
sudo rustnmap -PU53 192.168.1.0/24

# Skip discovery
sudo rustnmap -Pn 192.168.1.0/24
```

---

## Service Detection

```bash
# Basic service detection
sudo rustnmap -sV 192.168.1.1

# Version intensity 0-9
sudo rustnmap -sV --version-intensity 5 192.168.1.1

# Light version scan
sudo rustnmap -sV --version-intensity 2 192.168.1.1

# All probes
sudo rustnmap -sV --version-intensity 9 192.168.1.1
```

---

## OS Detection

```bash
# OS detection
sudo rustnmap -O 192.168.1.1

# Limit matches
sudo rustnmap -O --osscan-limit 192.168.1.1

# Aggressive guess
sudo rustnmap -O --osscan-guess 192.168.1.1

# Combined scan
sudo rustnmap -A 192.168.1.1  # -sV -sC -O --traceroute
```

---

## Timing Templates

| Template | Flag | Delay | Use Case |
|----------|------|-------|----------|
| Paranoid | `-T0` | 5 min | IDS evasion |
| Sneaky | `-T1` | 15 sec | IDS evasion |
| Polite | `-T2` | 0.4 sec | Slow network |
| Normal | `-T3` | Default | General use |
| Aggressive | `-T4` | Faster | Fast network |
| Insane | `-T5` | Very fast | Local network |

```bash
# Examples
sudo rustnmap -T0 192.168.1.1   # Paranoid
sudo rustnmap -T4 192.168.1.1   # Aggressive
```

---

## Output Formats

```bash
# Normal output
sudo rustnmap -oN results.nmap 192.168.1.1

# XML output
sudo rustnmap -oX results.xml 192.168.1.1

# JSON output
sudo rustnmap -oJ results.json 192.168.1.1

# NDJSON output
sudo rustnmap --output-ndjson results.ndjson 192.168.1.1

# Markdown output
sudo rustnmap --output-markdown results.md 192.168.1.1

# Grepable output
sudo rustnmap -oG results.gnmap 192.168.1.1

# Script kiddie (console)
sudo rustnmap --output-script-kiddie 192.168.1.1

# All formats
sudo rustnmap -oA results 192.168.1.1

# Append output
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

---

## NSE Scripts

```bash
# Default scripts
sudo rustnmap -sC 192.168.1.1

# Specific script
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts
sudo rustnmap --script http-title,http-headers 192.168.1.1

# Script category
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1

# Script with arguments
sudo rustnmap --script http-title --script-args "http.useragent=Mozilla" 192.168.1.1

# List scripts
rustnmap --script-help default
```

---

## Evasion Techniques

```bash
# Fragment packets
sudo rustnmap -f 192.168.1.1
sudo rustnmap -f8 192.168.1.1

# Decoy scan
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1
sudo rustnmap -D RND:10 192.168.1.1

# Source IP spoofing
sudo rustnmap -S 192.168.1.100 192.168.1.1

# Source port
sudo rustnmap -g 53 192.168.1.1

# Custom data
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1
sudo rustnmap --data-string "Hello" 192.168.1.1
sudo rustnmap --data-length 100 192.168.1.1
```

---

## Verbosity

```bash
# Verbose
sudo rustnmap -v 192.168.1.1
sudo rustnmap -vv 192.168.1.1

# Debug
sudo rustnmap -d 192.168.1.1
sudo rustnmap -dd 192.168.1.1

# Quiet
sudo rustnmap -q 192.168.1.1

# Show reasons
sudo rustnmap --reason 192.168.1.1

# Packet trace
sudo rustnmap --packet-trace 192.168.1.1
```

---

## Common Scenarios

### Network Audit

```bash
# Full network scan
sudo rustnmap -A -T4 -oA network-audit 192.168.1.0/24
```

### Web Server Scan

```bash
sudo rustnmap -sV -p 80,443,8080,8443 --script http-* 192.168.1.1
```

### Database Discovery

```bash
sudo rustnmap -sV -p 3306,5432,1433,27017,6379,9200 192.168.1.0/24
```

### Vulnerability Scan

```bash
sudo rustnmap -sV --script vuln 192.168.1.1
```

### Stealth Scan

```bash
sudo rustnmap -sS -T0 -f -D RND:10 --data-length 20 192.168.1.1
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | No targets specified |
| `4` | Network error |
| `5` | Permission denied |

---

## Help

```bash
# General help
rustnmap --help
```
