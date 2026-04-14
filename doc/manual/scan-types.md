# RustNmap Scan Types

> **Version**: 1.0.0
> **Status**: This document describes the scan types in RustNmap 1.0.0. Version 2.0 is under development; see [CHANGELOG.md](../CHANGELOG.md).

> Detailed documentation for each scan type

---

## Overview

RustNmap supports 12 different scan types, each designed for specific scenarios. Understanding how each scan works helps you choose the right technique for your target environment.

---

## TCP SYN Scan (`-sS`)

### Description

TCP SYN scan is the default and most popular scan type. It performs a "half-open" scan by sending SYN packets and analyzing responses without completing the TCP 3-way handshake.

### How It Works

```
Scanner          Target
   |    SYN      |
   | ----------> |
   |  SYN-ACK    |  <- Port is OPEN
   | <---------- |
   |    RST      |  <- RST sent instead of ACK
   | ----------> |

   |    SYN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |

   |    SYN      |
   | ----------> |
   |   (timeout) |  <- Port is FILTERED
   |             |
```

### Usage

```bash
# Default scan
sudo rustnmap -sS 192.168.1.1

# With port specification
sudo rustnmap -sS -p 22,80,443 192.168.1.1

# With service detection
sudo rustnmap -sS -sV 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Reliability | High |
| Firewall friendly | Moderate |

### Advantages

1. **Stealthy**: Does not complete TCP connection, less likely to be logged
2. **Fast**: No need to complete 3-way handshake
3. **Reliable**: Works against most TCP stacks

### Disadvantages

1. Requires root/administrator privileges
2. May still be detected by modern IDS/IPS systems

---

## TCP Connect Scan (`-sT`)

### Description

TCP Connect scan performs a full 3-way TCP handshake. This is the default when SYN scan is not available (no root privileges).

### How It Works

```
Scanner          Target
   |    SYN      |
   | ----------> |
   |  SYN-ACK    |  <- Port is OPEN
   | <---------- |
   |    ACK      |  <- Complete handshake
   | ----------> |
   |   (data)    |
   | <---------> |
   |  RST/FIN    |  <- Close connection
   | ----------> |

   |    SYN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage

```bash
# Without root
rustnmap -sT 192.168.1.1

# Full port scan
rustnmap -sT -p- 192.168.1.1

# With OS detection
rustnmap -sT -O 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | No |
| Stealthy | No |
| Speed | Moderate |
| Reliability | High |
| Logged | Yes |

### Advantages

1. **No root required**: Works with standard user privileges
2. **Reliable**: Standard TCP connection
3. **Universal**: Works on all systems

### Disadvantages

1. **Logged**: Full connection is logged by target
2. **Slower**: Must complete full handshake
3. **Resource intensive**: Uses more resources on target

---

## UDP Scan (`-sU`)

### Description

UDP scan detects open UDP ports by sending UDP packets and analyzing responses (or lack thereof). UDP scanning is generally slower than TCP scanning due to the connectionless nature of UDP.

### How It Works

```
Scanner          Target
   |   UDP       |
   | ----------> |
   |   UDP       |  <- Port is OPEN (application response)
   | <---------- |

   |   UDP       |
   | ----------> |
   |   ICMP      |  <- Port is CLOSED (ICMP port unreachable)
   | <---------- |
   |  Unreachable|

   |   UDP       |
   | ----------> |
   |  (timeout)  |  <- Port is OPEN or FILTERED
   |             |
```

### Usage

```bash
# UDP scan
sudo rustnmap -sU 192.168.1.1

# Common UDP ports
sudo rustnmap -sU -p 53,67,68,123,161,162 192.168.1.1

# With version detection
sudo rustnmap -sU -sV 192.168.1.1

# Combine with TCP
sudo rustnmap -sS -sU 192.168.1.1
```

### Common UDP Ports

| Port | Service | Description |
|------|---------|-------------|
| 53 | DNS | Domain Name System |
| 67/68 | DHCP | Dynamic Host Configuration |
| 69 | TFTP | Trivial File Transfer |
| 123 | NTP | Network Time Protocol |
| 161/162 | SNMP | Simple Network Management |
| 500 | ISAKMP | VPN Key Exchange |
| 514 | Syslog | System Logging |
| 520 | RIP | Routing Information |

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Moderate |
| Speed | Slow |
| Reliability | Moderate |
| Firewall friendly | Low |

### Advantages

1. **Finds UDP services**: Detects services TCP scans miss
2. **Standard method**: Well-established technique

### Disadvantages

1. **Slow**: Many timeouts due to no response
2. **Ambiguous results**: Difficult to distinguish open from filtered
3. **Resource intensive**: Requires sending many packets

---

## TCP FIN Scan (`-sF`)

### Description

FIN scan sends packets with only the FIN flag set. According to RFC 793, closed ports should respond with RST, while open ports should ignore the packet.

### How It Works

```
Scanner          Target
   |    FIN      |
   | ----------> |
   |   (nothing) |  <- Port is OPEN (per RFC 793)
   |             |

   |    FIN      |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |

   |    FIN      |
   | ----------> |
   |   RST       |  <- Port is OPEN (non-RFC compliant, e.g., Windows)
   | <---------- |     or CLOSED/FILTERED
```

### Usage

```bash
# FIN scan
sudo rustnmap -sF 192.168.1.1

# Specific ports
sudo rustnmap -sF -p 22,80,443 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Best for | UNIX systems |
| Windows response | All closed |

### Platform Differences

| OS | Behavior |
|----|----------|
| UNIX/Linux | Follows RFC 793 |
| Windows | Sends RST for all ports |
| Cisco | Follows RFC 793 |
| BSD | Follows RFC 793 |

---

## TCP NULL Scan (`-sN`)

### Description

NULL scan sends packets with no TCP flags set. Like FIN scan, RFC 793 specifies that closed ports should respond with RST while open ports ignore the packet.

### How It Works

```
Scanner          Target
   |   (no flags)|
   | ----------> |
   |   (nothing) |  <- Port is OPEN
   |             |

   |   (no flags)|
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage

```bash
# NULL scan
sudo rustnmap -sN 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Best for | UNIX systems |

---

## TCP XMAS Scan (`-sX`)

### Description

XMAS scan sends packets with FIN, PSH, and URG flags set, "lighting up the packet like a Christmas tree." Like other stealth scans, it relies on RFC 793 behavior.

### How It Works

```
Scanner          Target
   | FIN+PSH+URG |
   | ----------> |
   |   (nothing) |  <- Port is OPEN
   |             |

   | FIN+PSH+URG |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage

```bash
# XMAS scan
sudo rustnmap -sX 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Speed | Fast |
| Best for | UNIX systems |
| Packet appearance | Unusual |

---

## TCP ACK Scan (`-sA`)

### Description

ACK scan is used to map firewall rulesets, not to determine open ports. It sends ACK packets and analyzes whether ports are filtered or unfiltered.

### How It Works

```
Scanner          Target
   |    ACK      |
   | ----------> |
   |    RST      |  <- Port is UNFILTERED (regardless of state)
   | <---------- |

   |    ACK      |
   | ----------> |
   |   (timeout) |  <- Port is FILTERED
   |             |
   |   or ICMP   |
   |  admin-proh |
```

### Usage

```bash
# ACK scan for firewall mapping
sudo rustnmap -sA 192.168.1.1

# Determine firewall rules
sudo rustnmap -sA -p 1-65535 192.168.1.1
```

### Port States

| Response | State | Meaning |
|----------|-------|---------|
| RST | unfiltered | Port is not filtered by firewall |
| Timeout/ICMP | filtered | Port is filtered by firewall |

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Best for | Firewall mapping |
| Determines | Filtered status |

---

## TCP Window Scan (`-sW`)

### Description

Window scan is similar to ACK scan but examines the TCP Window field of RST responses to determine if ports are open or closed.

### How It Works

```
Scanner          Target
   |    ACK      |
   | ----------> |
   | RST(Window) |  <- Window > 0: OPEN
   | <---------- |     Window = 0: CLOSED
```

### Usage

```bash
# Window scan
sudo rustnmap -sW 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Reliability | Low (system dependent) |
| Best for | Specific systems |

---

## TCP Maimon Scan (`-sM`)

### Description

Maimon scan (named after Uriel Maimon) sends packets with FIN and ACK flags. Some BSD systems drop the packet if port is open (revealing it).

### How It Works

```
Scanner          Target
   |  FIN+ACK    |
   | ----------> |
   |   (nothing) |  <- Port is OPEN (on some BSD)
   |             |

   |  FIN+ACK    |
   | ----------> |
   |    RST      |  <- Port is CLOSED
   | <---------- |
```

### Usage

```bash
# Maimon scan
sudo rustnmap -sM 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | Yes |
| Stealthy | Yes |
| Best for | BSD systems |

---

## FTP Bounce Scan (`-b`)

### Description

FTP bounce attack exploits FTP servers with proxy capabilities to bounce scans through them. The FTP server acts as a proxy, making the scan appear to originate from the FTP server.

### How It Works

```
Scanner        FTP Server      Target
   |   Connect  |              |
   | ---------> |              |
   |   Login    |              |
   | ---------> |              |
   |   PORT     |              |
   | ---------> |              |
   |   PASV     |              |
   | ---------> |              |
   |            |   Connect    |
   |            | ---------->  |  <- FTP server connects to target
   |            |   Response   |
   |            | <----------  |
   |  Response  |              |
   | <--------- |              |
```

### Usage

```bash
# FTP bounce scan
rustnmap -b ftp.example.com 192.168.1.1

# With username/password
rustnmap -b user:pass@ftp.example.com:21 192.168.1.1
```

### Characteristics

| Feature | Value |
|---------|-------|
| Requires root | No |
| Stealthy | Yes |
| Requires | Vulnerable FTP server |
| Modern usage | Rare |

### Advantages

1. **No root required**
2. **Hides source address**

### Disadvantages

1. **Rare today**: Modern FTP servers don't allow this
2. **Slow**: Requires FTP protocol overhead
3. **Limited ports**: Can only scan ports FTP server can reach

---

## Scan Type Comparison

| Scan Type | Root | Stealth | Speed | Reliability | Best For |
|-----------|------|---------|-------|-------------|----------|
| `-sS` SYN | Yes | High | Fast | High | General use |
| `-sT` Connect | No | Low | Medium | High | No root |
| `-sU` UDP | Yes | Medium | Slow | Medium | UDP services |
| `-sF` FIN | Yes | High | Fast | Low | UNIX stealth |
| `-sN` NULL | Yes | High | Fast | Low | UNIX stealth |
| `-sX` XMAS | Yes | High | Fast | Low | UNIX stealth |
| `-sA` ACK | Yes | High | Fast | Medium | Firewall mapping |
| `-sW` Window | Yes | High | Fast | Low | Advanced |
| `-sM` Maimon | Yes | High | Fast | Low | BSD systems |
| `-b` FTP Bounce | No | High | Slow | Low | Legacy systems |

---

## Choosing the Right Scan

### Quick Decision Guide

```
Do you have root/admin?
+-- No  -> Use -sT (Connect scan)
+-- Yes -> What is your goal?
    +-- General port scanning   -> -sS (SYN scan)
    +-- UDP services            -> -sU (UDP scan)
    +-- Firewall rule mapping   -> -sA (ACK scan)
    +-- IDS evasion on UNIX     -> -sF/-sN/-sX
```

### Scenario Examples

#### Internal Network Audit

```bash
# Fast SYN scan with service detection
sudo rustnmap -sS -sV -T4 -p- 192.168.1.0/24
```

#### External Penetration Test

```bash
# Stealthy scan with decoys
sudo rustnmap -sS -T2 -f -D RND:10 10.0.0.1
```

#### Firewall Assessment

```bash
# ACK scan to map rules
sudo rustnmap -sA -p- 192.168.1.1
```

#### No Root Access

```bash
# Connect scan
rustnmap -sT -p 22,80,443,8080 target.example.com
```

---

## Port State Definitions

| State | Meaning |
|-------|---------|
| `open` | Service is listening |
| `closed` | Port accessible, no service |
| `filtered` | Cannot determine state (firewall) |
| `unfiltered` | Port accessible (ACK scan) |
| `open|filtered` | Cannot determine if open or filtered |
| `closed|filtered` | Cannot determine if closed or filtered |

---

## References

- [RFC 793](https://tools.ietf.org/html/rfc793) - TCP Specification
- Nmap Scan Types Documentation
- Targeted Cyber Intrusion Detection: The Xmas Scan
