# Configuration File

> **Version**: 1.0.0
> **Status**: This document describes the RustNmap 1.0.0 configuration file. Version 2.0 is under development; see [CHANGELOG.md](../CHANGELOG.md).

> **Configuration file format and options**

---

## Overview

RustNmap supports configuration files for persistent settings. Configuration files use a simple key-value format similar to INI files.

---

## Configuration File Locations

RustNmap searches for configuration files in the following order:

| Order | Location | Description |
|-------|----------|-------------|
| 1 | `./rustnmap.conf` | Current directory |
| 2 | `~/.rustnmap/rustnmap.conf` | User home directory |
| 3 | `~/.rustnmap.conf` | User home (alternate) |
| 4 | `/etc/rustnmap/rustnmap.conf` | System-wide |
| 5 | `/etc/rustnmap.conf` | System-wide (alternate) |

---

## Configuration File Format

### Basic Syntax

```ini
# This is a comment
key = value

# Boolean values
debug = true
verbose = yes
quiet = no

# Numeric values
timing = 4
max-retries = 3

# String values
output-format = xml
log-file = /var/log/rustnmap.log

# Lists (comma-separated)
default-ports = 22,80,443
exclude-ports = 25,110,143

# Multiple values per key
exclude = 192.168.1.1
exclude = 192.168.1.254
```

### Sections

Configuration files support sections for organizing options:

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

## Configuration Options

### Scan Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `scan-type` | string | Default scan type (`syn`, `connect`, `udp`, etc.) | `syn` |
| `timing` | integer | Timing template (0-5) | `3` |
| `max-retries` | integer | Maximum retry attempts | `10` |
| `host-timeout` | integer | Host timeout in seconds | `0` (no timeout) |
| `scan-delay` | integer | Delay between probes in ms | `0` |
| `min-rate` | integer | Minimum packets per second | `0` |
| `max-rate` | integer | Maximum packets per second | `0` |

**Example:**

```ini
[scan]
scan-type = syn
timing = 4
max-retries = 3
host-timeout = 300
```

---

### Port Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `default-ports` | list | Default ports to scan | `top-1000` |
| `exclude-ports` | list | Ports to exclude | (none) |
| `fast-scan` | boolean | Use fast scan (top 100) | `false` |
| `all-ports` | boolean | Scan all 65535 ports | `false` |

**Example:**

```ini
[ports]
default-ports = 22,80,443,8080,8443
exclude-ports = 25,110,143
fast-scan = false
```

---

### Host Discovery

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `skip-ping` | boolean | Skip host discovery | `false` |
| `ping-type` | string | Ping type (`icmp`, `tcp`, `udp`, `arp`) | `auto` |
| `tcp-ping-ports` | list | TCP ping ports | `80,443` |
| `udp-ping-ports` | list | UDP ping ports | `53,161` |

**Example:**

```ini
[discovery]
skip-ping = false
ping-type = tcp
tcp-ping-ports = 22,80,443,3389
udp-ping-ports = 53,161,162
```

---

### Service Detection

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `service-detection` | boolean | Enable service detection | `false` |
| `version-intensity` | integer | Version detection intensity (0-9) | `7` |
| `version-light` | boolean | Use light version detection | `false` |
| `version-all` | boolean | Use all version probes | `false` |

**Example:**

```ini
[service]
service-detection = true
version-intensity = 5
version-light = false
```

---

### OS Detection

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `os-detection` | boolean | Enable OS detection | `false` |
| `oscan-limit` | boolean | Limit OS detection | `false` |
| `oscan-guess` | boolean | Aggressive OS guessing | `false` |

**Example:**

```ini
[os]
os-detection = true
oscan-limit = false
oscan-guess = true
```

---

### Output Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `output-format` | string | Output format (`normal`, `xml`, `json`, `grepable`) | `normal` |
| `output-directory` | string | Default output directory | `.` |
| `append-output` | boolean | Append to output files | `false` |
| `show-reason` | boolean | Show port state reasons | `false` |
| `open-only` | boolean | Show only open ports | `false` |
| `packet-trace` | boolean | Show packet trace | `false` |

**Example:**

```ini
[output]
output-format = xml
output-directory = /var/log/scans
append-output = false
show-reason = true
open-only = false
```

---

### NSE Scripts

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `default-scripts` | boolean | Run default scripts | `false` |
| `script-timeout` | integer | Script timeout in seconds | `120` |
| `script-args` | string | Default script arguments | (none) |
| `script-categories` | list | Script categories to run | (none) |

**Example:**

```ini
[scripts]
default-scripts = true
script-timeout = 180
script-args = http.useragent=Mozilla/5.0
script-categories = safe,discovery
```

---

### Evasion Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `fragment-mtu` | integer | Fragment MTU size | (none) |
| `decoys` | list | Decoy IP addresses | (none) |
| `source-ip` | string | Spoofed source IP | (none) |
| `source-port` | integer | Fixed source port | (none) |
| `data-length` | integer | Random data length | `0` |
| `randomize-hosts` | boolean | Randomize target order | `false` |

**Example:**

```ini
[evasion]
fragment-mtu = 8
source-port = 53
randomize-hosts = true
```

---

### Network Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `interface` | string | Network interface | (auto) |
| `source-ip` | string | Source IP address | (auto) |
| `dns-servers` | list | Custom DNS servers | (system) |
| `system-dns` | boolean | Use system DNS | `true` |

**Example:**

```ini
[network]
interface = eth0
source-ip = 192.168.1.100
dns-servers = 8.8.8.8,8.8.4.4
system-dns = false
```

---

### Logging Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `verbose` | integer | Verbosity level (0-3) | `0` |
| `debug` | integer | Debug level (0-3) | `0` |
| `quiet` | boolean | Quiet mode | `false` |
| `log-file` | string | Log file path | (none) |

**Example:**

```ini
[logging]
verbose = 1
debug = 0
quiet = false
log-file = /var/log/rustnmap.log
```

---

## Complete Configuration Example

### Basic Configuration

```ini
# ~/.rustnmap/rustnmap.conf
# Basic RustNmap configuration

[default]
# Scan options
timing = 3
max-retries = 3

# Output options
verbose = 1
show-reason = true

# Service detection
service-detection = true
version-intensity = 5
```

### Security Analyst

```ini
# ~/.rustnmap/rustnmap.conf
# Security analyst configuration

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

### Stealth Scanning

```ini
# ~/.rustnmap/rustnmap.conf
# Stealth scanning configuration

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
# Use specific interface
interface = eth0

[output]
# Minimal output
quiet = true
show-reason = false
```

### Network Administrator

```ini
# /etc/rustnmap/rustnmap.conf
# System-wide configuration

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

## Configuration with Environment Variables

Configuration files can reference environment variables:

```ini
[default]
# Use environment variable
output-directory = ${HOME}/scans

# With default value
log-file = ${RUSTNMAP_LOG_FILE:-/tmp/rustnmap.log}

[scripts]
# Script directory from env
script-directory = ${RUSTNMAP_SCRIPTS}
```

---

## Loading Configuration

### Automatic Loading

RustNmap automatically loads configuration from the locations listed above.

---

## Configuration Precedence

Options are applied in the following order (later overrides earlier):

1. Built-in defaults
2. System-wide configuration (`/etc/rustnmap.conf`)
3. User configuration (`~/.rustnmap.conf`)
4. Local configuration (`./rustnmap.conf`)
5. Environment variables
6. Command-line options

---

## Troubleshooting

### Configuration Not Loading

```bash
# Check file permissions
ls -la ~/.rustnmap/rustnmap.conf

# Check file location
find ~ -name "rustnmap.conf" 2>/dev/null

# Verify syntax
cat ~/.rustnmap/rustnmap.conf | grep -v "^#" | grep -v "^$"
```

### Invalid Option

```bash
# Error: Invalid option 'timingg'
# Check spelling
# timingg -> timing

# Check available options
rustnmap --help
```

---

## Configuration Templates

### Quick Templates

Save these as starting points:

**fast-scan.conf:**
```ini
[default]
timing = 5
max-retries = 2
fast-scan = true
```

**stealth-scan.conf:**
```ini
[default]
timing = 1
max-retries = 1
scan-delay = 5000
randomize-hosts = true

[evasion]
fragment-mtu = 8
```

**comprehensive-scan.conf:**
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

## Related Documentation

- [Environment Variables](environment.md) - Environment configuration
- [Options Reference](options.md) - Command-line options
