# RustNmap Environment Variables

> **Version**: 1.0.0
> **Status**: This document describes environment variables for RustNmap 1.0.0. Version 2.0 is under development; see [CHANGELOG.md](../CHANGELOG.md) for details.

> Environment variables reference for RustNmap

---

## Overview

RustNmap supports several environment variables that control various aspects of its behavior. These can be set in your shell or in configuration files.

---

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `RUSTNMAP_HOME` | RustNmap home directory | `~/.rustnmap` |
| `RUSTNMAP_SCRIPTS` | Scripts directory | `/usr/share/rustnmap/scripts` |
| `RUSTNMAP_DATA` | Data directory | `/usr/share/rustnmap` |
| `RUSTNMAP_OUTPUT` | Default output directory | Current directory |
| `RUSTNMAP_OPTIONS` | Default command-line options | None |
| `RUSTNMAP_TARGETS` | Default target list | None |

---

## Path Variables

### RUSTNMAP_HOME

**Description**

Sets the RustNmap home directory for user-specific files.

**Default**

```
~/.rustnmap
```

**Usage**

```bash
# Set custom home directory
export RUSTNMAP_HOME=/opt/rustnmap

# Files stored in:
# $RUSTNMAP_HOME/scripts/     # User scripts
# $RUSTNMAP_HOME/data/        # User data
# $RUSTNMAP_HOME/config/      # User config
```

---

### RUSTNMAP_SCRIPTS

**Description**

Sets the directory containing NSE scripts.

**Default**

```
/usr/share/rustnmap/scripts
```

**Usage**

```bash
# Use custom scripts directory
export RUSTNMAP_SCRIPTS=/path/to/custom/scripts

# Run with custom scripts
rustnmap --script my-script 192.168.1.1
```

---

### RUSTNMAP_DATA

**Description**

Sets the data directory for fingerprint databases and other data files.

**Default**

```
/usr/share/rustnmap
```

**Contents**

```
$RUSTNMAP_DATA/
├── nmap-service-probes      # Service detection probes
├── nmap-os-db               # OS fingerprints
├── nmap-mac-prefixes        # MAC vendor database
└── scripts/                 # NSE scripts
```

**Usage**

```bash
# Use custom data directory
export RUSTNMAP_DATA=/var/lib/rustnmap

# Update databases in custom location
rustnmap --script-updatedb
```

---

## Default Options

### RUSTNMAP_OPTIONS

**Description**

Sets default command-line options that are automatically added to every scan.

**Default**

```
(none)
```

**Usage**

```bash
# Always use verbose output
export RUSTNMAP_OPTIONS="-v"

# Always use specific timing
export RUSTNMAP_OPTIONS="-T4 --reason"

# Multiple options
export RUSTNMAP_OPTIONS="-v -T4 --open"

# Now 'rustnmap 192.168.1.1' is equivalent to:
# rustnmap -v -T4 --open 192.168.1.1
```

**Note**

Options specified on the command line override environment variable options.

---

### RUSTNMAP_TARGETS

**Description**

Sets default target hosts if none are specified on the command line.

**Default**

```
(none)
```

**Usage**

```bash
# Set default network to scan
export RUSTNMAP_TARGETS="192.168.1.0/24"

# Run scan without specifying targets
rustnmap -sS  # Scans 192.168.1.0/24

# Override with command-line target
rustnmap -sS 10.0.0.1  # Scans 10.0.0.1, not default
```

---

## Network Configuration

### RUSTNMAP_INTERFACE

**Description**

Sets the default network interface to use for scanning.

**Default**

```
(auto-detected)
```

**Usage**

```bash
# Always use eth0
export RUSTNMAP_INTERFACE=eth0

# Override per-scan
rustnmap -e wlan0 192.168.1.1
```

---

### RUSTNMAP_SOURCE_IP

**Description**

Sets the default source IP address for packets.

**Default**

```
(auto-detected)
```

**Usage**

```bash
# Set default source IP
export RUSTNMAP_SOURCE_IP=192.168.1.100

# Override per-scan
rustnmap -S 10.0.0.100 192.168.1.1
```

---

## Output Configuration

### RUSTNMAP_OUTPUT_DIR

**Description**

Sets the default directory for output files.

**Default**

```
(current working directory)
```

**Usage**

```bash
# Set default output directory
export RUSTNMAP_OUTPUT_DIR=/var/log/scans

# Results saved to:
# /var/log/scans/scan_results.nmap
rustnmap -oN scan_results.nmap 192.168.1.1
```

---

### RUSTNMAP_OUTPUT_FORMAT

**Description**

Sets the default output format.

**Default**

```
normal
```

**Values**

- `normal` - Human-readable text
- `xml` - XML format
- `json` - JSON format
- `grepable` - Grepable format

**Usage**

```bash
# Always output XML
export RUSTNMAP_OUTPUT_FORMAT=xml

# Override per-scan
rustnmap -oN normal.txt 192.168.1.1
```

---

## Script Configuration

### RUSTNMAP_SCRIPT_ARGS

**Description**

Sets default arguments for NSE scripts.

**Default**

```
(none)
```

**Usage**

```bash
# Set default User-Agent for HTTP scripts
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"

# Multiple default arguments
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla,smb.domain=WORKGROUP"
```

---

### RUSTNMAP_SCRIPT_TIMEOUT

**Description**

Sets the default timeout for script execution (in seconds).

**Default**

```
120
```

**Usage**

```bash
# Increase default script timeout
export RUSTNMAP_SCRIPT_TIMEOUT=300

# Decrease for faster scans
export RUSTNMAP_SCRIPT_TIMEOUT=60
```

---

## Performance Configuration

### RUSTNMAP_TIMING

**Description**

Sets the default timing template.

**Default**

```
3 (Normal)
```

**Values**

| Value | Template | Description |
|-------|----------|-------------|
| `0` | Paranoid | Very slow, IDS evasion |
| `1` | Sneaky | Slow, IDS evasion |
| `2` | Polite | Moderate speed |
| `3` | Normal | Default |
| `4` | Aggressive | Fast |
| `5` | Insane | Very fast |

**Usage**

```bash
# Always use aggressive timing
export RUSTNMAP_TIMING=4

# Override per-scan
rustnmap -T2 192.168.1.1
```

---

### RUSTNMAP_MIN_RATE

**Description**

Sets the minimum packet rate (packets per second).

**Default**

```
(auto)
```

**Usage**

```bash
# Ensure minimum rate
export RUSTNMAP_MIN_RATE=100

rustnmap 192.168.1.1  # Uses --min-rate 100
```

---

### RUSTNMAP_MAX_RETRIES

**Description**

Sets the maximum number of port scan probe retransmissions.

**Default**

```
10
```

**Usage**

```bash
# Reduce retries for faster scans
export RUSTNMAP_MAX_RETRIES=2

# Increase for unreliable networks
export RUSTNMAP_MAX_RETRIES=20
```

---

## Security Configuration

### RUSTNMAP_NO_PING

**Description**

Disables host discovery by default.

**Default**

```
false
```

**Usage**

```bash
# Always skip ping scan
export RUSTNMAP_NO_PING=1

# Equivalent to always using -Pn
rustnmap 192.168.1.1  # Scans all targets without ping
```

---

### RUSTNMAP_RANDOMIZE

**Description**

Randomizes target order by default.

**Default**

```
false
```

**Usage**

```bash
# Always randomize targets
export RUSTNMAP_RANDOMIZE=1

# Equivalent to always using --randomize-hosts
rustnmap 192.168.1.0/24  # Random order
```

---

## Logging Configuration

### RUSTNMAP_LOG_LEVEL

**Description**

Sets the default logging level.

**Default**

```
warn
```

**Values**

- `error` - Error messages only
- `warn` - Warnings and errors
- `info` - Informational messages
- `debug` - Debug messages
- `trace` - All messages

**Usage**

```bash
# Enable debug logging
export RUSTNMAP_LOG_LEVEL=debug

# Minimal logging
export RUSTNMAP_LOG_LEVEL=error
```

---

### RUSTNMAP_LOG_FILE

**Description**

Sets the log file path.

**Default**

```
(stderr)
```

**Usage**

```bash
# Log to file
export RUSTNMAP_LOG_FILE=/var/log/rustnmap.log

# Disable file logging
unset RUSTNMAP_LOG_FILE
```

---

## Setting Environment Variables

### Temporary (Current Session)

```bash
# Set for current session only
export RUSTNMAP_OPTIONS="-v -T4"

# Unset
unset RUSTNMAP_OPTIONS
```

### Permanent (Bash)

Add to `~/.bashrc` or `~/.bash_profile`:

```bash
# RustNmap configuration
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=180
```

Then reload:

```bash
source ~/.bashrc
```

### Permanent (Zsh)

Add to `~/.zshrc`:

```bash
# RustNmap configuration
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason"
```

### System-wide

Add to `/etc/environment` or `/etc/profile.d/rustnmap.sh`:

```bash
# /etc/profile.d/rustnmap.sh
export RUSTNMAP_DATA="/usr/share/rustnmap"
export RUSTNMAP_SCRIPTS="/usr/share/rustnmap/scripts"
```

---

## Viewing Environment Variables

### List All RustNmap Variables

```bash
# Show all RustNmap environment variables
env | grep RUSTNMAP

# Show with values
env | grep RUSTNMAP | sort
```

### Check Specific Variable

```bash
# Check specific variable
echo $RUSTNMAP_OPTIONS
echo $RUSTNMAP_HOME
echo $RUSTNMAP_TIMING
```

### In Scripts

```bash
#!/bin/bash

# Check if variable is set
if [ -n "$RUSTNMAP_OPTIONS" ]; then
    echo "Default options: $RUSTNMAP_OPTIONS"
else
    echo "No default options set"
fi

# Use with default fallback
OPTIONS="${RUSTNMAP_OPTIONS:--T3}"
rustnmap $OPTIONS 192.168.1.1
```

---

## Complete Configuration Example

### Scanning Workstation

```bash
# ~/.bashrc

# RustNmap configuration
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v --reason --open"
export RUSTNMAP_TIMING=4
export RUSTNMAP_SCRIPT_TIMEOUT=120
export RUSTNMAP_LOG_LEVEL=info
export RUSTNMAP_OUTPUT_DIR="$HOME/scans"

# Create directories if they don't exist
mkdir -p "$RUSTNMAP_HOME/scripts"
mkdir -p "$RUSTNMAP_OUTPUT_DIR"
```

### Security Analyst

```bash
# ~/.bashrc

# RustNmap configuration for security work
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T3 --reason --traceroute"
export RUSTNMAP_SCRIPT_ARGS="http.useragent=Mozilla/5.0"
export RUSTNMAP_OUTPUT_DIR="$HOME/security-audits"
export RUSTNMAP_LOG_LEVEL=debug
export RUSTNMAP_LOG_FILE="$HOME/logs/rustnmap.log"
```

### Stealth Scanning

```bash
# ~/.bashrc

# RustNmap configuration for stealth scanning
export RUSTNMAP_HOME="$HOME/.rustnmap"
export RUSTNMAP_OPTIONS="-v -T1 --randomize-hosts"
export RUSTNMAP_TIMING=1
export RUSTNMAP_MIN_RATE=1
export RUSTNMAP_MAX_RETRIES=1
export RUSTNMAP_RANDOMIZE=1
```

---

## Environment Variable Precedence

Options are applied in the following order (later overrides earlier):

1. Default values
2. Environment variables
3. Configuration file settings
4. Command-line options

Example:

```bash
# Environment sets default timing
export RUSTNMAP_TIMING=3

# Config file overrides to aggressive
# (in rustnmap.conf: timing = 4)

# Command line overrides everything
rustnmap -T5 192.168.1.1  # Uses -T5 (Insane)
```

---

## Related Documentation

- [Configuration](configuration.md) - Configuration file options
- [Options Reference](options.md) - Command-line options
