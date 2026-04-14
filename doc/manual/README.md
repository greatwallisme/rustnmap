# RustNmap User Manual

> **Version**: 1.0.0
> **Status**: This document describes RustNmap 1.0.0 features. Version 2.0 is in development, see [CHANGELOG.md](../CHANGELOG.md).
> **Last Updated**: 2026-02-16

---

## Manual Overview

Welcome to the RustNmap User Manual. This manual provides comprehensive documentation for the RustNmap network scanner.

---

## Contents

| File | Description |
|------|-------------|
| [quick-reference.md](quick-reference.md) | Quick reference card for common tasks |
| [options.md](options.md) | Complete command-line options reference |
| [scan-types.md](scan-types.md) | Detailed scan type documentation |
| [output-formats.md](output-formats.md) | Output format specifications |
| [nse-scripts.md](nse-scripts.md) | NSE scripting engine guide |
| [exit-codes.md](exit-codes.md) | Exit codes and error handling |
| [environment.md](environment.md) | Environment variables |
| [configuration.md](configuration.md) | Configuration file format |

---

## Quick Start

### Installation

```bash
# Build from source
cargo build --release

# Install to system
sudo cp target/release/rustnmap /usr/local/bin/
```

### Basic Usage

```bash
# TCP SYN scan (requires root)
sudo rustnmap -sS 192.168.1.1

# TCP Connect scan (no root required)
rustnmap -sT 192.168.1.1

# Scan specific ports
sudo rustnmap -p 22,80,443 192.168.1.1

# Service detection
sudo rustnmap -sV 192.168.1.1

# OS detection
sudo rustnmap -O 192.168.1.1

# Full aggressive scan
sudo rustnmap -A 192.168.1.1
```

---

## Documentation Conventions

### Syntax Notation

- `<arg>` - Required argument
- `[arg]` - Optional argument
- `a|b` - Alternative options
- `-opt` - Short option
- `--option` - Long option

### Examples

All examples use `sudo` for scans requiring root privileges.

---

## Related Documentation

- [README](../../README.md) - Project overview
- [Architecture](../architecture.md) - System architecture
- [Manual](../README.md) - Manual overview

---

## Support

- GitHub Issues: https://github.com/greatwallisme/rust-nmap/issues
- GitHub Discussions: https://github.com/greatwallisme/rust-nmap/discussions

---

**Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before scanning networks you do not own.
