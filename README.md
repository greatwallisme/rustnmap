# RustNmap - Rust Network Mapper

> **Version**: 1.0.0
> **Status**: Production Ready
> **Platform**: Linux x86_64 (AMD64)
> **Language**: Rust 1.80+

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/greatwallisme/rust-nmap)
[![Tests](https://img.shields.io/badge/tests-970%2B%20passing-brightgreen)](https://github.com/greatwallisme/rust-nmap)
[![Coverage](https://img.shields.io/badge/coverage-63.77%25-yellow)](https://github.com/greatwallisme/rust-nmap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**[中文文档](README.zh.md)** | [User Manual](doc/manual/) | [User Guide](doc/user-guide.md)

---

## Overview

RustNmap is a modern, high-performance network scanning tool written in Rust, providing 100% functional parity with Nmap while leveraging Rust's memory safety and async capabilities.

**Key Features:**
- **12 Scan Types**: SYN, Connect, UDP, FIN, NULL, XMAS, ACK, Maimon, Window, IP Protocol, Idle, FTP Bounce
- **Service & OS Detection**: 6000+ service probes, 5000+ OS signatures
- **NSE Scripting**: Full Lua 5.4 engine with Nmap library compatibility
- **5 Output Formats**: Normal, XML, JSON, Grepable, Script Kiddie
- **Advanced Evasion**: Fragmentation, decoys, spoofing, timing control

---

## Quick Start

### Installation

```bash
git clone https://github.com/greatwallisme/rust-nmap.git
cd rust-nmap
cargo build --release
sudo ./target/release/rustnmap --help
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

## Documentation

| Document | Description |
|----------|-------------|
| [User Manual](doc/manual/) | Complete command reference and usage guide |
| [User Guide](doc/user-guide.md) | Comprehensive scanning tutorials |
| [Architecture](doc/architecture.md) | System design and crate structure |

### Manual Contents

- [Quick Reference](doc/manual/quick-reference.md) - One-page command cheat sheet
- [Options Reference](doc/manual/options.md) - Complete CLI options
- [Scan Types](doc/manual/scan-types.md) - Detailed scan documentation
- [Output Formats](doc/manual/output-formats.md) - Format specifications
- [NSE Scripts](doc/manual/nse-scripts.md) - Scripting guide
- [Exit Codes](doc/manual/exit-codes.md) - Error handling reference
- [Environment Variables](doc/manual/environment.md) - Configuration via env vars
- [Configuration File](doc/manual/configuration.md) - Config file format

---

## Examples

### Target Specification

```bash
# Single IP, CIDR, range, hostname
rustnmap 192.168.1.1
rustnmap 192.168.1.0/24
rustnmap 192.168.1.1-100
rustnmap example.com

# From file
rustnmap -iL targets.txt
```

### Scan Types

```bash
sudo rustnmap -sS 192.168.1.1    # TCP SYN (stealth)
rustnmap -sT 192.168.1.1          # TCP Connect (no root)
sudo rustnmap -sU 192.168.1.1    # UDP
sudo rustnmap -sF 192.168.1.1    # FIN scan
sudo rustnmap -sA 192.168.1.1    # ACK (firewall mapping)
```

### Output Formats

```bash
sudo rustnmap -oN results.nmap 192.168.1.1    # Normal
sudo rustnmap -oX results.xml 192.168.1.1     # XML
sudo rustnmap -oJ results.json 192.168.1.1    # JSON
sudo rustnmap -oG results.gnmap 192.168.1.1   # Grepable
sudo rustnmap -oA results 192.168.1.1         # All formats
```

### NSE Scripts

```bash
sudo rustnmap -sC 192.168.1.1                           # Default scripts
sudo rustnmap --script http-title 192.168.1.1           # Specific script
sudo rustnmap --script "vuln" 192.168.1.1               # Category
sudo rustnmap --script "http-*" 192.168.1.1             # Pattern
```

---

## Development

```bash
# Run tests
just test

# Run clippy
just clippy

# Build release
just release

# Generate docs
just doc
```

---

## Security

- **Memory Safety**: Rust ownership prevents buffer overflows
- **Safe Concurrency**: Compile-time data race prevention
- **Security Grade**: A-
- Only 7 unsafe blocks (all FFI with SAFETY comments)

---

## Comparison with Nmap

| Feature | RustNmap | Nmap |
|---------|----------|------|
| Scan Types | 12 | 12 |
| Service Detection | 6000+ probes | 6000+ probes |
| OS Detection | 5000+ signatures | 5000+ signatures |
| NSE Scripts | Full Lua 5.4 | Full Lua 5.4 |
| Output Formats | 5 | 5 |
| Memory Safety | Guaranteed | No |
| Concurrency | Async/await | Event-driven |

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before scanning networks you do not own.
