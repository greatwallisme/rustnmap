# RustNmap Design Documentation

> **Version**: 1.0.0
> **Status**: This document describes the design of RustNmap 1.0.0. Version 2.0 is under development, see [CHANGELOG.md](CHANGELOG.md).
> **Date**: 2026-02-11
> **Target Platform**: Linux x86_64 (AMD64)

---

## RustNmap 2.0 Roadmap

RustNmap 2.0 is under development, upgrading from a "port scanner" to an "attack surface management platform."

### 2.0 New Features Preview

| Feature Category | New Features | Priority | Expected Completion |
|---------|---------|--------|---------|
| Vulnerability Intelligence | CVE/CPE correlation, EPSS scoring, KEV tagging | P0 | Week 5-7 |
| Streaming Output | NDJSON, Host-level streaming | P1 | Week 3-4 |
| Scan Management | SQLite persistence, Diff, YAML Profile | P1 | Week 8-9 |
| Performance Optimization | Two-phase scanning, adaptive batching, stateless scanning | P0 | Week 10-11 |
| Platform | REST API, Rust SDK | P1 | Week 12 |


### Documentation Status

| Document Type | Status | Notes |
|---------|------|------|
| Core Design Documents | 1.0 | Will be updated progressively during 2.0 development |
| User Manual | 1.0 + Markers | Version markers added, will be updated after 2.0 is complete |
| New 2.0 Documents | To be created | New documents created per Phase progress |

---

## Documentation Navigation

This document has been split into modules. Please select the content you need from the links below:

### Part 1: Project Overview and Architecture

| Document | Description | File |
|------|------|------|
| System Architecture | Overall architecture diagram, module dependencies | [architecture.md](architecture.md) |
| Project Structure | Cargo Workspace structure | [structure.md](structure.md) |

### Part 2: Core Feature Modules

| Module | Description | File |
|------|------|------|
| **CLI Interface** | **Command-line argument parsing (lexopt, migrated 2026-03-10)** | **[modules/cli.md](modules/cli.md)** |
| Host Discovery | ICMP/TCP/UDP host discovery techniques | [modules/host-discovery.md](modules/host-discovery.md) |
| Port Scanning | TCP SYN/CONNECT/UDP scanning techniques | [modules/port-scanning.md](modules/port-scanning.md) |
| Service Detection | Service version identification and fingerprint matching | [modules/service-detection.md](modules/service-detection.md) |
| OS Detection | Operating system fingerprinting | [modules/os-detection.md](modules/os-detection.md) |
| NSE Engine | Lua script engine core design | [modules/nse-engine.md](modules/nse-engine.md) |
| Traceroute | Network route tracing | [modules/traceroute.md](modules/traceroute.md) |
| Evasion Techniques | Firewall/IDS evasion | [modules/evasion.md](modules/evasion.md) |
| Output Module | Multi-format output design | [modules/output.md](modules/output.md) |
| Target Parsing | Target specification parsing | [modules/target-parsing.md](modules/target-parsing.md) |
| Raw Packets | Linux x86_64 packet engine (legacy architecture) | [modules/raw-packet.md](modules/raw-packet.md) |
| **Packet Engine** | **PACKET_MMAP V2 technical specification (current)** | **[modules/packet-engineering.md](modules/packet-engineering.md)** |
| Concurrency Model | Rust concurrency and zero-copy optimization | [modules/concurrency.md](modules/concurrency.md) |

### Part 3: Database and Project Structure

| Document | Description | File |
|------|------|------|
| Database Design | Service detection and OS fingerprint database | [database.md](database.md) |
| Project Structure | Cargo Workspace structure | [structure.md](structure.md) |

### Part 4: Development and Implementation

| Document | Description | File |
|------|------|------|
| 2.0 Evolution Roadmap | RustNmap 2.0 complete roadmap (12-week execution plan) | [../RETHINK.md](../RETHINK.md) |
| 2.0 Change Log | Document change records during 2.0 development | [CHANGELOG.md](CHANGELOG.md) |
| Development Roadmap | Phase 1-4 development plan (1.0) | [roadmap.md](roadmap.md) |

### User Documentation

| Document | Description | File |
|------|------|------|
| Man Page | Unix manual page | [rustnmap.1](rustnmap.1) |
| Development Roadmap | Phase 1-4 development plan (1.0) | [roadmap.md](roadmap.md) |

> **Note**: A complete user guide will be available after the official 2.0 release. Currently, please refer to the CLI help (`rustnmap --help`).

### Appendix

| Document | Description | File |
|------|------|------|
| Nmap Command Reference | Nmap command parameter reference | [appendix/nmap-commands.md](appendix/nmap-commands.md) |
| Data Structure Reference | Nmap core data structure mapping | [appendix/nmap-data-structures.md](appendix/nmap-data-structures.md) |
| Function Reference | Nmap core function signature reference | [appendix/nmap-function-reference.md](appendix/nmap-function-reference.md) |
| Constants Reference | Nmap source code constant definitions | [appendix/nmap-constants.md](appendix/nmap-constants.md) |
| References | Related technical documentation links | [appendix/references.md](appendix/references.md) |
| Deployment Guide | Linux x86_64 deployment guide | [appendix/deployment.md](appendix/deployment.md) |

---

## Project Overview

### 1.1 Project Background

Nmap ("Network Mapper") is one of the most well-known open-source tools in the network security field, and has been an industry standard since its release in 1997. However, Nmap has the following limitations:

| Limitation | Description |
|--------|------|
| Single-threaded Core | Although parallel scanning exists, the core architecture is constrained by C language legacy baggage |
| Performance Bottleneck | Full port scans still take several minutes |
| Memory Safety | C language has potential memory safety issues |
| Insufficient Modernization | Configuration and extension methods are relatively traditional |

### 1.2 Project Goals

Develop a modern vulnerability scanning tool written in **Rust**, achieving:

1. **100% Feature Parity** - Cover all core Nmap functionality
2. **Performance Leap** - Leverage Rust's async features for higher concurrency
3. **Memory Safety** - GC-free memory safety guarantees
4. **Modern Architecture** - Modular, extensible design
5. **Script Compatibility** - Maintain full compatibility with the Lua scripting engine

### 1.3 Target Users

- Penetration testers
- Security researchers
- System administrators
- DevSecOps engineers
- Enterprise security teams
