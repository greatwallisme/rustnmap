# Task Plan: Complete RustNmap Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Status**: COMPLETE - VERIFIED
> **Created**: 2026-02-13
> **Updated**: 2026-02-13
> **Goal**: Strictly follow design documents @doc/ to complete all remaining features

---

## Goal

Complete the RustNmap project according to the design documentation. The project currently has 12 crates with 334 tests passing, but several critical features requiring root/CAP_NET_RAW privileges remain as TODOs:

1. UDP scanning implementation
2. Host discovery (TCP ping, ICMP, ARP)
3. Traceroute with raw sockets
4. OS detection probes
5. Service detection probes
6. Complete NSE libraries
7. Integration tests for privileged features

---

## Current State Analysis

### Completed (from findings.md)
| Phase | Crate | Tests | Status |
|-------|-------|-------|--------|
| Phase 1 | rustnmap-common | 14 | COMPLETE |
| Phase 1 | rustnmap-net | 0 | COMPLETE (raw socket support added) |
| Phase 1 | rustnmap-packet | 0 | COMPLETE |
| Phase 2 | rustnmap-target | 85 | COMPLETE |
| Phase 2 | rustnmap-scan | 20+ | COMPLETE (SYN/Connect implemented) |
| Phase 3 | rustnmap-fingerprint | 36 | COMPLETE (structure ready) |
| Phase 3 | rustnmap-traceroute | 76 | COMPLETE (structure ready) |
| Phase 3 | rustnmap-evasion | 85 | COMPLETE |
| Phase 4 | rustnmap-nse | 35 | COMPLETE (Lua engine ready) |
| Phase 5 | rustnmap-output | 25 | COMPLETE |
| Phase 5 | rustnmap-core | 39 | COMPLETE |
| Phase 5 | rustnmap-cli | 9 | COMPLETE |

**Total**: 334 tests passing (326 unit + 8 integration)

### TODOs Requiring Implementation (from findings.md)

| # | Feature | Location | Priority | Root Required |
|---|---------|----------|----------|---------------|
| 1 | UDP scanner implementation | rustnmap-scan/src/lib.rs | P0 | Yes |
| 2 | TCP ping (host discovery) | rustnmap-target/src/discovery.rs:65 | P0 | Yes |
| 3 | ICMP discovery | rustnmap-target/src/discovery.rs:87 | P0 | Yes |
| 4 | ARP discovery | rustnmap-target/src/discovery.rs:118 | P0 | Yes |
| 5 | Traceroute ICMP/TCP/UDP | rustnmap-traceroute/src/*.rs | P1 | Yes |
| 6 | OS detection probes | rustnmap-fingerprint/src/os/detector.rs | P1 | Yes |
| 7 | Service detection probes | rustnmap-fingerprint/src/service/detector.rs | P1 | Yes |
| 8 | NSE network libraries | rustnmap-nse | P2 | Some |
| 9 | Additional scan types (FIN/NULL/Xmas/ACK) | rustnmap-scan | P1 | Yes |
| 10 | Performance benchmarks | benches/ | P2 | No |

---

## Phases

### Phase 1: UDP Scanning Implementation

**Goal**: Implement UDP scanner with raw socket support

- [x] Read existing UDP scan TODOs and design doc
- [x] Implement UdpScanner struct in rustnmap-scan
- [x] Add UDP packet builder in rustnmap-net
- [x] Implement port state detection (Open, Closed, Filtered, OpenFiltered)
- [x] Add unit tests for UDP scanner
- [x] Add integration tests with real UDP services
- **Status**: complete

### Phase 2: Host Discovery (Privileged Features)

**Goal**: Implement TCP ping, ICMP, and ARP discovery

- [x] Implement TCP SYN ping (-PS)
- [x] Implement TCP ACK ping (-PA)
- [x] Implement ICMP echo ping (-PE)
- [x] Implement ICMP timestamp ping (-PP)
- [x] Implement ARP ping (-PR) for local network
- [x] Add privilege detection framework
- [x] Add unit tests for each discovery method
- [x] Add integration tests
- **Status**: complete

### Phase 3: Additional TCP Scan Types

**Goal**: Implement FIN, NULL, Xmas, ACK, Maimon scans

- [x] Implement TcpFinScanner (-sF)
- [x] Implement TcpNullScanner (-sN)
- [x] Implement TcpXmasScanner (-sX)
- [x] Implement TcpAckScanner (-sA)
- [x] Implement TcpMaimonScanner (-sM)
- [x] Add unit tests for each scanner
- [x] Add integration tests
- **Status**: complete

### Phase 4: Traceroute Implementation

**Goal**: Complete traceroute with raw socket support

- [x] Read current traceroute implementation
- [x] Implement ICMP traceroute
- [x] Implement TCP SYN traceroute
- [x] Implement UDP traceroute
- [x] Add hop detection and RTT measurement
- [x] Add unit tests
- [x] Add integration tests
- **Status**: complete

### Phase 5: OS Detection Implementation

**Goal**: Complete OS fingerprinting probes

- [x] Read OS detection design doc
- [x] Implement TCP SEQ probe analysis (6 SYN probes with 100ms intervals)
- [x] Implement TCP option analysis (OPS) - WScale, NOP, MSS, Timestamp, SACK
- [x] Implement T1-T7 test probes with various flag combinations
- [x] Implement ECN probe with ECE/CWR flags
- [x] Implement ICMP echo probes (IE1, IE2)
- [x] Implement UDP probe (U1) to closed port
- [x] Implement ISN analysis (GCD, ISR, SP calculation)
- [x] Implement IP ID sequence classification
- [x] Integrate with fingerprint database
- [x] Add unit tests for all analysis functions
- [x] Add integration tests (marked with #[ignore] for root-required)
- **Status**: complete

### Phase 6: Service Detection Implementation

**Goal**: Complete service version detection

- [x] Read service detection design doc
- [x] Implement probe database loading
- [x] Implement banner grabbing
- [x] Implement version extraction from responses
- [x] Add unit tests
- **Status**: complete

### Phase 7: NSE Libraries

**Goal**: Implement core NSE libraries

- [x] Implement nmap base library
- [x] Implement stdnse library
- [x] Implement comm library
- [x] Implement shortport library
- [x] Add unit tests
- **Status**: complete

### Phase 8: Performance & Documentation

**Goal**: Performance benchmarks and documentation

- [x] Add Criterion benchmarks for hot paths
- [x] Create benchmark suite for scanning
- [x] Create benchmark suite for packet I/O
- [x] Create benchmark suite for fingerprinting
- [x] Create benchmark suite for NSE
- [x] Add rustnmap-benchmarks crate with 13 crates total
- **Status**: complete

---

## Key Questions

1. **How to test privileged features in CI?**
   - Use #[ignore] for root-required tests
   - Run with sudo in privileged containers
   - Mark tests with clear privilege requirements

2. **What localhost services are available for testing?**
   - Port 22 (SSH)
   - Port 8501 (Streamlit)
   - Ports 18789/18791/18792 (clawdbot-gateway)
   - Can use netcat for UDP testing

3. **How to handle privilege detection?**
   - Implement PrivilegeLevel enum
   - Runtime detection of CAP_NET_RAW
   - Graceful degradation to Connect scans

---

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use #[ignore] for privileged tests | Allows tests to run without root by default |
| Implement privilege detection | Runtime detection allows graceful degradation |
| Follow design docs exactly | Ensures Nmap compatibility and feature parity |
| Root required for raw socket features | Linux kernel requirement for raw packets |

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| None yet | - | - |

---

## Project Context

**Technology Stack**:
- Rust 1.85+
- Tokio async runtime
- mlua for Lua scripting
- pnet for packet crafting
- clap for CLI parsing

**Required Privileges**:
- TCP SYN scan: CAP_NET_RAW
- UDP scan: CAP_NET_RAW
- ICMP ping: CAP_NET_RAW
- ARP discovery: CAP_NET_RAW
- Traceroute: CAP_NET_RAW
- OS detection: CAP_NET_RAW

**Design Document References**:
- doc/architecture.md - System architecture
- doc/modules/port-scanning.md - Scan types
- doc/modules/host-discovery.md - Discovery methods
- doc/modules/os-detection.md - OS fingerprinting
- doc/modules/traceroute.md - Traceroute
- doc/modules/service-detection.md - Service detection
- doc/modules/nse-engine.md - NSE scripting
- doc/roadmap.md - Development roadmap
