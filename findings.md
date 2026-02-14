# Findings: RustNmap Research and Analysis

> **Created**: 2026-02-12
> **Updated**: 2026-02-13
> **Purpose**: Document discoveries, research results, and analysis

---

## Project Status Summary

### Completed Work

| Phase | Crate | Tests | Description |
|-------|-------|-------|-------------|
| Phase 1 | rustnmap-common | 14 | Core types, errors, utilities |
| Phase 1 | rustnmap-net | 0 | Raw socket abstractions (raw socket support added) |
| Phase 1 | rustnmap-packet | 0 | PACKET_MMAP V3 engine |
| Phase 2 | rustnmap-target | 85 | Target parsing, host discovery (structure ready) |
| Phase 2 | rustnmap-scan | 20+ | Port scanning (TCP SYN/Connect implemented) |
| Phase 3 | rustnmap-fingerprint | 36 | Service/OS detection (structure ready) |
| Phase 3 | rustnmap-traceroute | 76 | Network route tracing (structure ready) |
| Phase 3 | rustnmap-evasion | 85 | Firewall/IDS evasion |
| Phase 4 | rustnmap-nse | 35 | Lua 5.4 script engine (core ready) |
| Phase 5 | rustnmap-output | 25 | Output formatters |
| Phase 5 | rustnmap-core | 39 | Scan orchestrator |
| Phase 5 | rustnmap-cli | 9 | CLI entry point |

**Total**: 334 tests passing across 12 crates (326 unit + 8 integration)

---

## Remaining Work Per Design Documents (@doc/)

Based on strict review of design documents, the following features remain to be implemented:

### High Priority (P0) - Core Functionality

| Feature | Design Doc | Status | Implementation Location |
|---------|------------|--------|------------------------|
| UDP scanning (-sU) | port-scanning.md | TODO | rustnmap-scan/src/lib.rs |
| TCP SYN ping (-PS) | host-discovery.md | TODO | rustnmap-target/src/discovery.rs:65 |
| ICMP echo ping (-PE) | host-discovery.md | TODO | rustnmap-target/src/discovery.rs:87 |
| ICMP timestamp ping (-PP) | host-discovery.md | TODO | rustnmap-target/src/discovery.rs:87 |
| ARP ping (-PR) | host-discovery.md | TODO | rustnmap-target/src/discovery.rs:118 |

### Medium Priority (P1) - Complete Scan Types

| Feature | Design Doc | Status | Implementation Location |
|---------|------------|--------|------------------------|
| TCP FIN scan (-sF) | port-scanning.md | TODO | rustnmap-scan |
| TCP NULL scan (-sN) | port-scanning.md | TODO | rustnmap-scan |
| TCP Xmas scan (-sX) | port-scanning.md | TODO | rustnmap-scan |
| TCP ACK scan (-sA) | port-scanning.md | TODO | rustnmap-scan |
| TCP Maimon scan (-sM) | port-scanning.md | TODO | rustnmap-scan |
| ICMP traceroute | traceroute.md | TODO | rustnmap-traceroute/src/icmp.rs:32 |
| TCP traceroute | traceroute.md | TODO | rustnmap-traceroute/src/tcp.rs:37,61 |
| UDP traceroute | traceroute.md | TODO | rustnmap-traceroute/src/udp.rs:29 |
| OS detection probes | os-detection.md | TODO | rustnmap-fingerprint/src/os/detector.rs |
| Service detection probes | service-detection.md | TODO | rustnmap-fingerprint/src/service/detector.rs |

### Lower Priority (P2) - Advanced Features

| Feature | Design Doc | Status | Implementation Location |
|---------|------------|--------|------------------------|
| NSE nmap library | nse-engine.md | TODO | rustnmap-nse |
| NSE stdnse library | nse-engine.md | TODO | rustnmap-nse |
| NSE comm library | nse-engine.md | TODO | rustnmap-nse |
| NSE shortport library | nse-engine.md | TODO | rustnmap-nse |
| Performance benchmarks | roadmap.md | TODO | benches/ |

---

## Architecture Findings

### Module Dependencies (from doc/architecture.md)

```
Application Binary
    └── rustnmap-cli (CLI, output formatting)
        └── rustnmap-core (scan orchestrator)
            ├── rustnmap-scan (port scanning)
            ├── rustnmap-nse (script engine)
            └── rustnmap-fingerprint (OS/service detection)
                └── rustnmap-net (raw sockets, packet I/O)
                    └── rustnmap-common (types, errors)
```

### Key Design Patterns

1. **ScanSession Context**: Central abstraction for dependency injection
   - Config, target_set, packet_engine, output_sink
   - fingerprint_db, nse_registry, stats

2. **PacketEngine Trait**: Enables testing without root
   - send_packet, send_batch, recv_stream
   - set_bpf, local_mac, if_index

3. **Zero-Copy Packet Path**: PACKET_MMAP V3 for performance
   - bytes::Bytes for zero-copy references
   - Kernel bypass for high-throughput scanning

---

## Implementation Details by Module (from Design Docs)

### Port Scanning (doc/modules/port-scanning.md)

**Scan Types Required**:
| Type | Nmap Flag | Implementation | Status |
|------|-----------|----------------|--------|
| TCP SYN | -sS | TcpSynScanner | IMPLEMENTED |
| TCP Connect | -sT | TcpConnectScanner | IMPLEMENTED |
| TCP FIN | -sF | TcpFinScanner | TODO |
| TCP NULL | -sN | TcpNullScanner | TODO |
| TCP Xmas | -sX | TcpXmasScanner | TODO |
| TCP ACK | -sA | TcpAckScanner | TODO |
| TCP Window | -sW | TcpWindowScanner | TODO |
| TCP Maimon | -sM | TcpMaimonScanner | TODO |
| UDP | -sU | UdpScanner | TODO |
| IP Protocol | -sO | IpProtocolScanner | TODO |

**Port State Machine** (10 states):
1. Unknown - Initial state
2. Closed - RST received
3. Open - SYN-ACK received
4. Filtered - No response or ICMP unreachable
5. Unfiltered - ACK scan response
6. OpenFiltered - UDP/IP protocol no response
7. ClosedFiltered - Error response
8. OpenClosed - Conflicting responses
9. FilteredClosed - Cannot determine
10. FilteredUnfiltered - Previous state filtered

### Host Discovery (doc/modules/host-discovery.md)

**Discovery Methods**:
| Method | Nmap Flag | Description | Status |
|--------|-----------|-------------|--------|
| ARP Ping | -PR | Local network only | TODO |
| ICMP Echo | -PE | Standard ping | TODO |
| ICMP Timestamp | -PP | Alternative ICMP | TODO |
| ICMP Address Mask | -PM | Rarely used | TODO |
| TCP SYN Ping | -PS | TCP SYN to specified ports | TODO |
| TCP ACK Ping | -PA | TCP ACK to specified ports | TODO |
| UDP Ping | -PU | UDP to specified ports | TODO |
| IP Protocol Ping | -PO | IP protocol scan | TODO |

### Service Detection (doc/modules/service-detection.md)

**Probe Database Structure**:
- ProbeDefinition: name, protocol, ports, payload, rarity, matches
- MatchRule: pattern (regex), service, product, version, info, hostname, ostype, devicetype, cpe
- Intensity levels (0-9) control probe selection

**Status**: Structure ready, actual probe transmission TODO

### NSE Script Engine (doc/modules/nse-engine.md)

**Core Components**:
1. **Lua Runtime**: mlua with Lua 5.4 - IMPLEMENTED
2. **Script Database**: Loading, parsing, selection - IMPLEMENTED
3. **Script Scheduler**: Concurrent execution with limits - IMPLEMENTED
4. **Script Engine**: Main execution entry point - IMPLEMENTED
5. **NSE Libraries**: 32 libraries to implement - TODO

**Status**: Core engine ready, libraries TODO

### OS Detection (doc/modules/os-detection.md)

**TCP/IP Fingerprinting**:
- SEQ probes: TCP ISN analysis (GCD, increments, randomness) - TODO
- T1-T7 probes: Various TCP flag combinations - TODO
- IE probes: ICMP echo analysis - TODO
- U1 probe: UDP port unreachable analysis - TODO
- ECN probe: Explicit Congestion Notification - TODO

**Status**: Structure ready, probe transmission TODO

### Traceroute (doc/modules/traceroute.md)

**Supported Methods**:
| Method | Protocol | Default Port | Status |
|--------|----------|--------------|--------|
| UDP | UDP | 40125 | TODO |
| TCP SYN | TCP | 80 | TODO |
| ICMP Echo | ICMP | N/A | TODO |
| ICMP DCE | ICMP | N/A | TODO |
| IP Protocol | IP | 0 | TODO |

**Status**: Structure ready, probe transmission TODO

### Evasion Techniques (doc/modules/evasion.md)

**Implemented Techniques**:
| Technique | Description | Status |
|-----------|-------------|--------|
| Decoy Scan | -D flag, send probes from spoofed IPs | Structure ready |
| Source Port Manipulation | -g flag, set specific source port | Structure ready |
| IP Options | Add custom IP options | Structure ready |
| Packet Fragmentation | -f flag, split packets | Structure ready |
| Bad Checksum | --badsum, corrupt checksums | Structure ready |
| Custom MTU | --mtu, set specific MTU | Structure ready |
| Data Length | Add random data to packets | Structure ready |

---

## Technical Decisions

### Async Runtime: Tokio

**Rationale**:
- Industry standard with excellent ecosystem
- Proven in network scanning tools
- Built-in task scheduling (work stealing)
- Comprehensive timer support

### Lua Integration: mlua

**Rationale**:
- Best-in-class Lua bindings for Rust
- Lua 5.4 support
- Sandboxing capabilities
- Performance (can use LuaJIT)

### Packet I/O: pnet + raw sockets

**Rationale**:
- Mature packet parsing library
- Cross-protocol support
- Linux raw socket support
- PACKET_MMAP V3 for zero-copy

### CLI: clap

**Rationale**:
- Derive API for clean code
- Excellent help generation
- Shell completion support
- Nmap-compatible argument parsing

---

## Performance Targets (from doc/roadmap.md)

| Metric | Target | Nmap Reference |
|--------|--------|----------------|
| Full port scan (1000 hosts) | <30s | ~60-120s |
| SYN scan throughput | >10^6 pps | ~5×10^5 pps |
| Host discovery (/24) | <5s | ~5-10s |
| Memory (large scan) | <500MB | ~200-800MB |
| Script overhead | <10% | ~5-15% |
| Startup time | <100ms | ~50-200ms |

---

## Code Quality Standards

### Required Checks (from CLAUDE.md)

```bash
# Before committing any code:
cargo test --workspace                    # All tests pass
cargo clippy --workspace -- -D warnings   # Zero warnings
cargo fmt --all -- --check                # Code formatted
cargo doc --no-deps --workspace           # Docs build without errors
```

### Current Status

| Check | Status |
|-------|--------|
| Tests passing | 334/334 |
| Clippy warnings | 0 (all fixed) |
| Format check | Pass |
| Doc build | Pass |

---

## Privilege Handling Strategy (from findings.md)

### Option 1: Runtime Privilege Detection (Recommended)

Implement privilege detection at runtime and gracefully degrade:

```rust
pub enum PrivilegeLevel {
    /// Full root/CAP_NET_RAW access - all features available
    Privileged,
    /// Unprivileged - limited to TCP Connect scans
    Unprivileged,
}

impl ScanSession {
    pub fn detect_privileges() -> PrivilegeLevel {
        // Try to create a raw socket
        match create_raw_socket() {
            Ok(_) => PrivilegeLevel::Privileged,
            Err(_) => PrivilegeLevel::Unprivileged,
        }
    }
}
```

### Option 2: Linux Capabilities (Preferred for Production)

Grant only required capabilities without full root:

```bash
# Build the binary
cargo build --release

# Set capabilities (as root)
sudo setcap cap_net_raw,cap_net_admin+eip target/release/rustnmap

# Now binary can run without sudo for raw socket operations
./target/release/rustnmap -sS 192.168.1.1
```

---

## Reference Links

- Nmap Source: `reference/nmap/`
- Design Docs: `doc/modules/*.md`
- Architecture: `doc/architecture.md`
- Roadmap: `doc/roadmap.md`
- Task Plan: `task_plan.md`
- Progress: `progress.md`
