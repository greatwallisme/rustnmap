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
| Phase 1 | rustnmap-net | 0 | Raw socket abstractions |
| Phase 1 | rustnmap-packet | 0 | PACKET_MMAP V3 engine |
| Phase 2 | rustnmap-target | 85 | Target parsing, host discovery |
| Phase 2 | rustnmap-scan | 0 | Port scanning implementations |
| Phase 3 | rustnmap-fingerprint | 36 | Service/OS detection |
| Phase 3 | rustnmap-traceroute | 76 | Network route tracing |
| Phase 3 | rustnmap-evasion | 85 | Firewall/IDS evasion |
| Phase 4 | rustnmap-nse | 35 | Lua 5.4 script engine |
| Phase 5 | rustnmap-output | 25 | Output formatters |
| Phase 5 | rustnmap-cli | 0 | CLI entry point (IN PROGRESS) |

**Total**: 284 tests passing across 11 crates

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

## Implementation Details by Module

### Port Scanning (doc/modules/port-scanning.md)

**Scan Types Required**:
| Type | Nmap Flag | Implementation |
|------|-----------|----------------|
| TCP SYN | -sS | TcpSynScanner |
| TCP Connect | -sT | TcpConnectScanner |
| TCP FIN | -sF | TcpFinScanner |
| TCP NULL | -sN | TcpNullScanner |
| TCP Xmas | -sX | TcpXmasScanner |
| TCP ACK | -sA | TcpAckScanner |
| TCP Window | -sW | TcpWindowScanner |
| TCP Maimon | -sM | TcpMaimonScanner |
| UDP | -sU | UdpScanner |
| IP Protocol | -sO | IpProtocolScanner |

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

**Ultra Scan Architecture**:
- UltraProbe: Probe specification with retry tracking
- CongestionControl: RFC2581 TCP congestion control
- TimeoutTracker: RFC 2988 adaptive timeout
- RateMeter: Packet rate monitoring

### Host Discovery (doc/modules/host-discovery.md)

**Discovery Methods**:
| Method | Nmap Flag | Description |
|--------|-----------|-------------|
| ARP Ping | -PR | Local network only |
| ICMP Echo | -PE | Standard ping |
| ICMP Timestamp | -PP | Alternative ICMP |
| ICMP Address Mask | -PM | Rarely used |
| TCP SYN Ping | -PS | TCP SYN to specified ports |
| TCP ACK Ping | -PA | TCP ACK to specified ports |
| UDP Ping | -PU | UDP to specified ports |
| IP Protocol Ping | -PO | IP protocol scan |

### Service Detection (doc/modules/service-detection.md)

**Probe Database Structure**:
- ProbeDefinition: name, protocol, ports, payload, rarity, matches
- MatchRule: pattern (regex), service, product, version, info, hostname, ostype, devicetype, cpe
- Intensity levels (0-9) control probe selection

**Version Extraction**:
- Template variable substitution ($1-$N for capture groups)
- CPE (Common Platform Enumeration) generation
- Confidence scoring (0-10)

### NSE Script Engine (doc/modules/nse-engine.md)

**Core Components**:
1. **Lua Runtime**: mlua with Lua 5.4
2. **Script Database**: Loading, parsing, selection
3. **Script Scheduler**: Concurrent execution with limits
4. **Script Engine**: Main execution entry point

**NSE Libraries to Implement** (32 total):
- Core: nmap, stdnse, comm, shortport
- Protocol: http, ssh, ssl, snmp, smb, ftp, smtp, ldap, mysql, pgsql, msrpc, dns, dhcp, vnc, rdp, mongodb
- Utility: brute, creds, datafiles, target, unpwdb, stringaux, tab, json, base64, bit, openssl, packet

**Script Execution Flow**:
1. Script Loading & Parsing
2. Rule Evaluation (hostrule/portrule)
3. Lua Environment Preparation
4. Action Execution
5. Result Collection

### OS Detection (doc/modules/os-detection.md)

**TCP/IP Fingerprinting**:
- SEQ probes: TCP ISN analysis (GCD, increments, randomness)
- T1-T7 probes: Various TCP flag combinations
- IE probes: ICMP echo analysis
- U1 probe: UDP port unreachable analysis
- ECN probe: Explicit Congestion Notification

**Fingerprint Matching**:
- nmap-os-db format parsing
- Test-by-test comparison
- Score-based classification
- Fuzzy matching for unknown systems

### Evasion Techniques (doc/modules/evasion.md)

**Implemented Techniques**:
| Technique | Description |
|-----------|-------------|
| Decoy Scan | -D flag, send probes from spoofed IPs |
| Source Port Manipulation | -g flag, set specific source port |
| IP Options | Add custom IP options |
| Packet Fragmentation | -f flag, split packets |
| Bad Checksum | --badsum, corrupt checksums |
| Custom MTU | --mtu, set specific MTU |
| Data Length | Add random data to packets |

### Output Formats (doc/modules/output.md)

**Required Formats**:
| Format | Extension | Description |
|--------|-----------|-------------|
| Normal | .nmap | Human-readable text |
| XML | .xml | Machine-parseable XML |
| JSON | .json | JSON output |
| Grepable | .gnmap | One-line per host |
| Script Kiddie | - | 1337 speak |

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

## Risk Assessment (from doc/roadmap.md)

| Risk | Impact | Mitigation |
|------|--------|------------|
| Lua compatibility | High | mlua crate, strict NSE API compatibility |
| Raw socket permissions | Medium | CAP_NET_RAW, TCP Connect fallback |
| Kernel compatibility | Medium | Support Linux 3.10+, feature detection |
| SELinux/AppArmor | Medium | Policy configs, documentation |
| Fingerprint maintenance | Medium | Auto-update mechanism |
| Performance | Medium | Async I/O, zero-copy, eBPF |
| Legal compliance | High | Clear terms, authorization checks |

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
| Tests passing | 284/284 |
| Clippy warnings | 0 (all fixed) |
| Format check | Pass |
| Doc build | Pass |

### Clippy Warnings Fixed (2026-02-13)

**rustnmap-target (2 warnings fixed)**:
1. `self_only_used_in_recursion` - Fixed expected lint name
2. `unfulfilled_lint_expectations` - Resolved by fixing lint name

**rustnmap-traceroute (20 warnings fixed)**:
1. `uninlined_format_args` - Changed to inline format strings
2. `cast_precision_loss` - Added #[allow] annotations with justification
3. `derivable_impls` - Changed ProbeType to use #[derive(Default)]
4. `match_same_arms` - Merged identical match arms
5. `unused_result_ok` - Changed to `let _ =`
6. `must_use_candidate` - Added #[must_use] to format()
7. `unused_async` - Removed async from functions without await
8. `single_match_else` - Changed to `if let`

**Files modified**:
- `crates/rustnmap-target/src/parser.rs`
- `crates/rustnmap-traceroute/src/error.rs`
- `crates/rustnmap-traceroute/src/hops.rs`
- `crates/rustnmap-traceroute/src/lib.rs`
- `crates/rustnmap-traceroute/src/probe.rs`
- `crates/rustnmap-traceroute/src/icmp.rs`
- `crates/rustnmap-traceroute/src/tcp.rs`
- `crates/rustnmap-traceroute/src/udp.rs`

---

## Remaining Work

### Phase 5: Integration

1. **Fix clippy warnings in rustnmap-traceroute**
   - 20 unused_async errors
   - Files: tcp.rs, udp.rs, icmp.rs

2. **Complete rustnmap-cli crate**
   - CLI argument parsing with clap
   - Nmap-compatible options
   - Integration with all modules

3. **Implement Scan Orchestrator**
   - Coordinate all scanning phases
   - Manage scan session lifecycle
   - Handle concurrent execution

4. **Add Integration Tests**
   - End-to-end scan workflows
   - Mock network testing
   - Performance benchmarks

### Future Enhancements

1. **IPv6 Support**: Full dual-stack operation
2. **Performance Optimization**: eBPF filters, XDP
3. **Database Updates**: Online fingerprint updates
4. **NSE Library Completion**: All 32 libraries
5. **Documentation**: User guide, API docs

---

## TODO Items Requiring Root/Sudo Privileges

The following TODO items require root privileges or CAP_NET_RAW capability to implement and test:

### 1. Raw Socket Packet Transmission

**Location**: `crates/rustnmap-scan/src/syn_scan.rs:110`
```rust
// TODO: This is a simulation method. Replace with actual raw socket packet transmission
```

**What needs root**: Creating raw sockets with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` requires CAP_NET_RAW or root.

**Implementation approach**:
- The `rustnmap-net` crate already has raw socket creation code
- Need to integrate with `PacketEngine` trait in `rustnmap-core/src/session.rs`
- Add privilege detection and graceful fallback to TCP Connect scan

### 2. Host Discovery - TCP Ping

**Location**: `crates/rustnmap-target/src/discovery.rs:65`
```rust
// TODO: Implement actual TCP ping
```

**What needs root**: Sending custom TCP SYN packets (not through kernel TCP stack) requires raw sockets.

### 3. Host Discovery - ICMP

**Location**: `crates/rustnmap-target/src/discovery.rs:87`
```rust
// TODO: Implement ICMP discovery
```

**What needs root**: ICMP sockets (SOCK_DGRAM with IPPROTO_ICMP) are restricted on many systems; raw ICMP requires CAP_NET_RAW.

### 4. Host Discovery - ARP

**Location**: `crates/rustnmap-target/src/discovery.rs:118`
```rust
// TODO: Implement ARP discovery
```

**What needs root**: ARP packets are at layer 2 (ethernet frame level), requiring raw packet sockets (AF_PACKET).

### 5. Traceroute Implementations

**Locations**:
- `crates/rustnmap-traceroute/src/icmp.rs:32`
- `crates/rustnmap-traceroute/src/tcp.rs:37,61`
- `crates/rustnmap-traceroute/src/udp.rs:29`

**What needs root**: All traceroute methods require sending custom packets with specific TTL values and receiving ICMP responses.

### 6. OS Detection Probes

**Location**: `crates/rustnmap-fingerprint/src/os/detector.rs`

Multiple TODOs for:
- SEQ probes (ISN analysis)
- T1-T7 TCP tests
- ICMP echo probes
- UDP probe to closed port

**What needs root**: All OS detection requires crafting packets with specific TCP flags, options, and analyzing responses.

---

## Privilege Handling Strategy

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

### Option 3: Setuid Binary (Not Recommended)

```bash
sudo chown root:root target/release/rustnmap
sudo chmod u+s target/release/rustnmp
```

**Security risk**: Entire binary runs as root. Not recommended.

### Option 4: Capability-Aware Testing

For CI/CD and testing without root:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_raw_socket_scan() {
        // Only runs when explicitly enabled
    }
}
```

Run with: `cargo test -- --ignored`

---

## Implementation Plan for Privileged Features

### Phase A: Privilege Detection Framework
1. Add `PrivilegeLevel` enum to `rustnmap-common`
2. Implement `detect_privileges()` function
3. Add privilege checks before raw socket operations
4. Provide clear error messages when privileges are missing

### Phase B: Capability-Based Deployment
1. Document capability setup in deployment guide
2. Add helper script for setting capabilities
3. Update CLI to warn about missing privileges

### Phase C: Implement Privileged Features (with sudo)

For each TODO, implement and test with sudo:

```bash
# Development workflow
sudo cargo test -p rustnmap-scan syn_scan::tests -- --nocapture

# Or set capabilities on test binary
sudo setcap cap_net_raw+eip target/debug/deps/rustnmap_scan-*
cargo test -p rustnmap-scan
```

---

## Testing Strategy

### Unit Tests (No Privileges Required)
- Packet construction logic
- State machines
- Protocol parsing

### Integration Tests (Requires Privileges)
- Mark with `#[ignore = "requires root"]`
- Run in CI with privileged container or skip

### Manual Testing
```bash
# Build with release optimizations
cargo build --release

# Set capabilities
sudo setcap cap_net_raw,cap_net_admin+eip target/release/rustnmap

# Test SYN scan (now works without sudo)
./target/release/rustnmap -sS 127.0.0.1

# Or use sudo for full root
sudo ./target/release/rustnmap -sS 192.168.1.1
```

---

## Reference Links

## Reference Links

- Nmap Source: `reference/nmap/`
- Design Docs: `doc/modules/*.md`
- Architecture: `doc/architecture.md`
- Roadmap: `doc/roadmap.md`
