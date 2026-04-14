# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RustNmap is a network scanner written in Rust, targeting 100% functional parity with Nmap. It supports 12 scan types, service/OS detection, NSE scripting, vulnerability intelligence, and a REST API.

**Platform**: Linux x86_64 | **Rust**: 1.90+ | **License**: GPL-3.0-or-later

## Build & Test Commands

```bash
# Build profiles
cargo build                                  # Dev (opt-level=0, incremental, fast compile)
cargo build --profile dev-fast               # Dev-fast (opt-level=1, for iteration)
cargo build --release                        # Release (LTO, opt-level=3, strip, panic=abort)
cargo build --profile release-with-debug     # Release+debug (for profiling/crash diagnosis)

# Test
cargo test --workspace                       # All tests
cargo test -p <crate>                        # Single crate (e.g., rustnmap-scan)
cargo test -p <crate> test_name              # Single test
cargo test -- --skip requires_root           # Skip root-required tests

# Lint & Format
cargo clippy --workspace -- -D warnings      # Zero warnings required
cargo fmt --all -- --check                   # Format check

# Full CI
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test --workspace

# Benchmarks
cargo bench -p rustnmap-benchmarks                           # All benchmarks
cargo bench -p rustnmap-benchmarks -- <benchmark_name>       # Specific benchmark

# Comparison tests (rustnmap vs nmap)
cargo build --release && ./benchmarks/comparison_test.sh

# Docs
cargo doc --workspace --no-deps --all-features
```

**Environment**: Debian system with root privileges. No `sudo` needed.

## Critical Rules

0. **Optimization Compliance** - Do not reduce timeouts to fake speed improvements. Fix actual logic.
1. **Design Compliance** - Follow `doc/` design documents. Unimplementable designs require user confirmation before changing approach.
2. **Zero warnings, zero errors** - Never relax clippy standards in Cargo.toml.
3. **No simplification** - 100% nmap parity required (12 scan types, 10 port states, T0-T5 timing).
4. **No mock engines** - Testing must use actual network targets, not localhost.
5. **Before ANY commit**: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`

## Architecture

### Workspace Crate Dependency Graph

```
                    rustnmap-common (types, errors, databases)
                    /     |      \      \       \        \
             rustnmap-net  |  rustnmap-output  |    rustnmap-vuln
              /     |      |       |           |         |
    rustnmap-packet |      |       |     rustnmap-scan-management
         |          |      |       |           |
    rustnmap-target |      |       |     rustnmap-api (REST daemon)
         |          |      |       |
    rustnmap-scan   |      |       |
         |          |      |       |
    rustnmap-fingerprint    |       |
         |          |      |       |
    rustnmap-traceroute     |       |
         |          |      |       |
    rustnmap-evasion        |       |
         \          |      |       /
          rustnmap-core (orchestrator)
                |              |
         rustnmap-nse    rustnmap-stateless-scan
                |              |
          rustnmap-cli    rustnmap-sdk (builder API)
```

### Crate Roles

| Crate | Role |
|-------|------|
| `rustnmap-common` | Foundation types (`Port`, `PortState`, `ScanType`), error types, `ServiceDatabase` global singleton |
| `rustnmap-net` | Raw socket wrappers, packet construction helpers, checksums |
| `rustnmap-packet` | PACKET_MMAP V2 ring buffer engine (`MmapPacketEngine`), zero-copy `AsyncPacketEngine` via `AsyncFd` |
| `rustnmap-target` | Target parsing (CIDR, ranges, hostnames), host discovery (ICMP/TCP/ARP ping) |
| `rustnmap-scan` | 12 scan types, `ParallelScanEngine` (ultrascan), adaptive RTT, congestion control |
| `rustnmap-fingerprint` | Service detection (nmap-service-probes), OS fingerprinting (nmap-os-db), TLS cert analysis |
| `rustnmap-traceroute` | Route tracing via ICMP/TCP/UDP probes with TTL manipulation |
| `rustnmap-evasion` | Fragmentation, decoy rotation, source spoofing, timing control |
| `rustnmap-nse` | Lua 5.4 script engine with process isolation (`rustnmap-nse-runner` binary) |
| `rustnmap-output` | 5 output formats: Normal, XML, JSON, Grepable, Script Kiddie |
| `rustnmap-core` | Central `ScanOrchestrator` coordinating all scan phases via `ScanSession` DI container |
| `rustnmap-vuln` | CVE/CPE lookup, EPSS scoring, CISA KEV feed - backed by SQLite |
| `rustnmap-scan-management` | Scan persistence (SQLite), diff between scans, YAML profiles |
| `rustnmap-stateless-scan` | Masscan-like high-speed stateless scanning (SYN cookie based) |
| `rustnmap-api` | REST API daemon (Axum) with SSE streaming, auth middleware |
| `rustnmap-sdk` | Builder API for programmatic usage, supports local and remote (via API) scanning |
| `rustnmap-cli` | CLI binary (`rustnmap`) with clap arg parsing, progress bars |
| `rustnmap-benchmarks` | Criterion benchmarks for packet, scan, fingerprint, and NSE hot paths |

### Key Design Patterns

**ScanSession** - DI container holding `Arc<ScanConfig>`, `Arc<dyn PacketEngine>`, `Arc<dyn OutputSink>`, `Arc<ScanStats>`.

**PacketEngine** - Strategy pattern. `MmapPacketEngine` (production) vs `RecvfromPacketEngine` (fallback). All scanners use `ScannerPacketEngine` adapter.

**Two-Stage Bind** (packet engine) - Bind with protocol=0 for ring buffer setup, then re-bind with ETH_P_ALL for reception. Follows nmap's `libpcap/pcap-linux.c`.

**Process Isolation** (NSE) - Scripts execute in `rustnmap-nse-runner` child process. `ProcessExecutor` enforces timeouts via OS-level process kill.

**Zero-Copy** - `ZeroCopyPacket` holds `Arc<MmapPacketEngine>` to keep mmap alive; `Drop` releases frame back to kernel.

## Rust Code Standards

```rust
// Type names in docs use backticks: `OsReference`
// Result functions MUST have # Errors section
// Builder methods MUST have #[must_use]
// Numeric literals use separators: 1_000_000
// Well-known constants: Ipv4Addr::LOCALHOST
// Explicit casts: u64::from(x), NOT x as u64
// Inlined format strings: format!("{var}")
// Match arms combined when identical: "A" | "B" => result
// Lint attributes: #[expect(clippy::lint, reason = "...")] at item level
// NEVER use module-level #![allow(...)]
```

## Timing Template Parameters

| Parameter | T0 | T1 | T2 | T3 | T4 | T5 |
|-----------|-----|-----|-----|-----|-----|-----|
| initial_rtt | 1s | 1s | 1s | 1s | 500ms | 250ms |
| max_retries | 10 | 10 | 10 | 10 | 6 | 2 |
| scan_delay | 5min | 15s | 400ms | 0ms | 0ms | 0ms |

## Documentation

| What | Where |
|------|-------|
| System Architecture | `doc/architecture.md` |
| Crate Structure | `doc/structure.md` |
| Packet Engineering | `doc/modules/packet-engineering.md` |
| Nmap Reference Source | `reference/nmap/` |

## License

GPL-3.0-or-later. Uses Nmap fingerprint databases under NPSL. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
