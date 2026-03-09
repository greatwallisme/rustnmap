# RustNmap - Rust Network Mapper

> **Version**: 2.0.0 | **Platform**: Linux x86_64 | **Rust**: 1.90+

---

## Develop and Test
-  Develop enviroment is a debian system with root previledge, any commond can be executed without `sudo` or password.

## CRITICAL RULES (Never Violate)
1. **Design Compliance** - All development must strictly follow the designs in the doc/ design documents. No alternative implementations are allowed. If a design is found to be unimplementable, user confirmation is required before modifying the technical approach.
2. **Zero warnings, zero errors** - Never relax clippy standards in Cargo.toml
3. **Code Quality Hook** - Pay attention to hook error messages, never bypass
4. **No simplification** - 100% nmap parity required (12 scan types, 10 port states, T0-T5 timing)
5. **No mock engines** - Testing must use actual network targets, not localhost


```bash
# Before ANY commit:
cargo test && cargo clippy -- -D warnings && cargo fmt --check
```

---

## CURRENT FOCUS: NSE Script Timeout Configuration

> **Status**: Phase 10 Complete - Process isolation implemented
> **Last Updated**: 2026-03-08

### Recent Completions

**Packet Engine (Phase 40)**: COMPLETE
- `MmapPacketEngine` with TPACKET_V2 ring buffer
- `ZeroCopyPacket` with Arc lifecycle management
- `AsyncPacketEngine` with Tokio AsyncFd
- All scanners migrated to `ScannerPacketEngine`

**NSE Resource Leak (Phase 10)**: COMPLETE
- Process-based isolation for script execution
- `rustnmap-nse-runner` binary for isolated execution
- `ProcessExecutor` with reliable timeout handling
- Default script timeout: 10 minutes (matching nmap)

### Performance Targets (Packet Engine)
| Metric | Target | Status |
|--------|--------|--------|
| PPS | ~1,000,000 | PENDING BENCHMARK |
| CPU (T5) | 30% | PENDING BENCHMARK |
| Packet Loss (T5) | <1% | PENDING BENCHMARK |
| Zero-copy | Verified | COMPLETE |

**See**: `task_plan.md` for current task plan

---

## Project Structure

```
rust-nmap/
├── crates/rustnmap-packet/    # PACKET_MMAP V2 engine (COMPLETE)
├── crates/rustnmap-scan/      # 12 scan types (MIGRATED TO PacketEngine)
├── crates/rustnmap-nse/       # NSE engine (PROCESS ISOLATION COMPLETE)
├── crates/rustnmap-core/      # Orchestration
├── crates/rustnmap-cli/       # CLI interface
├── doc/                       # All documentation
│   ├── architecture.md        # System architecture
│   ├── modules/               # Module-specific docs
│   └── manual/                # User manual
├── reference/nmap/            # Original nmap C++ source (use as reference)
├── task_plan.md               # Current task plan
├── progress.md                # Progress tracking
└── findings.md                # Research findings
```

---

## Essential Commands

```bash
just build              # Build all crates
just test               # Run all tests
just clippy             # Zero warnings required
just ci                 # Full CI pipeline

# Packet engine tests (requires root)
sudo cargo test -p rustnmap-packet
```

---

## Module Completion Criteria

- Unit tests coverage >= 80%
- Zero compiler warnings (`cargo clippy -- -D warnings`)
- All public APIs documented with `# Errors` and `# Panics` sections
- Benchmarks for hot paths
- Documentation in `doc/modules/` updated

---

## Network Volatility Handling (from nmap research)

Required components (partially implemented):

1. **Adaptive RTT** (RFC 6298): `SRTT = (7/8)*SRTT + (1/8)*RTT`
2. **Congestion Control**: cwnd, ssthresh, slow start, congestion avoidance
3. **Scan Delay Boost**: Exponential backoff on high drop rate
4. **Rate Limiting**: Token bucket for `--max-rate`/`--min-rate`
5. **ICMP Classification**: HOST_UNREACH, NET_UNREACH, PORT_UNREACH handling

**See**: `doc/architecture.md` Section 2.3 for full architecture

---

## Rust Code Standards (Mandatory)

```rust
// 1. Type names in docs use backticks
/// Load database. Returns `OsReference` or error.

// 2. Result functions MUST have # Errors section
/// # Errors
/// Returns error if file not found.

// 3. Builder methods MUST have #[must_use]
#[must_use]
pub fn with_timeout(mut self, timeout: Duration) -> Self { ... }

// 4. Numeric literals use separators
let timeout = 1_000_000;  // NOT 1000000

// 5. Use well-known constants
let addr = Ipv4Addr::LOCALHOST;  // NOT Ipv4Addr::new(127, 0, 0, 1)

// 6. Explicit casts with u64::from(x), NOT x as u64

// 7. Inlined format strings
format!("{var}")  // NOT format!("{}", var)

// 8. Match arms combined when identical
match x { "A" | "B" => result, _ => default }

// 9. Lint attributes: #[expect(clippy::lint, reason = "...")] at item level
// NEVER use module-level #![allow(...)]
```

---

## Key Design Patterns

### ScanSession Context
```rust
pub struct ScanSession {
    pub config: ScanConfig,
    pub target_set: Arc<TargetSet>,
    pub packet_engine: Arc<dyn PacketEngine>,  // Strategy pattern
    pub output_sink: Arc<dyn OutputSink>,
    pub stats: Arc<ScanStats>,
}
```

### Memory Ordering (for ring buffers)
```rust
// Producer
self.write_idx.fetch_add(1, Ordering::Relaxed);
atomic::fence(Ordering::Release);

// Consumer
let value = self.read_idx.load(Ordering::Acquire);
```

**See**: `doc/architecture.md` for full pattern documentation

---

## Documentation Index

| What | Where |
|------|-------|
| System Architecture | `doc/architecture.md` |
| Crate Structure | `doc/structure.md` |
| Packet Engineering | `doc/modules/packet-engineering.md` |
| Implementation Plan | `task_plan.md` |
| Research Findings | `findings.md` |
| Progress Log | `progress.md` |
| Nmap Reference | `reference/nmap/` |

---

## Timing Template Parameters

| Parameter | T0 | T1 | T2 | T3 | T4 | T5 |
|-----------|-----|-----|-----|-----|-----|-----|
| initial_rtt | 1s | 1s | 1s | 1s | 500ms | 250ms |
| max_retries | 10 | 10 | 10 | 10 | 6 | 2 |
| scan_delay | 5min | 15s | 400ms | 0ms | 0ms | 0ms |

---

## License

GPL-3.0-or-later. Uses Nmap fingerprint databases under NPSL.
See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
