# RustNmap - Rust Network Mapper

> **Version**: 2.0.0 | **Platform**: Linux x86_64 | **Rust**: 1.90+

---

## Develop and Test
- `nmap` and `/target/release/rustnmap` have been added in `/etc/sudoers`, so they can be executed with sudo without password

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

## CURRENT FOCUS: Packet Engine Redesign (Phase 40)

> **Status**: P0 - Blocks all performance fixes
> **Root Cause**: `rustnmap-packet` claims PACKET_MMAP V3 but uses `recvfrom()`

### Evidence
`crates/rustnmap-packet/src/lib.rs:764-765`:
```rust
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

### Impact
| Issue | Current | Cause |
|-------|---------|-------|
| T5 Insane | ~30% packet loss | recvfrom syscall overhead |
| UDP Scan | 3x slower than nmap | No zero-copy |
| CPU Usage | 80% under load | Per-packet syscalls |

### Architecture Decision: TPACKET_V2 (not V3)
- V3 has bugs in kernels < 3.19
- nmap uses V2 by default (`reference/nmap/libpcap/pcap-linux.c`)
- More stable and well-tested

### Key Components to Implement
| Component | File | Purpose |
|-----------|------|---------|
| `PacketEngine` trait | `engine.rs` | Core abstraction |
| `MmapPacketEngine` | `mmap.rs` | TPACKET_V2 ring buffer |
| `AsyncPacketEngine` | `async_engine.rs` | Tokio AsyncFd wrapper |
| `BpfFilter` | `bpf.rs` | Kernel-space filtering |

### Performance Targets
| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| PPS | ~50,000 | ~1,000,000 | 20x |
| CPU (T5) | 80% | 30% | 2.7x |
| Packet Loss (T5) | ~30% | <1% | 30x |

**See**: `task_plan.md` for 6-phase implementation plan

---

## Project Structure

```
rust-nmap/
├── crates/rustnmap-packet/    # PACKET_MMAP V2 engine (REDESIGN IN PROGRESS)
├── crates/rustnmap-scan/      # 12 scan types (NEEDS PACKET ENGINE MIGRATION)
├── crates/rustnmap-core/      # Orchestration
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
