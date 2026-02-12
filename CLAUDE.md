# RustNmap - Rust Network Mapper

> **Version**: 1.0.0
> **Status**: Design Phase
> **Platform**: Linux x86_64 (AMD64)
> **Language**: Rust

## Project Overview

RustNmap is a modern, high-performance network scanning tool written in Rust, designed to provide 100% functional parity with Nmap while leveraging Rust's safety guarantees and asynchronous capabilities for improved performance.

## Project Structure

```
rust-nmap/
├── reference/                    # Reference materials
│   ├── nmap/                     # Original Nmap C++ source code
│   └── third_party_design/       # Third-party design references
├── doc/                          # Design documentation
│   ├── README.md                 # Documentation index
│   ├── architecture.md           # System architecture
│   ├── modules/                 # Module-specific design docs
│   │   ├── host-discovery.md
│   │   ├── port-scanning.md
│   │   ├── service-detection.md
│   │   ├── os-detection.md
│   │   ├── nse-engine.md
│   │   ├── traceroute.md
│   │   ├── evasion.md
│   │   ├── output.md
│   │   ├── target-parsing.md
│   │   ├── raw-packet.md
│   │   └── concurrency.md
│   └── appendix/                # Reference appendices
├── justfile                      # Just command runner recipes
├── task_plan.md                  # Task planning document
├── progress.md                   # Progress tracking
└── findings.md                   # Analysis findings
```

## Development Principles

### 0. Pay Attention to Code Quality Hook Error Messages. Do not attempt to bypass or disable the Hook

### 1. No Simplification

**CRITICAL**: This project aims for 100% functional parity with Nmap. NO simplifications are permitted:

| Feature | Nmap Behavior | Required Implementation |
|---------|---------------|------------------------|
| Scan Types | SYN, CONNECT, FIN, NULL, XMAS, MAIMON, UDP, SCTP, IP Protocol | ALL must be implemented |
| Port States | 10 distinct states (OPEN, CLOSED, FILTERED, etc.) | Exact state machine |
| OS Detection | TCP/IP fingerprint matching with 1000+ signatures | Full FP engine |
| NSE Scripts | Complete Lua 5.4 engine with all nmap libraries | Full compatibility |
| Output Formats | Normal, XML, JSON, Grepable, Script Kiddie | All formats |
| Timing Templates | T0 (Paranoid) through T5 (Insane) | Exact timing behavior |
| Evasion Techniques | Decoy, source port manipulation, fragmentation | Full evasion support |
| IPv6 Support | Complete dual-stack operation | Full IPv6 parity |

### 2. Module-by-Module Development 

Development must proceed through modules in strict order. Each module must be **fully complete** before proceeding to the next:

```
Phase 1: Infrastructure
├── rustnmap-common      (基础类型、错误、工具)
├── rustnmap-net         (原始套接字、数据包构造)
└── rustnmap-packet      (PACKET_MMAP V3 零拷贝引擎)

Phase 2: Core Scanning
├── rustnmap-target      (目标解析、主机发现)
├── rustnmap-scan        (端口扫描、超时控制)
└── rustnmap-fingerprint (OS/服务指纹匹配)

Phase 3: Advanced Features
├── rustnmap-nse         (Lua 脚本引擎)
├── rustnmap-traceroute  (路由追踪)
└── rustnmap-evasion     (规避技术)

Phase 4: Integration
└── rustnmap-cli         (CLI、输出格式化)
```

**Module Completion Criteria:**
- All public APIs documented with examples
- Unit tests coverage >= 80%
- Integration tests for major workflows
- Zero compiler warnings (`cargo clippy -- -D warnings`)
- Benchmarks for hot paths
- Documentation in `doc/modules/` updated

### 3. Quality Standards

```bash
# Before committing any code:
cargo test                            # All tests pass
cargo clippy -- -D warnings          # Zero warnings
cargo fmt --check                    # Code formatted
cargo doc --no-deps                 # Docs build without errors
```

## Cargo Workspace Structure

The project uses a Cargo workspace with the following crates:

| Crate | Description | Status |
|-------|-------------|--------|
| `rustnmap-common` | Common types, errors, utilities | Planned |
| `rustnmap-net` | Network primitives, socket abstractions | Planned |
| `rustnmap-packet` | PACKET_MMAP V3 zero-copy packet engine | Planned |
| `rustnmap-target` | Target parsing and host discovery | Planned |
| `rustnmap-scan` | Port scanning implementations | Planned |
| `rustnmap-fingerprint` | OS and service fingerprinting | Planned |
| `rustnmap-nse` | Lua script engine with Nmap compatibility | Planned |
| `rustnmap-traceroute` | Network route tracing | Planned |
| `rustnmap-evasion` | Firewall/IDS evasion techniques | Planned |
| `rustnmap-cli` | Command-line interface and output | Planned |

## Build and Test Commands

```bash
# Build all crates
just build

# Run tests for all crates
just test

# Run clippy on all crates
just clippy

# Format code
just fmt

# Build release binary
just release

# Run benchmarks
just bench
```

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Rust 1.85+ | Memory safety, zero-cost abstractions |
| Async Runtime | tokio | High-performance async I/O |
| Packet I/O | AF_PACKET + PACKET_MMAP V3 | Zero-copy kernel bypass |
| CLI | clap | Argument parsing with derive API |
| Serialization | serde | XML/JSON output formats |
| Scripting | mlua (Lua 5.4) | NSE script compatibility |
| Networking | pnet + raw sockets | Cross-protocol packet crafting |
| Testing | proptest | Property-based testing |

## Key Design Patterns

### ScanSession Context

All modules interact through a `ScanSession` context for dependency injection and testability:

```rust
pub struct ScanSession {
    pub config: ScanConfig,
    pub target_set: Arc<TargetSet>,
    pub packet_engine: Arc<dyn PacketEngine>,
    pub output_sink: Arc<dyn OutputSink>,
    pub fingerprint_db: Arc<FingerprintDatabase>,
    pub nse_registry: Arc<ScriptRegistry>,
    pub stats: Arc<ScanStats>,
}
```

### Zero-Copy Packet Path

Hot path packet handling uses PACKET_MMAP V3 ring buffers:

```rust
pub struct PacketBuffer {
    pub data: bytes::Bytes,  // Zero-copy reference
    pub len: usize,
    pub timestamp: std::time::Duration,
}
```

### Memory-Ordered Atomics

Packet queues use proper memory ordering:

```rust
// Producer
self.write_idx.fetch_add(1, Ordering::Relaxed);
atomic::fence(Ordering::Release);

// Consumer
let value = self.read_idx.load(Ordering::Acquire);
```

## Testing Strategy

1. **Unit Tests**: Per-module logic testing
2. **Integration Tests**: Cross-module workflows
3. **Property Tests**: Invariant validation with proptest
4. **Benchmarks**: Criterion for hot paths
5. **Mock Engine**: PacketEngine trait allows testing without root

## Reference Documentation

- Nmap Source: `reference/nmap/` - Original C++ implementation
- Deepseek Design: `reference/third_party_design/deepseek.md` - Architecture reference
- Module Docs: `doc/modules/*.md` - Detailed design per module
- Nmap Reference: `doc/appendix/nmap-*.md` - Data structures, functions, constants

## Progress Tracking

Current progress is tracked in:
- `progress.md` - Session-by-session progress log
- `task_plan.md` - Detailed task breakdown
- `findings.md` - Analysis and gap identification

## Notes

- All development targets Linux x86_64 only (no cross-platform concerns)
- Root privileges required for raw socket operations
- Follow `rust-guidelines` for all Rust code patterns
- Refer to Nmap source code when behavior is ambiguous
