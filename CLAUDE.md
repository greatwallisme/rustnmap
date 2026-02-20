# RustNmap - Rust Network Mapper

> **Version**: 2.0.0 (In Development)
> **Status**: Production Ready (1.0) / Development (2.0)
> **Platform**: Linux x86_64 (AMD64)
> **Language**: Rust 1.90+
> **Completion Date**: 2026-02-16 (1.0)
> **2.0 Roadmap**: See [RETHINK.md](RETHINK.md)

---

## Most Important
- Pay Attention to Code Quality Hook Error Messages. **Do not** attempt to bypass or disable the Hook
- **Zero warning**, **Zero error**. **NEVER** allow any warning or error by relaxing clippy standards in configuration 

## Project Overview

RustNmap is a modern, high-performance network scanning tool written in Rust, designed to provide 100% functional parity with Nmap while leveraging Rust's safety guarantees and asynchronous capabilities for improved performance.

### RustNmap 2.0 Vision

Evolving from a "port scanner" to an "Attack Surface Management Platform" with:
- **Vulnerability Intelligence**: CVE/CPE association, EPSS scoring, CISA KEV marking
- **Platform Integration**: REST API, Rust SDK, daemon mode
- **Scan Management**: SQLite persistence, diff comparison, YAML profiles
- **Performance**: Two-phase scanning, stateless mode, adaptive batching

---

### Project Metrics

| Metric | Value |
|--------|-------|
| Total Lines of Code | 35,356 |
| Workspace Crates | 14 (1.0) / 17 (2.0 planned) |
| Tests Passing | 970+ |
| Code Coverage | 75.09% |
| Compiler Warnings | 0 |
| Clippy Warnings | 0 |
| Security Audit | Grade A- |

## Project Structure

```
rust-nmap/
├── reference/                    # Reference materials
│   ├── nmap/                     # Original Nmap C++ source code
│   └── third_party_design/       # Third-party design references
├── doc/                          # Design documentation
│   ├── README.md                 # Documentation index
│   ├── architecture.md           # System architecture
│   ├── user-guide.md             # Comprehensive user guide
│   ├── manual/                   # User manual (9 files, 5,371 lines)
│   │   ├── README.md             # Manual index
│   │   ├── quick-reference.md    # Quick reference card
│   │   ├── options.md            # CLI options reference
│   │   ├── scan-types.md         # Scan type documentation
│   │   ├── output-formats.md     # Output format specs
│   │   ├── nse-scripts.md        # NSE scripting guide
│   │   ├── exit-codes.md         # Exit codes reference
│   │   ├── environment.md        # Environment variables
│   │   └── configuration.md      # Config file format
│   ├── rustnmap.1                # Unix man page
│   ├── modules/                  # Module-specific design docs
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
│   └── appendix/                 # Reference appendices
├── crates/                       # Cargo workspace crates (14 total)
├── justfile                      # Just command runner recipes
├── rust-toolchain.toml           # Rust toolchain specification
├── task_plan.md                  # Task planning document
├── progress.md                   # Progress tracking
└── findings.md                   # Security audit findings
```

## Development Principles


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

### Current Crates (1.0)

| Crate | Description | Status | Tests |
|-------|-------------|--------|-------|
| `rustnmap-common` | Common types, errors, utilities | Complete | 50+ |
| `rustnmap-net` | Network primitives, socket abstractions | Complete | 25+ |
| `rustnmap-packet` | PACKET_MMAP V3 zero-copy packet engine | Complete | 30+ |
| `rustnmap-target` | Target parsing and host discovery | Complete | 100+ |
| `rustnmap-scan` | Port scanning implementations | Complete | 104+ |
| `rustnmap-fingerprint` | OS and service fingerprinting | Complete | 200+ |
| `rustnmap-nse` | Lua script engine with Nmap compatibility | Complete | 109+ |
| `rustnmap-traceroute` | Network route tracing | Complete | 99+ |
| `rustnmap-evasion` | Firewall/IDS evasion techniques | Complete | 58+ |
| `rustnmap-cli` | Command-line interface and output | Complete | 76+ |
| `rustnmap-core` | Core orchestration and state management | Complete | 140+ |
| `rustnmap-output` | Output formatters (XML, JSON, etc.) | Complete | 53+ |
| `rustnmap-benchmarks` | Performance benchmarks | Complete | - |
| `rustnmap-macros` | Procedural macros | Complete | - |

### Planned Crates (2.0)

| Crate | Description | Phase | Status |
|-------|-------------|-------|--------|
| `rustnmap-vuln` | Vulnerability intelligence (CVE/CPE, EPSS, KEV) | Phase 2 | Documented |
| `rustnmap-api` | REST API / Daemon mode | Phase 5 | Documented |
| `rustnmap-sdk` | Rust SDK (Builder API) | Phase 5 | Documented |

## Build and Test Commands

```bash
# Build commands
just build              # Build all crates
just build-release      # Build release binary
just check              # Fast syntax check

# Test commands
just test               # Run all tests
just test-unit          # Unit tests only
just test-integration   # Integration tests only
just test-crate <name>  # Tests for specific crate

# Code quality
just clippy             # Run clippy linter
just fmt                # Format all code
just fmt-check          # Check formatting without changes

# Documentation
just doc                # Build documentation
just doc-open           # Build and open docs

# Benchmarks
just bench              # Run all benchmarks
just bench-scan         # Scan benchmarks only
just bench-packet       # Packet benchmarks only
just bench-fingerprint  # Fingerprint benchmarks only
just bench-nse          # NSE benchmarks only

# Code coverage
just coverage           # Generate HTML coverage report
just coverage-text      # Generate text coverage report
just coverage-summary   # Summary only
just coverage-lcov      # LCOV format for CI
just coverage-clean     # Clean coverage artifacts

# Security
just audit              # Run cargo-audit security check

# CI pipeline
just ci                 # Run full CI pipeline
just install-tools      # Install required dev tools
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

## Security Audit Results

**Overall Grade: A-**

| Category | Status | Details |
|----------|--------|---------|
| Unsafe Code | PASS | 7 unsafe blocks, all documented with SAFETY comments |
| Panic Analysis | PASS | 18 panics (minimal, acceptable for programming errors) |
| Input Validation | PASS | Comprehensive validation on all CLI inputs |
| Buffer Overflow | PASS | Rust memory safety prevents overflows |
| Error Handling | PASS | Proper Result types throughout |
| Secrets in Logs | PASS | No credential leakage |
| File Path Validation | PASS | Path traversal prevented |
| Network Validation | PASS | IP/port validation on all network inputs |

See `findings.md` for detailed security audit report.

## Implementation Status

### Phase 1: Infrastructure - COMPLETE
- rustnmap-common: Base types, errors, utilities
- rustnmap-net: Raw sockets, packet construction
- rustnmap-packet: PACKET_MMAP V3 zero-copy engine

### Phase 2: Core Scanning - COMPLETE
- rustnmap-target: Target parsing, host discovery (IPv4/IPv6)
- rustnmap-scan: 12 scan types, timeout control
- rustnmap-fingerprint: OS/service fingerprint matching, TLS detection

### Phase 3: Advanced Features - COMPLETE
- rustnmap-nse: Full Lua 5.4 engine with nmap/stdnse/comm libraries
- rustnmap-traceroute: All methods (ICMP, TCP, UDP)
- rustnmap-evasion: Fragmentation, decoys, spoofing

### Phase 4: Integration - COMPLETE
- rustnmap-cli: Full CLI with 60+ options
- rustnmap-core: Orchestration and state management
- rustnmap-output: All 5 output formats

## User Documentation

| Document | Location | Description |
|----------|----------|-------------|
| User Guide | `doc/user-guide.md` | Complete guide with examples (1,100+ lines) |
| Manual Index | `doc/manual/README.md` | Navigate all manual sections |
| Quick Reference | `doc/manual/quick-reference.md` | Command cheat sheet |
| CLI Reference | `doc/manual/options.md` | All 60+ options documented |
| Scan Types | `doc/manual/scan-types.md` | 12 scan type explanations |
| Output Formats | `doc/manual/output-formats.md` | Format specifications |
| NSE Scripts | `doc/manual/nse-scripts.md` | Scripting guide |
| Man Page | `doc/rustnmap.1` | Unix manual page |

## Next Steps

1. **Continuous Testing**: Run `just ci` before any commits
2. **Documentation**: Refer to `doc/manual/` for user-facing features
3. **Security**: Run `just audit` periodically to check dependencies
4. **Coverage**: Use `just coverage` to identify untested code paths

## Reference Documentation

### 1.0 Documentation
- Nmap Source: `reference/nmap/` - Original C++ implementation
- Deepseek Design: `reference/third_party_design/deepseek.md` - Architecture reference
- Module Docs: `doc/modules/*.md` - Detailed design per module
- Nmap Reference: `doc/appendix/nmap-*.md` - Data structures, functions, constants

### 2.0 Documentation
- **Roadmap**: `RETHINK.md` - RustNmap 2.0 evolution plan (12-week execution)
- **Module Docs**: `doc/modules/vulnerability.md` - Vulnerability intelligence
- **API Docs**: `doc/modules/rest-api.md` - REST API / Daemon mode
- **SDK Docs**: `doc/modules/sdk.md` - Rust SDK Builder API
- **Management**: `doc/modules/scan-management.md` - Scan management (SQLite, diff, profiles)
- **Stateless**: `doc/modules/stateless-scan.md` - Stateless fast scanning
- **Progress**: `doc/CHANGELOG.md` - 2.0 documentation changelog

## Progress Tracking

### 1.0 Tracking
- `progress.md` - Session-by-session progress log
- `task_plan.md` - Detailed task breakdown
- `findings.md` - Analysis and gap identification

### 2.0 Tracking
- `RETHINK.md` - 2.0 evolution roadmap (simplified historical doc)
- `doc/CHANGELOG.md` - 2.0 documentation changelog
- `doc/architecture.md` - Updated architecture with 2.0 crates
- `doc/structure.md` - Updated crate structure (17 crates)

## Notes

### 1.0 Notes
- All development targets Linux x86_64 only (no cross-platform concerns)
- Root privileges required for raw socket operations
- Follow `rust-guidelines` for all Rust code patterns
- Refer to Nmap source code when behavior is ambiguous

### Rust Code Standards (Mandatory)

**ALL code MUST follow these rules. Violations will be rejected:**

#### 1. Documentation Requirements
- **Type names in docs MUST use backticks**: `OsReference`, `HashMap`, etc.
- **Functions returning Result MUST have `# Errors` section**
- **Functions that may panic MUST have `# Panics` section**
- Example:
```rust
/// Load database from file.
///
/// # Errors
/// Returns error if file not found or invalid format.
///
/// # Panics
/// Panics if config is not initialized.
pub fn load(path: &str) -> Result<Self> { ... }
```

#### 2. Builder Pattern Methods MUST have `#[must_use]`
```rust
#[must_use]
pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
}
```

#### 3. Numeric Literals MUST Use Separators
```rust
// Bad
let timeout = 1000000;

// Good
let timeout = 1_000_000;
```

#### 4. Use Well-Known Constants Instead of Hard-coded Values
```rust
// Bad
let addr = Ipv4Addr::new(127, 0, 0, 1);

// Good
let addr = Ipv4Addr::LOCALHOST;
```

#### 5. Casts MUST Be Explicit and Safe
```rust
// Bad - lossy cast
let val = x as u64;

// Good - explicit conversion
let val = u64::from(x);

// Or with allow attribute if intentional
#[allow(clippy::cast_possible_truncation)]
let val = x as u8;  // Safe because we know x < 256
```

#### 6. Format Strings MUST Be Inlined
```rust
// Bad
format!("{}", var)
format!("Error: {}", e)

// Good
format!("{var}")
format!("Error: {e}")
```

#### 7. Match Arms MUST NOT Have Identical Bodies
```rust
// Bad
match x {
    "A" => result,
    "B" => result,  // Same as above
    _ => default,
}

// Good
match x {
    "A" | "B" => result,
    _ => default,
}
```

#### 8. Functions MUST NOT Return Unnecessary Result/Option
```rust
// Bad - never returns Err
fn get_value() -> Result<i32> {
    Ok(42)
}

// Good
fn get_value() -> i32 {
    42
}
```

#### 9. Async Functions MUST Use await
```rust
// Bad - no await, should be sync
async fn get_data() -> i32 {
    42
}

// Good - either add await or make sync
fn get_data() -> i32 {
    42
}
```

#### 10. Clone Assignments MUST Use clone_from
```rust
// Bad
dest = source.clone();

// Good
dest.clone_from(&source);
```

### 2.0 Development Notes
- See `RETHINK.md` for the complete 2.0 evolution plan
- 2.0 adds 3 new crates: `rustnmap-vuln`, `rustnmap-api`, `rustnmap-sdk`
- 2.0 modules are documented in `doc/modules/` (vulnerability, rest-api, sdk, etc.)
- Phase 0 baseline fixes must be completed before Phase 1-5 features

## License

RustNmap is licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

| Component | License | File |
|-----------|---------|------|
| RustNmap Source Code | GPL-3.0-or-later | [LICENSE](LICENSE) |
| Nmap Fingerprint Databases | NPSL | [NOTICE](NOTICE) |

### Nmap Data Dependency

RustNmap uses Nmap's fingerprint databases which are licensed under the Nmap Public Source License (NPSL):
- `nmap-service-probes` - Service version detection
- `nmap-os-db` - OS fingerprinting

When using these databases, you must comply with NPSL terms. See:
- [COPYING](COPYING) - Nmap attribution
- [NOTICE](NOTICE) - Data dependency notice
- https://nmap.org/npsl/ - NPSL full text

### Why GPL-3.0-or-later?

GPL-3.0-or-later was chosen because:
1. **NPSL Compatibility**: GPL-3.0 is compatible with GPL-2.0 works (NPSL's base)
2. **Copyleft Protection**: Prevents closed-source derivatives
3. **Patent Protection**: Explicit patent grant in GPL-3.0
4. **Future-Proof**: "Or-later" allows upgrade to future GPL versions
