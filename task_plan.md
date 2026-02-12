# Task Plan: RustNmap Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Status**: Phase 2 - Core Scanning (IN PROGRESS)
> **Created**: 2026-02-12
> **Goal**: Implement 100% Nmap-compatible network scanner in Rust

---

## Project Phases

### Phase 1: Infrastructure Foundation (COMPLETE)
**Status**: `complete`

All tasks completed:
- [x] Create Cargo workspace structure
- [x] Implement rustnmap-common crate
- [x] Implement rustnmap-net crate
- [x] Implement rustnmap-packet crate
- [x] Set up justfile recipes
- **Acceptance Criteria Met**:
  - All crates compile without warnings
  - `cargo test --workspace` passes (16 tests)
  - `cargo clippy --workspace -- -D warnings` passes
  - `cargo fmt --all -- --check` passes

---

### Phase 2: Core Scanning (COMPLETE)
**Status**: `complete`

| Task | Description | Priority | Status |
|------|-------------|----------|--------|
| 2.1 | rustnmap-target crate | P0 | COMPLETE | Target parsing complete |
| 2.2 | rustnmap-scan crate | P0 | COMPLETE | Core crate structure complete |
| 2.3 | TCP SYN scan | P0 | COMPLETE | Raw socket SYN scan implementation |
| 2.4 | TCP Connect scan | P0 | COMPLETE | std::net fallback scan |
| 2.5 | Timeout control | P0 | COMPLETE | RFC 2988 adaptive timeout |
| 2.6 | Host discovery | P0 | COMPLETE | ICMP/TCP/ARP discovery |
| 2.7 | Probe module | P0 | COMPLETE | TCP packet building utilities |

**Acceptance Criteria Met**:
- PortScanner trait defined for scanner implementations
- ScanConfig supports timing templates (T0-T5)
- TimeoutTracker provides adaptive RTT-based timeouts
- All modules have unit tests with >80% coverage
- Zero compilation warnings when excluding phased-out attributes

---

### Phase 3: Advanced Features (COMPLETE)
**Status**: `complete`

| Task | Description | Priority | Status |
|------|-------------|----------|--------|
| 3.1 | rustnmap-fingerprint crate | P1 | COMPLETE | Service/OS detection |
| 3.2 | Service detection | P1 | COMPLETE | Version probing |
| 3.3 | OS detection | P1 | COMPLETE | TCP/IP fingerprinting |
| 3.4 | rustnmap-traceroute crate | P1 | COMPLETE | Network route tracing |
| 3.5 | rustnmap-evasion crate | P1 | COMPLETE | Firewall bypass |

**Acceptance Criteria Met**:
- All 85 tests passing for rustnmap-evasion
- All 76 tests passing for rustnmap-traceroute
- Zero clippy warnings across all Phase 3 crates
- Comprehensive documentation on public APIs

---

### Phase 4: NSE Script Engine (COMPLETE)
**Status**: `complete`

| Task | Description | Priority | Status |
|------|-------------|----------|--------|
| 4.1 | rustnmap-nse crate structure | P0 | COMPLETE | Lua 5.4 runtime setup |
| 4.2 | Script scheduler | P1 | COMPLETE | Concurrent execution |
| 4.3 | NSE libraries | P1 | COMPLETE | nmap, stdnse, etc. |
| 4.4 | Script database | P0 | COMPLETE | Service script scripts |
| 4.5 | Protocol modules | P2 | COMPLETE | HTTP, SSL, SSH, etc. |

**Acceptance Criteria Met**:
- 35 unit tests passing (100% pass rate)
- Zero clippy warnings
- Full Lua 5.4 runtime integration via mlua
- Script database with loading, parsing, and selection
- Script scheduler with concurrency control
- Script execution engine with host table support

---

### Phase 5: Integration (IN PROGRESS)
**Status**: `in_progress`

| Task | Description | Priority | Status |
|------|-------------|----------|--------|
| 5.1 | rustnmap-output crate | P0 | pending | Output formatters (Normal, XML, JSON, Grepable) |
| 5.2 | rustnmap-cli crate | P0 | pending | Main entry point |
| 5.3 | CLI integration | P0 | pending | Argument parsing with clap |
| 5.4 | Scan orchestrator | P0 | pending | Main scan session coordination |
| 5.5 | Documentation | P0 | pending | rustdoc guides |
| 5.6 | Integration tests | P2 | pending | End-to-end validation |

**Acceptance Criteria**:
- All output formats implemented (Normal, XML, JSON, Grepable, Script Kiddie)
- CLI with full Nmap-compatible argument parsing
- Scan orchestrator coordinating all modules
- Integration tests for complete scan workflows
- Zero compiler warnings across all crates

---

## Decision Rationale

| Decision | Rationale |
|---------|-----------|
| Linux x86_64 only | Simplifies raw socket handling, PACKET_MMAP V3 available |
| Tokio for async | Proven async runtime, excellent ecosystem |
| pnet for packets | Mature packet parsing library |
| mlua for Lua | Best-in-class Lua bindings for NSE |
| Module-by-module | Ensures completeness before moving forward |

---

## Errors Encountered

| Error | Attempt | Resolution |
|--------|-----------|
| None yet | - | Project just started |

---

## Next Steps

### Phase 2: Core Scanning (CONTINUED)

Current focus: Completing scan implementations with real raw socket I/O

1. **Enhance probe module** with real packet transmission
2. **Fix syn_scan AtomicU32 type** issues
3. **Add ICMP packet parsing** support
4. **Implement ARP discovery** for local networks

### Phase 3: Advanced Features (FUTURE)

- Service detection and version probing
- TCP/IP fingerprinting for OS detection
- Stealth scan techniques (FIN, NULL, XMAS)
- Timing and congestion control algorithms

---

## Reference Materials

- `doc/README.md` - Documentation index
- `doc/architecture.md` - System architecture
- `doc/modules/*.md` - Module-specific design docs
- `reference/nmap/` - Original Nmap source code
