# Progress Log

 RustNmap Packet Capture Architecture Redesign

> **Created**: 2026-02-21
> **Updated**: 2026-03-05
> **Status**: Phase 40 - Architecture Redesign

---

## Phase 40: Architecture Redesign Planning (2026-03-05)

### Current Status
- Completed comprehensive research on packet capture architectures
- Identified root cause: `recvfrom` instead of PACKET_MMAP ring buffer
- Created detailed task plan with 6 implementation phases
- Updated documentation with architecture design
- **NEW: Researched nmap's network volatility handling mechanisms**

### Research Completed
1. **PACKET_MMAP V2 Architecture**: Ring buffer design, frame/block structure
2. **Async Integration Patterns**: AsyncFd, channels, backpressure
3. **Network Volatility Handling**:
   - Adaptive RTT estimation (RFC 2988)
   - TCP-like congestion control (cwnd, ssthresh)
   - Dynamic scan delay boost
   - Rate limiting (token bucket)
   - Error recovery mechanisms

### Key Decisions
1. Use **TPACKET_V2** (not V3) for stability - following nmap's choice
2. Implement true PACKET_MMAP with ring buffers in `rustnmap-packet`
3. Use Tokio `AsyncFd` for async integration
4. Strategy pattern for multiple engine implementations
5. Channel-based packet distribution for concurrency
6. **NEW: Implement full network volatility handling suite**

### Missing Components Identified
| Component | Status | Priority |
|-----------|--------|----------|
| PACKET_MMAP V2 ring buffer | Not implemented | Critical |
| AsyncFd integration | Not implemented | Critical |
| Rate limiting (token bucket) | Not implemented | High |
| Dynamic scan delay boost | Partial | High |
| min/max RTT clamping | Partial | Medium |
| ICMP error classification | Partial | Medium |
| Network condition detection | Not implemented | Medium |

### Documentation Updates (2026-03-05)
- ✅ Updated `task_plan.md` with granular task breakdown for all 6 phases

---

## Phase 41-42: Design Document Systematic Fixes (2026-03-05)

### Issues Fixed

| Priority | Issue | Files Modified | Status |
|----------|-------|---------------|--------|
| HIGH | V2/V3 architecture inconsistency | structure.md, raw-packet.md, stateless-scan.md, roadmap.md | FIXED |
| HIGH | nmap version negotiation missing | architecture.md | FIXED |
| HIGH | Async implementation safety (double-close, raw pointers) | architecture.md | FIXED |
| MEDIUM | Kernel structure field error (tp_usec → tp_nsec) | packet-engineering.md | FIXED |
| MEDIUM | Documentation navigation broken links | README.md | FIXED |

### Requirement Verdict (Updated)
- Requirement 1 (not patch-style refactor): **PASS**
- Requirement 2 (Rust async/concurrency + design patterns): **PASS**
- Requirement 3 (no missing technical details): **PASS**

### Key Technical Corrections

1. **TPACKET Version**: Consistently use V2 across all docs (V3 has bugs in kernels < 3.19)
2. **nmap Reference**: Added version negotiation code from `reference/nmap/libpcap/pcap-linux.c:2974-3013`
3. **Async Safety**: Fixed `File::from_raw_fd` double-close by using `libc::dup()`
4. **Async Pattern**: Fixed raw pointer in spawn by using `Arc<Mutex<>>` pattern
5. **Kernel Header**: `tpacket2_hdr.tp_nsec` (nanoseconds, not `tp_usec`)
- ✅ Updated `findings.md` with nmap network volatility research
- ✅ Updated `doc/modules/packet-engineering.md` with:
  - TPACKET_V2 structure definitions
  - V2 vs V3 comparison table
  - mmap flags documentation
  - Error handling catalog
  - Testing strategy (actual targets, no mocks)
  - Dependency version specifications
  - Migration guide
- ✅ Updated `doc/architecture.md` with:
  - Packet Engine Architecture section (Section 2.3)
  - Current problem diagnosis table
  - Layered design diagram
  - Core component definitions (PacketEngine trait, MmapPacketEngine, AsyncPacketEngine)
  - Network volatility handling architecture diagram
  - Timing template parameter reference table
  - File structure planning
- ✅ Updated `doc/structure.md` with:
  - rustnmap-packet detailed structure (Section 5.3)
  - File structure for PACKET_MMAP V2 refactor
  - Key API examples
  - Dependency relationships
  - Performance targets
- ✅ Updated `CLAUDE.md` (project root) with:
  - Critical architecture issue section (Section 3)
  - TPACKET_V2 decision rationale
  - Redesign plan overview
  - Performance targets table
  - Network volatility handling summary
- ✅ Updated `crates/rustnmap-packet/CLAUDE.md` with:
  - Critical issue warning
  - Current vs target architecture comparison
  - Planned file structure
  - PacketEngine trait definition
  - TPACKET_V2 header structure
  - Memory ordering requirements
  - Testing requirements
- ✅ Updated `crates/rustnmap-scan/CLAUDE.md` with:
  - Packet engine migration notice
  - Network volatility handling gaps
  - Timing template parameters table
  - Updated dependencies

### Design Document Review (2026-03-05)
**Status**: COMPLETED - Documents Updated

#### Review Results Against Requirements

| Requirement | Status | Details |
|-------------|--------|---------|
| 1. Not patch-style refactoring | **PASS** | Complete architecture redesign with layered design |
| 2. Rust async/design patterns | **FIXED** | Added async-trait, memory ordering, Stream impl |
| 3. No missing technical details | **FIXED** | Added nmap implementation details |

#### Critical Gaps Fixed

| Gap | Fix Location |
|-----|--------------|
| Socket Option Sequence | `task_plan.md` Phase 1.2, `packet-engineering.md` |
| Memory Ordering (Acquire/Release) | `task_plan.md` Phase 1.1, `architecture.md`, `packet-engineering.md` |
| tpacket_req Calculations | `packet-engineering.md` - calculate_tpacket_req() |
| ENOMEM 5% Recovery | `task_plan.md` Phase 1.3, `packet-engineering.md` |
| Frame Pointer Array | `packet-engineering.md` - init_frame_pointers() |
| VLAN Reconstruction | `packet-engineering.md` - reconstruct_vlan_packet() |
| breakloop Pattern | `packet-engineering.md` - InterruptibleReceiver |
| async-trait Dependency | `task_plan.md`, `packet-engineering.md` |

#### Documents Updated

1. **doc/modules/packet-engineering.md**:
   - Added "nmap 实现研究" section with all critical patterns
   - Added socket option sequence with error consequences
   - Added tpacket_req calculation formulas
   - Added ENOMEM 5% recovery strategy
   - Added memory ordering requirements (Acquire/Release)
   - Added frame pointer array initialization
   - Added VLAN tag reconstruction logic
   - Added breakloop pattern with eventfd

2. **task_plan.md**:
   - Phase 1.1: Added memory ordering requirements
   - Phase 1.2: Added socket option sequence
   - Phase 1.3: Added tpacket_req calculations and ENOMEM strategy
   - Dependencies: Added async-trait = "0.1"

3. **doc/architecture.md**:
   - Fixed memory ordering in MmapPacketEngine (Acquire/Release)
   - Added SAFETY comments for atomic operations

### Next Steps
1. ~~Update project CLAUDE.md with packet engine architecture~~ ✅
2. ~~Update crate-level CLAUDE.md files (rustnmap-packet, rustnmap-scan)~~ ✅
3. ~~Simplify project CLAUDE.md~~ ✅ (612 lines → ~200 lines)
4. ~~Review design documents for completeness~~ ✅ (Gaps identified)
5. **Update design documents with missing technical details** (PENDING)
6. Review and approve task plan
7. Begin Phase 1: Core Infrastructure
8. Implement PACKET_MMAP V2 ring buffer
9. Add async support with AsyncFd
10. Implement network volatility handling mechanisms

### Zero-Memory Development Verification

**Can a new developer start with zero context?**

| Document | Purpose | Status | Sufficient |
|----------|---------|--------|------------|
| `CLAUDE.md` | Quick context, critical rules | ✅ Simplified | YES |
| `task_plan.md` | Implementation plan | ✅ Complete | YES |
| `findings.md` | Research findings | ✅ Complete | YES |
| `doc/architecture.md` | System architecture | ✅ Updated | YES |
| `doc/structure.md` | Crate structure | ✅ Updated | YES |
| `doc/modules/packet-engineering.md` | Technical specs | ✅ Updated | YES |
| `crates/rustnmap-packet/CLAUDE.md` | Crate guidance | ✅ Rewritten | YES |
| `crates/rustnmap-scan/CLAUDE.md` | Crate guidance | ✅ Updated | YES |

**Conclusion**: Documentation is sufficient for zero-memory development.

### Files to Modify (Planned)
**New Files:**
- `crates/rustnmap-packet/src/engine.rs` - PacketEngine trait
- `crates/rustnmap-packet/src/mmap.rs` - MmapPacketEngine
- `crates/rustnmap-packet/src/bpf.rs` - BPF utilities
- `crates/rustnmap-packet/src/async_engine.rs` - Async wrapper
- `crates/rustnmap-packet/src/stream.rs` - PacketStream

**Modified Files:**
- `crates/rustnmap-packet/src/lib.rs` - Re-export new API
- `crates/rustnmap-scan/src/ultrascan.rs` - Use new engine
- `crates/rustnmap-scan/src/syn_scan.rs` - Use new engine
- `crates/rustnmap-scan/src/stealth_scans.rs` - Use new engine
- `doc/modules/packet-engineering.md` - Update documentation

---

## Phase 39: T1 Timing Full Fix (2026-03-03)

### Completed
**Problem:** T1 timing was 4.8x faster than nmap (16s vs 76s)

**Solution:**
1. Added `enforce_scan_delay()` method to `ScanOrchestrator`
2. Initialize `last_probe_send_time` to `Some(Instant::now())`
3. Call `enforce_scan_delay()` before each probe

**Verification (3 runs):**
```
Test 1: nmap=45.81s, rustnmap=46.02s (diff=0.21s)
Test 2: nmap=45.89s, rustnmap=45.90s (diff=0.01s)
Test 3: nmap=45.81s, rustnmap=46.92s (diff=1.11s)
```

**Result:** T1 timing now matches nmap exactly (±1s)

### Remaining Issues
- UDP Scan: 3x slower than nmap (architecture issue)
- T5 Insane: Unreliable results (architecture issue)

---

## Phase 35-38: Stealth Scan Timing Fixes

### Completed
- Added `AdaptiveTiming` struct for nmap-style RTT estimation
- Fixed initial timeout calculation
- Removed artificial delays between retry rounds
- Updated all 6 batch scanners (FIN, NULL, XMAS, MAIMON, ACK, Window)

### Results
| Scan | Before | After | Nmap | Status |
|------|--------|-------|------|--------|
| FIN | 22283ms | 4558ms | 6229ms | 1.36x faster |
| NULL | 22331ms | 5279ms | 4208ms | OK |
| XMAS | 22832ms | 5338ms | 4930ms | OK |
| MAIMON | 22632ms | 4953ms | 6486ms | 1.30x faster |
| ACK | N/A | 712ms | 862ms | 1.21x faster |
| Window | N/A | 799ms | 680ms | OK |

---

## Test Results History

| Date | Pass | Fail | Skip | Rate | Notes |
|------|------|------|------|------|-------|
| 2026-03-05 | - | - | - | - | Architecture redesign planned |
| 2026-03-03 | 37 | 2 | 3 | 92.5% | T1 timing fixed |
| 2026-03-02 | 36 | 2 | 3 | 92.3% | OS Detection port fix |
| 2026-03-02 | 37 | 1 | 3 | 94.8% | Stealth timing fix |
| 2026-02-28 | 40 | 1 | 3 | 97.6% | BPF filter implementation |

---

## Phase 41: Doc Coverage Audit (2026-03-05)

### Completed
- Reviewed `doc/` design docs for packet-engine redesign coverage.
- Cross-checked against local nmap/libpcap reference:
  - `reference/nmap/libpcap/pcap-linux.c`
  - `prepare_tpacket_socket()` version negotiation
  - ring creation, ENOMEM 5% reduction, VLAN reconstruction, breakloop/eventfd paths

### Audit Result
- Requirement 1 (non-patch refactor): **PARTIAL**
- Requirement 2 (Rust async + patterns): **PARTIAL**
- Requirement 3 (no missing technical details): **FAIL**

### Blocking Gaps Logged
1. V2/V3 mixed guidance across docs (`structure.md`, `raw-packet.md`, `stateless-scan.md`, `roadmap.md`).
2. nmap version strategy not fully documented (V3-first then V2 fallback).
3. async examples in `architecture.md` contain ownership/lifetime issues.
4. `packet-engineering.md` has V2 header field inconsistency (`tp_usec` vs `tp_nsec`).
5. `doc/README.md` contains missing file links.

---

## Phase 42: Doc Re-Check After User Fixes (2026-03-05)

### Completed
- Re-audited updated `doc/` files against previous blockers.
- Verified V2 convergence and nmap negotiation reference updates.

### Current Status
- Previous high-priority blockers: mostly resolved.
- Remaining issues: mostly precision and example correctness.

### Completed Items
1. **TPACKET2 header padding/size** - FIXED: Changed `tp_padding[8]` to `tp_padding[4]`, size 48→32 bytes
2. **PacketStream busy-spin** - FIXED: Replaced with `ReceiverStream` pattern
3. **AsyncFd clone issue** - FIXED: Using `Arc<AsyncFd<OwnedFd>>` pattern
4. **nmap behavior consistency** - VERIFIED: Already consistent across docs
5. **Broken links** - VERIFIED: Links point to existing files

### All Issues Resolved
All 5 issues from Phase 42 audit have been fixed or verified as non-issues.

---

## Phase 43: Final Verification (2026-03-05)

### Completed
- Re-checked all five previously flagged items after latest edits.
- Validated `tpacket2_hdr` shape against `/usr/include/linux/if_packet.h`.

### Verification Result
- Blocking issues: **0**
- Non-blocking optimization: `doc/architecture.md` contains duplicate `Cargo.toml` dependency snippets in the Stream section; can be merged for clarity.

---

## Phase 44: Core Infrastructure Implementation (2026-03-05)

### Completed: Task 1.1 - System Call Wrappers

**Files Created:**
- `crates/rustnmap-packet/src/sys/mod.rs` - Module entry point
- `crates/rustnmap-packet/src/sys/tpacket.rs` - TPACKET_V2 structures
- `crates/rustnmap-packet/src/sys/if_packet.rs` - AF_PACKET constants

**Key Implementations:**
1. `Tpacket2Hdr` struct (32 bytes):
   - Correct field layout: `tp_status`, `tp_len`, `tp_snaplen`, `tp_mac`, `tp_net`, `tp_sec`, `tp_nsec`, `tp_vlan_tci`, `tp_vlan_tpid`, `tp_padding`
   - V2 uses `tp_nsec` (nanoseconds), NOT `tp_usec` (microseconds)
   - `tp_padding` is `[u8; 4]`, NOT `[u8; 8]`

2. `TpacketReq` struct:
   - `validate()` method with proper error handling
   - `ring_size()` calculation with overflow protection
   - Uses `is_multiple_of()` for alignment checks

3. `TpacketReqError` enum:
   - Comprehensive error variants for validation failures
   - Proper thiserror derive

4. Constants exported:
   - `AF_PACKET`, `SOCK_RAW`, `SOCK_DGRAM`
   - `ETH_P_ALL`, `ETH_P_IP`, `ETH_P_IPV6`, `ETH_P_ARP`
   - `PACKET_RX_RING`, `PACKET_TX_RING`, `PACKET_VERSION`, `PACKET_RESERVE`
   - `TPACKET_V2`, `TPACKET_ALIGNMENT`, `TPACKET2_HDRLEN`
   - `TP_STATUS_KERNEL`, `TP_STATUS_USER`, etc.

**Quality Verification:**
- All 22 tests pass
- Zero clippy warnings (`cargo clippy -- -D warnings`)
- All documentation has proper backticks for code items
- SAFETY comments for unsafe blocks
- Proper use of `std::ptr::from_ref().cast()` for pointer conversion

### Next Steps
- [x] Task 1.1: System call wrappers (COMPLETED)
- [x] Task 1.2: Create `engine.rs` - PacketEngine trait (COMPLETED)
- [x] Task 1.3: Create `error.rs` - PacketError enum (COMPLETED)
- [ ] Task 1.4: Create `mmap.rs` - MmapPacketEngine
- [ ] Task 1.5: Create `bpf.rs` - BPF filter utilities
- [ ] Task 1.6: Create `async_engine.rs` - AsyncPacketEngine
- [ ] Task 1.7: Create `stream.rs` - PacketStream

---

## Phase 44.5: Task 1.2 & 1.3 Completion (2026-03-05)

### Completed: Task 1.2 - PacketEngine Trait & Task 1.3 - Error Types

**Files Modified/Created:**
- `crates/rustnmap-packet/src/engine.rs` - Fixed file corruption, completed implementation
- `crates/rustnmap-packet/src/error.rs` - Already completed in previous session
- `crates/rustnmap-packet/src/lib.rs` - Removed duplicate tests

**Key Implementations:**

1. **`PacketEngine` trait** (async with async-trait):
   - `start()` - Start the packet engine
   - `recv()` - Receive a packet (async)
   - `send()` - Send a packet (async)
   - `stop()` - Stop the packet engine
   - `stats()` - Get engine statistics
   - `flush()` - Flush buffered packets
   - `set_filter()` - Set BPF filter

2. **`RingConfig` struct**:
   - `block_size`, `block_nr`, `frame_size`, `frame_timeout`
   - `enable_rx`, `enable_tx` flags
   - `validate()` method with proper error handling
   - Builder methods: `with_frame_timeout()`, `with_rx()`, `with_tx()`
   - `total_size()` and `frames_per_block()` helpers

3. **`PacketBuffer` struct**:
   - Zero-copy using `Bytes`
   - Timestamp tracking
   - Captured/original length tracking
   - VLAN TCI/TPID support
   - Methods: `from_data()`, `empty()`, `with_capacity()`, `resize()`, etc.

4. **`EngineStats` struct**:
   - Packets received/sent/dropped counters
   - Bytes received/sent counters
   - Error counters

**Quality Verification:**
- All 28 tests pass (16 new tests in engine.rs)
- Zero clippy warnings
- Proper rustfmt formatting
- Documentation with proper backticks
- SAFETY comments for unsafe blocks
- Proper `#[expect]` attributes for allowed lints

**Next Steps:**
- [ ] Task 1.4: Create `mmap.rs` - MmapPacketEngine (ring buffer implementation)
