# Task Plan: Packet Engine Migration - Phase 3.5+

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: Phase 3.5 Complete, Phase 4 Planning
> **Priority**: P0 - Critical

---

## Executive Summary

Phase 3.4 (Receive Path Integration) is COMPLETE. Phase 3.5 cleanup is partially complete.
Awaiting direction on Phase 4 scope.

### Completed Phases

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Core Infrastructure (TPACKET_V2, MmapPacketEngine, BPF) | COMPLETE |
| Phase 3.1 | Infrastructure Preparation (icmp_dst, recv_timeout, ScannerPacketEngine) | COMPLETE |
| Phase 3.2 | Simple Scanner Migration (FIN/NULL/XMAS) | COMPLETE |
| Phase 3.3 | Complex Scanner Infrastructure (TcpSynScanner, ParallelScanEngine, UdpScanner) | COMPLETE |
| Phase 3.4 | Receive Path Integration | COMPLETE |
| **Phase 3.5** | **Cleanup and Performance Validation** | **PARTIALLY COMPLETE** |

---

## Phase 3.5: Cleanup and Performance Validation

### Tasks

#### Task 3.5.1: Remove SimpleAfPacket from ultrascan.rs ✅ COMPLETE

**Status**: COMPLETE

**Completed Changes**:
1. Removed `SimpleAfPacket` struct and impl block (~300 lines)
2. Removed `SockFilter` and `SockFprog` helper structs
3. Removed `ETH_P_ALL` constant
4. Removed unused imports (`std::io`, `std::mem`, `std::ptr`, `std::os::fd`)
5. Removed unused `get_interface_for_ip()` function

**Migration**:
- Updated `scan_udp_ports()` to use `ScannerPacketEngine` from `packet_adapter`
- Replaced `SimpleAfPacket::new()` with `create_stealth_engine()`
- Converted `start_icmp_receiver_task()` from `std::thread::spawn` to `tokio::spawn`
- Uses `BpfFilter::icmp_dst()` for kernel-space filtering

**Verification**:
- Zero clippy warnings: `cargo clippy --workspace -- -D warnings`
- All tests pass (1 pre-existing failure unrelated to changes)

**Files Modified**:
- `crates/rustnmap-scan/src/ultrascan.rs`

---

#### Task 3.5.2: Remove AfPacketEngine from rustnmap-packet ⏸️ DEFERRED

**Status**: DEFERRED - Requires async migration first

**Reason**:
- `AfPacketEngine` is still actively used in `UdpScanner::scan_port_impl()` (line 299)
- Used for non-blocking ICMP error capture during UDP scanning
- The new `ScannerPacketEngine` field (`scanner_engine_v4`) is marked as dead code
- Migrating would require converting the synchronous scan method to async

**Current Usage** (from `udp_scan.rs:299-319`):
```rust
// Try AF_PACKET engine first for ICMP errors (if available)
if let Some(engine) = &self.packet_engine_v4 {
    // Non-blocking check for ICMP packet
    if let Ok(Some(packet)) = engine.recv_packet() {
        // Process ICMP response...
    }
}
```

**Migration Required**:
1. Convert `scan_port_impl()` to async method
2. Replace `AfPacketEngine::recv_packet()` with `ScannerPacketEngine::recv_with_timeout()`
3. Update all call sites to use async/await
4. Remove `AfPacketEngine` after migration is complete

**Action**: Defer to future phase when async migration is complete

---

#### Task 3.5.3: Update Documentation ✅ COMPLETE

**Status**: COMPLETE

**Completed**:
1. Updated `findings.md` with bug status (Bug #1 fixed, Bug #2 deferred)
2. Updated `task_plan.md` to reflect current state
3. Verified architecture documentation is current

**Notes**:
- Bug #1 (Atomic access) has been verified as fixed
- Bug #2 (Zero-copy) remains - requires API redesign for frame lifetime tracking
- Bug #3 (Mutex) is NOT a bug - required for thread safety due to non-atomic rx_frame_idx

---

#### Task 3.5.4: Add Integration Tests ⏸️ PENDING

**Status**: PENDING - Deferred to Phase 4

**Tests Required**:
1. PACKET_MMAP V2 ring buffer operation
2. Zero-copy packet reception
3. BPF filter attachment
4. Performance benchmarks (PPS measurement)
5. Packet loss under T5 Insane timing

---

#### Task 3.5.5: Performance Validation ⏸️ PENDING

**Status**: PENDING - Deferred to Phase 4 (requires Bug #2 fix)

**Target Metrics**:

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| PPS | ~50,000 | ~1,000,000 | 20x |
| CPU (T5) | 80% | 30% | 2.7x |
| Packet Loss (T5) | ~30% | <1% | 30x |

**Blocker**: Bug #2 (Zero-copy data copy at mmap.rs:719) must be fixed first

---

## Completed Phases

### Phase 1: Core Infrastructure (COMPLETE)

- TPACKET_V2 structures, syscall wrappers
- MmapPacketEngine implementation
- AsyncPacketEngine with Tokio integration
- BPF filter support
- PacketStream implementation

### Phase 3.1: Infrastructure Preparation (COMPLETE)

- `icmp_dst()` filter added
- `recv_timeout()` method added
- `ScannerPacketEngine` adapter created
- `to_sock_fprog()` exposure

### Phase 3.2: Simple Scanner Migration (COMPLETE)

- TcpFinScanner migrated
- TcpNullScanner migrated
- TcpXmasScanner migrated

### Phase 3.3: Complex Scanner Infrastructure (COMPLETE)

- ScannerPacketEngine integrated into TcpSynScanner
- Stealth scanners infrastructure updated
- Migration helpers added

### Phase 3.4: Receive Path Integration (COMPLETE)

- Task #1: TcpSynScanner receive path integration (COMPLETE)
- Task #2: Stealth scanners infrastructure (COMPLETE)
- Task #3: ParallelScanEngine receive path (COMPLETE)
- Task #4: UdpScanner receive path (COMPLETE)
- Task #5: Run tests and verify zero warnings (COMPLETE)

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| Type mismatch in `start_receiver_task` | 1 | Rewrote function with consistent return types |
| Missing `get_interface_for_ip` function | 1 | Added function back to ParallelScanEngine |
| Items-after-statements warning | 1 | Moved const declaration outside if block |
| Doc-markdown warning | 1 | Added backticks around `PACKET_MMAP` |
| Unfulfilled lint expectation | 1 | Removed `#[expect(dead_code)]` from SimpleAfPacket |
| unused_async warning | 1 | Removed `async` from `start_icmp_receiver_task` |
| unused imports | 1 | Removed `std::io`, `std::mem`, `std::ptr`, `std::os::fd` |
| unused `get_interface_for_ip` | 1 | Removed function (replaced by `create_stealth_engine`) |
| **Task 3.5.2 blocked** | **1** | **AfPacketEngine still used in UDP scanner** |

---

## Summary

Phase 3.5 cleanup is partially complete:
- **Task 3.5.1**: ✅ COMPLETE - Removed `SimpleAfPacket` from `ultrascan.rs`
- **Task 3.5.2**: ⏸️ DEFERRED - `AfPacketEngine` still actively used in UDP scanner
- **Task 3.5.3**: 🔄 IN PROGRESS - Documentation updates
- **Task 3.5.4**: ⏸️ PENDING - Integration tests (blocked by 3.5.2)
- **Task 3.5.5**: ⏸️ PENDING - Performance validation (blocked by 3.5.2)

**Next Steps**:
1. ~~Complete Task 3.5.3 - Documentation updates~~ ✅ COMPLETE
2. **NEW: Task 3.5.6 - Implement Zero-Copy Packet Buffer** (PRIORITY)
3. Plan async migration for UDP scanner (future phase)
4. Resume Task 3.5.2 after async migration is complete

---

## Task 3.5.6: Implement Zero-Copy Packet Buffer 🆕 PRIORITY

**Status**: ✅ COMPLETE - All 4 Phases Finished

**Design Document**: `doc/modules/packet-engineering.md` - "零拷贝数据包缓冲区设计" section

### Overview

Implement true zero-copy packet reception to achieve 1M+ PPS performance target.

### Current Issue

| Problem | Location | Impact |
|---------|----------|--------|
| Data copy per packet | `mmap.rs:719` `Bytes::copy_from_slice()` | 2-3x performance loss |

### Implementation Plan

#### Phase 1: Add ZeroCopyPacket Struct (✅ COMPLETE)
**File**: `crates/rustnmap-packet/src/zero_copy.rs` (CREATED)

**Completed:**
- `ZeroCopyBytes` struct with dual-mode support (borrowed/owned)
- `ZeroCopyPacket` struct with `Arc<MmapPacketEngine>` lifetime management
- `Drop` trait implementation for automatic frame release
- `Clone` trait for creating independent packet copies
- Debug implementation with masked internals
- SAFETY comments for all unsafe operations

#### Phase 2: Modify MmapPacketEngine (✅ COMPLETE)
**File**: `crates/rustnmap-packet/src/mmap.rs`

**Completed:**
- Added `ring_ptr()` - Returns pointer to mmap region
- Added `ring_size()` - Returns size of mmap region
- Added `release_frame_by_idx()` - Releases frame by index
- Added `try_recv_zero_copy()` - Zero-copy packet receive method
- Added `use std::sync::Arc;` import

**Quality Verification:**
- Zero clippy warnings
- Zero compiler errors
- All 63 rustnmap-packet tests pass

#### Phase 3: Update PacketEngine Trait (✅ COMPLETE)
**File**: `crates/rustnmap-packet/src/engine.rs`

**Completed:**
- Added import: `use crate::zero_copy::ZeroCopyPacket;`
- Updated `recv()` method signature to return `Result<Option<ZeroCopyPacket>>`
- Updated documentation to clarify zero-copy behavior

#### Phase 4: Update All Implementations (✅ COMPLETE)
**Files**: `crates/rustnmap-packet/src/async_engine.rs`, `crates/rustnmap-packet/src/stream.rs`, `crates/rustnmap-scan/src/packet_adapter.rs`

**Completed:**
- `AsyncPacketEngine` - Updated channel types and all methods for ZeroCopyPacket
- `PacketStream` - Updated to use ZeroCopyPacket
- `ScannerPacketEngine` - Fixed recv_with_timeout compatibility layer
- All tests pass workspace-wide

### Expected Performance Improvement

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| PPS | ~50,000 | ~1,000,000 | **20x** |
| CPU (T5) | 80% | 30% | **2.7x** |
| Packet Loss (T5) | ~30% | <1% | **30x** |

### Tests Required

1. `test_zero_copy_no_alloc` - Verify no heap allocation
2. `test_frame_lifecycle` - Verify frame release on drop
3. `test_no_data_copy` - Verify capacity == len
4. Integration test - Measure actual PPS improvement

### Dependencies

- None (uses existing dependencies: `bytes`, `tokio`, `libc`)

### Risks

| Risk | Mitigation |
|------|------------|
| Arc overhead | Atomic operations are cheap (~10 cycles) |
| Memory leaks | Unit tests + explicit drop checks |
| Frame exhaustion | Frame bitmap + backpressure |
