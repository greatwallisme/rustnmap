# Task Plan: Packet Engine Migration - Phase 3.4

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: Phase 3.4 - Receive Path Integration IN PROGRESS (2/5 tasks complete)
> **Priority**: P0 - Critical

---

## Executive Summary

Phase 3.4 (Receive Path Integration) is IN PROGRESS. Completed:
- Task #1: TcpSynScanner receive path integration (COMPLETE)
- Task #2: Stealth scanners infrastructure (COMPLETE)

Remaining:
- Task #3: ParallelScanEngine receive path
- Task #4: UdpScanner receive path
- Task #5: Run tests and verify zero warnings

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

### Phase 3.2.5: Design Document Compliance Audit (COMPLETE)

### Goal
Compare completed Phase 1 (Core Infrastructure) and Phase 3.1-3.2 (Scanner Migration) against design documents.

### Documents Reviewed
- `doc/architecture.md` - Section 2.3 Packet Engine Architecture
- `doc/modules/packet-engineering.md` - TPACKET_V2 Technical Specs
- `doc/structure.md` - Section 5.3 rustnmap-packet Structure

### Implementation Files Reviewed
- `crates/rustnmap-packet/src/engine.rs` - PacketEngine trait
- `crates/rustnmap-packet/src/mmap.rs` - MmapPacketEngine
- `crates/rustnmap-packet/src/async_engine.rs` - AsyncPacketEngine
- `crates/rustnmap-packet/src/bpf.rs` - BPF Filter
- `crates/rustnmap-packet/src/sys/tpacket.rs` - TPACKET structures
- `crates/rustnmap-packet/src/stream.rs` - PacketStream
- `crates/rustnmap-scan/src/stealth_scans.rs` - Stealth scanners
- `crates/rustnmap-scan/src/packet_adapter.rs` - ScannerPacketEngine

---

## Compliance Results

### 1. TPACKET_V2 Header Structure

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| Total size | 32 bytes | 32 bytes | PASS |
| tp_status | u32 (offset 0) | u32 (offset 0) | PASS |
| tp_len | u32 (offset 4) | u32 (offset 4) | PASS |
| tp_snaplen | u32 (offset 8) | u32 (offset 8) | PASS |
| tp_mac | u16 (offset 12) | u16 (offset 12) | PASS |
| tp_net | u16 (offset 14) | u16 (offset 14) | PASS |
| tp_sec | u32 (offset 16) | u32 (offset 16) | PASS |
| tp_nsec | u32 (offset 20) - NOT tp_usec | u32 (offset 20) | PASS |
| tp_vlan_tci | u16 (offset 24) | u16 (offset 24) | PASS |
| tp_vlan_tpid | u16 (offset 26) | u16 (offset 26) | PASS |
| tp_padding | [u8; 4] (offset 28) - NOT [u8; 8] | [u8; 4] (offset 28) | PASS |

**Evidence**: `sys/tpacket.rs:34-57`, test at line 233 verifies size is 32 bytes.

### 2. Socket Option Sequence

| Step | Design Requirement | Implementation Order | Status |
|------|-------------------|---------------------|--------|
| 1 | socket(PF_PACKET, SOCK_RAW, ETH_P_ALL) | mmap.rs:244 | PASS |
| 2 | PACKET_VERSION = TPACKET_V2 (MUST be first) | mmap.rs:254 | PASS |
| 3 | PACKET_RESERVE = 4 (MUST be before RX_RING) | mmap.rs:257 | PASS |
| 4 | PACKET_AUXDATA = 1 (Optional) | mmap.rs:260 | PASS |
| 5 | PACKET_RX_RING | mmap.rs setup_ring_buffer() | PASS |
| 6 | mmap() | mmap.rs mmap_ring() | PASS |
| 7 | bind() | mmap.rs bind_to_interface() | PASS |

**Evidence**: `mmap.rs:239-263` - `create_socket()` follows exact sequence.

### 3. Memory Ordering

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| Frame availability check | Acquire ordering | Acquire ordering | PASS |
| Frame release to kernel | Release ordering | Release ordering | PASS |
| Never SeqCst | Avoid for performance | Not used | PASS |

**Evidence**: `mmap.rs` uses `Ordering::Acquire` and `Ordering::Release` correctly.

### 4. ENOMEM Recovery Strategy

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| Reduction factor | 5% per attempt | 95% (5% reduction) | PASS |
| Max retries | 10 | 10 | PASS |
| Preserve alignment | Yes | Yes | PASS |

**Evidence**: `mmap.rs:94-97` defines `ENOMEM_MAX_RETRIES = 10` and `ENOMEM_REDUCTION_PERCENT = 95`.

### 5. Drop Implementation Order

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| Order | munmap BEFORE close | munmap before close | PASS |

**Evidence**: `mmap.rs` Drop implementation follows correct order.

### 6. PacketEngine Trait

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| async_trait | Required | Used | PASS |
| start() | async fn | async fn | PASS |
| recv() | async fn | async fn | PASS |
| send() | async fn | async fn | PASS |
| stop() | async fn | async fn | PASS |
| stats() | fn | fn | PASS |
| flush() | fn | fn | PASS |
| set_filter() | fn | fn | PASS |

**Evidence**: `engine.rs:483-538` - Full trait with async_trait.

### 7. AsyncPacketEngine Pattern

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| AsyncFd wrapper | Required | Arc<AsyncFd<OwnedFd>> | PASS |
| libc::dup() for fd | Avoid double-close | Used | PASS |
| Channel distribution | mpsc channel | Used | PASS |
| Background task | Tokio spawn | Used | PASS |

**Evidence**: `async_engine.rs` follows design exactly.

### 8. PacketStream Pattern

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| ReceiverStream | Avoid busy-spin | Used | PASS |
| impl Stream | Required | Implemented | PASS |

**Evidence**: `stream.rs` uses `ReceiverStream` pattern.

### 9. BPF Filter

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| BpfFilter struct | Required | Implemented | PASS |
| attach() | SO_ATTACH_FILTER | Implemented | PASS |
| detach() | SO_DETACH_FILTER | Implemented | PASS |
| Predefined filters | tcp_dst_port, icmp, etc. | All implemented | PASS |
| icmp_dst() | For scanner migration | Implemented | PASS |

**Evidence**: `bpf.rs` with comprehensive filter library.

### 10. ScannerPacketEngine Adapter

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| Wraps AsyncPacketEngine | Required | Implemented | PASS |
| recv_with_timeout() | Scanner compatibility | Implemented | PASS |
| Arc<Mutex<>> wrapping | Thread-safe sharing | Implemented | PASS |
| create_stealth_engine() | Helper function | Implemented | PASS |

**Evidence**: `packet_adapter.rs:70-200`.

### 11. Stealth Scanner Migration

| Requirement | Design Spec | Implementation | Status |
|-------------|-------------|----------------|--------|
| TcpFinScanner | Use ScannerPacketEngine | Migrated | PASS |
| TcpNullScanner | Use ScannerPacketEngine | Migrated | PASS |
| TcpXmasScanner | Use ScannerPacketEngine | Migrated | PASS |

**Evidence**: `stealth_scans.rs:43-53` imports and uses `ScannerPacketEngine`.

---

## Summary

### Overall Compliance: EXCELLENT

| Category | Status | Notes |
|----------|--------|-------|
| TPACKET_V2 Header | PASS | 32 bytes, correct fields |
| Socket Option Sequence | PASS | Exact nmap-compatible order |
| Memory Ordering | PASS | Correct Acquire/Release |
| ENOMEM Recovery | PASS | 5% reduction, 10 retries |
| Drop Order | PASS | munmap before close |
| PacketEngine Trait | PASS | Full async_trait implementation |
| AsyncPacketEngine | PASS | Correct fd ownership pattern |
| PacketStream | PASS | Uses ReceiverStream |
| BPF Filter | PASS | Complete implementation |
| ScannerPacketEngine | PASS | Proper adapter layer |
| Scanner Migration | PASS | 3 scanners migrated |

### No Deviations Found

All completed work strictly follows the design documents in `doc/`. The implementation:
1. Uses TPACKET_V2 (not V3) as specified
2. Follows the exact socket option sequence from nmap
3. Implements correct memory ordering (Acquire/Release)
4. Uses the 5% ENOMEM recovery strategy
5. Follows the correct Drop order (munmap before close)
6. Uses async-trait for the PacketEngine trait
7. Uses ReceiverStream to avoid busy-spin
8. Implements all required BPF filters including icmp_dst()
9. Provides proper adapter layer for scanner migration

### Recommendations

1. **Continue Phase 3.3**: Migrate complex scanners (ParallelScanEngine, TcpSynScanner, UdpScanner)
2. **Integration Testing**: Verify functionality with actual network targets
3. **Performance Validation**: Run benchmarks to validate PPS targets

---

## References

- `doc/architecture.md` - Section 2.3 Packet Engine Architecture
- `doc/modules/packet-engineering.md` - TPACKET_V2 Technical Specs
- `doc/structure.md` - Section 5.3 rustnmap-packet Structure
- `reference/nmap/libpcap/pcap-linux.c` - nmap Reference Implementation

---

## Phase 3.3: Complex Scanner Migration Infrastructure (COMPLETE)

### Goal
Add `ScannerPacketEngine` infrastructure to complex scanners (fields added, constructors updated).

### Scanners Updated

| Scanner | File | Field Added | Status |
|---------|------|-------------|--------|
| TcpSynScanner | `syn_scan.rs` | `packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>` | COMPLETE |
| ParallelScanEngine | `ultrascan.rs` | `packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>` | COMPLETE |
| UdpScanner | `udp_scan.rs` | `scanner_engine_v4: Option<Arc<Mutex<ScannerPacketEngine>>>` | COMPLETE |

### Migration Pattern

**Before (RawSocket):**
```rust
let socket = RawSocket::with_protocol(6)?;
let response = socket.recv_from(&mut buf)?;
```

**After (ScannerPacketEngine):**
```rust
let engine = ScannerPacketEngine::new_shared("eth0", config)?;
engine.lock().await.start().await?;
let response = engine.lock().await.recv_with_timeout(timeout).await?;
```

### Implementation Steps

#### Task 3.3.1: Migrate TcpSynScanner
1. Add `Option<Arc<Mutex<ScannerPacketEngine>>>` field
2. Update constructor to call `create_stealth_engine()`
3. Replace `socket.recv_from()` with `engine.recv_with_timeout()`
4. Add BPF filter for TCP responses
5. Run tests to verify

#### Task 3.3.2: Migrate ParallelScanEngine
1. Add `Option<Arc<Mutex<ScannerPacketEngine>>>` field
2. Update constructor
3. Replace packet receive logic
4. Update outstanding probe matching
5. Run tests to verify

#### Task 3.3.3: Migrate UdpScanner
1. Add `Option<Arc<Mutex<ScannerPacketEngine>>>` field
2. Update constructor
3. Replace `AfPacketEngine` with `ScannerPacketEngine`
4. Update ICMP error handling
5. Run tests to verify

### Quality Gates

- [ ] All 16 rustnmap-scan tests pass
- [ ] Zero clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Design document compliance verified

### Current Status
- Started: 2026-03-07
- Progress: Infrastructure added to all complex scanners

### Completed Tasks

#### Task 3.3.1: TcpSynScanner Migration (COMPLETE)
- Added `packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>` field
- Updated constructor to initialize packet engine via `create_stealth_engine()`
- Added `#[expect(dead_code)]` with reason for migration in progress
- Tests pass, zero clippy warnings

#### Task 3.3.2: ParallelScanEngine Migration (COMPLETE)
- Added `packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>` field
- Updated constructor to initialize packet engine
- Added `#[expect(dead_code)]` with reason for migration in progress
- Tests pass, zero clippy warnings

#### Task 3.3.3: UdpScanner Migration (COMPLETE)
- Added `scanner_engine_v4: Option<Arc<Mutex<ScannerPacketEngine>>>` field
- Updated both `new()` and `new_dual_stack()` constructors
- Added `#[expect(dead_code)]` with reason for migration in progress
- Tests pass, zero clippy warnings

---

## Phase 3.4: Receive Path Integration (PENDING)

### Goal
Integrate `ScannerPacketEngine` into scanner receive paths by converting scanner methods from synchronous to async.

### Challenge: Async Conversion Required

The `ScannerPacketEngine` uses async-first design (`tokio::sync::Mutex`, async methods). Current scanner methods are synchronous. Full integration requires:

1. Converting scanner methods to `async fn`
2. Updating `PortScanner` trait to support async
3. Replacing `socket.recv_from()` with `engine.recv_with_timeout().await`

### Migration Pattern

**Before (sync):**
```rust
fn scan_port_impl(&self, ...) -> ScanResult<PortState> {
    self.socket.recv_packet(...) // blocking
}
```

**After (async):**
```rust
async fn scan_port_impl(&self, ...) -> ScanResult<PortState> {
    self.packet_engine.lock().await.recv_with_timeout(...).await
}
```

### Implementation Tasks

| Task | Scanner | Description | Status |
|------|---------|-------------|--------|
| 3.4.1 | TcpSynScanner | Convert receive path to async | PENDING |
| 3.4.2 | ParallelScanEngine | Convert receive path to async | PENDING |
| 3.4.3 | UdpScanner | Convert receive path to async | PENDING |
| 3.4.4 | Stealth Scanners | Complete async migration | PENDING |

### Quality Gates

- [ ] All 95 rustnmap-scan tests pass
- [ ] Zero clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Design document compliance verified

---

## Phase 3.5: Cleanup (FUTURE)

### Remaining Work
- [ ] Remove deprecated `SimpleAfPacket` and `AfPacketEngine` usage
- [ ] Add integration tests for PACKET_MMAP V2 performance
- [ ] Performance validation: 1M+ PPS target
