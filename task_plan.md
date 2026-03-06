# Task Plan: RustNmap Packet Engine Refactoring

> **Created**: 2026-03-05
> **Status**: Phase 1 - Core Infrastructure (Task 1.1 Complete)
> **Priority**: P0 - Critical

---

## Executive Summary

Refactor `rustnmap-packet` to implement true PACKET_MMAP V2 ring buffer, following the design documents in `doc/`.

### Root Problem
The current implementation claims TPACKET_V3 but actually uses `recvfrom()` syscall:
```rust
// src/lib.rs:764-765
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

### Impact
- T5 Insane: ~30% packet loss, unreliable
- UDP Scan: 3x slower than nmap
- CPU Usage: 80% under load (should be ~30%)

---

## Phase 1: Core Infrastructure (Current)

### Goal
Implement true PACKET_MMAP V2 ring buffer in `rustnmap-packet`

### 1.1 System Call Wrappers (Day 1) - COMPLETED

- [x] Create `src/sys/mod.rs` - Module exports
- [x] Create `src/sys/tpacket.rs` - TPACKET_V2 structures
  - [x] `Tpacket2Hdr` (32 bytes, NOT 48)
  - [x] `TPACKET_V2`, `TP_STATUS_*` constants
  - [x] `tpacket_req` structure
  - [x] `TpacketReqError` enum with validation
- [x] Create `src/sys/if_packet.rs` - AF_PACKET constants
  - [x] `AF_PACKET`, `ETH_P_ALL`, `PACKET_RX_RING`
  - [x] `PACKET_VERSION`, `PACKET_RESERVE`
- [x] Add unit tests for structure sizes
- [x] Zero clippy warnings
- [x] All 22 tests pass

### 1.2 PacketEngine Trait (Day 1-2) - COMPLETED

- [x] Create `src/engine.rs`
  - [x] `PacketEngine` trait with `async_trait`
  - [x] `PacketBuffer` struct (zero-copy with `Bytes`)
  - [x] `EngineStats` struct
  - [x] `RingConfig` struct (V2-specific)
- [x] Create `src/error.rs` - Error types
- [x] Add unit tests

### 1.3 Ring Buffer Implementation (Day 2-4) - COMPLETED

**FIXED**: Removed ~95 lines of forbidden `#![allow(...)]` directives.

- [x] **Task 1.3.1: Remove all global `#![allow(...)]` directives**
  - Deleted all self-deception allow attributes
  - Fixed code properly using item-level `#[expect(...)]` only when justified

- [x] **Task 1.3.2: Fix actual clippy warnings properly**
  - All warnings fixed at source
  - Only `#[expect(clippy::cast_ptr_alignment, reason = "...")]` for kernel contract alignment
  - Zero warnings with `-D warnings -D clippy::all`

- [x] **Task 1.3.3: Complete MmapPacketEngine implementation**
  - [x] `MmapPacketEngine` struct with `#[derive(Debug)]`
  - [x] Socket creation with correct option sequence
  - [x] `setup_ring_buffer()` with ENOMEM 5% reduction strategy
  - [x] `recv_packet()` with Acquire/Release memory ordering
  - [x] `send_packet()`
  - [x] `Drop` implementation (munmap BEFORE close)
  - [x] `unsafe impl Send + Sync for MmapPacketEngine` with SAFETY comments
  - [x] All compilation errors fixed
  - [x] Unit tests added (34 tests pass)
  - [x] Exported from `lib.rs`

### 1.4 BPF Filter (Day 4-5) - COMPLETED

- [x] Create `src/bpf.rs`
  - [x] `BpfFilter` struct
  - [x] `BpfInstruction` struct for raw BPF instructions
  - [x] `attach()` - Attach to socket
  - [x] `detach()` - Detach filter from socket
  - [x] Predefined filters:
    - [x] `tcp_dst_port()`, `tcp_src_port()`
    - [x] `udp_dst_port()`, `udp_src_port()`
    - [x] `icmp()`, `icmp_echo_request()`, `icmp_echo_reply()`
    - [x] `tcp_syn()`, `tcp_ack()`
    - [x] `ipv4()`, `ipv6()`, `arp()`
    - [x] `ipv4_src()`, `ipv4_dst()`
    - [x] `any()` for OR combination
- [x] Add unit tests (24 new tests)
- [x] Zero clippy warnings
- [x] Exported from `lib.rs`

### 1.5 Async Integration (Day 5-7) - COMPLETED

- [x] Create `src/async_engine.rs`
  - [x] `AsyncPacketEngine` struct
  - [x] `AsyncFd<OwnedFd>` wrapper (use `Arc<AsyncFd<OwnedFd>>`)
  - [x] `start()` - Spawn receiver task
  - [x] `recv()` - Channel-based receive
  - [x] Handle `libc::dup()` for fd ownership
- [x] Create `src/stream.rs`
  - [x] `PacketStream` implementing `Stream`
  - [x] Use `ReceiverStream` to avoid busy-spin
- [x] Add unit tests

### 1.6 Integration (Day 7) - COMPLETED

- [x] Update `src/lib.rs` - Re-export new API (already exported)
- [x] All unit tests pass (60 tests)
- [x] Zero clippy warnings (`cargo clippy -- -D warnings -W clippy::pedantic`)

### Phase 1 Summary

**Status**: COMPLETE (2026-03-06)
- All 6 tasks completed
- 60 unit tests passing
- Zero compiler warnings
- Full design document compliance

### Files to Create
- `crates/rustnmap-packet/src/sys/mod.rs`
- `crates/rustnmap-packet/src/sys/tpacket.rs`
- `crates/rustnmap-packet/src/sys/if_packet.rs`
- `crates/rustnmap-packet/src/engine.rs`
- `crates/rustnmap-packet/src/error.rs`
- `crates/rustnmap-packet/src/mmap.rs`
- `crates/rustnmap-packet/src/bpf.rs`
- `crates/rustnmap-packet/src/async_engine.rs`
- `crates/rustnmap-packet/src/stream.rs`
- `crates/rustnmap-packet/src/stats.rs`
- `crates/rustnmap-packet/tests/integration_test.rs`

### Files to Modify
- `crates/rustnmap-packet/src/lib.rs` - Major rewrite
- `crates/rustnmap-packet/Cargo.toml` - Add dependencies

### Dependencies to Add
```toml
[dependencies]
async-trait = "0.1"
futures = "0.3"
tokio-stream = "0.1"

[dev-dependencies]
tokio-test = "0.4"
```

---

## Phase 2: Async Integration

### Goal
Build async packet capture pipeline with Tokio integration

### Tasks
- [ ] `AsyncFd` wrapper with proper ownership
- [ ] `PacketStream` implementation
- [ ] Channel-based packet distribution
- [ ] Graceful shutdown handling

---

## Phase 3: Scanner Migration (IN PROGRESS)

### Goal
Migrate all scanners to use new `PacketEngine` trait

### Architecture Challenge

**Current Architecture:**
- `SimpleAfPacket` with blocking operations
- Wrapped in `spawn_blocking` for async compatibility
- Direct `recvfrom()` syscall

**New Architecture:**
- `AsyncPacketEngine` with `AsyncFd` for true async I/O
- Channel-based packet distribution
- Zero-copy PACKET_MMAP V2

**Challenge:** Fundamental architectural difference requires careful migration strategy.

### Migration Plan

#### 3.1 Infrastructure Preparation (COMPLETED 2026-03-06)
- [x] Add `icmp_dst()` filter to `BpfFilter` for ICMP with destination filtering
- [x] Fix critical atomic status check bug in `mmap.rs`
- [x] Add timeout support to `AsyncPacketEngine` (`recv_timeout` method)
- [x] Create adapter layer (`ScannerPacketEngine`) for gradual migration
- [x] Expose `to_sock_fprog()` method in `BpfFilter` for adapter integration
- [x] Document migration patterns in `progress.md`

#### 3.2 Simple Scanner Migration (IN PROGRESS)
- [x] Migrate `TcpFinScanner` (stealth_scans.rs) - PARTIAL COMPLETE
  - [x] Struct updated to use `ScannerPacketEngine`
  - [x] Constructor updated to use `create_stealth_engine()`
  - [x] All tests pass, zero clippy warnings
  - [ ] TODO: Implement async bridge for actual packet reception
- [ ] Migrate `TcpNullScanner` (stealth_scans.rs)
- [ ] Migrate `TcpXmasScanner` (stealth_scans.rs)
- [ ] Verify functionality with integration tests

**Adapter Layer Status:**
- `ScannerPacketEngine` adapter created in `packet_adapter.rs`
- Thread-safe via `Arc<Mutex<ScannerPacketEngine>>`
- API matches `SimpleAfPacket::recv_packet_with_timeout()`
- All 95 tests pass,- Zero clippy warnings

#### 3.3 Complex Scanner Migration
- [ ] Migrate `ParallelScanEngine` (ultrascan.rs)
- [ ] Migrate `TcpSynScanner` (syn_scan.rs)
- [ ] Migrate `UdpScanner` (udp_scan.rs)

#### 3.4 Cleanup
- [ ] Remove `SimpleAfPacket` from stealth_scans.rs
- [ ] Remove `SimpleAfPacket` from ultrascan.rs
- [ ] Update documentation
- [ ] Performance validation

### Dependencies
- Phase 1 must be complete (DONE)
- BPF filter for ICMP destination (DONE)
- Timeout support in `AsyncPacketEngine` (TODO)

---

## Phase 4: Testing & Validation

### Goal
Comprehensive testing and validation against nmap

### Tasks
- [ ] Unit tests (coverage >= 80%)
- [ ] Integration tests
- [ ] Stress tests
- [ ] Nmap comparison tests

---

## Phase 5: Documentation

### Goal
Complete documentation and cleanup

### Tasks
- [ ] API documentation with examples
- [ ] Update architecture docs
- [ ] Migration guide
- [ ] Code cleanup

---

## Phase 6: Benchmarking

### Goal
Validate performance targets

### Targets
| Metric | Current | Target |
|--------|---------|--------|
| PPS | ~50,000 | ~1,000,000 |
| CPU (T5) | 80% | 30% |
| Packet Loss (T5) | ~30% | <1% |

---

## Critical Technical Details

### TPACKET_V2 Header (32 bytes)
```rust
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,      // 4 bytes
    pub tp_len: u32,         // 4 bytes
    pub tp_snaplen: u32,     // 4 bytes
    pub tp_mac: u16,         // 2 bytes
    pub tp_net: u16,         // 2 bytes
    pub tp_sec: u32,         // 4 bytes
    pub tp_nsec: u32,        // 4 bytes (NOT tp_usec!)
    pub tp_vlan_tci: u16,    // 2 bytes
    pub tp_vlan_tpid: u16,   // 2 bytes
    pub tp_padding: [u8; 4], // 4 bytes (NOT [u8; 8]!)
}  // Total: 32 bytes
```

### Memory Ordering
```rust
// Check frame availability (Acquire)
let status = AtomicU32::from_ptr(&(*hdr).tp_status)
    .load(Ordering::Acquire);

// Release frame to kernel (Release)
AtomicU32::from_ptr(&(*hdr).tp_status)
    .store(TP_STATUS_KERNEL, Ordering::Release);
```

### Socket Option Sequence (CRITICAL)
```
1. socket(PF_PACKET, SOCK_RAW, ETH_P_ALL)
2. setsockopt(PACKET_VERSION, TPACKET_V2)  // MUST be first
3. setsockopt(PACKET_RESERVE, 4)           // MUST be before RX_RING
4. setsockopt(PACKET_AUXDATA, 1)           // Optional
5. setsockopt(PACKET_RX_RING, &req)
6. mmap()
7. bind()
```

### Drop Order (CRITICAL)
```rust
impl Drop for MmapPacketEngine {
    fn drop(&mut self) {
        // 1. munmap FIRST
        libc::munmap(self.ring_ptr, self.ring_size);
        // 2. close SECOND
        libc::close(self.fd);
    }
}
```

---

## References
- `doc/architecture.md` Section 2.3 - Packet Engine Architecture
- `doc/modules/packet-engineering.md` - Technical specs
- `doc/structure.md` Section 5.3 - rustnmap-packet structure
- `reference/nmap/libpcap/pcap-linux.c` - nmap implementation
