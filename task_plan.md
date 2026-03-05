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

### 1.3 Ring Buffer Implementation (Day 2-4)

- [ ] Create `src/mmap.rs`
  - [ ] `MmapPacketEngine` struct
  - [ ] Socket creation with correct option sequence:
    1. `socket(PF_PACKET, SOCK_RAW, ETH_P_ALL)`
    2. `setsockopt(PACKET_VERSION, TPACKET_V2)` - MUST be first
    3. `setsockopt(PACKET_RESERVE, 4)` - MUST be before RX_RING
    4. `setsockopt(PACKET_RX_RING, &req)`
    5. `mmap()`
    6. `bind()`
  - [ ] `setup_ring_buffer()` with ENOMEM 5% reduction strategy
  - [ ] `recv_packet()` with Acquire/Release memory ordering
  - [ ] `send_packet()`
  - [ ] `Drop` implementation (munmap BEFORE close)
- [ ] Add unit tests

### 1.4 BPF Filter (Day 4-5)

- [ ] Create `src/bpf.rs`
  - [ ] `BpfFilter` struct
  - [ ] `compile()` - Compile filter expression
  - [ ] `attach()` - Attach to socket
  - [ ] Predefined filters: `tcp_dst_port()`, `udp_dst_port()`, `icmp()`
- [ ] Add unit tests

### 1.5 Async Integration (Day 5-7)

- [ ] Create `src/async_engine.rs`
  - [ ] `AsyncPacketEngine` struct
  - [ ] `AsyncFd<OwnedFd>` wrapper (use `Arc<AsyncFd<OwnedFd>>`)
  - [ ] `start()` - Spawn receiver task
  - [ ] `recv()` - Channel-based receive
  - [ ] Handle `libc::dup()` for fd ownership
- [ ] Create `src/stream.rs`
  - [ ] `PacketStream` implementing `Stream`
  - [ ] Use `ReceiverStream` to avoid busy-spin
- [ ] Add unit tests

### 1.6 Integration (Day 7)

- [ ] Update `src/lib.rs` - Re-export new API
- [ ] Create `tests/integration_test.rs`
- [ ] Run `cargo clippy -- -D warnings`
- [ ] Run `cargo test`

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

## Phase 3: Scanner Migration

### Goal
Migrate all scanners to use new `PacketEngine` trait

### Tasks
- [ ] Define `AsyncScanEngine` trait
- [ ] Migrate `TcpSynScanner`
- [ ] Migrate stealth scanners (FIN/NULL/XMAS/ACK/Window/Maimon)
- [ ] Migrate `UdpScanner`
- [ ] Remove `SimpleAfPacket` duplication

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
