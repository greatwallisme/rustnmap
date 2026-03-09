# rustnmap-packet

> **Status**: COMPLETE - PACKET_MMAP V2 Implemented
> **Version**: 2.0.0
> **Last Updated**: 2026-03-08

## Implementation Status

PACKET_MMAP V2 with zero-copy is **FULLY IMPLEMENTED**.

| Component | File | Status |
|-----------|------|--------|
| `MmapPacketEngine` | `mmap.rs` | COMPLETE |
| `ZeroCopyPacket` | `zero_copy.rs` | COMPLETE |
| `AsyncPacketEngine` | `async_engine.rs` | COMPLETE |
| `BpfFilter` | `bpf.rs` | COMPLETE |
| `PacketEngine` trait | `engine.rs` | COMPLETE |
| `RecvfromPacketEngine` | `recvfrom.rs` | FALLBACK ONLY |

### Test Coverage

- 865+ workspace tests passing
- Zero clippy warnings
- All scanners migrated to `ScannerPacketEngine`

## Purpose

High-performance packet capture and transmission using Linux PACKET_MMAP V2 for zero-copy operation. This is the hot path for packet I/O.

> **Architecture Decision**: TPACKET_V2 (not V3)
> V3 has stability bugs in kernels < 3.19. See `reference/nmap/libpcap/pcap-linux.c`.

## Architecture

| Aspect | Implementation |
|--------|----------------|
| Capture Method | PACKET_MMAP V2 ring buffer |
| Buffer Size | 16MB (256 blocks x 64KB) |
| Async I/O | `AsyncFd<OwnedFd>` |
| Zero-Copy | Yes (Arc lifecycle) |
| Syscalls | Batched |

## File Structure

```
crates/rustnmap-packet/src/
├── lib.rs              # Public API exports
├── engine.rs           # PacketEngine trait + RingConfig
├── mmap.rs             # MmapPacketEngine (TPACKET_V2)
├── async_engine.rs     # AsyncPacketEngine (Tokio AsyncFd)
├── recvfrom.rs         # RecvfromPacketEngine (fallback only)
├── bpf.rs              # BPF filter utilities
├── stream.rs           # PacketStream (impl Stream)
├── zero_copy.rs        # ZeroCopyPacket + ZeroCopyBytes
├── error.rs            # PacketError enum
└── sys/
    ├── mod.rs          # Linux syscall wrappers
    ├── tpacket.rs      # TPACKET_V2 constants/structs
    └── if_packet.rs    # AF_PACKET constants
```

## Key Implementation Details

### Two-Stage Bind Pattern (CRITICAL)

Following nmap's `libpcap/pcap-linux.c:1297-1302`:

```rust
// Stage 1: Bind with protocol=0 (allows ring buffer setup)
Self::bind_to_interface(&fd, if_index)?;

// Stage 2: Setup ring buffer
let (ring_ptr, ring_size, frame_ptrs, frame_count) =
    Self::setup_ring_buffer(&fd, &config)?;

// Stage 3: Re-bind with ETH_P_ALL (enables packet reception)
Self::bind_to_interface_with_protocol(&fd, if_index, ETH_P_ALL.to_be())?;
```

### Zero-Copy Implementation

```rust
// crates/rustnmap-packet/src/zero_copy.rs
pub struct ZeroCopyPacket {
    _engine: Arc<MmapPacketEngine>,  // Keeps mmap alive
    frame_idx: u32,                   // For frame release
    data: Bytes,                      // Zero-copy view
    // ...
}

impl Drop for ZeroCopyPacket {
    fn drop(&mut self) {
        // Release frame back to kernel
        self._engine.release_frame_by_idx(self.frame_idx);
    }
}
```

### Memory Ordering

```rust
// Acquire when reading frame status
AtomicU32::from_ptr(addr_of!((*hdr).tp_status))
    .load(Ordering::Acquire) != TP_STATUS_KERNEL

// Release when returning frame to kernel
AtomicU32::from_ptr(addr_of!((*hdr).tp_status))
    .store(TP_STATUS_KERNEL, Ordering::Release);
```

### TPACKET_V2 Header (32 bytes)

```rust
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,      // Frame status
    pub tp_len: u32,         // Packet length
    pub tp_snaplen: u32,     // Captured length
    pub tp_mac: u16,         // MAC header offset
    pub tp_net: u16,         // Network header offset
    pub tp_sec: u32,         // Timestamp (seconds)
    pub tp_nsec: u32,        // Timestamp (nanoseconds)
    pub tp_vlan_tci: u16,    // VLAN TCI
    pub tp_vlan_tpid: u16,   // VLAN TPID
    pub tp_padding: [u8; 4], // Padding
}  // Total: 32 bytes
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| rustnmap-common | path | Common types |
| tokio | 1.42 | Async runtime |
| bytes | 1.9 | Zero-copy byte buffers |
| libc | 0.2 | System calls |
| socket2 | 0.5 | Socket abstractions |
| thiserror | 2.0 | Error types |
| async-trait | 0.1 | Trait async support |

## Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| PPS | ~1,000,000 | PENDING BENCHMARK |
| CPU (T5) | 30% | PENDING BENCHMARK |
| Packet Loss (T5) | <1% | PENDING BENCHMARK |
| Zero-copy | Verified | COMPLETE |

## Testing

**CRITICAL**: No mock engines. Use actual target machines.

```bash
# Requires root for AF_PACKET
sudo cargo test -p rustnmap-packet

# Integration tests require actual network targets
sudo cargo test -p rustnmap-packet --test integration
```

## Usage

```rust
use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};

#[tokio::main]
async fn main() -> Result<(), PacketError> {
    let config = RingConfig::default();
    let mut engine = AsyncPacketEngine::new("eth0", config)?;

    engine.start().await?;

    // Zero-copy packet receive
    while let Some(packet) = engine.recv().await? {
        println!("Received {} bytes", packet.len());
    }

    engine.stop().await?;
    Ok(())
}
```

## Kernel Requirements

- Linux kernel 3.2+ for PACKET_MMAP V2
- Root privileges or CAP_NET_RAW capability
- TPACKET_V2 support (all modern kernels)

## Reference Documentation

- `doc/modules/packet-engineering.md` - Detailed design specs
- `doc/architecture.md` - System architecture (Section 2.3)
- `reference/nmap/libpcap/pcap-linux.c` - nmap's PACKET_MMAP implementation

## Fallback: RecvfromPacketEngine

`RecvfromPacketEngine` exists as a fallback when PACKET_MMAP is unavailable:
- Used only in benchmarks for comparison
- NOT used by production scanners
- All scanners use `ScannerPacketEngine` which wraps `AsyncPacketEngine`
