# rustnmap-packet

> **Status**: CRITICAL - Architecture Redesign Required
> **Version**: 1.0 (Broken) / 2.0 (Planned)
> **Last Updated**: 2026-03-05

## CRITICAL ISSUE

**Current Implementation Uses `recvfrom()` NOT PACKET_MMAP**

Evidence from `src/lib.rs:764-765`:
```rust
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

**Impact:**
- T5 Insane: ~30% packet loss, unreliable results
- UDP Scan: 3x slower than nmap
- CPU Usage: 80% under load (should be ~30%)

## Purpose

High-performance packet capture and transmission using Linux PACKET_MMAP **V2** (not V3) for zero-copy operation. This is the hot path for packet I/O.

> **Architecture Decision**: Use TPACKET_V2 following nmap's choice.
> V3 has stability bugs in kernels < 3.19. See `reference/nmap/libpcap/pcap-linux.c`.

## Current vs Target Architecture

| Aspect | Current (Broken) | Target (Redesigned) |
|--------|------------------|---------------------|
| Capture Method | `recvfrom()` syscall | PACKET_MMAP V2 ring buffer |
| Buffer Size | Socket queue (default) | 4MB ring (2 blocks x 2MB) |
| Async I/O | `spawn_blocking` | `AsyncFd<RawFd>` |
| Zero-Copy | No (memory copy) | Yes (mmap) |
| Syscalls | Per-packet | Batched |

## Planned File Structure (Phase 40)

```
crates/rustnmap-packet/src/
├── lib.rs              # Public API exports
├── engine.rs           # PacketEngine trait definition
├── mmap.rs             # MmapPacketEngine (TPACKET_V2)
│   - RingBuffer management
│   - BlockManager (V2 blocks)
│   - FrameIterator (zero-copy)
├── async_engine.rs     # AsyncPacketEngine (Tokio AsyncFd)
│   - AsyncFd wrapper
│   - Channel distribution
├── bpf.rs              # BPF filter utilities
│   - BpfFilter struct
│   - compile() / attach()
├── stream.rs           # PacketStream (impl Stream)
├── stats.rs            # EngineStats
├── error.rs            # PacketError enum
└── sys/
    ├── mod.rs          # Linux syscall wrappers
    ├── tpacket.rs      # TPACKET_V2 constants/structs
    └── if_packet.rs    # AF_PACKET constants
```

## Key Components (Planned)

### PacketEngine Trait

```rust
#[async_trait]
pub trait PacketEngine: Send + Sync {
    async fn start(&mut self) -> Result<(), PacketError>;
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;
    async fn send(&self, packet: &[u8]) -> Result<usize, PacketError>;
    async fn stop(&mut self) -> Result<(), PacketError>;
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), PacketError>;
    fn flush(&self) -> Result<(), PacketError>;
    fn stats(&self) -> EngineStats;
}
```

### TPACKET_V2 Header (48 bytes)

```rust
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,      // Frame status (TP_STATUS_*)
    pub tp_len: u32,         // Packet length
    pub tp_snaplen: u32,     // Captured length
    pub tp_mac: u16,         // MAC header offset
    pub tp_net: u16,         // Network header offset
    pub tp_sec: u32,         // Timestamp (seconds)
    pub tp_nsec: u32,        // Timestamp (nanoseconds) - V2 uses nsec!
    pub tp_vlan_tci: u16,    // VLAN TCI
    pub tp_vlan_tpid: u16,   // VLAN TPID
    pub tp_padding: [u8; 8], // Padding
}
```

### Ring Buffer Configuration

```rust
pub struct RingConfig {
    pub block_count: u32,    // Recommended: 2
    pub block_size: u32,     // Recommended: 2MB = 2097152
    pub frame_size: u32,     // Recommended: 512 (TPACKET_ALIGNMENT)
}
```

### Memory Ordering

```rust
// Producer (kernel -> userspace)
self.write_idx.fetch_add(1, Ordering::Relaxed);
atomic::fence(Ordering::Release);

// Consumer (userspace reads)
let value = self.read_idx.load(Ordering::Acquire);
```

**CRITICAL**: See `rust-concurrency` skill for memory ordering rules.
- NEVER use SeqCst unless you understand the 5-10x performance cost
- Use Acquire/Release for synchronization
- Use Relaxed for simple counters

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| rustnmap-common | path | Common types |
| tokio | 1.42 | Async runtime (net, io-util, sync) |
| bytes | 1.9 | Zero-copy byte buffers |
| libc | 0.2 | System calls (mmap, socket) |
| socket2 | 0.5 | Socket abstractions |
| thiserror | 2.0 | Error types |

## Performance Targets

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| PPS | ~50,000 | ~1,000,000 | 20x |
| CPU (T5) | 80% | 30% | 2.7x |
| Packet Loss (T5) | ~30% | <1% | 30x |
| Syscalls | Per-packet | Batched | ~100x |

## Testing

**CRITICAL**: No mock engines. Use actual target machines.

```bash
# Requires root for AF_PACKET
sudo cargo test -p rustnmap-packet

# Integration tests require actual network targets
sudo cargo test -p rustnmap-packet --test integration
```

### Test Requirements
- Actual target machines (not localhost)
- Various network conditions (LAN, WAN, lossy)
- Timing template coverage (T0-T5)
- Packet loss scenarios

## Usage (Planned)

```rust
use rustnmap_packet::{AsyncPacketEngine, RingConfig, BpfFilter};

#[tokio::main]
async fn main() -> Result<(), PacketError> {
    let config = RingConfig::default();
    let mut engine = AsyncPacketEngine::new("eth0", config).await?;

    // Set BPF filter
    let filter = BpfFilter::tcp_dst_port(80);
    engine.set_filter(&filter)?;

    engine.start().await?;

    // Receive packets as Stream
    use tokio_stream::StreamExt;
    let mut stream = engine.into_stream();
    while let Some(packet) = stream.next().await {
        println!("Received {} bytes", packet?.len);
    }

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
- `reference/nmap/timing.cc` - Network volatility handling

## Migration Notes

When migrating from current implementation:
1. Replace `SimpleAfPacket` with `AsyncPacketEngine`
2. Update all scanners to use `PacketEngine` trait
3. Remove duplicate code in `ultrascan.rs` and `stealth_scans.rs`
4. Implement proper BPF filter attachment
5. Add network volatility handling (RTT estimation, congestion control)
