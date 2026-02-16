# rustnmap-packet

Zero-copy packet engine using PACKET_MMAP V3 for RustNmap.

## Purpose

High-performance packet capture and transmission using Linux PACKET_MMAP V3 for zero-copy operation. This is the hot path for packet I/O.

## Key Components

### Ring Buffer

- `PacketRing` - PACKET_MMAP V3 ring buffer management
- `PacketBuffer` - Zero-copy packet reference using `bytes::Bytes`
- `RingConfig` - Ring size and block configuration

### Packet Processing

- `PacketProcessor` - Async packet processing pipeline
- `RxQueue` / `TxQueue` - Receive/transmit queues with proper memory ordering

### Memory Ordering

```rust
// Producer
self.write_idx.fetch_add(1, Ordering::Relaxed);
atomic::fence(Ordering::Release);

// Consumer
let value = self.read_idx.load(Ordering::Acquire);
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| bytes | Zero-copy byte buffers |
| tokio | Async runtime |

## Performance

- Zero-copy packet access via mmap
- Lock-free SPSC queue for packet distribution
- Batch processing for reduced syscall overhead

## Testing

```bash
# Requires root for PACKET_MMAP
sudo cargo test -p rustnmap-packet
```

## Usage

```rust
use rustnmap_packet::{PacketRing, RingConfig};

let config = RingConfig::default();
let ring = PacketRing::new("eth0", config)?;
```

## Kernel Requirements

- Linux kernel 3.2+ for PACKET_MMAP V3
- Root privileges or CAP_NET_RAW capability
