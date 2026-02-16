# rustnmap-net

Network primitives and socket abstractions for RustNmap.

## Purpose

Provides low-level network primitives including raw socket operations, packet construction helpers, and cross-platform socket abstractions.

## Key Components

### Raw Sockets

- `RawSocket` - Raw socket wrapper with Linux-specific optimizations
- `SocketOptions` - Socket configuration (timeout, buffer sizes, etc.)

### Packet Construction

- `PacketBuilder` - Helper for building network packets
- `Checksum` - IP/TCP/UDP checksum calculations

### Network Types

- `MacAddress` - Ethernet MAC address handling
- `NetworkInterface` - Interface enumeration and selection

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| libc | FFI to POSIX socket APIs |
| pnet | Packet parsing and construction |
| socket2 | Advanced socket options |
| tokio | Async runtime support |

## Safety

This crate contains `unsafe` blocks for FFI calls to libc. All unsafe code is documented with SAFETY comments explaining the invariants.

## Testing

```bash
# Requires root for raw socket tests
sudo cargo test -p rustnmap-net
```

## Usage

```rust
use rustnmap_net::RawSocket;

let socket = RawSocket::new_ipv4()?;
socket.set_timeout(Duration::from_secs(5))?;
```

## Platform Support

- Linux x86_64 (primary)
- Requires root privileges for raw sockets
