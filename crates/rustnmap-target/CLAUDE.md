# rustnmap-target

Target parsing and host discovery for RustNmap.

## Purpose

Target specification parsing (CIDR, ranges, hostnames) and host discovery methods (ping sweeps, ARP, etc.).

## Key Components

### Target Parsing

- `TargetParser` - Parse target specifications
  - Single IPs: `192.168.1.1`
  - CIDR notation: `192.168.1.0/24`
  - Ranges: `192.168.1.1-100`
  - Hostnames: `example.com`
  - From file: `-iL targets.txt`

- `TargetSet` - Collection of targets with deduplication

### Host Discovery

- `HostDiscovery` - Unified discovery engine
- `IcmpPing` - ICMP echo request/reply
- `IcmpTimestamp` - ICMP timestamp ping
- `TcpSynPing` - TCP SYN ping
- `TcpAckPing` - TCP ACK ping
- `ArpPing` - ARP request (local networks)

### IPv6 Support

- `Icmpv6Ping` - ICMPv6 echo
- `Icmpv6NeighborDiscovery` - NDP neighbor solicitation

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw socket operations |
| tokio | Async runtime |
| trust-dns-resolver | Async DNS resolution |

## Testing

```bash
# Unit tests (no root required)
cargo test -p rustnmap-target -- --skip requires_root

# Full tests (requires root)
sudo cargo test -p rustnmap-target
```

## Usage

```rust
use rustnmap_target::{TargetParser, HostDiscovery};

let targets = TargetParser::parse("192.168.1.0/24")?;
let discovery = HostDiscovery::new().add_ping();
```
