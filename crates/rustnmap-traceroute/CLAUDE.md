# rustnmap-traceroute

Network route tracing for RustNmap.

## Purpose

Implements traceroute functionality using multiple probe types (ICMP, TCP, UDP) with proper TTL handling.

## Key Components

### Traceroute Engine

- `Traceroute` - Main traceroute controller
- `TraceOptions` - Configuration (max hops, timeout, etc.)
- `TraceResult` - Hop-by-hop results

### Probe Types

| Type | Module | Description |
|------|--------|-------------|
| ICMP | `icmp.rs` | ICMP echo with increasing TTL |
| TCP | `tcp.rs` | TCP SYN/ACK probes |
| UDP | `udp.rs` | UDP to high ports |

### Hop Detection

- `Hop` - Single hop information
- `HopDetector` - Probe/response matching
- `IcmpParser` - ICMP TimeExceeded parsing

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw sockets |
| tokio | Async runtime |
| pnet | Packet construction |
| rand | Source port randomization |

## Testing

```bash
# Requires root for raw sockets
sudo cargo test -p rustnmap-traceroute
```

## Usage

```rust
use rustnmap_traceroute::{Traceroute, TraceOptions};

let options = TraceOptions::new().max_hops(30);
let traceroute = Traceroute::new(options)?;
let result = traceroute.trace(target).await?;

for hop in result.hops {
    println!("{}: {:?}", hop.ttl, hop.address);
}
```

## Probe Methods

1. **ICMP**: Most compatible, often rate-limited
2. **TCP SYN**: Bypasses some firewalls, good for TCP services
3. **TCP ACK**: Bypasses stateless firewalls
4. **UDP**: Traditional traceroute method
