# rustnmap-evasion

Firewall and IDS evasion techniques for RustNmap network scanner.

## Purpose

Implements various evasion techniques to bypass firewall rules and IDS detection.

## Evasion Techniques

### Fragmentation

- `Fragmenter` - IP packet fragmentation
- `FragmentConfig` - MTU and fragment size configuration
- Reassembly evasion via overlapping fragments

### Decoy Scanning

- `DecoyScheduler` - Rotate decoy IP addresses
- `DecoyConfig` - Decoy list and position settings
- Makes scan origin harder to identify

### Source Spoofing

- `SourceSpoofer` - Spoof source IP and port
- `SourceConfig` - Spoofing configuration
- Requires root and proper routing

### Packet Modification

- `PacketModifier` - Mutate packet fields
- Bad checksum injection
- Random padding addition

### Timing Control

- `TimingController` - T0-T5 timing templates
- `AdaptiveTiming` - RTT-based rate adjustment

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw sockets |
| tokio | Async runtime |
| pnet | Packet modification |

## Testing

```bash
cargo test -p rustnmap-evasion
```

## Usage

```rust
use rustnmap_evasion::{EvasionConfig, Fragmenter, DecoyScheduler};

let config = EvasionConfig::new()
    .with_fragmentation(16)
    .with_decoys(vec!["10.0.0.1", "10.0.0.2"]);
```

## Security Note

These techniques should only be used for authorized security testing. Misuse may violate network policies or laws.
