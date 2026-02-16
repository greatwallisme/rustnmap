# rustnmap-scan

Port scanning implementations for RustNmap.

## Purpose

Implements all 12 scan types with proper timeout handling and state machine management.

## Scan Types

| Scan | Module | Requires Root |
|------|--------|---------------|
| TCP SYN | `syn.rs` | Yes |
| TCP Connect | `connect.rs` | No |
| UDP | `udp.rs` | Yes |
| TCP FIN | `stealth_scans.rs` | Yes |
| TCP NULL | `stealth_scans.rs` | Yes |
| TCP XMAS | `stealth_scans.rs` | Yes |
| TCP ACK | `stealth_scans.rs` | Yes |
| TCP Maimon | `stealth_scans.rs` | Yes |
| TCP Window | `window_scan.rs` | Yes |
| IP Protocol | `ip_protocol_scan.rs` | Yes |
| Idle (Zombie) | `idle_scan.rs` | Yes |
| FTP Bounce | `ftp_bounce_scan.rs` | No |

## Key Components

- `Scanner` trait - Common interface for all scan types
- `ScanResult` - Port state with timing metadata
- `Probe` - Packet probe construction and matching

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw sockets |
| rustnmap-packet | Zero-copy packets |
| rustnmap-target | Target handling |
| tokio | Async runtime |
| pnet | Packet construction |

## Testing

```bash
# Unit tests
cargo test -p rustnmap-scan -- --skip requires_root

# Integration tests (requires root)
sudo cargo test -p rustnmap-scan
```

## Usage

```rust
use rustnmap_scan::{SynScanner, Scanner};

let scanner = SynScanner::new("eth0")?;
let result = scanner.scan_port(target, 80).await?;
```

## Port States

Implements all 10 Nmap port states:
- `open`, `closed`, `filtered`
- `unfiltered`, `open_filtered`, `closed_filtered`
- `open_closed`, `filtered_closed`, `unknown`
