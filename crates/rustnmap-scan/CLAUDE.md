# rustnmap-scan

> **Status**: COMPLETE - Migrated to ScannerPacketEngine
> **Last Updated**: 2026-03-08

Port scanning implementations for RustNmap.

## Packet Engine Migration: COMPLETE

All scanners now use `ScannerPacketEngine` which wraps `AsyncPacketEngine`:

```rust
// Migrated - all scanners use ScannerPacketEngine
let engine = ScannerPacketEngine::new(interface)?;
engine.start().await?;
```

**Migration Completed:**
- `src/ultrascan.rs` - Uses `ScannerPacketEngine`
- `src/stealth_scans.rs` - Uses `ScannerPacketEngine`
- `src/syn_scan.rs` - Uses `ScannerPacketEngine`
- `src/udp_scan.rs` - Uses `ScannerPacketEngine`

## Purpose

Implements all 12 scan types with proper timeout handling and state machine management.

## Scan Types

| Scan | Module | Requires Root |
|------|--------|---------------|
| TCP SYN | `syn_scan.rs` | Yes |
| TCP Connect | `connect_scan.rs` | No |
| UDP | `udp_scan.rs` | Yes |
| TCP FIN | `stealth_scans.rs` | Yes |
| TCP NULL | `stealth_scans.rs` | Yes |
| TCP XMAS | `stealth_scans.rs` | Yes |
| TCP ACK | `stealth_scans.rs` | Yes |
| TCP Maimon | `stealth_scans.rs` | Yes |
| TCP Window | `stealth_scans.rs` | Yes |
| IP Protocol | `ip_protocol_scan.rs` | Yes |
| Idle (Zombie) | `idle_scan.rs` | Yes |
| FTP Bounce | `ftp_bounce_scan.rs` | No |

## Key Components

- `Scanner` trait - Common interface for all scan types
- `ScanResult` - Port state with timing metadata
- `Probe` - Packet probe construction and matching
- `ScannerPacketEngine` - Adapter wrapping `AsyncPacketEngine`
- `ParallelScanEngine` (ultrascan) - Concurrent multi-target scanning

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw sockets |
| rustnmap-packet | Zero-copy PACKET_MMAP V2 |
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
use rustnmap_scan::{TcpSynScanner, Scanner};

let scanner = TcpSynScanner::new("eth0")?;
let result = scanner.scan_port(target, 80).await?;
```

## Port States

Implements all 10 Nmap port states:
- `open`, `closed`, `filtered`
- `unfiltered`, `open_filtered`, `closed_filtered`
- `open_closed`, `filtered_closed`, `unknown`

## Network Volatility Handling

Based on nmap's `timing.cc` and `scan_engine.cc` research:

### 1. Adaptive RTT Estimation (RFC 6298)
- Location: `src/timeout.rs`
- Formula: `SRTT = (7/8)*SRTT + (1/8)*RTT`
- Timeout: `Timeout = SRTT + 4*RTTVAR`
- Status: IMPLEMENTED

### 2. Congestion Control (TCP-like)
- Location: `src/congestion.rs`, `src/ultrascan.rs`
- Components: cwnd, ssthresh, slow start, congestion avoidance
- Status: IMPLEMENTED

### 3. Dynamic Scan Delay Boost
- Location: `src/adaptive_delay.rs`
- Behavior: Exponential backoff on high drop rate
- Status: IMPLEMENTED

### 4. ICMP Error Classification
- Location: `src/icmp_handler.rs`
- Types: HOST_UNREACH, NET_UNREACH, PORT_UNREACH, ADMIN_PROHIBITED
- Status: IMPLEMENTED

## Timing Template Parameters

| Parameter | T0 | T1 | T2 | T3 | T4 | T5 |
|-----------|-----|-----|-----|-----|-----|-----|
| min_rtt_timeout | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| max_rtt_timeout | 10s | 10s | 10s | 10s | 10s | 300ms |
| initial_rtt | 1s | 1s | 1s | 1s | 500ms | 250ms |
| max_retries | 10 | 10 | 10 | 10 | 6 | 2 |
| scan_delay | 5min | 15s | 400ms | 0ms | 0ms | 0ms |
