# rustnmap-scan

> **Status**: Requires Migration to New PacketEngine Architecture
> **Last Updated**: 2026-03-05

Port scanning implementations for RustNmap.

## CRITICAL: Packet Engine Migration Required

**Current Issue:**
- Uses `SimpleAfPacket` with `recvfrom()` (not PACKET_MMAP)
- Duplicated code in `ultrascan.rs` and `stealth_scans.rs`
- Missing proper async integration with Tokio

**Migration Plan:**
Replace `SimpleAfPacket` with `AsyncPacketEngine` from `rustnmap-packet`:
```rust
// OLD (broken)
let mut socket = SimpleAfPacket::new(interface)?;

// NEW (PACKET_MMAP V2)
let mut engine = AsyncPacketEngine::new(interface, RingConfig::default()).await?;
engine.start().await?;
```

**Files to Update:**
- `src/ultrascan.rs` - Lines 166-211 (SimpleAfPacket)
- `src/stealth_scans.rs` - Lines 164-211 (SimpleAfPacket)
- `src/syn_scan.rs` - Uses RawSocket, needs PacketEngine trait

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

## Network Volatility Handling

Based on nmap's `timing.cc` and `scan_engine.cc` research:

### 1. Adaptive RTT Estimation (RFC 6298)
- Location: `src/timeout.rs`
- Formula: `SRTT = (7/8)*SRTT + (1/8)*RTT`
- Timeout: `Timeout = SRTT + 4*RTTVAR`
- **Gap**: Missing min/max RTT clamping

### 2. Congestion Control (TCP-like)
- Location: `src/ultrascan.rs` - `InternalCongestionStats`
- Components: cwnd, ssthresh, slow start, congestion avoidance
- **Gap**: Group-level vs host-level drop handling

### 3. Dynamic Scan Delay Boost
- Location: Partial in orchestrator
- Behavior: Exponential backoff on high drop rate
- **Gap**: Not fully implemented

### 4. Rate Limiting
- Location: Not implemented
- Required: Token bucket for `--max-rate`/`--min-rate`
- **Gap**: Complete missing feature

### 5. ICMP Error Classification
- Location: Partial in packet parsing
- Types: HOST_UNREACH, NET_UNREACH, PORT_UNREACH, ADMIN_PROHIBITED
- **Gap**: Proper error response mapping

## Timing Template Parameters

| Parameter | T0 | T1 | T2 | T3 | T4 | T5 |
|-----------|-----|-----|-----|-----|-----|-----|
| min_rtt_timeout | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| max_rtt_timeout | 10s | 10s | 10s | 10s | 10s | 300ms |
| initial_rtt | 1s | 1s | 1s | 1s | 500ms | 250ms |
| max_retries | 10 | 10 | 10 | 10 | 6 | 2 |
| scan_delay | 5min | 15s | 400ms | 0ms | 0ms | 0ms |

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Raw sockets, packet construction |
| rustnmap-packet | **PacketEngine (migration target)** |
| tokio | Async runtime |
| parking_lot | Fast mutex/rwlock |
