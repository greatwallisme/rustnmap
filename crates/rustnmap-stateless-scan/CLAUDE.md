# rustnmap-stateless-scan

Masscan-like high-speed stateless scanning for RustNmap.

## Purpose

Implements stateless SYN scanning using cryptographic cookies (similar to masscan) for extremely high packet rates without per-connection state tracking.

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `StatelessScanner` | `stateless.rs` | Main stateless scan engine |
| `CookieGenerator` | `cookie.rs` | SYN cookie generation/verification (BLAKE3) |
| `PacketSender` | `sender.rs` | High-rate SYN packet transmission |
| `PacketReceiver` | `receiver.rs` | Response processing and cookie verification |

## Architecture

Unlike the stateful `ultrascan` in `rustnmap-scan`, this engine encodes port/index information into SYN cookies, allowing stateless packet matching at very high rates.

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-core | Core orchestration |
| rustnmap-packet | PACKET_MMAP engine |
| rustnmap-output | Output models |
| blake3 | Cookie cryptography |
| pnet | Packet construction |

## Testing

```bash
cargo test -p rustnmap-stateless-scan
```
