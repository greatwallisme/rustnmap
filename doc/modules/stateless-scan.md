# Stateless Scan Module (rustnmap-stateless-scan)

> **Version**: 2.0.0 (in development)
> **Phase**: Phase 4 (Week 10-11)
> **Priority**: P1

---

## Overview

The stateless scan module implements masscan-like high-speed scanning capabilities. By using encrypted cookies to encode source ports and sequence numbers, it can match responses without maintaining a connection state table. This is the core component of the RustNmap 2.0 performance leap.

---

## Features

### 1. Stateless SYN Scan

- No connection state table to maintain
- Sending and receiving are completely decoupled
- Theoretically capable of line-rate scanning

### 2. Cookie Encoding

- Uses encrypted cookies to encode source ports
- Cookies encode sequence numbers
- Responses can be verified without a state table

### 3. High-Rate Scanning

- Target rate: 10 million PPS (packets per second)
- Suitable for large-scale network asset discovery
- Supports rate limiting

### 4. Experimental Feature Flag

- Enabled via `--fast` or `-F2` option
- Disabled by default (requires explicit enablement)
- Only supports SYN scan mode

---

## How It Works

### Traditional Stateful Scanning

```
Sender Thread                      Receiver Thread
   |                                |
   |---> Send SYN (src_port=12345)  |
   |     Record state table {12345 -> target}
   |                                |
   |              SYN-ACK <---------|
   |                                |
   |---> Lookup state table [12345] |
   |     Matched target             |
   |     Send RST                   |
```

### Stateless Scanning

```
Sender Thread                      Receiver Thread
   |                                |
   |---> Compute Cookie = HMAC(key, target_ip)
   |---> src_port = Cookie >> 16    |
   |---> seq_num = Cookie & 0xFFFF  |
   |---> Send SYN (src_port, seq)   |
   |     (no state recording)       |
   |                                |
   |              SYN-ACK <---------|
   |              (carries src_port,|
   |               ack_num = seq+1) |
   |                                |
   |                                |---> Receive SYN-ACK
   |                                |---> Reconstruct Cookie
   |                                |   = (src_port << 16) | (ack_num - 1)
   |                                |---> Verify Cookie = HMAC(key, target_ip)
   |                                |   Match -> port open
   |                                |   No match -> discard
```

---

## Core Algorithms

### Cookie Generation

```rust
use blake3::Hasher;

/// Stateless scan cookie generator
pub struct StatelessCookie {
    /// Encryption key (randomly generated)
    key: [u8; 32],
}

impl StatelessCookie {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        Self { key }
    }

    /// Generate a cookie for a target IP
    pub fn generate(&self, target: IpAddr, timestamp: u64) -> Cookie {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        hasher.update(&target.octets());
        hasher.update(&timestamp.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Source port: use upper 16 bits of hash (excluding privileged ports)
        let source_port = 1024 + ((u16::from_le_bytes([hash_bytes[0], hash_bytes[1]]) % 64511) as u16);

        // Sequence number: use lower 32 bits of hash
        let sequence_num = u32::from_le_bytes([
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7],
        ]);

        Cookie {
            source_port,
            sequence_num,
            timestamp,
        }
    }

    /// Verify a received response
    pub fn verify(&self, target: IpAddr, source_port: u16, ack_num: u32, max_age: Duration) -> VerifyResult {
        // Reconstruct sequence number
        let sequence_num = ack_num - 1;

        // Verify time window (prevent replay attacks)
        let current_time = current_timestamp();
        let cookie_timestamp = extract_timestamp(sequence_num);

        if current_time - cookie_timestamp > max_age.as_secs() {
            return VerifyResult::Expired;
        }

        // Recompute and verify cookie
        let expected = self.generate(target, cookie_timestamp);
        if expected.source_port == source_port && expected.sequence_num == sequence_num {
            VerifyResult::Valid
        } else {
            VerifyResult::Invalid
        }
    }
}

/// Cookie structure
pub struct Cookie {
    pub source_port: u16,
    pub sequence_num: u32,
    pub timestamp: u64,
}

/// Verification result
pub enum VerifyResult {
    Valid,
    Invalid,
    Expired,
}
```

### Sender

```rust
/// Stateless SYN sender
pub struct StatelessSender {
    socket: RawSocket,
    cookie_gen: StatelessCookie,
    rate_limiter: RateLimiter,
    targets: Vec<Target>,
}

impl StatelessSender {
    /// Create sender
    pub fn new(config: StatelessConfig) -> Result<Self>;

    /// Send SYN packet (stateless)
    pub async fn send_syn(&self, target: IpAddr, port: u16) -> Result<()> {
        // Generate cookie
        let cookie = self.cookie_gen.generate(target, current_timestamp());

        // Build SYN packet
        let mut packet = TcpPacket::new();
        packet.set_source(self.local_ip);
        packet.set_destination(target);
        packet.set_source_port(cookie.source_port);
        packet.set_dest_port(port);
        packet.set_seq(cookie.sequence_num);
        packet.set_syn(true);

        // Send
        self.socket.send(packet.build()).await?;
        self.rate_limiter.tick().await;

        Ok(())
    }

    /// Batch send (performance optimization)
    pub async fn send_batch(&self, targets: &[(IpAddr, u16)]) -> Result<usize> {
        let mut packets = Vec::with_capacity(targets.len());

        for &(target, port) in targets {
            let cookie = self.cookie_gen.generate(target, current_timestamp());
            let mut packet = TcpPacket::new();
            packet.set_source(self.local_ip);
            packet.set_destination(target);
            packet.set_source_port(cookie.source_port);
            packet.set_dest_port(port);
            packet.set_seq(cookie.sequence_num);
            packet.set_syn(true);
            packets.push(packet.build());
        }

        // Batch send (using sendmmsg)
        let sent = self.socket.send_batch(packets).await?;
        for _ in 0..sent {
            self.rate_limiter.tick().await;
        }

        Ok(sent)
    }
}
```

### Receiver

```rust
/// Stateless SYN receiver
pub struct StatelessReceiver {
    socket: RawSocket,
    cookie_gen: StatelessCookie,
    results_tx: mpsc::Sender<ScanResult>,
}

impl StatelessReceiver {
    /// Create receiver
    pub fn new(config: StatelessConfig, results_tx: mpsc::Sender<ScanResult>) -> Self;

    /// Receive and verify responses
    pub async fn recv_loop(&self) -> Result<()> {
        loop {
            // Receive packet
            let packet = self.socket.recv().await?;

            // Parse TCP header
            let tcp = TcpPacket::parse(&packet)?;

            // Only process SYN-ACK
            if !tcp.get_syn() || !tcp.get_ack() {
                continue;
            }

            let target = tcp.get_source();
            let source_port = tcp.get_source_port();
            let ack_num = tcp.get_ack();

            // Verify cookie
            match self.cookie_gen.verify(target, source_port, ack_num, Duration::from_secs(30)) {
                VerifyResult::Valid => {
                    // Port open
                    let result = ScanResult {
                        ip: target,
                        port: tcp.get_dest_port(),
                        state: PortState::Open,
                    };
                    self.results_tx.send(result).await?;

                    // Send RST to close connection
                    self.send_rst(target, source_port, ack_num).await?;
                }
                VerifyResult::Invalid => {
                    // Cookie mismatch, possible forged response
                    continue;
                }
                VerifyResult::Expired => {
                    // Cookie expired, possible replay attack
                    continue;
                }
            }
        }
    }

    /// Send RST packet
    async fn send_rst(&self, target: IpAddr, source_port: u16, ack_num: u32) -> Result<()> {
        let mut packet = TcpPacket::new();
        packet.set_source(self.local_ip);
        packet.set_destination(target);
        packet.set_source_port(0);  // Arbitrary port
        packet.set_dest_port(source_port);
        packet.set_seq(ack_num);
        packet.set_ack(0);
        packet.set_rst(true);

        self.socket.send(packet.build()).await?;
        Ok(())
    }
}
```

---

## Architecture Design

### Module Structure

```
rustnmap-stateless/
├── src/
│   ├── lib.rs           # Public API
│   ├── cookie.rs        # Cookie generation and verification
│   ├── sender.rs        # Stateless sender
│   ├── receiver.rs      # Stateless receiver
│   ├── rate_limiter.rs  # Rate limiter
│   └── config.rs        # Configuration management
└── tests/
    └── integration.rs   # Integration tests
```

### Scan Flow

```
                    ┌─────────────────┐
                    │  Scanner::fast() │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌────────────────┐ ┌───────────┐ ┌───────────┐
    │StatelessSender │ │ Receiver  │ │RateLimiter│
    │ (Send SYN pkts)│ │(Recv SYN- │ │ (Rate     │
    │                │ │ ACK)      │ │  limiting)│
    └───────┬────────┘ └─────┬─────┘ └─────┬─────┘
            │                │             │
            │                │             │
            └────────────────┼─────────────┘
                             │
                             ▼
                   ┌─────────────────┐
                   │  Results Channel │
                   │  (mpsc::Sender)  │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ OutputSink      │
                   │ (Stream output  │
                   │  results)       │
                   └─────────────────┘
```

---

## CLI Options

### Enabling Stateless Scanning

```bash
# Basic usage
rustnmap --fast -p 1-65535 192.168.1.0/8

# Or use -F2 (distinct from -F fast scan)
rustnmap -F2 -p 1-10000 10.0.0.0/8

# Set send rate (packets per second)
rustnmap --fast --rate 1000000 -p 80,443 192.168.1.0/24

# Only discover open ports (no service detection)
rustnmap --fast --ports-only -p 1-1000 192.168.1.0/24
```

### Two-Phase Scanning

```bash
# Phase 1: Stateless fast discovery
rustnmap --fast -p 1-65535 192.168.1.0/24 -oG fast-results.gnmap

# Phase 2: Detailed analysis (only for discovered open ports)
rustnmap -iL open-ports.txt -sV -sC -O 192.168.1.0/24
```

---

## Performance Optimization

### Batch Sending

```rust
/// Batch send using sendmmsg
pub async fn send_batch_optimized(&self, packets: &[TcpPacket]) -> Result<usize> {
    // Prepare iovec array
    let mut iovs: Vec<libc::iovec> = packets
        .iter()
        .map(|pkt| libc::iovec {
            iov_base: pkt.data().as_ptr() as *mut libc::c_void,
            iov_len: pkt.data().len(),
        })
        .collect();

    // Prepare mmsghdr array
    let mut msgs: Vec<libc::mmsghdr> = iovs
        .iter_mut()
        .map(|iov| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut _,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        })
        .collect();

    // Batch send
        unsafe {
        libc::sendmmsg(
            self.socket_fd,
            msgs.as_mut_ptr(),
            msgs.len() as libc::c_uint,
            0,
        )
    };

    Ok(sent as usize)
}
```

### Zero-Copy Receiving

```rust
/// Zero-copy receive using PACKET_MMAP V2
/// Reference: doc/modules/packet-engineering.md, reference/nmap/libpcap/pcap-linux.c
pub struct ZeroCopyReceiver {
    engine: MmapPacketEngine,
}

impl ZeroCopyReceiver {
    pub async fn recv_next(&mut self) -> Result<Option<&TcpPacket>> {
        // Get reference directly from ring buffer, no copy needed
        let packet = self.engine.recv_packet();
        if let Some(pkt) = packet {
            let tcp = TcpPacket::parse(&pkt.data)?;
            Ok(Some(tcp))
        } else {
            Ok(None)
        }
    }
}
```

---

## Security Considerations

### 1. Cookie Key Protection

```rust
/// Secure key generation
fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    // Use system RNG
    getrandom::getrandom(&mut key).expect("Failed to generate random key");
    key
}

/// Key rotation (every 24 hours)
pub struct KeyRotator {
    current_key: [u8; 32],
    previous_key: [u8; 32],
    last_rotation: Instant,
    rotation_interval: Duration,
}
```

### 2. Replay Attack Prevention

- Cookies include timestamps
- Time window verification (default 30 seconds)
- Expired cookies are automatically rejected

### 3. Rate Limiting

```rust
/// Token Bucket rate limiter
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,  // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub async fn acquire(&mut self) {
        while self.tokens < 1.0 {
            self.refill();
            tokio::time::sleep(Duration::from_micros(10)).await;
        }
        self.tokens -= 1.0;
    }
}
```

---

## Alignment with RETHINK.md

| Section | Corresponding Content |
|---------|----------------------|
| 4.2.3 Stateless Scanning | Encrypted cookie encoding, stateless SYN |
| 12.3 Phase 4 | Performance backbone optimization (Week 10-11) |
| 14.5 Phase 4-5 | Scan main loop refactoring |

---

## Dependencies

```toml
[dependencies]
# Cryptography
blake3 = "1"
getrandom = "0.2"

# Async
tokio = { version = "1", features = ["full"] }

# Internal dependencies
rustnmap-common = { path = "../rustnmap-common" }
rustnmap-net = { path = "../rustnmap-net" }
rustnmap-packet = { path = "../rustnmap-packet" }
```

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation() {
        let cookie_gen = StatelessCookie::new();
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        let cookie1 = cookie_gen.generate(target, 1000);
        let cookie2 = cookie_gen.generate(target, 1000);

        // Same target and timestamp should generate the same cookie
        assert_eq!(cookie1.source_port, cookie2.source_port);
        assert_eq!(cookie1.sequence_num, cookie2.sequence_num);
    }

    #[test]
    fn test_cookie_verification() {
        let cookie_gen = StatelessCookie::new();
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        let cookie = cookie_gen.generate(target, 1000);

        // Verification should succeed
        let result = cookie_gen.verify(
            target,
            cookie.source_port,
            cookie.sequence_num + 1,  // ack_num = seq + 1
            Duration::from_secs(30),
        );
        assert!(matches!(result, VerifyResult::Valid));
    }
}
```

---

## Next Steps

1. **Week 10**: Implement cookie generation and verification algorithms
2. **Week 10**: Implement stateless sender and receiver
3. **Week 11**: Integrate rate limiting and batch sending
4. **Week 11**: Write integration tests and performance benchmarks

---

## References

- [masscan Principles](https://github.com/robertdavidgraham/masscan)
- [TCP Cookie TCP (RFC 6013)](https://datatracker.ietf.org/doc/html/rfc6013)
- [BLAKE3 Hash Function](https://docs.rs/blake3)
