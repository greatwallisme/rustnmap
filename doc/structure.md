# 5. Project Structure and Module Organization

> **Version**: 1.0.0 (2.0 in development)
> **Last Updated**: 2026-02-17

---

## 5.0 RustNmap 2.0 Project Overview

### 5.0.1 Crate List (1.0 + 2.0)

| Crate | Purpose | Status |
|-------|---------|--------|
| `rustnmap-common` | Common types, utility functions, error handling, ServiceDatabase | 1.0 |
| `rustnmap-net` | Raw sockets, packet construction | 1.0 |
| `rustnmap-packet` | PACKET_MMAP V2 zero-copy engine | 1.0 |
| `rustnmap-target` | Target parsing, host discovery | 1.0 |
| `rustnmap-scan` | Port scan implementations (12 scan types) | 1.0 |
| `rustnmap-fingerprint` | Service/OS fingerprint matching, database loading (MAC/RPC/protocols) | 1.0 |
| `rustnmap-nse` | Lua script engine (process isolation) | 1.0 |
| `rustnmap-traceroute` | Network route tracing | 1.0 |
| `rustnmap-evasion` | Firewall/IDS evasion techniques | 1.0 |
| `rustnmap-cli` | Command-line interface (lexopt parser) | 1.0 |
| `rustnmap-core` | Core orchestrator, ScanSession DI container | 1.0 |
| `rustnmap-output` | Output formatting (7 formats) | 1.0 |
| `rustnmap-benchmarks` | Performance benchmarks | 1.0 |
| `rustnmap-stateless-scan` | Masscan-like stateless high-speed scanning (SYN Cookie) | **2.0 NEW** |
| `rustnmap-scan-management` | Scan persistence (SQLite), scan comparison, YAML configuration | **2.0 NEW** |
| `rustnmap-vuln` | Vulnerability intelligence (CVE/CPE/EPSS/KEV) | **2.0 NEW** |
| `rustnmap-api` | REST API / Daemon mode (Axum) | **2.0 NEW** |
| `rustnmap-sdk` | Rust SDK (Builder API, supports local and remote scanning) | **2.0 NEW** |

**Total**: 13 (1.0) + 5 (2.0 new) = **18 Crates**

---

## 5.1 Cargo Workspace Structure

```
crates/
├── rustnmap-common/           # Common types, error handling, ServiceDatabase
├── rustnmap-net/              # Raw sockets, packet construction
├── rustnmap-packet/           # PACKET_MMAP V2 zero-copy engine
│   └── src/ (engine, mmap, zero_copy, async_engine, bpf, stream)
├── rustnmap-target/           # Target parsing, host discovery
├── rustnmap-scan/             # Port scan implementations (12 scan types)
├── rustnmap-fingerprint/      # Service/OS fingerprint matching
│   └── src/database/ (mac, rpc, protocols, service/, os/)
├── rustnmap-nse/              # Lua script engine (process isolation)
│   ├── src/ (engine, libs, parser, process_executor)
│   └── src/bin/runner.rs      # rustnmap-nse-runner standalone process
├── rustnmap-traceroute/       # Network route tracing
├── rustnmap-evasion/          # Firewall/IDS evasion techniques
├── rustnmap-output/           # Output formatting (7 formats)
│   └── src/ (formatter, models, database_context)
├── rustnmap-core/             # Core orchestrator, ScanSession DI container
│   └── src/ (orchestrator, session, timing)
├── rustnmap-cli/              # Command-line interface (lexopt)
├── rustnmap-benchmarks/       # Performance benchmarks
├── rustnmap-stateless-scan/   # Stateless high-speed scanning (SYN Cookie)
├── rustnmap-scan-management/  # Scan persistence, comparison, YAML configuration
├── rustnmap-vuln/             # Vulnerability intelligence (CVE/CPE/EPSS/KEV)
├── rustnmap-api/              # REST API (Axum)
└── rustnmap-sdk/              # Rust SDK (Builder API)

data/                          # Nmap-compatible database files
├── nmap-service-probes
├── nmap-os-db
├── nmap-mac-prefixes
├── nmap-rpc
└── nmap-payloads

scripts/                       # NSE script library (Nmap-compatible)
```

## 5.2 Dependency Graph

### 5.2.1 Internal Dependency Relationships

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Internal Crate Dependencies                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  rustnmap-common          (no internal dependencies - base types)   │
│     ^                                                               │
│     ├── rustnmap-net                                               │
│     │      ^                                                       │
│     │      ├── rustnmap-target                                     │
│     │      ├── rustnmap-evasion                                    │
│     │      └── rustnmap-scan ──> rustnmap-packet                   │
│     │                                                               │
│     ├── rustnmap-packet                                            │
│     │      ^                                                       │
│     │      └── rustnmap-scan                                       │
│     │                                                               │
│     ├── rustnmap-fingerprint ──> rustnmap-net, rustnmap-packet     │
│     │      ^                                                       │
│     │      └── rustnmap-output                                     │
│     │                                                               │
│     ├── rustnmap-nse ──> rustnmap-target                           │
│     │                                                               │
│     ├── rustnmap-traceroute ──> rustnmap-net                       │
│     │                                                               │
│     ├── rustnmap-vuln ──> rustnmap-output                          │
│     │      ^                                                       │
│     │      └── rustnmap-scan-management                            │
│     │                                                               │
│     └── rustnmap-core ──> common, net, packet, scan, target,       │
│            evasion, fingerprint, nse, traceroute, output           │
│            ^                                                        │
│            ├── rustnmap-cli ──> common, core, scan, target,        │
│            │       fingerprint, nse, output, evasion, vuln,        │
│            │       scan-management                                  │
│            │                                                        │
│            ├── rustnmap-api ──> core, output, scan-management      │
│            │                                                        │
│            ├── rustnmap-sdk ──> core, output, target, evasion,     │
│            │       common                                           │
│            │                                                        │
│            └── rustnmap-stateless-scan ──> core, packet, output    │
│                                                                     │
│  rustnmap-benchmarks ──> common, fingerprint, net, nse, packet,    │
│     scan, target                                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2.2 Key External Dependencies

| Dependency | Purpose |
|------------|---------|
| tokio | Async runtime |
| mlua | Lua 5.4 bindings (NSE scripts) |
| pnet | Packet processing |
| lexopt | CLI argument parsing |
| serde/serde_json | Serialization |
| regex | Regex matching |
| trust-dns | DNS resolution |
| rustls/tokio-rustls | TLS/SSL |
| axum | REST API framework (2.0) |
| rusqlite | SQLite database (2.0) |
| reqwest | HTTP client (NVD API) |
| x509-parser | Certificate parsing |

### 5.2.3 Complete Dependency Chains

```
rustnmap-cli ──> rustnmap-core ──> rustnmap-scan ──> rustnmap-net
                              │                       rustnmap-packet
                              │                       rustnmap-target
                              │                       rustnmap-evasion
                              ├──> rustnmap-nse ──> rustnmap-target
                              ├──> rustnmap-fingerprint ──> rustnmap-net
                              │                          rustnmap-packet
                              ├──> rustnmap-traceroute ──> rustnmap-net
                              └──> rustnmap-output ──> rustnmap-fingerprint

rustnmap-sdk ──> rustnmap-core (local scanning)
             ──> rustnmap-output, rustnmap-target, rustnmap-evasion

rustnmap-api ──> rustnmap-core
             ──> rustnmap-output
             ──> rustnmap-scan-management ──> rustnmap-vuln ──> rustnmap-output
```

---

## 5.3 rustnmap-packet Detailed Structure (PACKET_MMAP V2 Redesign)

> **Important**: This crate is the core of performance optimization, requiring a complete redesign for true PACKET_MMAP V2 ring buffer support.

### 5.3.1 File Structure (After Redesign)

```
crates/rustnmap-packet/
├── Cargo.toml                     # Dependency configuration
│   [dependencies]
│   rustnmap-common = { path = "../rustnmap-common" }
│   tokio = { version = "1.42", features = ["net", "io-util", "rt-multi-thread", "sync"] }
│   bytes = "1.9"
│   libc = "0.2"
│   socket2 = "0.5"
│   thiserror = "2.0"
│
├── src/
│   ├── lib.rs                     # Public API exports
│   │   pub mod engine;
│   │   pub mod mmap;
│   │   pub mod async_engine;
│   │   pub mod bpf;
│   │   pub mod stream;
│   │   pub mod stats;
│   │   pub mod error;
│   │   pub mod sys;
│   │
│   ├── engine.rs                  # PacketEngine trait definition
│   │   pub trait PacketEngine: Send + Sync
│   │   pub struct PacketBuffer { data: Bytes, len, timestamp, ... }
│   │   pub struct EngineStats { packets_received, packets_dropped, ... }
│   │
│   ├── mmap.rs                    # MmapPacketEngine core implementation
│   │   pub struct MmapPacketEngine { fd, config, ring_ptr, ... }
│   │   pub struct RingConfig { block_count, block_size, frame_size }
│   │   pub struct Tpacket2Hdr { tp_status, tp_len, tp_snaplen, ... }
│   │   impl MmapPacketEngine:
│   │     - fn new(interface, config) -> Result<Self>
│   │     - fn setup_ring_buffer(&mut self) -> Result<()>
│   │     - fn mmap_ring(&mut self) -> Result<NonNull<u8>>
│   │     - fn current_frame_ptr(&self) -> *mut Tpacket2Hdr
│   │     - fn advance_frame(&mut self)
│   │     - fn try_recv(&mut self) -> Result<Option<PacketBuffer>>
│   │
│   ├── async_engine.rs            # AsyncPacketEngine (Tokio integration)
│   │   pub struct AsyncPacketEngine { engine, async_fd, packet_tx, packet_rx }
│   │   impl AsyncPacketEngine:
│   │     - async fn new(interface, config) -> Result<Self>
│   │     - async fn start(&mut self) -> Result<()>
│   │     - async fn recv(&mut self) -> Result<Option<PacketBuffer>>
│   │     - async fn send(&self, packet) -> Result<usize>
│   │     - async fn stop(&mut self) -> Result<()>
│   │
│   ├── bpf.rs                     # BPF filter
│   │   pub struct BpfFilter { instructions: Vec<sock_filter> }
│   │   pub struct BpfProgram { bf_len, bf_insns }
│   │   impl BpfFilter:
│   │     - fn compile(expr: &str) -> Result<Self>
│   │     - fn attach(&self, fd: i32) -> Result<()>
│   │     - fn tcp_dst_port(port: u16) -> Self
│   │     - fn udp_dst_port(port: u16) -> Self
│   │     - fn icmp() -> Self
│   │
│   ├── stream.rs                  # PacketStream (impl Stream)
│   │   pub struct PacketStream { engine: Arc<Mutex<AsyncPacketEngine>> }
│   │   impl Stream for PacketStream:
│   │     - fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<PacketBuffer>>
│   │
│   ├── stats.rs                   # Statistics
│   │   pub struct EngineStats {
│   │     packets_received: AtomicU64,
│   │     packets_dropped: AtomicU64,
│   │     bytes_received: AtomicU64,
│   │     filter_accepts: AtomicU64,
│   │     filter_rejects: AtomicU64,
│   │   }
│   │
│   ├── error.rs                   # Error type definitions
│   │   pub enum PacketError {
│   │     SocketCreation(io::Error),
│   │     MmapFailed(io::Error),
│   │     InvalidConfig(String),
│   │     InterfaceNotFound(String),
│   │     BpfError(String),
│   │     ChannelClosed,
│   │   }
│   │
│   └── sys/                       # Linux syscall wrappers
│       ├── mod.rs                 # Export all sys modules
│       ├── tpacket.rs             # TPACKET_V2 constants and structures
│       │   pub const TPACKET_V2: i32 = 2;
│       │   pub const TP_STATUS_KERNEL: u32 = 0;
│       │   pub const TP_STATUS_USER: u32 = 1;
│       │   pub const TP_STATUS_COPY: u32 = 2;
│       │   pub const TP_STATUS_LOSING: u32 = 4;
│       │   pub const TP_ALIGNMENT: usize = 16;
│       │
│       ├── if_packet.rs           # AF_PACKET constants
│       │   pub const AF_PACKET: i32 = 17;
│       │   pub const ETH_P_ALL: u16 = 0x0003;
│       │   pub const ETH_P_IP: u16 = 0x0800;
│       │   pub const ETH_P_IPV6: u16 = 0x86DD;
│       │   pub const ETH_P_ARP: u16 = 0x0806;
│       │   pub const PACKET_MMAP: i32 = 8;
│       │   pub const PACKET_RX_RING: i32 = 5;
│       │   pub const PACKET_TX_RING: i32 = 7;
│       │   pub const PACKET_ADD_MEMBERSHIP: i32 = 1;
│       │   pub const PACKET_DROP_MEMBERSHIP: i32 = 2;
│       │
│       └── sock_addr.rs           # Socket address structure
│           pub struct SockaddrLl {
│             sll_family: u16,
│             sll_protocol: u16,
│             sll_ifindex: i32,
│             sll_hatype: u16,
│             sll_pkttype: u8,
│             sll_halen: u8,
│             sll_addr: [u8; 8],
│           }
│
└── tests/                         # Integration tests (requires root)
    ├── mmap_ring_test.rs          # Ring buffer tests
    ├── async_engine_test.rs       # Async engine tests
    └── bpf_filter_test.rs         # BPF filter tests
```

### 5.3.2 Key API Examples

```rust
use rustnmap_packet::{MmapPacketEngine, AsyncPacketEngine, RingConfig, BpfFilter};
use tokio_stream::StreamExt;

// Synchronous API (low-level)
fn sync_example() -> Result<(), PacketError> {
    let config = RingConfig::default();  // 2 blocks x 2MB
    let mut engine = MmapPacketEngine::new("eth0", config)?;

    // Set BPF filter (receive only TCP port 80)
    let filter = BpfFilter::tcp_dst_port(80);
    engine.set_filter(&filter)?;

    engine.start()?;

    // Receive packets
    while let Some(packet) = engine.recv()? {
        println!("Received {} bytes", packet.len);
    }

    engine.stop()?;
    Ok(())
}

// Async API (recommended)
#[tokio::main]
async fn async_example() -> Result<(), PacketError> {
    let config = RingConfig::default();
    let mut engine = AsyncPacketEngine::new("eth0", config).await?;

    engine.start().await?;

    // Use Stream trait
    let mut stream = engine.into_stream();
    while let Some(packet) = stream.next().await {
        match packet {
            Ok(pkt) => println!("Received {} bytes", pkt.len),
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    Ok(())
}
```

### 5.3.3 Dependencies

```
┌─────────────────────────────────────────────────────────────────────┐
│                   rustnmap-packet Dependencies                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  rustnmap-packet                                                    │
│       │                                                             │
│       ├──> rustnmap-common (type definitions)                       │
│       │                                                             │
│       ├──> tokio (async runtime)                                    │
│       │     - net: AsyncFd support                                  │
│       │     - io-util: AsyncRead/Write                              │
│       │     - sync: mpsc channel                                    │
│       │                                                             │
│       ├──> bytes (zero-copy buffer)                                 │
│       │     - Bytes: reference-counted slices                       │
│       │                                                             │
│       ├──> libc (syscalls)                                          │
│       │     - mmap/munmap                                           │
│       │     - socket/bind/setsockopt                                │
│       │     - AF_PACKET, TPACKET_V2                                 │
│       │                                                             │
│       ├──> socket2 (socket wrapper)                                 │
│       │     - Type::RAW                                             │
│       │     - Protocol::from(ETH_P_ALL)                             │
│       │                                                             │
│       └──> thiserror (error definitions)                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3.4 Performance Targets

| Metric | Current (recvfrom) | Target (PACKET_MMAP V2) | Improvement |
|--------|--------------------|------------------------|-------------|
| Packets/sec (PPS) | ~50,000 | ~1,000,000 | 20x |
| CPU Usage | 80% (single core) | 30% (single core) | 2.7x |
| Memory Copies | 1 per packet | Zero-copy | N/A |
| System Calls | 1 per packet | Batched | ~100x |
| Packet Loss (T5) | ~30% | <1% | 30x |
