# 2. System Architecture Design

> **Version**: 1.1.0
> **Last Updated**: 2026-04-12

---

## 2.1 RustNmap 2.0 Architecture Overview

RustNmap 2.0 has been upgraded from a "port scanner" to an "attack surface management platform" with the following core new modules:

### 2.1.1 2.0 New Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| `rustnmap-stateless-scan` | Masscan-style stateless high-speed scanning (SYN Cookie) | Created |
| `rustnmap-scan-management` | Scan persistence (SQLite), scan comparison, YAML configuration | Created |
| `rustnmap-vuln` | Vulnerability intelligence (CVE/CPE correlation, EPSS/KEV) | Created |
| `rustnmap-api` | REST API / Daemon mode (Axum) | Created |
| `rustnmap-sdk` | Rust SDK (Builder API, supports local and remote scanning) | Created |

### 2.1.2 2.0 New Feature Modules

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        RustNmap 2.0 Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    API & SDK Layer (2.0 NEW)                       │  │
│  │  ┌─────────────────────┐  ┌─────────────────────────────────────┐ │  │
│  │  │   REST API (axum)   │  │      Rust SDK (Builder API)         │ │  │
│  │  │   POST /api/scans   │  │   Scanner::new().targets().run()    │ │  │
│  │  │   GET  /api/scans/1 │  │                                     │ │  │
│  │  └─────────────────────┘  └─────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Core Engine Layer                           │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Scan Orchestrator                         │  │  │
│  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────────┐  │  │  │
│  │  │  │ Scheduler │ │ Executor  │ │ State     │ │ Result      │  │  │  │
│  │  │  │           │ │           │ │ Manager   │ │ Aggregator  │  │  │  │
│  │  │  └───────────┘ └───────────┘ └───────────┘ └─────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Scan Modules Layer                         │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   Host     │ │   Port     │ │  Service   │ │      OS        │ │  │
│  │  │  Discovery │ │  Scanning  │ │  Detection │ │  Fingerprinting│ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │ Traceroute │ │   NSE      │ │  Vulnerability│ │  Evasion     │ │  │
│  │  │            │ │   Engine   │ │  (2.0 NEW)  │ │               │ │  │
│  │  └────────────┘ └────────────┘ └─────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Infrastructure Layer                        │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │    Raw     │ │   Packet   │ │   Async    │ │   Logging &    │ │  │
│  │  │  Socket    │ │   Builder  │ │   Runtime  │ │   Metrics      │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2.2 Overall Architecture Diagram (1.0 Baseline)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           RustNmap Architecture                          │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                        CLI Interface Layer                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │  │
│  │  │  lexopt CLI │  │  Config     │  │  Output Formatters          │ │  │
│  │  │  Parser     │  │  Manager    │  │  (Normal/XML/JSON/Grepable) │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Core Engine Layer                           │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Scan Orchestrator                         │  │  │
│  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────────┐  │  │  │
│  │  │  │ Scheduler │ │ Executor  │ │ State     │ │ Result      │  │  │  │
│  │  │  │           │ │           │ │ Manager   │ │ Aggregator  │  │  │  │
│  │  │  └───────────┘ └───────────┘ └───────────┘ └─────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Scan Modules Layer                         │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   Host     │ │   Port     │ │  Service   │ │      OS        │ │  │
│  │  │  Discovery │ │  Scanning  │ │  Detection │ │  Fingerprinting│ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │  Traceroute│ │   NSE      │ │   Vuln     │ │     NAT        │ │  │
│  │  │            │ │   Engine   │ │  Detection │ │  Traversal     │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Infrastructure Layer                        │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │    Raw     │ │   Packet   │ │   Async    │ │   Logging &    │ │  │
│  │  │  Socket    │ │   Builder  │ │   Runtime  │ │   Metrics      │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2.3 Module Dependency Relationships

### 2.3.1 1.0 Baseline Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Binary                      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      rustnmap-cli                           │
│  (Command-line parsing, configuration loading, output       │
│   formatting)                                               │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      rustnmap-core                          │
│  (Scan orchestrator, state management, result aggregation)  │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐
│ rustnmap-scan │   │ rustnmap-nse  │   │rustnmap-finger│
│ (Scan module) │   │ (Script       │   │ (Fingerprint  │
│               │   │  engine)      │   │  recognition) │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    rustnmap-net                             │
│  (Raw sockets, packet construction, async networking)       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    rustnmap-common                          │
│  (Type definitions, utility functions, error handling)      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   rustnmap-output                           │
│  (Output formatting: Normal/XML/JSON/Grepable)              │
└─────────────────────────────────────────────────────────────┘
```

### 2.3.2 2.0 New Dependencies

```
rustnmap-sdk (2.0) ──> rustnmap-core (local scanning)
                   ──> rustnmap-output, rustnmap-target, rustnmap-evasion

rustnmap-api (2.0) ──> rustnmap-core
                   ──> rustnmap-output
                   ──> rustnmap-scan-management ──> rustnmap-vuln ──> rustnmap-output

rustnmap-stateless-scan (2.0) ──> rustnmap-core, rustnmap-packet, rustnmap-output
```

### 2.3.3 Complete Dependency Chain (1.0 + 2.0)

```
rustnmap-cli ──> rustnmap-core ──> rustnmap-scan, rustnmap-nse, rustnmap-fingerprint,
                              │    rustnmap-traceroute, rustnmap-evasion, rustnmap-output
                              └──> rustnmap-vuln, rustnmap-scan-management (for output/management)

rustnmap-sdk ──> rustnmap-core (local scanning, not via API)
             ──> rustnmap-output, rustnmap-target, rustnmap-evasion, rustnmap-common

rustnmap-api ──> rustnmap-core, rustnmap-output, rustnmap-scan-management
             (accesses vuln via scan-management, no direct dependency)

rustnmap-stateless-scan ──> rustnmap-core, rustnmap-packet, rustnmap-output
```

---

## 2.3 Packet Engine Architecture (PACKET_MMAP V2 Refactoring)

> **Important**: The current `rustnmap-packet` uses the `recvfrom()` system call instead of a true PACKET_MMAP ring buffer.
> This is the root cause of T5 Insane scan instability and poor UDP scan performance.
> This section describes the complete architectural refactoring plan based on the nmap reference implementation.

### 2.3.1 Current Problem Diagnosis

| Problem | Current Implementation | nmap Implementation | Impact |
|---------|----------------------|---------------------|--------|
| Packet capture method | `recvfrom()` system call | PACKET_MMAP V2 ring buffer | One syscall per packet, high overhead |
| Buffer size | Socket queue (default) | 4MB ring buffer | Packet loss under high load |
| Async I/O | `spawn_blocking` | nsock + epoll | Thread blocking, low efficiency |
| Zero-copy | None (memory copy) | Yes (mmap) | CPU and memory bandwidth waste |
| TPACKET version | Claims V3, not actually implemented | V2 (stability priority) | V3 has bugs on older kernels |

**nmap version negotiation strategy** (reference `reference/nmap/libpcap/pcap-linux.c:2974-3013`):
```c
// nmap actual implementation: try V3 first, fall back to V2 on failure
// but use V2 directly in immediate mode
if (!immediate_mode) {
    // Try TPACKET_V3
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v3, sizeof(v3)) == 0) {
        // V3 setup successful, continue configuration
    } else {
        // V3 failed, fall back to V2
        setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v2, sizeof(v2));
    }
} else {
    // immediate mode uses V2 directly
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v2, sizeof(v2));
}
```

**RustNmap architectural decision**: Use V2 directly, because:
1. Scanners typically need immediate mode (low-latency response)
2. V2 is stable across all kernel versions
3. nmap also uses V2 in most cases

**Code evidence** (`crates/rustnmap-packet/src/lib.rs:764-765`):
```rust
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

### 2.3.2 New Architecture: Layered Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Packet Engine Architecture (Redesigned)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Scanner Layer (rustnmap-scan)                       │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │  │
│  │  │ SYN Scanner │ │ UDP Scanner │ │Stealth Scan │ │  OS Fingerprint │  │  │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └────────┬────────┘  │  │
│  │         │               │               │                  │           │  │
│  │         └───────────────┴───────────────┴──────────────────┘           │  │
│  │                                   │                                    │  │
│  │                         dyn PacketEngine                               │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                  Async Integration Layer (NEW)                         │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    AsyncPacketEngine                             │  │  │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │  │
│  │  │  │ AsyncFd<Raw> │  │ mpsc Channel │  │  PacketStream        │   │  │  │
│  │  │  │  (Tokio)     │  │  (Backpress) │  │  (impl Stream)       │   │  │  │
│  │  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                   │                                    │  │
│  │                         PacketEngine trait                             │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                  Core Engine Layer (rustnmap-packet)                   │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                   MmapPacketEngine (NEW)                         │  │  │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │  │
│  │  │  │ RingBuffer   │  │ BlockManager │  │  FrameIterator       │   │  │  │
│  │  │  │ (mmap ptr)   │  │ (V2 Blocks)  │  │  (Zero-copy)         │   │  │  │
│  │  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                   BpfFilter (NEW)                                │  │  │
│  │  │  - Kernel-space packet filtering                                 │  │  │
│  │  │  - Compile BPF instructions from filter expression               │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                     Linux Kernel Interface                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │  │
│  │  │ AF_PACKET    │  │ TPACKET_V2   │  │  PACKET_MMAP                 │ │  │
│  │  │ Socket       │  │ Ring Buffer  │  │  (4MB: 2 blocks x 2MB)       │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3.3 Core Component Definitions

> **Note**: The following are definitions from the actual implementation code. The earlier design version (based on start/recv/send/stop API)
> has been replaced with a send_packet/send_batch/recv_stream-based API.

#### PacketEngine Trait (Actual Implementation)

Defined in `crates/rustnmap-core/src/session.rs`:

```rust
/// Packet engine abstraction (supports dependency injection)
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// Send a single packet
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize>;

    /// Send packets in batch (default: send individually)
    async fn send_batch(&self, pkts: &[PacketBuffer]) -> Result<usize>;

    /// Receive packet stream
    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>>;

    /// Set BPF filter
    fn set_bpf(&self, filter: &BpfProg) -> Result<()>;

    /// Get local MAC address
    fn local_mac(&self) -> Option<MacAddr>;

    /// Get interface index
    fn if_index(&self) -> libc::c_uint;
}
```

Additionally, the lower-level PacketEngine trait in `crates/rustnmap-packet/src/engine.rs` provides
a more hardware-close API (start/recv/send/stop/set_filter/flush/stats), implemented by MmapPacketEngine
and RecvfromPacketEngine. The `DefaultPacketEngine` in `session.rs` bridges the two layers.

#### MmapPacketEngine Implementation

```rust
use std::ptr::NonNull;
use libc::{mmap, munmap, PROT_READ, PROT_WRITE, MAP_SHARED};

/// TPACKET_V2 ring buffer configuration
#[derive(Debug, Clone)]
pub struct RingConfig {
    /// Number of blocks (recommended: 2)
    pub block_count: u32,
    /// Block size (recommended: 2MB = 2097152)
    pub block_size: u32,
    /// Frame size (recommended: TPACKET_ALIGNMENT = 512)
    pub frame_size: u32,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_count: 2,
            block_size: 2_097_152,  // 2MB per block
            frame_size: 512,         // TPACKET_ALIGNMENT
        }
    }
}

/// TPACKET_V2 header structure (32 bytes)
/// Reference: /usr/include/linux/if_packet.h:146-157
/// CRITICAL: tp_padding is [u8; 4], NOT [u8; 8]
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,      // Frame status (TP_STATUS_*)
    pub tp_len: u32,         // Packet length
    pub tp_snaplen: u32,     // Capture length
    pub tp_mac: u16,         // MAC header offset
    pub tp_net: u16,         // Network header offset
    pub tp_sec: u32,         // Timestamp (seconds)
    pub tp_nsec: u32,        // Timestamp (nanoseconds) - NOT tp_usec!
    pub tp_vlan_tci: u16,    // VLAN TCI
    pub tp_vlan_tpid: u16,   // VLAN TPID
    pub tp_padding: [u8; 4], // Padding - NOT [u8; 8]!
}

/// PACKET_MMAP V2 engine implementation
pub struct MmapPacketEngine {
    /// Raw socket file descriptor
    fd: i32,
    /// Ring buffer configuration
    config: RingConfig,
    /// mmap memory region pointer
    ring_ptr: NonNull<u8>,
    /// Ring buffer total size
    ring_size: usize,
    /// Current block index
    current_block: u32,
    /// Current frame index
    current_frame: u32,
    /// Interface index
    if_index: u32,
    /// Statistics
    stats: EngineStats,
}

impl MmapPacketEngine {
    /// Create a new PACKET_MMAP engine
    pub fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        // 1. Create AF_PACKET socket
        // 2. Set TPACKET_V2 version
        // 3. Configure ring buffer
        // 4. mmap memory mapping
        // 5. Bind to network interface
        // ...
    }

    /// Get current frame pointer
    fn current_frame_ptr(&self) -> *mut Tpacket2Hdr {
        // Calculate the position of the current frame in the ring buffer
        let block_offset = self.current_block as usize * self.config.block_size as usize;
        let frame_offset = self.current_frame as usize * self.config.frame_size as usize;
        unsafe {
            self.ring_ptr.as_ptr().add(block_offset + frame_offset)
                as *mut Tpacket2Hdr
        }
    }

    /// Wait for frame to become available
    fn wait_for_frame(&self, hdr: &Tpacket2Hdr) -> Result<(), PacketError> {
        // CRITICAL: Use Acquire semantics to ensure data visibility
        // From nmap research: __ATOMIC_ACQUIRE
        use std::sync::atomic::{AtomicU32, Ordering};
        loop {
            let status = unsafe {
                AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
                    .load(Ordering::Acquire)
            };
            if status & TP_STATUS_USER != 0 {
                return Ok(());
            }
            // Briefly yield CPU
            std::hint::spin_loop();
        }
    }

    /// Release frame back to kernel
    fn release_frame(&self, hdr: &mut Tpacket2Hdr) {
        // CRITICAL: Use Release semantics to ensure prior reads complete
        // From nmap research: __ATOMIC_RELEASE
        use std::sync::atomic::{AtomicU32, Ordering};
        unsafe {
            AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
                .store(TP_STATUS_KERNEL, Ordering::Release);
        }
    }
}

impl Drop for MmapPacketEngine {
    fn drop(&mut self) {
        // Clean up mmap memory
        if !self.ring_ptr.is_null() {
            unsafe {
                munmap(self.ring_ptr.as_ptr() as *mut _, self.ring_size);
            }
        }
        // Close socket
        if self.fd >= 0 {
            unsafe { libc::close(self.fd); }
        }
    }
}
```

#### AsyncPacketEngine Wrapper

```rust
use tokio::io::{AsyncFd, AsyncFdReadyGuard, Interest};
use tokio::sync::mpsc::{channel, Sender, Receiver};
use std::os::unix::io::OwnedFd;

/// Async packet engine (Tokio integration)
pub struct AsyncPacketEngine {
    /// Underlying MMAP engine
    engine: MmapPacketEngine,
    /// AsyncFd for non-blocking notification (wrapped in Arc for sharing)
    /// CRITICAL: AsyncFd<T> is not Clone, must be wrapped with Arc
    async_fd: std::sync::Arc<AsyncFd<OwnedFd>>,
    /// Packet send channel
    packet_tx: Sender<PacketBuffer>,
    /// Packet receive channel
    packet_rx: Receiver<PacketBuffer>,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl AsyncPacketEngine {
    /// Create async engine
    pub async fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        let engine = MmapPacketEngine::new(interface, config)?;

        // CRITICAL: Cannot use File::from_raw_fd(engine.fd)
        // because engine still owns the fd, which would cause a double-close
        // Correct approach: use libc::dup() to duplicate the fd, then wrap as OwnedFd
        let async_fd = unsafe {
            // Duplicate fd to avoid ownership issues
            let dup_fd = libc::dup(engine.fd);
            if dup_fd < 0 {
                return Err(PacketError::FdDupFailed);
            }
            // OwnedFd will automatically close the fd on drop
            let owned_fd = OwnedFd::from_raw_fd(dup_fd);
            AsyncFd::new(owned_fd)?
        };

        let (packet_tx, packet_rx) = channel(1024);

        Ok(Self {
            engine,
            async_fd: std::sync::Arc::new(async_fd),
            packet_tx,
            packet_rx,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start async receive loop
    pub async fn start(&mut self) -> Result<(), PacketError> {
        self.running.store(true, Ordering::Release);
        self.engine.start()?;

        // Start background receive task
        let running = self.running.clone();

        // CRITICAL: Cannot pass &mut self.engine raw pointer into async block
        // Correct approach: use Arc<Mutex<>> or move engine into task
        let engine = std::sync::Arc::new(tokio::sync::Mutex::new(
            std::mem::replace(&mut self.engine, MmapPacketEngine::placeholder())
        ));
        // CRITICAL: AsyncFd is not Clone, must use Arc for sharing
        let async_fd = self.async_fd.clone();  // Arc::clone()
        let packet_tx = self.packet_tx.clone();

        tokio::spawn(async move {
            while running.load(Ordering::Acquire) {
                // Wait for socket to be readable
                let mut ready_guard = match async_fd.readable().await {
                    Ok(guard) => guard,
                    Err(_) => break,
                };

                // Batch read packets
                let mut engine_guard = engine.lock().await;
                while let Some(packet) = engine_guard.try_recv().unwrap_or(None) {
                    if packet_tx.send(packet).await.is_err() {
                        break;
                    }
                }
                drop(engine_guard);

                ready_guard.clear_ready_matching(Interest::READABLE);
            }
        });

        Ok(())
    }

    /// Async receive packet
    pub async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError> {
        self.packet_rx.recv().await.ok_or(PacketError::ChannelClosed)
    }
}
```

#### PacketStream Implementation (impl Stream)

**Recommended pattern: Use ReceiverStream to avoid busy-spin**

```rust
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::wrappers::ReceiverStream;

/// Packet stream (channel-based, avoids busy-spin)
///
/// CRITICAL: Do not unconditionally wake_by_ref() in poll_next
/// This causes high-frequency CPU self-wakeup (busy-spin)
/// Correct approach: Use channel readiness-driven wakeup
pub struct PacketStream {
    /// Use ReceiverStream to wrap channel receiver
    /// When channel is empty, Stream correctly returns Pending instead of self-waking
    inner: ReceiverStream<Result<PacketBuffer, PacketError>>,
}

impl Stream for PacketStream {
    type Item = Result<PacketBuffer, PacketError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Delegate to ReceiverStream, which has correct readiness semantics
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl AsyncPacketEngine {
    /// Convert to Stream
    ///
    /// Use channel as backpressure mechanism to avoid busy-spin
    #[must_use]
    pub fn into_stream(self) -> PacketStream {
        // Get the internal packet_rx channel receiver
        // Note: This requires AsyncPacketEngine to expose a getter for packet_rx
        // Or use split() pattern to separate sender/receiver
        let packet_rx = self.packet_rx;
        PacketStream {
            inner: ReceiverStream::new(packet_rx),
        }
    }
}
```

**Cargo.toml dependencies:**
```toml
[dependencies]
futures = "0.3"       # REQUIRED: for Stream trait
tokio-stream = "0.1"  # REQUIRED: for ReceiverStream
```

#### Drop Implementation Safety Order (CRITICAL)

**MUST munmap BEFORE close fd - wrong order causes resource leaks**

```rust
impl Drop for MmapPacketEngine {
    fn drop(&mut self) {
        // 1. First unmap mmap
        // SAFETY: ring_ptr and ring_size are in valid state
        if !self.ring_ptr.is_null() {
            unsafe {
                // MUST come first - kernel expects mmap to be released before socket
                libc::munmap(self.ring_ptr.as_ptr() as *mut _, self.ring_size);
            }
            self.ring_ptr = NonNull::dangling(); // Prevent double-free
        }

        // 2. Then close socket
        // SAFETY: fd is valid and owned
        if self.fd >= 0 {
            unsafe {
                // MUST come second - after munmap
                libc::close(self.fd);
            }
            self.fd = -1; // Prevent double-close
        }
    }
}
```

**Consequences of wrong order:**
- Calling `close()` before `munmap()` causes `EBADF` errors
- The kernel may access a closed fd during munmap
- May cause memory leaks or undefined behavior

### 2.3.4 Network Volatility Handling Architecture

Based on research of nmap's `timing.cc` and `scan_engine.cc`, implements a complete network volatility handling mechanism:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Network Volatility Handling Architecture                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        AdaptiveTiming (RFC 6298)                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  SRTT = (7/8) * SRTT + (1/8) * RTT                              │  │  │
│  │  │  RTTVAR = (3/4) * RTTVAR + (1/4) * |RTT - SRTT|                 │  │  │
│  │  │  Timeout = SRTT + 4 * RTTVAR                                    │  │  │
│  │  │  Timeout = clamp(Timeout, min_rtt, max_rtt)                     │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    CongestionController (TCP-like)                     │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ cwnd (congestion  │  │ ssthresh          │  │ Phase Detection      │ │  │
│  │  │  window)          │  │  (threshold)      │  │ - Slow Start         │ │  │
│  │  │                  │  │                  │  │ - Congestion Avoid   │ │  │
│  │  │ Initial: 1       │  │ Initial: infinity │  │ - Recovery           │ │  │
│  │  │ Min: 1           │  │ On drop: cwnd/2  │  │                      │ │  │
│  │  │ Max: max_cwnd    │  │                  │  │                      │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ScanDelayBoost (Dynamic Delay)                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  On high drop rate:                                              │  │  │
│  │  │    if timing_level < 4: delay = min(10000, max(1000, delay*10)) │  │  │
│  │  │    else: delay = min(1000, max(100, delay*2))                   │  │  │
│  │  │                                                                  │  │  │
│  │  │  Decay after good responses:                                     │  │  │
│  │  │    if good_responses > threshold: delay = max(default, delay/2) │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      RateLimiter (Token Bucket)                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  --min-rate: guarantee minimum packet sending rate               │  │  │
│  │  │  --max-rate: limit maximum packet sending rate                   │  │  │
│  │  │  Tokens replenish at rate R per second                           │  │  │
│  │  │  Burst size = min_rate * burst_factor                            │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ErrorRecovery (ICMP Classification)               │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ HOST_UNREACH     │  │ NET_UNREACH      │  │ PORT_UNREACH (UDP)   │ │  │
│  │  │ -> Mark Down     │  │ -> Reduce cwnd   │  │ -> Mark Closed       │ │  │
│  │  │                  │  │ -> Boost delay   │  │                      │ │  │
│  │  ├──────────────────┤  ├──────────────────┤  ├──────────────────────┤ │  │
│  │  │ ADMIN_PROHIBITED │  │ FRAG_NEEDED      │  │ TIMEOUT              │ │  │
│  │  │ -> Mark Filtered │  │ -> Set DF=0      │  │ -> Retry w/ backoff  │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3.5 Timing Template Parameter Comparison Table

| Parameter | T0 Paranoid | T1 Sneaky | T2 Polite | T3 Normal | T4 Aggressive | T5 Insane |
|-----------|-------------|-----------|-----------|-----------|---------------|-----------|
| `min_rtt_timeout` | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| `max_rtt_timeout` | 10s | 10s | 10s | 10s | 10s | 300ms |
| `initial_rtt` | 1s | 1s | 1s | 1s | 500ms | 250ms |
| `max_retries` | 10 | 10 | 10 | 10 | 6 | 2 |
| `scan_delay` | 5min | 15s | 400ms | 0ms | 0ms | 0ms |
| `max_parallelism` | 1 | 1 | 1 | dynamic | dynamic | dynamic |
| `min_host_group` | 1 | 1 | 1 | 1 | 1 | 1 |
| `max_host_group` | 1 | 1 | 1 | 100 | 100 | 256 |
| `min_rate` | 0 | 0 | 0 | 0 | 0 | 0 |
| `max_rate` | 0 | 0 | 0 | 0 | 0 | 0 |
| `cwnd_initial` | 1 | 1 | 1 | 1 | 1 | 1 |
| `cwnd_max` | 10 | 10 | 10 | dynamic | dynamic | dynamic |


### 2.3.6 File Structure Plan

```
crates/rustnmap-packet/src/
├── lib.rs              # Public API exports
├── engine.rs           # PacketEngine trait definition
├── mmap.rs             # MmapPacketEngine implementation
│   ├── RingBuffer      # Ring buffer management
│   ├── BlockManager    # TPACKET_V2 block management
│   └── FrameIterator   # Zero-copy frame iterator
├── async_engine.rs     # AsyncPacketEngine (Tokio integration)
│   ├── AsyncFd wrapper
│   └── Channel dispatch
├── bpf.rs              # BPF filter
│   ├── BpfFilter       # Filter structure
│   ├── compile()       # Compile expression
│   └── attach()        # Attach to socket
├── stream.rs           # PacketStream (impl Stream)
├── stats.rs            # EngineStats statistics
├── error.rs            # PacketError error type
└── sys/
    ├── mod.rs          # Linux syscall wrappers
    ├── tpacket.rs      # TPACKET_V2 constants and structures
    └── if_packet.rs    # AF_PACKET constants
```

---

## 2.4 Core Abstraction: ScanSession

Based on the Deepseek design document, all functional modules interact through the `ScanSession` context, enabling dependency injection, mock testing, and session recovery.

### 2.3.1 ScanSession trait Definition

```rust
use std::sync::Arc;
use crate::common::{IpAddr, MacAddr, Target, PortState};
use crate::output::OutputSink;
use crate::fingerprint::FingerprintDatabase;
use crate::nse::ScriptRegistry;

/// Scan session context (core abstraction)
pub struct ScanSession {
    /// Scan configuration
    pub config: ScanConfig,
    /// Target set (thread-safe)
    pub target_set: Arc<TargetSet>,
    /// Packet engine (trait-based, injectable MockEngine)
    pub packet_engine: Arc<dyn PacketEngine>,
    /// Output sink (trait-based)
    pub output_sink: Arc<dyn OutputSink>,
    /// Fingerprint database (thread-safe)
    pub fingerprint_db: Arc<FingerprintDatabase>,
    /// NSE script registry (thread-safe)
    pub nse_registry: Arc<ScriptRegistry>,
    /// Scan statistics (thread-safe)
    pub stats: Arc<ScanStats>,
    /// Session recovery store (optional)
    pub resume_store: Option<Arc<ResumeStore>>,
}

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Timing template (T0-T5)
    pub timing_template: TimingTemplate,
    /// Scan types (SYN/CONNECT/UDP etc.)
    pub scan_types: Vec<ScanType>,
    /// Port range
    pub port_spec: PortSpec,
    /// Concurrent hosts
    pub min_parallel_hosts: usize,
    pub max_parallel_hosts: usize,
    /// Concurrent ports
    pub min_parallel_ports: usize,
    pub max_parallel_ports: usize,
    /// Rate limit (PPS)
    pub min_rate: Option<u64>,
    pub max_rate: Option<u64>,
    /// Host group size
    pub host_group_size: usize,
}

/// Scan statistics (thread-safe)
pub struct ScanStats {
    /// Completed hosts count
    pub hosts_completed: AtomicUsize,
    /// Total discovered open ports
    pub open_ports: AtomicUsize,
    /// Total sent packets
    pub packets_sent: AtomicU64,
    /// Total received packets
    pub packets_recv: AtomicU64,
    /// Start time
    pub start_time: std::time::Instant,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            hosts_completed: AtomicUsize::new(0),
            open_ports: AtomicUsize::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    /// Record completed host (using Relaxed memory ordering)
    #[inline]
    pub fn mark_host_complete(&self) {
        self.hosts_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get PPS (packets per second)
    pub fn pps(&self) -> u64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packets_sent.load(Ordering::Relaxed) as u64 / elapsed as u64
        } else {
            0
        }
    }
}
```

### 2.3.2 PacketEngine trait (Testable Abstraction)

```rust
/// Packet engine abstraction (supports dependency injection)
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// Send a single packet
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize, PacketError>;

    /// Send packets in batch (using sendmmsg)
    async fn send_batch(&self, pkts: &[PacketBuffer]) -> Result<usize, PacketError>;

    /// Receive packet stream
    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>>;

    /// Set BPF filter
    fn set_bpf(&self, filter: &BpfProg) -> Result<(), PacketError>;

    /// Get local MAC address
    fn local_mac(&self) -> Option<MacAddr>;

    /// Get interface index
    fn if_index(&self) -> libc::c_uint;
}

/// Packet buffer
pub struct PacketBuffer {
    /// Data (using Bytes for zero-copy)
    pub data: bytes::Bytes,
    /// Length
    pub len: usize,
    /// Timestamp
    pub timestamp: std::time::Duration,
    /// Protocol
    pub protocol: u16,
}

/// BPF filter program
#[repr(C)]
pub struct BpfProg {
    pub bf_len: libc::c_ushort,
    pub bf_insns: *const libc::sock_bpf,
}

unsafe impl Send for BpfProg {}
unsafe impl Sync for BpfProg {}
```

### 2.3.3 Dependency Injection Pattern (Testability)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Mock packet engine (for unit tests, no root required)
    struct MockPacketEngine {
        send_tx: mpsc::Sender<PacketBuffer>,
        recv_rx: mpsc::Receiver<PacketBuffer>,
    }

    #[async_trait]
    impl PacketEngine for MockPacketEngine {
        async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize, PacketError> {
            self.send_tx.send(pkt).await.unwrap();
            Ok(pkt.len)
        }

        fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>> {
            Box::pin(futures::stream::unfold(
                self.recv_rx.clone(),
                |rx| async move {
                    rx.recv().await.map(|pkt| (pkt, rx))
                }
            ))
        }

        fn set_bpf(&self, _filter: &BpfProg) -> Result<(), PacketError> {
            Ok(())
        }

        fn local_mac(&self) -> Option<MacAddr> {
            Some(MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
        }

        fn if_index(&self) -> libc::c_uint {
            1
        }
    }

    /// Unit test: no root privileges required
    #[tokio::test]
    async fn test_scan_with_mock_engine() {
        let (tx, rx) = mpsc::channel(100);
        let mock = Arc::new(MockPacketEngine {
            send_tx: tx,
            recv_rx: rx,
        });

        let session = ScanSession {
            config: ScanConfig::default(),
            target_set: Arc::new(TargetSet::new()),
            packet_engine: mock.clone(),
            output_sink: Arc::new(MockOutputSink::new()),
            fingerprint_db: Arc::new(FingerprintDatabase::mock()),
            nse_registry: Arc::new(ScriptRegistry::empty()),
            stats: Arc::new(ScanStats::new()),
            resume_store: None,
        };

        // Test scan logic...
    }
}

---

## 2.5 Localhost Scanning Limitations and Design Decisions

> **Status**: Known architectural limitation | **Priority**: P0
> **Analysis date**: 2026-03-08 | **Related documentation**: `doc/modules/localhost-scanning.md`

### 2.5.1 Problem Description

When scanning `127.0.0.1` (localhost), SYN scan cannot correctly identify port status; all ports show as `filtered`.

**Test result comparison**:
```bash
$ nmap -sS -p 22 127.0.0.1
PORT   STATE SERVICE
22/tcp open   ssh

$ rustnmap --scan-syn -p 22 127.0.0.1
PORT     STATE SERVICE
22/tcp  filtered ssh
```

### 2.5.2 Root Cause

#### Core Problem: Asymmetric Response Routing

```
Send path:
  RustNmap (192.168.15.237) -> SYN -> 127.0.0.1:22
  |
Response path:
  127.0.0.1:22 -> SYN-ACK -> 192.168.15.237 (external IP)
  |
Routing decision:
  Response to 192.168.15.237 is routed through ens33 interface
  RustNmap's PACKET_MMAP is bound to lo interface -> never sees the response
```

**tcpdump evidence**:
```
192.168.15.237 > 127.0.0.1.22: Flags [S]     # Our SYN
127.0.0.1.22 > 192.168.15.237: Flags [S.]   # SYN-ACK (note destination)
```

#### Technical Details

| Component | Current Behavior | Problem |
|-----------|-----------------|---------|
| `RawSocket` | Bound to system default address | Source address set by kernel to 192.168.15.237 |
| PACKET_MMAP | Bound to lo interface | Can only see traffic on lo |
| Routing table | 127.0.0.1 -> lo | 192.168.15.237 -> ens33 |
| Response destination | 192.168.15.237 | Not on lo interface |

### 2.5.3 Design Decision

#### Decision: Create Dedicated RawSocket for Localhost

**Approach**: Modify `TcpSynScanner` architecture to create a dedicated `RawSocket` for localhost targets, bound to `127.0.0.1`.

**Rationale**:
1. **Functional completeness**: SYN scan should work for all address types
2. **Nmap compliance**: nmap supports localhost SYN scanning on Linux
3. **Technical correctness**: The proper solution is to fix the root cause

**Architectural impact**:

```rust
pub struct TcpSynScanner {
    // Main scan socket (for remote targets)
    socket: RawSocket,

    // Localhost-specific socket (bound to 127.0.0.1)
    localhost_socket: Option<RawSocket>,

    // Configuration
    local_addr: Ipv4Addr,
    config: ScanConfig,
}

impl TcpSynScanner {
    fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // Select the correct socket based on target address
        let socket = if dst_addr.is_loopback() {
            self.localhost_socket.as_ref().unwrap_or(&self.socket)
        } else {
            &self.socket
        };

        // Send packet using the selected socket
        socket.send_packet(&packet, &dst_sockaddr)?;
        // ...
    }
}
```

### 2.5.4 Implementation Plan

#### Phase 1: Extend RawSocket API

**File**: `crates/rustnmap-net/src/lib.rs`

Add a `bind()` method:

```rust
impl RawSocket {
    /// Bind raw socket to a specific source address
    ///
    /// # Arguments
    /// * `src_addr` - Optional source address
    ///
    /// # Errors
    /// Returns an error if:
    /// - Socket is already bound
    /// - Invalid address
    /// - Permission denied
    pub fn bind(&self, src_addr: Option<Ipv4Addr>) -> io::Result<()> {
        // Implement bind() logic
    }
}
```

#### Phase 2: Modify TcpSynScanner

**File**: `crates/rustnmap-scan/src/syn_scan.rs`

1. Add `localhost_socket` field
2. Create and bind localhost socket in constructor
3. Select socket based on target in `send_syn_probe()`

#### Phase 3: Verification Tests

| Test Case | Expected Result |
|-----------|----------------|
| Single port localhost | Port status correct |
| Multi-port localhost | Mixed status correct |
| Mixed targets (localhost + remote) | Both correct |
| Comparison with nmap | Results consistent |

### 2.5.5 Technical Constraints

#### PACKET_MMAP Limitations

| Scenario | PACKET_MMAP | Reason |
|----------|------------|--------|
| Remote IP scanning | Supported | Symmetric routing |
| Localhost scanning | Limited | Responses routed to external interface |

#### Reference Implementation

**nmap source**: `reference/nmap/libnetutil/netutil.cc:1916-1946`
```c
int islocalhost(const struct sockaddr_storage *ss) {
    // Check 127.x.x.x
    if ((sin->sin_addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
        return 1;

    // Check local interface addresses
    if (ipaddr2devname(dev, ss) != -1)
        return 1;

    return 0;
}
```

**nmap Windows handling**: `reference/nmap/scan_engine.cc:2735-2739`
```c
#ifdef WIN32
  if (!o.have_pcap && scantype != CONNECT_SCAN &&
      Targets[0]->ifType() == devt_loopback) {
    // Windows does not support raw scanning of localhost, skip
    return;
  }
#endif
```

### 2.5.6 Alternative Approach (Fallback)

If the implementation complexity is too high, consider a fallback approach:

**Approach**: When localhost targets are detected, automatically switch to Connect scan

**Location**: `crates/rustnmap-core/src/orchestrator.rs`

```rust
// Scanner selection logic
if targets.iter().any(|t| t.is_loopback()) && scantype == ScanType::Syn {
    log_warning("SYN scan on localhost not fully supported, using Connect scan");
    return TcpConnectScanner::new(config)?;
}
```

**Drawback**: Loses the stealth advantage of SYN scanning

---

## 2.6 Architecture Update History

| Date | Change | Impact |
|------|--------|--------|
| 2026-04-12 | Design document proofreading: updated dependency graph, corrected PacketEngine trait, updated 2.0 crate list | Documentation aligned with implementation |
| 2026-03-08 | NSE engine changed to process isolation (ProcessExecutor + rustnmap-nse-runner) | Replaced original NseSandbox design |
| 2026-03-08 | Added localhost scanning limitation section | New known limitation documentation |
| 2026-03-07 | Completed PACKET_MMAP V2 implementation | Phase 5 complete |
| 2026-03-07 | Fixed T5 multi-port scan congestion control | 94.9% accuracy |
| 2026-02-17 | Initial architecture design | 1.0 baseline |
```

---
