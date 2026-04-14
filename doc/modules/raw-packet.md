## 3.10 Raw Packet Engine

Corresponding Nmap low-level: `libpcap`, `libdnet`, `raw sockets`

### 3.10.1 Linux x86_64 Network Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Raw Packet Engine Architecture (Linux x86_64)             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    Application Layer                               │  │
│  │         (Port Scanner, OS Detection, Service Probe)               │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │                                  │
│  ┌───────────────────────────────────▼───────────────────────────────┐  │
│  │                    Packet Builder Layer                            │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  PacketBuilder                                              │  │  │
│  │  │  ├── build_tcp_syn(ip, port, flags, options) -> Vec<u8>    │  │  │
│  │  │  ├── build_tcp_ack(ip, port, seq, ack) -> Vec<u8>          │  │  │
│  │  │  ├── build_udp(ip, port, payload) -> Vec<u8>               │  │  │
│  │  │  ├── build_icmp_echo(id, seq, data) -> Vec<u8>             │  │  │
│  │  │  ├── build_arp_request(src_mac, src_ip, target_ip)         │  │  │
│  │  │  └── calculate_checksums(pkt)                              │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │                                  │
│  ┌───────────────────────────────────▼───────────────────────────────┐  │
│  │                    Transport Layer Abstraction                     │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  trait Transport {                                          │  │  │
│  │  │      fn send_packet(&self, pkt: &[u8]) -> Result<()>;      │  │  │
│  │  │      fn recv_packet(&self, timeout: Duration)              │  │  │
│  │  │                   -> Result<Option<RawPacket>>;            │  │  │
│  │  │      fn set_promiscuous(&self, enable: bool);              │  │  │
│  │  │      fn set_filter(&self, filter: &str); // BPF filter     │  │  │
│  │  │  }                                                         │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │                                  │
│  ┌───────────────────────────────────▼───────────────────────────────┐  │
│  │                    Linux Platform Implementation (x86_64)          │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Linux Socket Options (sys/socket.h)                        │  │  │
│  │  │  ├── AF_PACKET (Layer 2 access)                             │  │  │
│  │  │  ├── SOCK_RAW (Raw IP packets)                              │  │  │
│  │  │  ├── SOCK_DGRAM (Cooked packets with link-level headers)    │  │  │
│  │  │  ├── IPPROTO_RAW (Raw IP protocol)                          │  │  │
│  │  │  └── packet_mreq (Promiscuous mode)                         │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Linux-Specific Performance Features                         │  │  │
│  │  │  ├── PACKET_MMAP (Zero-copy packet capture, kernel 2.6+)    │  │  │
│  │  │  ├── PACKET_TX_RING (Zero-copy transmit)                    │  │  │
│  │  │  ├── SO_ATTACH_FILTER (Kernel-space BPF filtering)          │  │  │
│  │  │  ├── SO_ATTACH_BPF (eBPF filtering, kernel 4.1+)           │  │  │
│  │  │  ├── SO_TIMESTAMPING (Hardware timestamps)                  │  │  │
│  │  │  ├── AF_XDP (High-performance XDP, kernel 4.18+)            │  │  │
│  │  │  ├── IOV_MAX (Maximum scatter-gather I/O vectors)           │  │  │
│  │  │  └── MSG_ZEROCOPY (Zero-copy send, kernel 4.14+)           │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  Crate Dependencies (Linux x86_64):                                 │  │
│  │  ├── pnet (platform independent packet manipulation)             │  │
│  │  ├── socket2 (socket configuration with Linux-specific options)  │  │
│  │  ├── pcap (libpcap wrapper for backward compatibility)           │  │
│  │  ├── libc (low-level system calls and constants)                 │  │
│  │  ├── nix (Linux-specific socket/ioctl helpers)                   │  │
│  │  ├── tokio::net::UnixSocket (Async socket support)               │  │
│  │  └── redbpf (eBPF programs support, optional)                    │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Linux Capabilities (replacing root privileges):                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── CAP_NET_RAW    - Use raw sockets and packet sockets          │  │
│  │  ├── CAP_NET_ADMIN  - Configure network interfaces and firewall rules │  │
│  │  ├── CAP_IPC_LOCK   - Lock memory (required for PACKET_MMAP)     │  │
│  │  └── Setup command: sudo setcap cap_net_raw,cap_net_admin+ep <binary> │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.10.2 Linux Capabilities Configuration Details

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Linux Capabilities Configuration (x86_64)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Privilege Management Comparison:                                       │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  Option A: Run as Root (Traditional)                              │  │
│  │  ├── Pros: Simple and direct, no additional configuration needed  │  │
│  │  └── Cons: High security risk, violates principle of least privilege │  │
│  │                                                                   │  │
│  │  Option B: Linux Capabilities (Recommended)                       │  │
│  │  ├── Pros: Fine-grained privilege control, reduced security risk  │  │
│  │  ├── Required Capabilities:                                       │  │
│  │  │   ├── CAP_NET_RAW    - Create raw sockets                     │  │
│  │  │   ├── CAP_NET_ADMIN  - Set promiscuous mode, modify routing tables │  │
│  │  │   └── CAP_IPC_LOCK   - Use mlock to lock memory (PACKET_MMAP) │  │
│  │  └── Setup method:                                                │  │
│  │      $ sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/rustnmap│  │
│  │                                                                   │  │
│  │  Option C: sudo Configuration (Passwordless Execution)            │  │
│  │  ├── Add to /etc/sudoers.d/rustnmap:                              │  │
│  │  │   username ALL=(ALL) NOPASSWD: /usr/bin/rustnmap             │  │
│  │  └── Pros: Convenient for multi-user environment management       │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Kernel Version Compatibility:                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Feature                │ Min Kernel │ Notes                     │  │
│  │  ├───────────────────────┼────────────┼─────────────────────────│  │
│  │  AF_PACKET              │ 2.2        │ Basic support              │  │
│  │  PACKET_MMAP            │ 2.6.22     │ Zero-copy receive          │  │
│  │  PACKET_TX_RING         │ 2.6.31     │ Zero-copy transmit         │  │
│  │  SO_ATTACH_BPF          │ 3.18       │ eBPF filter                │  │
│  │  AF_XDP                 │ 4.18       │ XDP high-performance mode  │  │
│  │  MSG_ZEROCOPY           │ 4.14       │ Zero-copy transmit         │  │
│  │  SO_TIMESTAMPING        │ 2.6.30     │ Hardware timestamps        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Performance Optimization Tips (x86_64):                                │
│  ├── Use PACKET_MMAP for zero-copy packet capture                       │  │
│  ├── Enable CPU affinity binding (taskset)                              │  │
│  ├── Set up huge pages (hugetlbfs) for DMA buffers                      │  │
│  └── Consider DPDK or AF_XDP for line-rate processing                  │  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.10.3 Packet Structure Definitions

```
// ============================================
// Packet Engine Types
// ============================================

use pnet::packet::{
    ethernet::EthernetPacket,
    ip::IpNextHeaderProtocol,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    icmp::IcmpPacket,
    arp::ArpPacket,
};

/// Raw packet wrapper
pub struct RawPacket {
    pub data: Vec<u8>,
    pub timestamp: Instant,
    pub interface: String,
}

/// Packet parser
pub struct PacketParser;

impl PacketParser {
    /// Parse Ethernet frame
    pub fn parse_ethernet<'a>(&self, data: &'a [u8]) -> Option<ParsedPacket<'a>> {
        let eth = EthernetPacket::new(data)?;
        
        match eth.get_ethertype() {
            EtherType::Ipv4 => {
                let ip = Ipv4Packet::new(eth.payload())?;
                self.parse_ipv4(&ip)
            }
            EtherType::Ipv6 => {
                let ip = Ipv6Packet::new(eth.payload())?;
                self.parse_ipv6(&ip)
            }
            EtherType::Arp => {
                let arp = ArpPacket::new(eth.payload())?;
                Some(ParsedPacket::Arp(arp))
            }
            _ => None,
        }
    }
    
    /// Parse IPv4 packet
    pub fn parse_ipv4<'a>(&self, ip: &Ipv4Packet<'a>) -> Option<ParsedPacket<'a>> {
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocol::Tcp => {
                let tcp = TcpPacket::new(ip.payload())?;
                Some(ParsedPacket::TcpV4 { ip, tcp })
            }
            IpNextHeaderProtocol::Udp => {
                let udp = UdpPacket::new(ip.payload())?;
                Some(ParsedPacket::UdpV4 { ip, udp })
            }
            IpNextHeaderProtocol::Icmp => {
                let icmp = IcmpPacket::new(ip.payload())?;
                Some(ParsedPacket::IcmpV4 { ip, icmp })
            }
            _ => None,
        }
    }
}

/// Parsed packet enumeration
pub enum ParsedPacket<'a> {
    TcpV4 {
        ip: Ipv4Packet<'a>,
        tcp: TcpPacket<'a>,
    },
    TcpV6 {
        ip: Ipv6Packet<'a>,
        tcp: TcpPacket<'a>,
    },
    UdpV4 {
        ip: Ipv4Packet<'a>,
        udp: UdpPacket<'a>,
    },
    UdpV6 {
        ip: Ipv6Packet<'a>,
        udp: UdpPacket<'a>,
    },
    IcmpV4 {
        ip: Ipv4Packet<'a>,
        icmp: IcmpPacket<'a>,
    },
    IcmpV6 {
        ip: Ipv6Packet<'a>,
        icmp: IcmpPacket<'a>,
    },
    Arp(ArpPacket<'a>),
}

/// Packet builder
pub struct PacketBuilder {
    src_mac: MacAddr,
    src_ip: IpAddr,
}

impl PacketBuilder {
    /// Build TCP SYN packet
    pub fn build_tcp_syn(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_port: u16,
        seq: u32,
        options: TcpOptions,
    ) -> Result<Vec<u8>, PacketError> {
        // 1. Build TCP header
        let mut tcp_builder = TcpBuilder {
            source: src_port,
            destination: dst_port,
            sequence: seq,
            acknowledgment: 0,
            flags: TcpFlags::SYN,
            window: 65535,
            options: options.to_vec(),
            payload: vec![],
        };
        
        // 2. Build IP header
        let ip_pkt = match dst_ip {
            IpAddr::V4(dst) => {
                self.build_ipv4_packet(dst, IpNextHeaderProtocol::Tcp, &tcp_builder.build()?)?
            }
            IpAddr::V6(dst) => {
                self.build_ipv6_packet(dst, IpNextHeaderProtocol::Tcp, &tcp_builder.build()?)?
            }
        };
        
        // 3. If Layer 2 frame is needed (e.g., ARP scan)
        // self.build_ethernet_frame(&ip_pkt)?;
        
        Ok(ip_pkt)
    }
    
    /// Build ICMP Echo Request
    pub fn build_icmp_echo(
        &self,
        dst_ip: IpAddr,
        id: u16,
        seq: u16,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PacketError> {
        let icmp_builder = IcmpEchoBuilder {
            icmp_type: IcmpType::EchoRequest,
            code: 0,
            id,
            seq,
            payload,
        };
        
        match dst_ip {
            IpAddr::V4(dst) => {
                self.build_ipv4_packet(dst, IpNextHeaderProtocol::Icmp, &icmp_builder.build_v4()?)
            }
            IpAddr::V6(dst) => {
                self.build_ipv6_packet(dst, IpNextHeaderProtocol::IcmpV6, &icmp_builder.build_v6()?)
            }
        }
    }
}

/// Socket sender
pub struct PacketSender {
    socket: RawSocket,
    interface: NetworkInterface,
}

impl PacketSender {
    pub async fn send(&self, packet: &[u8], dst: IpAddr) -> Result<(), IoError> {
        match dst {
            IpAddr::V4(_) => self.socket.send_to(packet, dst),
            IpAddr::V6(_) => self.socket.send_to_v6(packet, dst),
        }
    }
}

/// Socket receiver (with BPF filtering)
pub struct PacketReceiver {
    socket: RawSocket,
    buffer: Vec<u8>,
    filter: Option<String>,  // BPF filter expression
}

impl PacketReceiver {
    /// Receive matching packets
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<RawPacket>, IoError> {
        // Use poll/select for async timeout receive
        // If filter is set, apply BPF filtering logic
        unimplemented!()
    }
}
```

---

### 3.10.4 Linux PACKET_MMAP V2 Zero-Copy Optimization

> **Architecture Decision**: Use TPACKET_V2 instead of V3. V3 has known bugs in kernels < 3.19.
>
> **nmap Version Negotiation Strategy** (see `reference/nmap/libpcap/pcap-linux.c:2974-3013`):
> - Non-immediate mode: Try TPACKET_V3 first, fall back to TPACKET_V2 on failure
> - Immediate mode (common for scanners): Use TPACKET_V2 directly
>
> **RustNmap Decision**: Use V2 directly, because scanners typically require immediate mode (low-latency response).

Based on the nmap reference implementation and Linux kernel features, PACKET_MMAP V2 is used for zero-copy packet processing.

#### PACKET_MMAP V2 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zero-Copy Packet Path (Linux)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Application Space                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                    AfPacketEngine                               │  │
│  │  ┌─────────────────┐          ┌─────────────────────────────┐│  │
│  │  │   RX Ring       │          │    TX Ring                ││  │
│  │  │   (recv)        │          │    (send)                 ││  │
│  │  │   mmap area     │          │    mmap area              ││  │
│  │  └────────┬────────┘          └──────────┬──────────────┘│  │
│  └────────────┼───────────────────────────────┼───────────────────┘  │
│               │                            │                          │
│  ─────────────┼───────────────────────────────┼──────────────────────  │
│               │                            │                          │
│  ┌───────────▼────────────────────────────▼───────────────────────┐  │
│  │                    Kernel Space (tpacket_v2)                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Data Structure Definitions

```rust
use std::mem::size_of_val;
use libc::{c_uint, c_int, sockaddr_ll, timeval};

/// PACKET_MMAP V2 ring buffer configuration
/// Note: V2 uses tpacket_req (not V3's tpacket_req3)
#[derive(Debug, Clone)]
pub struct RingConfig {
    /// Block size (recommended: 2MB = 2_097_152, must be a multiple of page size)
    pub block_size: usize,
    /// Number of blocks (recommended: 2, minimum configuration)
    pub block_nr: usize,
    /// Frame size (recommended: multiple of TPACKET_ALIGNMENT = 16, typically 2048)
    pub frame_size: usize,
    /// Number of frames = (block_size * block_nr) / frame_size
    pub frame_nr: usize,
}

impl Default for RingConfig {
    fn default() -> Self {
        // High-performance defaults based on nmap
        Self {
            block_size: 2_097_152,   // 2MB per block
            block_nr: 2,              // 4MB total (nmap default)
            frame_size: 2048,         // Standard MTU 1500 + headers
            frame_nr: 0,              // Calculated
        }
    }
}

impl RingConfig {
    /// Calculate derived values (based on nmap pcap-linux.c)
    pub fn derive_frame_nr(&mut self) {
        self.frame_nr = (self.block_size * self.block_nr) / self.frame_size;
    }

    /// Total buffer size
    pub fn total_size(&self) -> usize {
        self.block_size * self.block_nr
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), PacketError> {
        if self.block_size % 4096 != 0 {
            return Err(PacketError::InvalidConfig("block_size must be page-aligned".into()));
        }
        if self.frame_size % 16 != 0 {
            return Err(PacketError::InvalidConfig("frame_size must be TPACKET_ALIGNMENT aligned".into()));
        }
        Ok(())
    }
}

/// tpacket_req structure (corresponds to Linux kernel tpacket_req, used by V2)
/// Reference: /usr/include/linux/if_packet.h
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TPacketReq {
    pub tp_block_size: u32,   // Block size
    pub tp_block_nr: u32,     // Number of blocks
    pub tp_frame_size: u32,   // Frame size
    pub tp_frame_nr: u32,     // Number of frames
}

/// tpacket2_hdr structure (V2 frame header, 32 bytes)
/// Reference: /usr/include/linux/if_packet.h:146-157
/// CRITICAL: tp_nsec field is nanoseconds in V2, not microseconds
/// CRITICAL: tp_padding is [u8; 4], not [u8; 8]
#[repr(C)]
pub struct TPacket2Hdr {
    pub tp_status: u32,       // Frame status (TP_STATUS_*) - 4 bytes
    pub tp_len: u32,          // Packet length - 4 bytes
    pub tp_snaplen: u32,      // Capture length - 4 bytes
    pub tp_mac: u16,          // MAC header offset - 2 bytes
    pub tp_net: u16,          // Network header offset - 2 bytes
    pub tp_sec: u32,          // Timestamp (seconds) - 4 bytes
    pub tp_nsec: u32,         // Timestamp (nanoseconds) - 4 bytes - NOT tp_usec!
    pub tp_vlan_tci: u16,     // VLAN TCI - 2 bytes
    pub tp_vlan_tpid: u16,    // VLAN TPID - 2 bytes
    pub tp_padding: [u8; 4],  // Padding - 4 bytes - NOT [u8; 8]!
}  // Total: 4+4+4+2+2+4+4+2+2+4 = 32 bytes

// V2 status constants
const TP_STATUS_KERNEL: u32 = 0;     // Owned by kernel, userspace should skip
const TP_STATUS_USER: u32 = 1;       // Owned by userspace, readable
const TP_STATUS_COPY: u32 = 2;       // Currently being copied
const TP_STATUS_LOSING: u32 = 4;     // Packets are being lost

// TPACKET alignment constants
const TPACKET_ALIGNMENT: usize = 16;
const TPACKET2_HDRLEN: usize = 32;   // sizeof(tpacket2_hdr) - corrected to 32 bytes
```

#### AfPacketEngine Implementation (Zero-Copy Version)

```rust
use std::os::unix::io::AsRawFd;
use libc::{socket, AF_PACKET, SOCK_RAW, htons, ETH_P_ALL};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use memmap2::MmapMut;

/// PACKET_MMAP V2 based packet engine
/// Note: Uses V2 instead of V3, V3 has bugs on older kernels
pub struct AfPacketEngine {
    /// Socket file descriptor
    fd: std::os::unix::io::RawFd,
    /// Receive ring buffer mmap
    rx_ring: MmapMut,
    /// Transmit ring buffer mmap (optional)
    tx_ring: Option<MmapMut>,
    /// Ring buffer configuration
    config: RingConfig,
    /// Network interface index
    if_index: c_uint,
    /// Local MAC address
    mac_addr: [u8; 6],
    /// Current frame index (V2 uses frame index, not block index)
    rx_frame_idx: usize,
}

impl AfPacketEngine {
    /// Create a new PACKET_MMAP V2 engine
    /// Reference nmap: reference/nmap/libpcap/pcap-linux.c
    pub fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        // 1. Create AF_PACKET socket
        let fd = unsafe {
            socket(
                AF_PACKET,
                SOCK_RAW,
                htons(ETH_P_ALL as u16)
            )
        };
        if fd < 0 {
            return Err(PacketError::SocketCreationFailed);
        }

        // 2. Set PACKET_VERSION to TPACKET_V2
        // CRITICAL: Must be set before all TPACKET operations
        let version = libc::TPACKET_V2 as i32;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                &version as *const i32,
                std::mem::size_of_val(&version) as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd); }
            return Err(PacketError::VersionSetFailed);
        }

        // 3. Get interface index
        let if_index = Self::get_interface_index(fd, interface)?;

        // 4. Bind to interface
        let sockaddr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: htons(ETH_P_ALL as u16),
            sll_ifindex: if_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &sockaddr as *const sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of_val(&sockaddr) as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd); }
            return Err(PacketError::BindFailed);
        }

        // 5. Configure and map receive ring (using V2's tpacket_req)
        let rx_ring = Self::setup_rx_ring(fd, &config)?;

        // 6. Get local MAC address
        let mac_addr = Self::get_mac_address(fd, if_index)?;

        Ok(Self {
            fd,
            rx_ring,
            tx_ring: None,
            config,
            if_index,
            mac_addr,
            rx_frame_idx: 0,
        })
    }

    /// Set up receive ring buffer (V2 version)
    fn setup_rx_ring(
        fd: std::os::unix::io::RawFd,
        config: &RingConfig
    ) -> Result<MmapMut, PacketError> {
        // Build tpacket_req (V2 uses this structure, not tpacket_req3)
        let req = TPacketReq {
            tp_block_size: config.block_size as u32,
            tp_block_nr: config.block_nr as u32,
            tp_frame_size: config.frame_size as u32,
            tp_frame_nr: config.frame_nr as u32,
        };

        // Apply receive ring configuration
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &req as *const TPacketReq as *const libc::c_void,
                std::mem::size_of_val(&req) as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(PacketError::RxRingSetupFailed);
        }

        // Calculate mmap size and map
        let size = config.total_size();
        unsafe {
            let mmap = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if mmap == libc::MAP_FAILED {
                return Err(PacketError::MmapFailed);
            }
            Ok(MmapMut::map_raw(size, mmap as *mut u8)?)
        }
    }

    /// Read packet from receive ring (zero-copy, V2 version)
    /// Uses frame index instead of block index
    pub fn recv_packet(&mut self) -> Option<PacketBuffer> {
        let frame_size = self.config.frame_size;
        let frame_idx = self.rx_frame_idx;
        let total_frames = self.config.frame_nr;

        // Calculate current frame address
        let frame_addr = unsafe {
            self.rx_ring.as_ptr().add(frame_idx * frame_size)
                as *const TPacket2Hdr
        };

        let frame_hdr = unsafe { &*frame_addr };

        // Check frame status (using Acquire semantics to ensure data visibility)
        // Reference nmap: __atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE)
        let status = unsafe {
            std::sync::atomic::AtomicU32::from_ptr(
                std::ptr::addr_of!((*frame_addr).tp_status)
            ).load(std::sync::atomic::Ordering::Acquire)
        };

        if status & TP_STATUS_USER == 0 {
            // Frame not yet ready
            return None;
        }

        // Create zero-copy packet buffer
        let data_ptr = unsafe {
            (frame_addr as *const u8).add(std::mem::size_of::<TPacket2Hdr>())
        };
        let data_len = frame_hdr.tp_snaplen as usize;

        let packet = PacketBuffer {
            data: bytes::Bytes::from_raw_parts(
                data_ptr,
                data_len,
            ),
            len: data_len,
            timestamp: Duration::new(
                frame_hdr.tp_sec as u64,
                frame_hdr.tp_nsec as u32,  // V2 uses tp_nsec (nanoseconds)
            ),
            protocol: frame_hdr.tp_vlan_tpid,
        };

        // Release frame back to kernel (using Release semantics)
        // Reference nmap: __atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE)
        unsafe {
            std::sync::atomic::AtomicU32::from_ptr(
                std::ptr::addr_of!((*frame_addr).tp_status)
            ).store(TP_STATUS_KERNEL, std::sync::atomic::Ordering::Release);
        }

        // Move to next frame
        self.rx_frame_idx = (self.rx_frame_idx + 1) % total_frames;

        Some(packet)
    }
}

/// Zero-copy packet buffer (using Bytes reference counting)
pub struct PacketBuffer {
    pub data: bytes::Bytes,  // References mmap region, no copy
    pub len: usize,
    pub timestamp: Duration,
    pub protocol: u16,
}
```

#### Performance Optimization Highlights

1. **Memory Ordering**: Use `Ordering::Acquire/Release` for ring buffer index handling
2. **Lock-Free Queue**: Consider using lock-free MPSC queues for packet delivery
3. **Batch Sending**: Use `sendmmsg` to send multiple packets at once
4. **CPU Affinity**: Bind packet processing threads to specific CPU cores

```rust
// Batch sending (sendmmsg)
use libc::{iovec, mmsghdr, sendmmsg};

impl AfPacketEngine {
    pub fn send_batch(&self, packets: &[&[u8]]) -> Result<usize, PacketError> {
        let mut iovs: Vec<iovec> = Vec::with_capacity(packets.len());
        let mut msgs: Vec<mmsghdr> = Vec::with_capacity(packets.len());

        for pkt in packets {
            iovs.push(iovec {
                iov_base: pkt.as_ptr() as *mut libc::c_void,
                iov_len: pkt.len(),
            });
            msgs.push(mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: &iovs[iovs.len() - 1] as *const iovec as *mut iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
                ..unsafe { std::mem::zeroed() }
            });
        }

        let ret = unsafe {
            sendmmsg(
                self.fd,
                msgs.as_mut_ptr(),
                packets.len() as c_uint,
                0,
            )
        };

        if ret < 0 {
            Err(PacketError::SendFailed)
        } else {
            Ok(ret as usize)
        }
    }
}
```

---
