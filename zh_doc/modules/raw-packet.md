## 3.10 原始数据包引擎

对应 Nmap 底层: `libpcap`, `libdnet`, `raw sockets`

### 3.10.1 Linux x86_64 网络层级架构

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
│  Linux Capabilities (替代 root 权限):                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── CAP_NET_RAW    - 使用 raw socket 和 packet socket            │  │
│  │  ├── CAP_NET_ADMIN  - 配置网络接口和防火墙规则                     │  │
│  │  ├── CAP_IPC_LOCK   - 锁定内存 (PACKET_MMAP 需要)                 │  │
│  │  └── 设置命令: sudo setcap cap_net_raw,cap_net_admin+ep <binary>  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.10.2 Linux Capabilities 配置详解

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Linux Capabilities Configuration (x86_64)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  权限管理方案对比:                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  方案 A: Root 运行 (传统方式)                                      │  │
│  │  ├── 优点: 简单直接，无需额外配置                                   │  │
│  │  └── 缺点: 安全风险高，违反最小权限原则                             │  │
│  │                                                                   │  │
│  │  方案 B: Linux Capabilities (推荐)                                │  │
│  │  ├── 优点: 精细化权限控制，降低安全风险                             │  │
│  │  ├── 需要的 Capabilities:                                         │  │
│  │  │   ├── CAP_NET_RAW    - 创建 raw socket                        │  │
│  │  │   ├── CAP_NET_ADMIN  - 设置混杂模式、修改路由表                │  │
│  │  │   └── CAP_IPC_LOCK   - 使用 mlock 锁定内存 (PACKET_MMAP)      │  │
│  │  └── 设置方式:                                                    │  │
│  │      $ sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/rustnmap│  │
│  │                                                                   │  │
│  │  方案 C: sudo 配置 (无密码执行)                                    │  │
│  │  ├── 在 /etc/sudoers.d/rustnmap 添加:                            │  │
│  │  │   username ALL=(ALL) NOPASSWD: /usr/bin/rustnmap             │  │
│  │  └── 优点: 便于多用户环境管理                                      │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  内核版本兼容性:                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Feature                │ Min Kernel │ Notes                     │  │
│  │  ├───────────────────────┼────────────┼─────────────────────────│  │
│  │  AF_PACKET              │ 2.2        │ 基础支持                   │  │
│  │  PACKET_MMAP            │ 2.6.22     │ 零拷贝接收                 │  │
│  │  PACKET_TX_RING         │ 2.6.31     │ 零拷贝发送                 │  │
│  │  SO_ATTACH_BPF          │ 3.18       │ eBPF 过滤器                │  │
│  │  AF_XDP                 │ 4.18       │ XDP 高性能模式             │  │
│  │  MSG_ZEROCOPY           │ 4.14       │ 零拷贝发送                 │  │
│  │  SO_TIMESTAMPING        │ 2.6.30     │ 硬件时间戳                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  性能优化建议 (x86_64):                                                  │
│  ├── 使用 PACKET_MMAP 进行零拷贝数据包捕获                               │
│  ├── 启用 CPU 亲和性绑定 (taskset)                                       │
│  ├── 设置大页内存 (hugetlbfs) 用于 DMA 缓冲区                            │
│  └── 考虑使用 DPDK 或 AF_XDP 进行线速处理                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.10.3 数据包结构定义

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

/// 原始数据包包装
pub struct RawPacket {
    pub data: Vec<u8>,
    pub timestamp: Instant,
    pub interface: String,
}

/// 数据包解析器
pub struct PacketParser;

impl PacketParser {
    /// 解析以太网帧
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
    
    /// 解析 IPv4 包
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

/// 解析后的数据包枚举
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

/// 数据包构造器
pub struct PacketBuilder {
    src_mac: MacAddr,
    src_ip: IpAddr,
}

impl PacketBuilder {
    /// 构建 TCP SYN 包
    pub fn build_tcp_syn(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_port: u16,
        seq: u32,
        options: TcpOptions,
    ) -> Result<Vec<u8>, PacketError> {
        // 1. 构建 TCP 头部
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
        
        // 2. 构建 IP 头部
        let ip_pkt = match dst_ip {
            IpAddr::V4(dst) => {
                self.build_ipv4_packet(dst, IpNextHeaderProtocol::Tcp, &tcp_builder.build()?)?
            }
            IpAddr::V6(dst) => {
                self.build_ipv6_packet(dst, IpNextHeaderProtocol::Tcp, &tcp_builder.build()?)?
            }
        };
        
        // 3. 如果需要二层帧 (如 ARP 扫描)
        // self.build_ethernet_frame(&ip_pkt)?;
        
        Ok(ip_pkt)
    }
    
    /// 构建 ICMP Echo Request
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

/// 套接字发送器
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

/// 套接字接收器 (带 BPF 过滤)
pub struct PacketReceiver {
    socket: RawSocket,
    buffer: Vec<u8>,
    filter: Option<String>,  // BPF filter expression
}

impl PacketReceiver {
    /// 接收匹配的数据包
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<RawPacket>, IoError> {
        // 使用 poll/select 实现异步超时接收
        // 如果设置了 filter，应用 BPF 过滤逻辑
        unimplemented!()
    }
}
```

---

### 3.10.4 Linux PACKET_MMAP V2 零拷贝优化

> **架构决策**: 使用 TPACKET_V2 而非 V3。V3 在内核 < 3.19 存在已知 bug。
>
> **nmap 版本协商策略** (参考 `reference/nmap/libpcap/pcap-linux.c:2974-3013`):
> - 非 immediate mode: 先尝试 TPACKET_V3，失败则回退 TPACKET_V2
> - immediate mode (扫描器常用): 直接使用 TPACKET_V2
>
> **RustNmap 决策**: 直接使用 V2，因为扫描器通常需要 immediate mode（低延迟响应）。

基于 nmap 参考实现和 Linux 内核特性，使用 PACKET_MMAP V2 实现零拷贝数据包处理。

#### PACKET_MMAP V2 架构

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
│  │  │   mmap区域       │          │    mmap区域               ││  │
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

#### 数据结构定义

```rust
use std::mem::size_of_val;
use libc::{c_uint, c_int, sockaddr_ll, timeval};

/// PACKET_MMAP V2 环形缓冲区配置
/// 注意: V2 使用 tpacket_req (非 V3 的 tpacket_req3)
#[derive(Debug, Clone)]
pub struct RingConfig {
    /// 块大小 (推荐: 2MB = 2_097_152，必须是页大小的倍数)
    pub block_size: usize,
    /// 块数量 (推荐: 2，最小配置)
    pub block_nr: usize,
    /// 帧大小 (推荐: TPACKET_ALIGNMENT = 16 的倍数，通常 2048)
    pub frame_size: usize,
    /// 帧数量 = (block_size * block_nr) / frame_size
    pub frame_nr: usize,
}

impl Default for RingConfig {
    fn default() -> Self {
        // 基于 nmap 的高性能默认配置
        Self {
            block_size: 2_097_152,   // 2MB per block
            block_nr: 2,              // 4MB total (nmap 默认)
            frame_size: 2048,         // 标准 MTU 1500 + 头部
            frame_nr: 0,              // 计算得出
        }
    }
}

impl RingConfig {
    /// 计算派生值 (基于 nmap pcap-linux.c)
    pub fn derive_frame_nr(&mut self) {
        self.frame_nr = (self.block_size * self.block_nr) / self.frame_size;
    }

    /// 总缓冲区大小
    pub fn total_size(&self) -> usize {
        self.block_size * self.block_nr
    }

    /// 验证配置有效性
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

/// tpacket_req 结构 (对应 Linux kernel tpacket_req, V2 使用)
/// 参考: /usr/include/linux/if_packet.h
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TPacketReq {
    pub tp_block_size: u32,   // 块大小
    pub tp_block_nr: u32,     // 块数量
    pub tp_frame_size: u32,   // 帧大小
    pub tp_frame_nr: u32,     // 帧数量
}

/// tpacket2_hdr 结构 (V2 帧头, 32 字节)
/// 参考: /usr/include/linux/if_packet.h:146-157
/// CRITICAL: tp_nsec 字段在 V2 中是纳秒，不是微秒
/// CRITICAL: tp_padding 是 [u8; 4]，不是 [u8; 8]
#[repr(C)]
pub struct TPacket2Hdr {
    pub tp_status: u32,       // 帧状态 (TP_STATUS_*) - 4 bytes
    pub tp_len: u32,          // 数据包长度 - 4 bytes
    pub tp_snaplen: u32,      // 捕获长度 - 4 bytes
    pub tp_mac: u16,          // MAC 头偏移 - 2 bytes
    pub tp_net: u16,          // 网络头偏移 - 2 bytes
    pub tp_sec: u32,          // 时间戳 (秒) - 4 bytes
    pub tp_nsec: u32,         // 时间戳 (纳秒) - 4 bytes - NOT tp_usec!
    pub tp_vlan_tci: u16,     // VLAN TCI - 2 bytes
    pub tp_vlan_tpid: u16,    // VLAN TPID - 2 bytes
    pub tp_padding: [u8; 4],  // 填充 - 4 bytes - NOT [u8; 8]!
}  // Total: 4+4+4+2+2+4+4+2+2+4 = 32 bytes

// V2 状态常量
const TP_STATUS_KERNEL: u32 = 0;     // 内核拥有，用户空间应跳过
const TP_STATUS_USER: u32 = 1;       // 用户空间拥有，可读取
const TP_STATUS_COPY: u32 = 2;       // 正在复制
const TP_STATUS_LOSING: u32 = 4;     // 有丢包

// TPACKET 对齐常量
const TPACKET_ALIGNMENT: usize = 16;
const TPACKET2_HDRLEN: usize = 32;   // sizeof(tpacket2_hdr) - 修正为 32 字节
```

#### AfPacketEngine 实现 (零拷贝版本)

```rust
use std::os::unix::io::AsRawFd;
use libc::{socket, AF_PACKET, SOCK_RAW, htons, ETH_P_ALL};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use memmap2::MmapMut;

/// 基于 PACKET_MMAP V2 的数据包引擎
/// 注意: 使用 V2 而非 V3，V3 在旧内核有 bug
pub struct AfPacketEngine {
    /// 套接字文件描述符
    fd: std::os::unix::io::RawFd,
    /// 接收环形缓冲区 mmap
    rx_ring: MmapMut,
    /// 发送环形缓冲区 mmap (可选)
    tx_ring: Option<MmapMut>,
    /// 环形缓冲区配置
    config: RingConfig,
    /// 网络接口索引
    if_index: c_uint,
    /// 本机 MAC 地址
    mac_addr: [u8; 6],
    /// 当前帧索引 (V2 使用帧索引，非块索引)
    rx_frame_idx: usize,
}

impl AfPacketEngine {
    /// 创建新的 PACKET_MMAP V2 引擎
    /// 参考 nmap: reference/nmap/libpcap/pcap-linux.c
    pub fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        // 1. 创建 AF_PACKET 套接字
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

        // 2. 设置 PACKET_VERSION 为 TPACKET_V2
        // CRITICAL: 必须在所有 TPACKET 操作之前设置
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

        // 3. 获取接口索引
        let if_index = Self::get_interface_index(fd, interface)?;

        // 4. 绑定到接口
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

        // 5. 配置并映射接收环 (使用 V2 的 tpacket_req)
        let rx_ring = Self::setup_rx_ring(fd, &config)?;

        // 6. 获取本机 MAC 地址
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

    /// 设置接收环形缓冲区 (V2 版本)
    fn setup_rx_ring(
        fd: std::os::unix::io::RawFd,
        config: &RingConfig
    ) -> Result<MmapMut, PacketError> {
        // 构建 tpacket_req (V2 使用此结构，非 tpacket_req3)
        let req = TPacketReq {
            tp_block_size: config.block_size as u32,
            tp_block_nr: config.block_nr as u32,
            tp_frame_size: config.frame_size as u32,
            tp_frame_nr: config.frame_nr as u32,
        };

        // 应用接收环配置
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

        // 计算 mmap 大小并映射
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

    /// 从接收环读取数据包 (零拷贝, V2 版本)
    /// 使用帧索引而非块索引
    pub fn recv_packet(&mut self) -> Option<PacketBuffer> {
        let frame_size = self.config.frame_size;
        let frame_idx = self.rx_frame_idx;
        let total_frames = self.config.frame_nr;

        // 计算当前帧地址
        let frame_addr = unsafe {
            self.rx_ring.as_ptr().add(frame_idx * frame_size)
                as *const TPacket2Hdr
        };

        let frame_hdr = unsafe { &*frame_addr };

        // 检查帧状态 (使用 Acquire 语义确保数据可见性)
        // 参考 nmap: __atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE)
        let status = unsafe {
            std::sync::atomic::AtomicU32::from_ptr(
                std::ptr::addr_of!((*frame_addr).tp_status)
            ).load(std::sync::atomic::Ordering::Acquire)
        };

        if status & TP_STATUS_USER == 0 {
            // 帧尚未准备好
            return None;
        }

        // 创建零拷贝数据包缓冲区
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
                frame_hdr.tp_nsec as u32,  // V2 使用 tp_nsec (纳秒)
            ),
            protocol: frame_hdr.tp_vlan_tpid,
        };

        // 释放帧回内核 (使用 Release 语义)
        // 参考 nmap: __atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE)
        unsafe {
            std::sync::atomic::AtomicU32::from_ptr(
                std::ptr::addr_of!((*frame_addr).tp_status)
            ).store(TP_STATUS_KERNEL, std::sync::atomic::Ordering::Release);
        }

        // 移动到下一帧
        self.rx_frame_idx = (self.rx_frame_idx + 1) % total_frames;

        Some(packet)
    }
}

/// 零拷贝数据包缓冲区 (使用 Bytes 引用计数)
pub struct PacketBuffer {
    pub data: bytes::Bytes,  // 引用 mmap 区域，无拷贝
    pub len: usize,
    pub timestamp: Duration,
    pub protocol: u16,
}
```

#### 性能优化要点

1. **内存序**: 使用 `Ordering::Acquire/Release` 处理环形缓冲区索引
2. **无锁队列**: 考虑使用 lock-free MPSC 队列传递数据包
3. **批量发送**: 使用 `sendmmsg` 一次发送多个包
4. **CPU 亲和性**: 绑定包处理线程到特定 CPU 核心

```rust
// 批量发送 (sendmmsg)
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

