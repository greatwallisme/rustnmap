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

