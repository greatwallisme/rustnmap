## 3.2 端口扫描模块

对应 Nmap 命令: `-sS`, `-sT`, `-sU`, `-sA`, `-sF`, `-sN`, `-sX`, `-sM`, `-sI`, `-sO`

### 3.2.1 扫描技术对比

| 扫描类型 | Nmap 参数 | 权限需求 | 隐蔽性 | 准确性 | RustNmap 实现结构体 |
|----------|-----------|----------|--------|--------|---------------------|
| TCP SYN | `-sS` | Root | ★★★★☆ | ★★★★★ | `TcpSynScanner` |
| TCP Connect | `-sT` | User | ★★☆☆☆ | ★★★★★ | `TcpConnectScanner` |
| TCP FIN | `-sF` | Root | ★★★★★ | ★★★☆☆ | `TcpFinScanner` |
| TCP NULL | `-sN` | Root | ★★★★★ | ★★★☆☆ | `TcpNullScanner` |
| TCP Xmas | `-sX` | Root | ★★★★★ | ★★★☆☆ | `TcpXmasScanner` |
| TCP ACK | `-sA` | Root | ★★★★☆ | ★★★★☆ | `TcpAckScanner` |
| TCP Window | `-sW` | Root | ★★★★☆ | ★★★☆☆ | `TcpWindowScanner` |
| TCP Maimon | `-sM` | Root | ★★★★★ | ★★★☆☆ | `TcpMaimonScanner` |
| UDP | `-sU` | Root | ★★★☆☆ | ★★★★☆ | `UdpScanner` |
| IP Protocol | `-sO` | Root | ★★★☆☆ | ★★★★☆ | `IpProtocolScanner` |
| FTP Bounce | `-b` | User | ★★☆☆☆ | ★★★☆☆ | `FtpBounceScanner` |
| Idle Scan | `-sI` | User | ★★★★★ | ★★★★☆ | `IdleScanner` |

### 3.2.2 端口扫描架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Port Scanner Architecture                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Scanner Trait Definition                    │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │  trait PortScanner {                                     │  │  │
│  │  │      async fn scan_port(&self, target: &Target,          │  │  │
│  │  │                          port: u16) -> Result<PortState>;│  │  │
│  │  │      async fn scan_range(&self, target: &Target,         │  │  │
│  │  │                            range: PortRange)             │  │  │
│  │  │                            -> Result<Vec<PortResult>>;   │  │  │
│  │  │      fn get_scan_type(&self) -> ScanType;                │  │  │
│  │  │      fn requires_root(&self) -> bool;                    │  │  │
│  │  │  }                                                       │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                 │                                   │
│          ┌──────────────────────┼──────────────────────┐            │
│          │                      │                      │            │
│  ┌───────▼───────┐    ┌─────────▼─────────┐  ┌────────▼────────┐   │
│  │  TcpScanner   │    │    UdpScanner     │  │ IpProtocolScanner│   │
│  │  Family       │    │                   │  │                  │   │
│  └───────┬───────┘    └───────────────────┘  └──────────────────┘   │
│          │                                                          │
│  ┌───────▼───────────────────────────────────────────────────────┐  │
│  │  TCP Scanner Implementations                                   │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐ │  │
│  │  │ TcpSyn      │ │ TcpConnect  │ │ TcpFin      │ │ TcpNull  │ │  │
│  │  │ Scanner     │ │ Scanner     │ │ Scanner     │ │ Scanner  │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘ │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐ │  │
│  │  │ TcpXmas     │ │ TcpAck      │ │ TcpWindow   │ │TcpMaimon │ │  │
│  │  │ Scanner     │ │ Scanner     │ │ Scanner     │ │ Scanner  │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2.3 端口状态机

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Port State Machine                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│                    ┌─────────────────┐                             │
│                    │    Pending      │                             │
│                    │  (Initial State)│                             │
│                    └────────┬────────┘                             │
│                             │                                       │
│              ┌──────────────┼──────────────┐                        │
│              │              │              │                        │
│     ┌────────▼────────┐    │    ┌─────────▼────────┐               │
│     │    Scanning     │    │    │    Timeout       │               │
│     │                 │    │    │    (Filtered)    │               │
│     └────────┬────────┘    │    └──────────────────┘               │
│              │             │                                       │
│   ┌──────────┴───────┐     │                                       │
│   │                  │     │                                       │
│ ┌─▼────────┐  ┌──────▼───┐ │ ┌───────────────┐ ┌───────────────┐   │
│ │   Open   │  │  Closed  │ │ │   Filtered    │ │ Open|Filtered │   │
│ │          │  │          │ │ │               │ │               │   │
│ │ SYN-ACK  │  │ RST      │ │ │ No Response  │ │ ACK w/Window  │   │
│ │ received │  │ received │ │ │ (or ICMP)    │ │ >0            │   │
│ └──────────┘  └──────────┘ │ └───────────────┘ └───────────────┘   │
│                             │                                       │
│                             │                                       │
│                    ┌────────▼────────┐                             │
│                    │    Completed    │                             │
│                    │  (Final State)  │                             │
│                    └─────────────────┘                             │
│                                                                     │
│  PortState Enum:                                                    │
│  ├── Open         - 目标响应 SYN/ACK                               │
│  ├── Closed       - 目标响应 RST                                   │
│  ├── Filtered     - 无响应或 ICMP 不可达                           │
│  ├── Unfiltered   - 可达但无法确定状态 (ACK 扫描)                  │
│  └── OpenFiltered - 可能开放 (UDP/IPP)                             │
│      ClosedFiltered - 特殊情况                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2.4 扫描策略配置

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Scan Strategy Config                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ScanConfig                                                         │
│  ├── scan_type: ScanType                                            │
│  │   ├── TcpSyn                                                     │
│  │   ├── TcpConnect                                                 │
│  │   ├── TcpFin / TcpNull / TcpXmas (Stealth)                      │
│  │   ├── TcpAck / TcpWindow (Firewall Detection)                   │
│  │   ├── Udp                                                        │
│  │   ├── IpProtocol                                                 │
│  │   └── Custom { packets: Vec<PacketTemplate> }                   │
│  │                                                                   │
│  ├── port_selection: PortSelection                                  │
│  │   ├── All (1-65535)                                              │
│  │   ├── Common (Top 1000)                                          │
│  │   ├── Range { start: u16, end: u16 }                            │
│  │   ├── List { ports: Vec<u16> }                                  │
│  │   └── ServiceBased { services: Vec<String> }                    │
│  │                                                                   │
│  ├── timing: TimingTemplate                                         │
│  │   ├── Paranoid (T0)  - 极慢，IDS规避                            │
│  │   ├── Sneaky (T1)    - 慢速，隐蔽扫描                           │
│  │   ├── Polite (T2)    - 礼貌，带宽友好                           │
│  │   ├── Normal (T3)    - 默认                                     │
│  │   ├── Aggressive (T4) - 快速                                    │
│  │   └── Insane (T5)    - 极快，可能丢包                           │
│  │                                                                   │
│  ├── performance: PerformanceConfig                                 │
│  │   ├── max_parallel_hosts: usize                                  │
│  │   ├── max_parallel_ports: usize                                  │
│  │   ├── min_rtt_timeout: Duration                                  │
│  │   ├── max_rtt_timeout: Duration                                  │
│  │   ├── initial_rtt_timeout: Duration                              │
│  │   ├── max_retries: u8                                            │
│  │   ├── host_timeout: Duration                                     │
│  │   └── scan_delay: Duration                                       │
│  │                                                                   │
│  └── evasion: Option<EvasionConfig>                                 │
│      ├── fragment: bool                                             │
│      ├── fragment_size: usize                                       │
│      ├── decoys: Vec<IpAddr>                                        │
│      ├── source_port: Option<u16>                                   │
│      ├── source_ip: Option<IpAddr>                                  │
│      ├── mac_address: Option<MacAddr>                               │
│      ├── bad_checksum: bool                                         │
│      └── data_length: Option<usize>                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

