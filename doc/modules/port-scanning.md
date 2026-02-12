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

### 3.2.5 Ultra Scan 实现细节

基于 Nmap `scan_engine.cc` 的第三代扫描引擎实现。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Ultra Scan Architecture (Nmap Reference)         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Nmap File                    RustNmap Module                         │
│  ─────────                  ────────────────                       │
│  scan_engine.cc              scanning/ultra_scan.rs              │
│  ├── ultra_scan()           ├── UltraScanInfo::scan()        │
│  ├── UltraScanInfo          ├── UltraProbe::send()           │
│  ├── UltraProbe             ├── HostScanStats::update()       │
│  └── HostScanStats          └── TimingController              │
│                                                                     │
│  timing.cc                  scanning/timing.rs                   │
│  ├── ultra_timing_vals       ├── CongestionControl             │
│  ├── timeout_info           ├── TimeoutTracker                │
│  └── RateMeter             └── RateMeter                    │
│                                                                     │
│  portlist.cc                port/state.rs                       │
│  ├── Port                   ├── Port::new()                  │
│  ├── PortList               └── PortList::add_result()        │
│  └── serviceDeductions                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 3.2.5.1 核心数据结构

**Nmap 源码映射:**

```rust
// 对应 Nmap scan_engine.h 中的 UltraProbe
pub struct UltraProbe {
    // 探测类型 (对应 Nmap probespec type)
    pub probe_type: ProbeType,  // PS_TCP, PS_UDP, PS_ICMP, PS_ARP, etc.

    // 重试机制 (对应 tryno_t)
    pub try_no: TryNo,
    pub try_no: TryNo {
        pub is_ping: bool,      // 是否为 ping 探测
        pub seq_num: u8,       // 序列号 (0-127)
    }

    // 探测规格
    pub spec: ProbeSpec,      // 对应 probespec 结构

    // 时间戳
    pub sent: Option<TimeVal>,
    pub prev_sent: Option<TimeVal>,

    // 状态标志
    pub timed_out: bool,
    pub retransmitted: bool,
}

// 对应 Nmap portlist.h 中的 Port state 常量
#[repr(u8)]
pub enum PortState {
    Unknown = 0,      // PORT_UNKNOWN
    Closed = 1,        // PORT_CLOSED
    Open = 2,          // PORT_OPEN
    Filtered = 3,       // PORT_FILTERED
    Testing = 4,        // PORT_TESTING
    Fresh = 5,          // PORT_FRESH
    Unfiltered = 6,     // PORT_UNFILTERED
    OpenFiltered = 7,   // PORT_OPENFILTERED
    ClosedFiltered = 8,  // PORT_CLOSEDFILTERED
}

// 对应 Nmap probespec.h
pub enum ProbeType {
    None,
    Tcp,              // PS_TCP
    Udp,              // PS_UDP
    Sctp,             // PS_SCTP
    Proto,             // PS_PROTO
    Icmp,             // PS_ICMP
    Arp,              // PS_ARP
    IcmpV6,           // PS_ICMPV6
    Nd,               // PS_ND
    ConnectTcp,       // PS_CONNECTTCP
}
```

#### 3.2.5.2 Ultra Scan 算法流程

基于 `scan_engine.cc::ultra_scan()` 的实现:

```rust
// 对应 Nmap: void ultra_scan(std::vector<Target *> &Targets, ...)
pub async fn ultra_scan(
    targets: Vec<Target>,
    scan_lists: &ScanLists,
    scan_type: ScanType,
    timeout_info: &TimeoutInfo,
) -> Result<Vec<ScanResult>> {
    // 1. 确定扫描组大小
    // 对应 determineScanGroupSize()
    let group_size = determine_scan_group_size(&targets, scan_lists);

    // 2. 初始化超时信息
    // 对应 initialize_timeout_info()
    let mut timeout = TimeoutInfo::new();

    // 3. 初始化速率计量器
    // 对应 PacketRateMeter
    let mut rate_meter = PacketRateMeter::new();

    // 4. 创建 UltraScanInfo
    let mut usi = UltraScanInfo::new(targets, scan_type, timeout);

    // 5. 主扫描循环
    while !usi.is_complete() {
        // 5.1 调度探测发送
        // 对应 sendPendingProbes()
        let probes = usi.get_pending_probes();
        for probe in probes {
            if usi.can_send_probe(&probe) {
                // 对应 sendArpScanProbe, sendIPScanProbe, etc.
                send_probe(&probe).await?;
                rate_meter.update(packet_len);
            }
        }

        // 5.2 处理响应
        // 对应 get_arp_result, get_pcap_result, etc.
        let responses = receive_responses().await?;
        for response in responses {
            match response {
                Response::Arp(resp) => usi.handle_arp_response(resp),
                Response::Pcap(resp) => usi.handle_pcap_response(resp),
                Response::Timeout => usi.handle_timeout(),
            }
        }

        // 5.3 更新超时
        // 对应 adjust_timeouts2()
        timeout.update(&sent_time, &recv_time);

        // 5.4 拥塞控制
        // 对应 ultra_timing_vals::ack(), drop()
        usi.update_congestion_control();
    }

    // 6. 返回结果
    Ok(usi.get_results())
}

// 对应 Nmap: int determineScanGroupSize(...)
fn determine_scan_group_size(
    hosts_scanned_so_far: usize,
    scan_lists: &ScanLists,
) -> usize {
    // Nmap 使用启发式算法确定并行主机数
    // 权衡效率 (更多并行) 和延迟 (等待所有主机完成)

    let num_ports = scan_lists.total_port_count();
    let base_size = match num_ports {
        1..=10 => 5,     // 少量端口：更多并行
        11..=100 => 10,   // 中等端口：中等并行
        101..=1000 => 15, // 多端口：较少并行
        _ => 20,           // 大量端口：最多并行
    };

    // 根据已扫描主机数动态调整
    match hosts_scanned_so_far {
        0..=5 => base_size,
        6..=20 => base_size / 2,
        _ => 1,  // 已扫描大量主机后，减少并行以降低内存
    }
}
```

#### 3.2.5.3 拥塞控制系统

基于 Nmap `timing.cc` 中的 RFC2581 TCP 拥塞控制:

```rust
// 对应 Nmap struct ultra_timing_vals
pub struct CongestionControl {
    // 拥塞窗口 (以探测数为单位)
    pub cwnd: f64,

    // 慢启动阈值
    pub ssthresh: i32,

    // 预期回复数 (如果每个探测都回复)
    pub num_replies_expected: i32,

    // 实际收到回复数
    pub num_replies_received: i32,

    // 更新次数
    pub num_updates: i32,

    // 上次丢包时间
    pub last_drop: TimeVal,
}

impl CongestionControl {
    // 对应 cc_scale()
    pub fn scale_factor(&self, perf: &ScanPerformanceVars) -> f64 {
        // 根据网络状况动态调整窗口增量
        let scale = (self.num_replies_expected as f64) /
                   (self.num_replies_received as f64).max(1.0);
        scale.min(perf.cc_scale_max as f64)
    }

    // 对应 ack()
    pub fn on_ack(&mut self, perf: &ScanPerformanceVars, scale: f64) {
        self.num_replies_received += 1;
        self.num_replies_expected += 1;
        self.num_updates += 1;

        if self.cwnd < self.ssthresh {
            // 慢启动模式：指数增长
            self.cwnd += perf.slow_incr as f64 * scale;
        } else {
            // 拥塞避免模式：线性增长
            self.cwnd += perf.ca_incr as f64 * scale;
        }

        // 限制最大窗口
        self.cwnd = self.cwnd.min(perf.max_cwnd as f64);
    }

    // 对应 drop()
    pub fn on_drop(&mut self, in_flight: usize,
                  perf: &ScanPerformanceVars, now: &TimeVal) {
        // 检查是否需要调整 (防止连续丢包导致过度调整)
        if now.saturating_sub(&self.last_drop)
             < Duration::from_millis(100) {
            // 新的拥塞窗口设置为当前飞行包的一半
            self.cwnd = (in_flight as f64) / perf.group_drop_cwnd_divisor;

            // 阈值设置为窗口的一半
            self.ssthresh = (self.cwnd as i32) as i32 /
                          perf.group_drop_ssthresh_divisor as i32;

            self.last_drop = *now;
        }
    }
}

// 对应 Nmap struct timeout_info
pub struct TimeoutTracker {
    // 平滑往返时间 (微秒)
    pub srtt: i32,

    // 往返时间方差
    pub rttvar: i32,

    // 当前超时阈值
    pub timeout: Duration,
}

impl TimeoutTracker {
    // 对应 adjust_timeouts2()
    pub fn update_timeout(&mut self,
                      sent: &TimeVal,
                      received: &TimeVal) {
        let rtt = received.saturating_sub(sent);

        // 计算新的 RTT
        if self.srtt == 0 {
            self.srtt = rtt.as_micros() as i32;
            self.rttvar = rtt.as_micros() as i32 / 2;
        } else {
            // RFC 2988 公式
            let rtt_diff = (rtt.as_micros() as i32) - self.srtt;
            self.rttvar = (3 * self.rttvar / 4 +
                         (rtt_diff).abs() / 2).min(i32::MAX);
            self.srtt = (7 * self.srtt / 8 +
                         rtt.as_micros() as i32 / 8);
        }

        // 计算超时 = SRTT + 4 * RTTVAR
        self.timeout = Duration::from_micros(
            (self.srtt + 4 * self.rttvar) as u64
        );
    }
}
```

#### 3.2.5.4 探测发送实现

基于 Nmap `scan_engine_raw.cc`:

```rust
// 对应 sendArpScanProbe(), sendNDScanProbe(), sendIPScanProbe()
pub trait ProbeSender {
    async fn send_probe(&mut self, probe: &UltraProbe)
        -> Result<()>;

    fn supports_probe_type(&self, probe_type: ProbeType) -> bool;
}

// 原始套接字发送器
pub struct RawSocketSender {
    raw_socket: RawSocket,
    pcap_handle: PcapHandle,
    interface: InterfaceInfo,
}

impl ProbeSender for RawSocketSender {
    async fn send_probe(&mut self, probe: &UltraProbe)
        -> Result<()> {
        match probe.spec.probe_type {
            ProbeType::Arp => {
                // 对应 sendArpScanProbe()
                let arp_packet = build_arp_packet(&probe)?;
                self.raw_socket.send_to(
                    &arp_packet,
                    &probe.target.mac_address
                ).await?;
            }

            ProbeType::Nd => {
                // 对应 sendNDScanProbe()
                let nd_packet = build_nd_packet(&probe)?;
                self.raw_socket.send_to(
                    &nd_packet,
                    &probe.target.ipv6_address
                ).await?;
            }

            ProbeType::Tcp => {
                // 构建原始 TCP/IP 数据包
                let ip_packet = build_ip_packet(&probe)?;
                self.raw_socket.send_to(
                    &ip_packet,
                    &probe.target.ip_address
                ).await?;
            }

            ProbeType::Udp => {
                let udp_packet = build_udp_packet(&probe)?;
                self.raw_socket.send_to(
                    &udp_packet,
                    &probe.target.ip_address
                ).await?;
            }

            _ => bail!("Unsupported probe type"),
        }

        // 记录发送时间
        probe.sent = Some(TimeVal::now());
        Ok(())
    }
}
```

#### 3.2.5.5 响应处理流程

```rust
// 对应 get_pcap_result()
pub async fn handle_pcap_response(
    pcap: &mut PcapHandle,
    usi: &mut UltraScanInfo,
) -> Result<()> {
    // 设置 BPF 过滤器
    let bpf_filter = usi.build_bpf_filter();
    pcap.set_filter(&bpf_filter)?;

    // 循环读取数据包
    loop {
        match pcap.next_packet().await? {
            Some(packet) => {
                // 解析数据包
                match parse_response(&packet)? {
                    Response::Tcp(resp) => {
                        // 匹配到发送的探测
                        if let Some(probe) = usi.find_probe_by_resp(&resp) {
                            // 处理 TCP 响应
                            handle_tcp_response(probe, resp, usi);
                        }
                    }
                    Response::Icmp(resp) => {
                        // ICMP 不可达 = 端口被过滤
                        if let Some(probe) = usi.find_probe_by_icmp(&resp) {
                            probe.port_state = PortState::Filtered;
                            probe.reason = Reason::IcmpUnreachable;
                        }
                    }
                    Response::Arp(resp) => {
                        // ARP 响应 = 主机在线
                        if let Some(probe) = usi.find_probe_by_arp(&resp) {
                            probe.target.is_online = true;
                        }
                    }
                }
            }
            None => {
                // 超时检查
                if usi.all_probes_timeout() {
                    break;
                }
            }
        }
    }
}

fn handle_tcp_response(
    probe: &mut UltraProbe,
    response: TcpResponse,
    usi: &mut UltraScanInfo,
) {
    match scan_type {
        ScanType::SynScan => {
            match response.flags {
                TcpFlags::SYN | TcpFlags::ACK => {
                    // SYN-ACK = 端口开放
                    probe.port_state = PortState::Open;
                    probe.reason = Reason::SynAck;
                }
                TcpFlags::RST => {
                    // RST = 端口关闭
                    probe.port_state = PortState::Closed;
                    probe.reason = Reason::Rst;
                }
                _ => {
                    // 其他响应
                    probe.port_state = PortState::Filtered;
                }
            }
        }
        ScanType::ConnectScan => {
            // connect() 系统调用返回
            probe.port_state = response.connect_result;
        }
        ScanType::FinScan | ScanType::NullScan |
        ScanType::XmasScan => {
            // 隐蔽扫描：无响应 = 开放或过滤
            probe.port_state = PortState::OpenFiltered;
        }
        ScanType::AckScan => {
            // ACK 扫描用于防火墙检测
            if let Some(ttl) = response.ttl {
                probe.ttl = ttl;
                probe.port_state = PortState::Unfiltered;
            }
        }
        _ => {}
    }
}
```

#### 3.2.5.6 常量定义

```rust
// 对应 scan_engine.cc
pub const RLD_TIME_MS: u64 = 1000;      // Rate Limit Detection 时间
pub const COMPL_HOST_LIFETIME_MS: u64 = 120000; // 已完成主机保留时间 (2分钟)

// 对应 timing.h
pub const DEFAULT_CURRENT_RATE_HISTORY: f64 = 5.0;

// 对应 service_scan.h
pub const DEFAULT_SERVICEWAITMS: u64 = 5000;
pub const DEFAULT_TCPWRAPPEDMS: u64 = 2000;
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 5000;
pub const DEFAULT_CONNECT_SSL_TIMEOUT: u64 = 8000;
pub const MAXFALLBACKS: usize = 20;
```

---