## 3.4 操作系统检测模块

对应 Nmap 命令: `-O`, `--osscan-limit`, `--osscan-guess`

### 3.4.1 OS 指纹识别技术

| 指纹类型 | 描述 | 检测方法 | Nmap 对应 |
|----------|------|----------|-----------|
| TCP ISN | 初始序列号模式 | 多次 SYN 收集 ISN | `SEQ` |
| IP ID | IP 标识符增量模式 | 多次探测 IP ID | `SEQ` |
| TCP Options | TCP 选项顺序和值 | SYN 包选项分析 | `OPS` |
| TCP Window | 窗口大小特征 | SYN-ACK 窗口值 | `WIN` |
| T1-T7 | TCP 响应测试 | 各种 TCP 包响应 | `T1`-`T7` |
| IE | ICMP 响应特征 | ICMP Echo 响应 | `IE` |
| U1 | UDP 响应特征 | UDP 探测响应 | `U1` |
| ECN | ECN 支持 | ECN 标志位 | `ECN` |

### 3.4.2 OS 检测流程

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OS Detection Pipeline                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Phase 1: Fingerprint Collection                                    │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                                                               │ │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │ │
│  │   │   TCP SEQ   │    │   TCP OPS   │    │    TCP WIN      │  │ │
│  │   │  Analysis   │    │  Analysis   │    │   Analysis      │  │ │
│  │   │  (6 probes) │    │  (1 probe)  │    │   (1 probe)     │  │ │
│  │   └──────┬──────┘    └──────┬──────┘    └────────┬────────┘  │ │
│  │          │                  │                     │           │ │
│  │   ┌──────▼──────────────────▼─────────────────────▼──────┐   │ │
│  │   │                    TCP Tests (T1-T7)                 │   │ │
│  │   │  T1: Open port response                              │   │ │
│  │   │  T2: Closed port, no flags                           │   │ │
│  │   │  T3: Open port, FIN/PSH/URG                          │   │ │
│  │   │  T4: Closed port, ACK                                │   │ │
│  │   │  T5: Closed port, SYN                                │   │ │
│  │   │  T6: Closed port, ACK                                │   │ │
│  │   │  T7: Closed port, FIN/PSH/URG                        │   │ │
│  │   └──────────────────────────────────────────────────────┘   │ │
│  │                                                               │ │
│  │   ┌─────────────────────────────────────────────────────────┐│ │
│  │   │  ICMP Tests (IE)                                        ││ │
│  │   │  IE1: Echo request with IP options                      ││ │
│  │   │  IE2: Echo request with different IP options            ││ │
│  │   └─────────────────────────────────────────────────────────┘│ │
│  │                                                               │ │
│  │   ┌─────────────────────────────────────────────────────────┐│ │
│  │   │  UDP Test (U1)                                          ││ │
│  │   │  U1: UDP probe to closed port                           ││ │
│  │   └─────────────────────────────────────────────────────────┘│ │
│  │                                                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                 │                                   │
│                                 ▼                                   │
│  Phase 2: Fingerprint Generation                                    │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  FingerprintBuilder                                           │ │
│  │  ├── seq: SeqFingerprint                                      │ │
│  │  │   ├── isp: ISPPattern (TCPISTimeStamp, TCPISN)            │ │
│  │  │   ├── ts: TimestampPattern                                │ │
│  │  │   └── gc: GCInterval                                      │ │
│  │  ├── ops: OpsFingerprint (TCP Options per test)              │ │
│  │  ├── win: WinFingerprint (Window sizes per test)             │ │
│  │  ├── ecn: EcnFingerprint                                     │ │
│  │  ├── t1-t7: TcpTestFingerprint                               │ │
│  │  ├── u1: UdpFingerprint                                      │ │
│  │  └── ie: IcmpFingerprint                                     │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                 │                                   │
│                                 ▼                                   │
│  Phase 3: Database Matching                                         │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  FingerprintMatcher                                           │ │
│  │  ├── Load nmap-os-db database                                 │ │
│  │  ├── Calculate match scores for each known fingerprint        │ │
│  │  ├── Apply scoring weights                                    │ │
│  │  └── Return top matches with accuracy percentages            │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4.3 OS 指纹数据结构

```
┌─────────────────────────────────────────────────────────────────────┐
│                      OS Fingerprint Types                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  OsFingerprint                                                      │
│  ├── seq: SeqFingerprint                                            │
│  │   ├── tcp_isn: IsnPattern                                        │
│  │   │   ├── gcd: u32            (GCD of ISN differences)          │
│  │   │   ├── isr: u8             (ISN rate)                        │
│  │   │   └── sp: u8              (Sequence predictability)         │
│  │   ├── ip_id: IpIdPattern                                         │
│  │   │   ├── zi: bool            (Zero IP ID)                      │
│  │   │   ├── inc: bool           (Incremental)                     │
│  │   │   └── ss: u8              (IP ID sequence)                  │
│  │   └── ts: TimestampPattern                                       │
│  │       ├── ts: u8              (Timestamp option)                │
│  │       └── hr: u32             (Hourly rate)                     │
│  │                                                                   │
│  ├── ops: HashMap<String, TcpOpsPattern>  // T1-T7 -> Options      │
│  │   └── TcpOpsPattern                                              │
│  │       ├── mss: Option<u16>    (Max Segment Size)               │
│  │       ├── wscale: Option<u8>  (Window Scale)                   │
│  │       ├── sack: bool          (Selective ACK)                  │
│  │       ├── timestamp: bool     (Timestamp option)               │
│  │       ├── nop: u8             (NOP count)                       │
│  │       └── eol: bool           (End of Options List)            │
│  │                                                                   │
│  ├── win: HashMap<String, u16>       // T1-T7 -> Window Size       │
│  │                                                                   │
│  ├── ecn: EcnPattern                                                │
│  │   ├── r: bool                 (ECE flag response)              │
│  │   ├── df: bool                (Don't Fragment)                 │
│  │   ├── t: u8                   (TOS value)                       │
│  │   └── ad: bool                (CWR set)                         │
│  │                                                                   │
│  └── tests: HashMap<String, TestResult>  // T1-T7, U1, IE          │
│                                                                     │
│  OsMatch                                                            │
│  ├── name: String              (e.g., "Linux 5.4")                 │
│  ├── os_family: OsFamily                                             │
│  │   ├── Linux                                                       │
│  │   ├── Windows                                                     │
│  │   ├── macOS                                                       │
│  │   ├── BSD                                                         │
│  │   ├── Solaris                                                     │
│  │   └── Other(String)                                              │
│  ├── accuracy: u8              (0-100)                              │
│  ├── vendor: Option<String>                                          │
│  ├── os_generation: Option<String>                                   │
│  ├── device_type: Option<String>                                     │
│  └── cpe: Option<Cpe>                                               │
│                                                                     │
│  OsDetectionResult                                                  │
│  ├── matches: Vec<OsMatch>      (Sorted by accuracy)               │
│  ├── fingerprint_used: OsFingerprint                                │
│  └── scan_duration: Duration                                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4.4 OS 检测实现细节

基于 Nmap `FPEngine.cc/h`, `osscan2.cc` 的实现。

#### 3.4.4.1 核心数据结构

**Nmap 源码映射:**

```rust
// 对应 Nmap FPEngine.h 中的 FPEngine 基类
pub trait FingerprintEngine {
    fn os_scan(&mut self, targets: Vec<Target>) -> Result<()>;
    fn reset(&mut self);
}

// 对应 FPEngine6 - IPv6 指纹识别
pub struct FingerprintEngineV6 {
    // 目标主机列表
    hosts: Vec<FpHostV6>,

    // 分组大小 (对应 OSSCAN_GROUP_SIZE)
    pub group_size: usize,

    // 网络控制器
    pub network_control: FpNetworkControl,
}

// 对应 FPNetworkControl - 网络访问管理器
pub struct FpNetworkControl {
    // Nsock 连接池
    pub nsock_pool: nsock_pool,

    // Pcap 描述符
    pub pcap_nsi: nsock_iod,

    // 上次调度的 pcap 事件 ID
    pub pcap_ev_id: nsock_event_id,

    // 是否已初始化
    pub nsock_init: bool,

    // 原始套接字
    pub raw_sd: i32,

    // 注册的调用者 (FPHost 列表)
    pub callers: Vec<FpHost>,

    // 已发送的探测数
    pub probes_sent: i32,

    // 收到的响应数
    pub responses_recv: i32,

    // 超时的探测数
    pub probes_timedout: i32,

    // 拥塞控制
    pub cc_cwnd: f32,        // Congestion window
    pub cc_ssthresh: f32,    // Slow start threshold

    // L2 帧支持判断
    pub fn l2_frames(&self) -> bool {
        self.raw_sd < 0
    }
}

impl FpNetworkControl {
    // 对应 cc_init()
    pub fn new() -> Result<Self> {
        Ok(Self {
            nsock_pool: nsock_pool_new()?,
            pcap_nsi: std::ptr::null(),
            pcap_ev_id: 0,
            nsock_init: false,
            raw_sd: -1,
            callers: Vec::new(),
            probes_sent: 0,
            responses_recv: 0,
            probes_timedout: 0,
            // 对应 OSSCAN_INITIAL_CWND
            cc_cwnd: NUM_FP_TIMEDPROBES_IPV6 as f32,
            // 对应 OSSCAN_INITIAL_SSTHRESH = 4 * CWND
            cc_ssthresh: (4 * NUM_FP_TIMEDPROBES_IPV6) as f32,
        })
    }

    // 对应 scheduleProbe()
    pub fn schedule_probe(&mut self,
                            probe: &mut FpProbe,
                            delay_ms: i32)
        -> Result<()> {
        // 检查拥塞窗口
        if !self.request_slots(1) {
            return Err(Error::CongestionWindowFull);
        }

        // 通过 nsock 调度发送
        nsock_schedule_timer(
            self.nsock_pool,
            delay_ms,
            Some(probe_transmission_handler),
            probe as *mut c_void,
        )?;

        self.probes_sent += 1;
        Ok(())
    }

    // 对应 request_slots()
    pub fn request_slots(&mut self, num_packets: usize) -> bool {
        // 检查是否有足够的拥塞窗口空间
        (self.callers.len() as f32) < self.cc_cwnd
    }

    // 对应 cc_update_sent()
    pub fn cc_on_sent(&mut self, pkts: i32) {
        // 更新拥塞控制状态
    }

    // 对应 cc_update_received()
    pub fn cc_on_received(&mut self) {
        self.responses_recv += 1;

        // 对应 cc_report_final_timeout()
        // 根据响应调整窗口
    }
}
```

#### 3.4.4.2 FPHost 每主机状态

```rust
// 对应 FPHost - 指纹识别的每主机状态
pub struct FpHost {
    // 总探测数
    pub total_probes: u32,

    // 定时探测数 (需要 100ms 间隔)
    pub timed_probes: u32,

    // 已发送探测数 (不含重传)
    pub probes_sent: u32,

    // 收到响应的探测数
    pub probes_answered: u32,

    // 超时未响应的探测数
    pub probes_unanswered: u32,

    // 是否完成
    pub incomplete_fp: bool,

    // 检测是否完成
    pub detection_done: bool,

    // 定时探测是否已发送
    pub timedprobes_sent: bool,

    // 目标主机信息
    pub target_host: Target,

    // 网络控制器链接
    pub netctl: Option<FpNetworkControl>,

    // 是否已在网络控制器注册
    pub netctl_registered: bool,

    // TCP 序列号基数
    pub tcp_seq_base: u32,

    // 开放的 TCP 端口 (用于 OS 探测)
    pub open_port_tcp: i32,

    // 关闭的 TCP 端口
    pub closed_port_tcp: i32,

    // 关闭的 UDP 端口
    pub closed_port_udp: i32,

    // TCP 探测起始端口
    pub tcp_port_base: i32,

    // UDP 探测端口
    pub udp_port_base: i32,

    // ICMPv6 序列计数器
    pub icmp_seq_counter: u16,

    // 重传超时 (RTO)
    pub rto: i32,

    // RTT 方差
    pub rttvar: i32,

    // 平滑往返时间
    pub srtt: i32,
}

impl FpHost {
    // 对应 update_RTO()
    pub fn update_rto(&mut self, measured_rtt_us: i32,
                       is_retransmission: bool) {
        if !is_retransmission {
            // 首次测量或正常响应
            if self.srtt == 0 {
                self.srtt = measured_rtt_us;
                self.rttvar = measured_rtt_us / 2;
            } else {
                // RFC 2988 公式
                let rtt_diff = measured_rtt_us - self.srtt;
                self.rttvar = (3 * self.rttvar / 4 +
                                   rtt_diff.abs() / 2)
                                  .min(i32::MAX);
                self.srtt = (7 * self.srtt / 8 +
                                   measured_rtt_us / 8);
            }
        }

        // 计算超时 = SRTT + 4 * RTTVAR
        self.rto = self.srtt + 4 * self.rttvar;

        // 对应 OSSCAN_INITIAL_RTO = 3 秒
        self.rto = self.rto.clamp(
            OSSCAN_INITIAL_RTO_MIN,
            OSSCAN_INITIAL_RTO_MAX
        );
    }

    // 对应 choose_osscan_ports()
    pub fn choose_osscan_ports(&mut self, ports: &PortList) -> Result<()> {
        // 选择一个开放端口和一个关闭端口用于 OS 探测
        self.open_port_tcp = ports.find_open_port()
            .ok_or(Error::NoOpenPort)?;
        self.closed_port_tcp = ports.find_closed_port()
            .ok_or(Error::NoClosedPort)?;

        // 对于 UDP，只需要一个关闭端口
        self.closed_port_udp = ports.find_closed_udp_port()
            .ok_or(Error::NoClosedUdpPort)?;

        Ok(())
    }
}
```

#### 3.4.4.3 FPProbe 探测结构

```rust
// 对应 FPProbe - OS 指纹探测包
pub struct FpProbe {
    // 探测 ID (如 "SEQ", "OPS", "T1", etc.)
    pub probe_id: Cow<'static, str>,

    // 探测编号
    pub probe_no: i32,

    // 重传次数
    pub retransmissions: i32,

    // 收到响应次数
    pub times_replied: i32,

    // 是否失败
    pub failed: bool,

    // 是否为定时探测
    pub timed: bool,

    // 关联的主机
    pub host: *mut FpHost,

    // 包数据 (继承自 FPPacket)
    pub packet: PacketData,

    // 发送时间
    pub sent_time: TimeVal,
}

// 对应 FPPacket
pub struct PacketData {
    pub pkt: PacketElement,
    pub link_eth: bool,
    pub eth_hdr: EthHeader,
    pub pkt_time: TimeVal,
}

impl FpProbe {
    // 对应 isResponse()
    pub fn is_response(&self, received: &PacketElement) -> bool {
        // 检查收到的包是否是对此探测的响应
        self.matches_probe(received)
    }

    // 对应 incrementRetransmissions()
    pub fn increment_retransmissions(&mut self) -> i32 {
        self.retransmissions += 1;
        self.retransmissions
    }

    // 对应 setFailed()
    pub fn set_failed(&mut self) {
        self.failed = true;
    }
}
```

#### 3.4.4.4 IPv6 OS 检测实现

```rust
// 对应 FPHost6
pub struct FpHostV6 {
    // 继承 FPHost
    pub base: FpHost,

    // IPv6 特定探测 (13 TCP + 4 ICMPv6 + 1 UDP)
    pub fp_probes: [FpProbe; NUM_FP_PROBES_IPV6],

    // 收到的响应
    pub fp_responses: [Option<FpResponse>; NUM_FP_PROBES_IPV6],

    // 定时探测的辅助响应
    pub aux_resp: [Option<FpResponse>; NUM_FP_TIMEDPROBES_IPV6],
}

impl FpHostV6 {
    // 对应 FPEngine6::os_scan()
    pub async fn os_scan(targets: Vec<Target>) -> Result<()> {
        // 1. 创建网络控制器
        let mut netctl = FpNetworkControl::new(&interface)?;

        // 2. 初始化每个目标的 FPHost
        let mut hosts: Vec<FpHostV6> = targets.iter()
            .map(|t| FpHostV6::new(t, &netctl))
            .collect();

        // 3. 选择 OS 扫描端口
        for host in &mut hosts {
            host.choose_osscan_ports(&ports)?;
        }

        // 4. 注册所有主机到网络控制器
        for host in &mut hosts {
            netctl.register_caller(host)?;
        }

        // 5. 设置 pcap sniffers
        netctl.setup_sniffer(&interface, &bpf_filter)?;

        // 6. 主扫描循环
        while !hosts.iter().all(|h| h.done()) {
            // 6.1 调度探测
            for host in hosts.iter().filter(|h| !h.done()) {
                host.schedule()?;
            }

            // 6.2 处理事件
            netctl.handle_events()?;

            // 6.3 检查超时
            for host in hosts.iter_mut() {
                if host.has_timed_out() {
                    host.retry_failed_probes()?;
                }
            }
        }

        // 7. 填充结果
        for host in hosts {
            host.fill_results()?;
        }

        Ok(())
    }

    // 对应 schedule()
    pub fn schedule(&mut self) -> Result<()> {
        // 如果所有探测已发送，等待响应
        if self.probes_sent >= self.total_probes {
            return Ok(());
        }

        // 获取下一个待发送探测
        let probe_idx = self.probes_sent as usize;
        let probe = &mut self.fp_probes[probe_idx];

        // 检查是否为定时探测 (需要 100ms 间隔)
        if probe.timed {
            // 确保定时探测按序发送
            if !self.timedprobes_sent {
                // 第一个定时探测
                self.timedprobes_sent = true;
            } else {
                // 检查距上次定时探测是否经过 100ms
                if !self.check_timed_probe_delay()? {
                    return Ok(());  // 等待更长时间
                }
            }
        }

        // 通过网络控制器发送
        self.host.netctl
            .as_ref()
            .ok_or(Error::NoNetworkControl)?
            .schedule_probe(probe, 0)?;

        self.probes_sent += 1;
        Ok(())
    }

    // 对应 callback()
    pub fn callback(&mut self,
                   pkt: &[u8],
                   pkt_len: usize,
                   tv: &TimeVal) -> Result<()> {
        // 解析收到的数据包
        let response = parse_fingerprint_response(pkt, pkt_len)?;

        // 查找匹配的探测
        let probe_id = response.matching_probe_id()?;

        // 存储响应
        self.fp_responses[probe_id] = Some(response);

        // 更新 RTT 和 RTO
        let rtt = tv.saturating_sub(&self.fp_probes[probe_id].sent_time);
        self.update_rto(rtt.as_micros() as i32, false)?;

        Ok(())
    }
}
```

#### 3.4.4.5 探测类型定义

```rust
// 对应 FPEngine.h 中的常量
pub const NUM_FP_PROBES_IPV6_TCP: usize = 13;
pub const NUM_FP_PROBES_IPV6_ICMPV6: usize = 4;
pub const NUM_FP_PROBES_IPV6_UDP: usize = 1;
pub const NUM_FP_PROBES_IPV6: usize =
    NUM_FP_PROBES_IPV6_TCP +
    NUM_FP_PROBES_IPV6_ICMPV6 +
    NUM_FP_PROBES_IPV6_UDP;

// 定时探测数 (需要特定时序)
pub const NUM_FP_TIMEDPROBES_IPV6: usize = 6;

// 拥塞控制常量
pub const OSSCAN_GROUP_SIZE: usize = 10;
pub const OSSCAN_INITIAL_CWND: usize = NUM_FP_TIMEDPROBES_IPV6;
pub const OSSCAN_INITIAL_SSTHRESH: usize = 4 * OSSCAN_INITIAL_CWND;
pub const OSSCAN_INITIAL_RTO: i32 = 3_000_000;  // 3 秒 (微秒)

// TCP 流标签 (用于 OS 检测)
pub const OSDETECT_FLOW_LABEL: u32 = 0x12345;

// 新度阈值 (匹配分数差异阈值)
pub const FP_NOVELTY_THRESHOLD: f64 = 15.0;

// IPv6 OS 探测类型
pub enum V6ProbeType {
    // TCP 探测 (13 个)
    SeqTest,
    IcmpEcho,
    TcpT1,  // Open port response
    TcpT2,  // Closed port, no flags
    TcpT3,  // Open port, FIN/PSH/URG
    TcpT4,  // Closed port, ACK
    TcpT5,  // Closed port, SYN
    TcpT6,  // Closed port, ACK
    TcpT7,  // Closed port, FIN/PSH/URG
    // ICMPv6 探测 (4 个)
    IcmpV6Echo,
    // UDP 探测 (1 个)
    UdpClosed,
}
```

#### 3.4.4.6 指纹匹配算法

```rust
// 对应 FingerMatch 和 load_fp_matches()
pub struct FingerprintMatcher {
    // 数据库中的所有指纹
    pub fingerprints: Vec<OsFingerprint>,
}

impl FingerprintMatcher {
    // 对应 load_fp_matches()
    pub fn load_from_db(db_path: &Path) -> Result<Self> {
        // 解析 nmap-os-db 文件
        let db_content = fs::read_to_string(db_path)?;
        Ok(Self {
            fingerprints: parse_fingerprints(&db_content)?,
        })
    }

    // 匹配指纹并评分
    pub fn match(&self,
               fp: &OsFingerprint) -> Vec<OsMatch> {
        let mut scores: Vec<OsMatch> = Vec::new();

        for known_fp in &self.fingerprints {
            let score = self.calculate_score(fp, known_fp);

            // 只有分数低于阈值才认为匹配
            if score < FP_NOVELTY_THRESHOLD {
                scores.push(OsMatch {
                    name: known_fp.name.clone(),
                    accuracy: ((100.0 - score.max(0.0)) as u8),
                    vendor: known_fp.vendor.clone(),
                    os_family: known_fp.os_family.clone(),
                    // ... 其他字段
                });
            }
        }

        // 按准确度排序
        scores.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));
        scores
    }

    // 计算两个指纹的差异分数
    fn calculate_score(&self, fp1: &OsFingerprint, fp2: &OsFingerprint)
        -> f64 {
        let mut total_diff = 0.0;

        // SEQ 指纹比较
        total_diff += self.compare_seq(&fp1.seq, &fp2.seq);

        // OPS 指纹比较 (每个测试)
        for (test, ops1) in &fp1.ops {
            if let Some(ops2) = fp2.ops.get(test) {
                total_diff += self.compare_ops(ops1, ops2);
            }
        }

        // WIN 指纹比较
        total_diff += self.compare_win(&fp1.win, &fp2.win);

        // ECN 指纹比较
        total_diff += self.compare_ecn(&fp1.ecn, &fp2.ecn);

        // T1-T7 测试比较
        for test in &["T1", "T2", "T3", "T4", "T5", "T6", "T7"] {
            if let Some(t1) = fp1.tests.get(test) {
                if let Some(t2) = fp2.tests.get(test) {
                    total_diff += self.compare_test_result(t1, t2);
                }
            }
        }

        total_diff
    }
}
```

---