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

---

