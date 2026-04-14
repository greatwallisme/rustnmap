## 3.7 防火墙/IDS 规避模块

对应 Nmap 命令: `-f`, `-D`, `-S`, `--source-port`, `-e`, `--badsum`, `--data-length`

### 3.7.1 规避技术矩阵

|技术|Nmap 参数|描述|实现复杂度|
|---|---|---|---|
|分片|`-f`, `--mtu`|IP 分片绕过|★★★☆☆|
|诱饵|`-D <decoy1,decoy2,...>`|诱饵 IP 扫描|★★★★☆|
|源 IP 欺骗|`-S <IP>`|伪造源 IP|★★☆☆☆|
|源端口伪装|`--source-port <port>`|指定源端口|★☆☆☆☆|
|接口指定|`-e <iface>`|指定网络接口|★★☆☆☆|
|MAC 欺骗|`--spoof-mac <addr>`|伪造 MAC 地址|★★☆☆☆|
|错误校验和|`--badsum`|发送错误校验和|★☆☆☆☆|
|数据填充|`--data-length <num>`|填充随机数据|★☆☆☆☆|
|IP 选项|`--ip-options <opts>`|自定义 IP 选项|★★★☆☆|
|TTL 设置|`--ttl <value>`|设置 TTL 值|★☆☆☆☆|
|随机目标|`--randomize-hosts`|随机化扫描顺序|★★☆☆☆|
|时序模板|`-T0` 到 `-T5`|时序控制|★★★☆☆|
### 3.7.2 分片规避实现

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     IP Fragmentation Evasion                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  分片模式:                                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  原始 TCP SYN 包 (无分片):                                        │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │  IP Header (20B) │ TCP Header (20B) │ Payload               │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  小分片模式 (-f, 8 bytes):                                        │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │  Fragment 1: IP Header + TCP Flags (8B TCP data)           │  │  │
│  │  │  ┌─────────────────────────────────────────┐               │  │  │
│  │  │  │  IP (20B) │ TCP [first 8B] │ MORE_FRAG │               │  │  │
│  │  │  └─────────────────────────────────────────┘               │  │  │
│  │  │                                                             │  │  │
│  │  │  Fragment 2: 剩余 TCP 数据                                   │  │  │
│  │  │  ┌─────────────────────────────────────────┐               │  │  │
│  │  │  │  IP (20B) │ TCP [remaining 12B+]       │               │  │  │
│  │  │  └─────────────────────────────────────────┘               │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  自定义 MTU (--mtu <value>):                                      │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │  根据 MTU 值计算分片偏移，确保每个分片不超过 MTU            │  │  │
│  │  │  每个分片包含: IP Header + 部分数据                         │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  分片配置结构:                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  FragmentConfig {                                                 │  │
│  │    enabled: bool,                                                 │  │
│  │    mode: FragmentMode,                                            │  │
│  │    │   ├── Default (8 bytes)                                     │  │
│  │    │   ├── CustomMTU(u16)                                        │  │
│  │    │   └── Random(usize, usize)  // min, max                     │  │
│  │    overlap: bool,           // 允许分片重叠                       │  │
│  │    timeout: Duration,       // 分片重组超时                       │  │
│  │  }                                                               │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.7.3 诱饵扫描实现

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Decoy Scanning Design                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  诱饵扫描原理:                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   -D <decoy1,decoy2,...,ME,decoyN>                                │  │
│  │                                                                   │  │
│  │   发送的探测包:                                                    │  │
│  │   ┌─────────────────────────────────────────────────────────────┐│  │
│  │   │  Packet 1: Source=decoy1  → Target:Port                    ││  │
│  │   │  Packet 2: Source=decoy2  → Target:Port                    ││  │
│  │   │  Packet 3: Source=ME      → Target:Port  (真实扫描)         ││  │
│  │   │  Packet 4: Source=decoy3  → Target:Port                    ││  │
│  │   │  Packet 5: Source=decoy4  → Target:Port                    ││  │
│  │   └─────────────────────────────────────────────────────────────┘│  │
│  │                                                                   │  │
│  │   目标看到的来源: 真实IP 淹没在诱饵中，难以识别真实攻击者          │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  诱饵扫描流程:                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │  │
│  │   │  Decoy      │───▶│  Round      │───▶│  Packet            │  │  │
│  │   │  Parser     │    │  Robin      │    │  Injector          │  │  │
│  │   └─────────────┘    │  Scheduler  │    └─────────────────────┘  │  │
│  │                      └─────────────┘                              │  │
│  │                            │                                      │  │
│  │                            ▼                                      │  │
│  │   ┌─────────────────────────────────────────────────────────┐    │  │
│  │   │                   DecoyPacket                            │    │  │
│  │   │                                                         │    │  │
│  │   │   ├── real_source: IpAddr        (真实IP)               │    │  │
│  │   │   ├── decoys: Vec<IpAddr>        (诱饵列表)             │    │  │
│  │   │   ├── position: usize            (ME在列表中的位置)     │    │  │
│  │   │   └── random_order: bool         (随机发送顺序)         │    │  │
│  │   │                                                         │    │  │
│  │   └─────────────────────────────────────────────────────────┘    │  │
│  │                                                                   │  │
│  │   特殊值:                                                         │  │
│  │   ├── ME      - 真实IP                                          │  │
│  │   ├── ME:<n>  - 在位置n放置真实IP                               │  │
│  │   └── RND:n   - 生成n个随机诱饵                                 │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.7.4 规避配置总览

```
// ============================================
// Evasion Configuration Types
// ============================================

/// 规避配置总结构
pub struct EvasionConfig {
    /// 分片配置
    pub fragmentation: Option<FragmentConfig>,
    
    /// 诱饵配置
    pub decoys: Option<DecoyConfig>,
    
    /// 源地址配置
    pub source: SourceConfig,
    
    /// 数据包修改配置
    pub packet_modification: PacketModConfig,
    
    /// 时序配置
    pub timing: TimingConfig,
}

/// 分片配置
pub struct FragmentConfig {
    pub enabled: bool,
    pub mode: FragmentMode,
    pub overlap: bool,
    pub timeout: Duration,
}

pub enum FragmentMode {
    Default,                        // 8 字节分片
    CustomMTU(u16),                 // 自定义 MTU
    Random { min: usize, max: usize }, // 随机分片大小
}

/// 诱饵配置
pub struct DecoyConfig {
    pub decoys: Vec<IpAddr>,
    pub real_ip_position: usize,    // ME 的位置
    pub random_order: bool,         // 是否随机顺序发送
}

/// 源地址配置
pub struct SourceConfig {
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub source_mac: Option<MacAddr>,
    pub interface: Option<String>,
}

/// 数据包修改配置
pub struct PacketModConfig {
    /// 发送错误校验和
    pub bad_checksum: bool,
    
    /// 附加随机数据长度
    pub data_length: Option<usize>,
    
    /// 自定义 IP 选项
    pub ip_options: Option<Vec<IpOption>>,
    
    /// TTL 值
    pub ttl: Option<u8>,
    
    /// TOS 值
    pub tos: Option<u8>,
    
    /// 不设置任何标志位 (用于某些防火墙绕过)
    pub no_flags: bool,
}

/// IP 选项
pub enum IpOption {
    RecordRoute { max_addresses: u8 },
    Timestamp { flags: u8, max_entries: u8 },
    LooseSourceRoute { addresses: Vec<IpAddr> },
    StrictSourceRoute { addresses: Vec<IpAddr> },
    Custom { type_code: u8, data: Vec<u8> },
}

/// 时序模板
#[derive(Debug, Clone, Copy)]
pub enum TimingTemplate {
    Paranoid,    // T0: 最慢，IDS规避
    Sneaky,      // T1: 慢速，隐蔽
    Polite,      // T2: 礼貌，低带宽
    Normal,      // T3: 默认
    Aggressive,  // T4: 快速
    Insane,      // T5: 极快
}

impl TimingTemplate {
    pub fn config(&self) -> TimingValues {
        match self {
            TimingTemplate::Paranoid => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(5),
                max_retries: 10,
                scan_delay: Duration::from_millis(300),
                max_parallel: 1,
            },
            TimingTemplate::Sneaky => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(5),
                max_retries: 5,
                scan_delay: Duration::from_millis(100),
                max_parallel: 2,
            },
            TimingTemplate::Polite => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 3,
                scan_delay: Duration::from_millis(10),
                max_parallel: 10,
            },
            TimingTemplate::Normal => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 2,
                scan_delay: Duration::ZERO,
                max_parallel: 100,
            },
            TimingTemplate::Aggressive => TimingValues {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(3),
                initial_rtt_timeout: Duration::from_millis(500),
                max_retries: 1,
                scan_delay: Duration::ZERO,
                max_parallel: 500,
            },
            TimingTemplate::Insane => TimingValues {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(1),
                initial_rtt_timeout: Duration::from_millis(250),
                max_retries: 0,
                scan_delay: Duration::ZERO,
                max_parallel: 1000,
            },
        }
    }
}

pub struct TimingValues {
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub initial_rtt_timeout: Duration,
    pub max_retries: u8,
    pub scan_delay: Duration,
    pub max_parallel: usize,
}
```

---

