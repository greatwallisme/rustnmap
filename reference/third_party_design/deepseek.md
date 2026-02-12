# Rustmap 产品设计文档（完整细化版）

**版本**: 1.0.1  
**状态**: 可指导开发  
**目标平台**: Linux x86-64（仅）  
**最后更新**: 2026年2月13日  

---

## 0. 设计总纲

### 0.1 项目定位

Rustmap 是一款完全用 Rust 语言实现、功能完整覆盖 Nmap 7.94 的网络扫描引擎，专为 Linux x86-64 平台深度优化，不承担任何跨平台兼容负担。通过充分利用 Linux 内核特性（AF_PACKET、PACKET_MMAP、SO_ATTACH_BPF、sendmmsg、MSG_ZEROCOPY），达到比 Nmap 更低的资源占用、更高的包处理吞吐量，并彻底解决 Nmap 在脚本更新、指纹库版本管理、零拷贝包捕获等领域的遗留缺陷。

**功能覆盖承诺**：Rustmap 必须完整实现 Nmap 7.94 官方文档列出的所有核心扫描技术与常见选项，并保证输出结果在 95% 以上的测试场景中与 Nmap 严格一致（允许因实现差异导致的极小偏差，如 RTT、时序字段）。

### 0.2 核心设计原则

- **Linux 原生**：所有网络 I/O 均基于 Linux 专用 API，绝不引入 libpcap 等跨平台抽象层（除非作为后备降级）。
- **零拷贝路径**：包捕获和发送必须通过 PACKET_MMAP 环形缓冲区实现，避免用户态内存分配。
- **确定性内存**：热路径中禁止使用 Box、Vec 动态分配，全部使用栈上数组或预分配池。
- **模块正交**：每个功能可独立编译为 Crate，最终通过 rustmap-cli 集成。
- **NSE 现代化**：在兼容 Nmap Lua 脚本生态的同时，增加版本声明、自动更新、沙箱资源限制。
- **可测试性**：所有模块通过 `ScanSession` 上下文依赖注入，支持模拟网络栈与全链路单元测试。

---

## 1. 系统架构（Linux 专用）

```
┌─────────────────────────────────────────────────────────────────────┐
│                           CLI/API 交互层                           │
│  - clap 派生命令行解析                                              │
│  - 流式输出（XML/JSONL/Grepable/脚本小子风格）                     │
│  - ratatui 实时仪表盘                                               │
│  - 会话恢复（--resume）                                             │
├─────────────────────────────────────────────────────────────────────┤
│                        扫描编排引擎 (Scheduler)                    │
│  - 目标展开与分组                                                   │
│  - Nmap T0–T5 时序模板                                              │
│  - 动态 RTT 估计 + 令牌桶速率限制                                   │
│  - 主机间/端口间并发控制                                           │
├─────────────────────────────────────────────────────────────────────┤
│                         扫描功能模块（完全重写）                    │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌────────────┐  │
│  │Host     │ │Port     │ │OS       │ │Service   │ │NSE        │  │
│  │Discovery│ │Scan     │ │Detect   │ │Version   │ │Engine     │  │
│  └─────────┘ └─────────┘ └─────────┘ └──────────┘ └────────────┘  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐                │
│  │Traceroute│ │FTP Bounce│ │Idle Scan│ │IP Proto  │                │
│  │         │ │         │ │         │ │Scan      │                │
│  └─────────┘ └─────────┘ └─────────┘ └──────────┘                │
├─────────────────────────────────────────────────────────────────────┤
│                     Linux 包引擎抽象层 (仅 AF_PACKET)              │
│  - PACKET_MMAP V3 零拷贝收发环                                      │
│  - BPF 过滤器热加载（精确五元组）                                  │
│  - sendmmsg + MSG_ZEROCOPY 批量发送                                │
│  - 可插拔实现（MockEngine 用于单元测试）                           │
├─────────────────────────────────────────────────────────────────────┤
│                   指纹库与 NSE 脚本管理子系统                      │
│  - 版本化本地存储 (MVCC)                                           │
│  - 官方 SVN 同步适配器                                             │
│  - 自动更新调度 (systemd timer)                                    │
│  - SELinux 策略模块（可选）                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.1 核心抽象：扫描会话（ScanSession）

所有功能模块通过 `ScanSession` 上下文交互，便于模拟测试、会话恢复和并行执行。

```rust
pub struct ScanSession {
    pub config: ScanConfig,
    pub target_set: Arc<TargetSet>,
    pub packet_engine: Arc<dyn PacketEngine>,  // trait 化，可注入 MockEngine
    pub output_sink: Arc<dyn OutputSink>,
    pub fingerprint_db: Arc<FingerprintDatabase>,
    pub nse_registry: Arc<ScriptRegistry>,
    pub stats: Arc<ScanStats>,
    pub resume_store: Option<Arc<ResumeStore>>,
}

#[async_trait]
pub trait PacketEngine: Send + Sync {
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize>;
    async fn send_batch(&self, pkts: &[PacketBuffer]) -> Result<usize>;
    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>>;
    fn set_bpf(&self, filter: &BpfProg) -> Result<()>;
    fn local_mac(&self) -> Option<MacAddr>;
    fn if_index(&self) -> c_uint;
}
```

**细化说明**：
- `packet_engine` 通过依赖注入，可替换为 `MockEngine`，其内部使用 `mpsc` 通道模拟收发包，无需 root 权限即可测试扫描逻辑。
- `recv_stream` 返回 `Stream`，便于异步迭代处理包。

---

## 2. 目标管理与展开模块（rustmap-target）

### 2.1 数据结构

```rust
pub enum TargetSpec {
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Ipv4Cidr(Ipv4Cidr),
    Ipv6Cidr(Ipv6Cidr),
    Ipv4Range(Ipv4Addr, Ipv4Addr),
    Ipv6Range(Ipv6Addr, Ipv6Addr),
    Hostname(String),
}

pub struct Target {
    pub addr: IpAddr,
    pub hostnames: Vec<String>,
    pub mac_addr: Option<MacAddr>,
    pub distance: Option<u8>,
    pub status: HostStatus,
    pub ports: BTreeMap<u16, PortState>,
}

pub enum HostStatus { Unknown, Alive, Dead }

pub struct TargetSet {
    targets: Vec<Target>,
    current_index: AtomicUsize,
    rng: ThreadRng,
}
```

### 2.2 核心算法（细化）

#### 2.2.1 目标展开
- **CIDR 展开**：使用 `ipnetwork::IpNetwork::iter()`，对于超大范围（如 /0）给出警告并限制为最大 65536 个地址（遵循 Nmap 行为），防止内存爆炸。
- **范围展开**：IPv4 通过 `Ipv4Addr::from(u32)` 循环递增实现；IPv6 范围通常较小，直接迭代。
- **主机名解析**：
  - 使用 `tokio::net::lookup_host`，通过信号量限制最大并发解析数（默认 `--max-parallel-resolve = 100`）。
  - 解析任务通过 `tokio::spawn_blocking` 调用标准库 `lookup_host`，结果通过 `tokio::sync::mpsc` 送回主任务。
  - 缓存：`DashMap` + `LRU` 策略，默认 2048 条目。
  - 支持 `-n`（完全跳过解析）、`-R`（强制反向 DNS）、`--system-dns`（强制系统解析器）、`--dns-servers`（自定义 DNS）。
- **反向 DNS**：当 `-R` 或未指定 `-n` 且需要输出主机名时，对每个 `IpAddr` 执行 `tokio::net::lookup_addr`，同样使用并发限制。
- **排除逻辑**：对展开后的 `Vec<IpAddr>` 进行 `retain`，支持 IP、CIDR、范围混合排除。排除列表解析方式与包含列表相同，先展开包含列表，再过滤排除项，避免双重展开内存膨胀。
- **随机化**：`--randomize-hosts` 时，组内使用 `rand::seq::SliceRandom::shuffle`。

#### 2.2.2 目标分组
- 按地址顺序切片，每组大小 = `clamp(config.host_group_size, 1, 65536)`。
- 若未指定 `--min-hostgroup` / `--max-hostgroup`，根据 T0–T5 时序模板自动调整：
  - T0: 16, T1: 32, T2: 64, T3: 128, T4: 256, T5: 512。
- 组内支持随机化：若 `randomize_hosts` 为 true，组内 shuffle。

#### 2.2.3 性能优化
- DNS 解析在独立线程池中执行，不阻塞包引擎。
- 解析结果通过 mpsc 通道送回主调度器。

---

## 3. Linux 包引擎模块（rustmap-packet）

### 3.1 套接字初始化

```rust
pub struct AfPacketEngine {
    fd: RawFd,
    rx_ring: Mmap,
    tx_ring: Mmap,
    frame_size: usize,
    block_size: usize,
    frame_count: usize,
    if_index: c_uint,
    mac_addr: [u8; 6],
}

pub struct RingSetup {
    pub block_size: usize,   // 建议 1MB (1<<20)
    pub frame_size: usize,   // 建议 2048 (足够以太网帧)
    pub block_nr: usize,     // 接收环块数，建议 64~256
    pub tx_ring: bool,       // 是否启用发送环（默认 true）
}
```

**细化初始化步骤**：
1. `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`
2. `setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tp_version)` 设置为 `TPACKET_V3`
3. 设置接收环：`setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req)`，其中 `req` 为 `tpacket_req3`
   - `tp_block_size`: 块大小（1MB）
   - `tp_block_nr`: 块数（64~256）
   - `tp_frame_size`: 帧大小（2048）
   - `tp_frame_nr`: 帧数 = (块大小 × 块数) / 帧大小
   - `tp_retire_blk_tov`: 64ms 超时强制刷新块
4. `mmap` 映射接收环，相同方式映射发送环（`PACKET_TX_RING`）
5. 通过 `ioctl(SIOCGIFINDEX)` 获取接口索引，`SIOCGIFHWADDR` 获取 MAC 地址
6. 若启用零拷贝发送，设置 `setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &1)`

### 3.2 零拷贝接收流程

```rust
pub fn recv_ring(&mut self) -> impl Iterator<Item = PacketBuffer> + '_ {
    // 遍历块描述符 tpacket_block_desc，检查 block_status & TP_STATUS_USER
    // 块内遍历帧描述符 tpacket3_hdr，提取 tp_len, tp_sec, tp_nsec, tp_mac
    // 返回 PacketBuffer，数据为 mmap 区域的切片，不拷贝
}
```

**PacketBuffer 结构**：
```rust
pub struct PacketBuffer {
    pub data: Bytes,           // 直接从 mmap 切片，无拷贝
    pub len: usize,
    pub timestamp: Duration,
    pub protocol: u16,        // ETH_P_IP / ETH_P_IPV6 / ETH_P_ARP
}
```

**安全保证**：`PacketBuffer` 内部 `Bytes` 通过 `Bytes::from_shared` 引用 `Mmap` 区域，并注册自定义释放逻辑（将帧归还内核）。多线程共享时，仅索引更新部分加锁，mmap 区域只读无需锁。

### 3.3 批量发送

- **发送环预留**：使用 `PACKET_TX_RING` 预留槽位，Worker 线程填充包头后调用 `send(fd, NULL, 0, MSG_ZEROCOPY)` 触发 DMA。
- **批量系统调用**：`sendmmsg` 封装为 `send_batch(&mut self, packets: &[PacketBuffer]) -> Result<usize>`，一次系统调用发最多 `UIO_MAXIOV` 个包。
- **备选路径**：若不启用 TX 环，直接使用 `sendto + MSG_ZEROCOPY`。
- **零拷贝发送完成通知**：通过 `poll` 等待 `EPOLLERR` 事件，获取 `SO_ZEROCOPY` 完成通知，释放缓冲区。

### 3.4 BPF 过滤器生成器

```rust
pub enum FilterSpec {
    Any,
    Ips(Vec<IpAddr>),
    Ports(Vec<u16>),
    Protocol(IpProtocol),
    And(Box<FilterSpec>, Box<FilterSpec>),
    Or(...),
    Not(...),
}

pub struct BpfProg {
    pub filter: sock_fprog,
}
```

**编译过程**：递归将 `FilterSpec` 转换为 BPF 指令数组。优先使用纯 Rust BPF 生成器（`bpf-sys` 或手动构造），可降级到 `libpcap` 的 `pcap_compile_nopcap`（通过 feature 控制）。

**加载**：`setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog)`。

### 3.5 错误处理（细化）

| 错误码  | 场景                  | 处理策略                                                     |
| ------- | --------------------- | ------------------------------------------------------------ |
| EPERM   | 无 CAP_NET_RAW        | 提示 `setcap cap_net_raw+ep` 或 `sudo`                       |
| ENOBUFS | 环形缓冲区满          | 降速等待 100ms，重试最多 3 次                                |
| ENETDOWN| 网卡 down             | 退出扫描                                                     |
| ENOMEM  | 内存不足              | 减小环形缓冲区大小并重试                                     |
| EINTR   | 系统调用中断          | 自动重试剩余包                                               |

---

## 4. 主机发现模块（rustmap-ping）

### 4.1 Probe trait

```rust
#[async_trait]
pub trait Probe: Send + Sync {
    async fn run(
        &self,
        target: IpAddr,
        engine: &dyn PacketEngine,
        config: &PingConfig,
        rtt_estimator: &RttEstimator,
    ) -> Option<ProbeResult>;
}
```

### 4.2 支持的探测类型（完整覆盖 Nmap）

| 探测类型                | 协议   | 发包构造                                   | 监听条件                         | 超时/重传                     |
| ----------------------- | ------ | ------------------------------------------ | -------------------------------- | ----------------------------- |
| -PS (TCP SYN Ping)      | TCP    | SYN 包到指定端口                           | SYN/ACK 或 RST                  | 3次，动态 RTT                |
| -PA (TCP ACK Ping)      | TCP    | ACK 包                                     | RST（存活）或无响应             | 同上                          |
| -PU (UDP Ping)          | UDP    | 空 UDP 包                                 | ICMP 端口不可达（存活）或无响应 | 同上                          |
| -PY (SCTP Ping)         | SCTP   | SCTP INIT 包                              | INIT-ACK 或 ABORT               | 同上                          |
| -PE (ICMP Echo)         | ICMP   | Echo Request                              | Echo Reply                      | 同上                          |
| -PP (ICMP Timestamp)    | ICMP   | Timestamp Request                        | Timestamp Reply                 | 同上                          |
| -PM (ICMP Netmask)      | ICMP   | Address Mask Request                     | Address Mask Reply              | 同上                          |
| -PO (IP Protocol Ping)  | IP     | IP 包（协议号0~255）                      | 同协议响应或 ICMP 不可达        | 同上                          |
| -PR (ARP Ping)          | ARP    | ARP Request                               | ARP Reply                       | 固定 50ms，无重传           |
| -sn (Ping Scan)         | 组合   | 根据配置选择以上若干种                   | 任一响应即判存活               | —                             |

### 4.3 特殊处理细化

#### ARP 扫描
- 构造以太网帧：目的 MAC `ff:ff:ff:ff:ff:ff`，源 MAC 取自 `PacketEngine.local_mac()`，类型 `ETH_P_ARP`。
- ARP 包：操作 1（request），发送者 MAC 为本机，发送者 IP 为 0.0.0.0（或配置源 IP），目标 MAC 全零，目标 IP 为待探测 IP。
- 等待响应：通过 `recv_stream` 过滤 ARP 包且目标 MAC 为本机、发送者 IP 为探测目标 IP。
- 超时 50ms，无重传。

#### ICMP 时间戳/掩码请求
- 构造 ICMP 包：类型 `Timestamp` (13) 或 `AddressMask` (17)，代码 0，校验和计算使用 `pnet_packet::icmp`。
- 响应匹配对应类型，超时算法与其他探测一致。

#### --traceroute
- 依赖端口扫描结果，选取第一个开放端口（TCP 或 UDP）作为目标。
- 发送 TTL=1 的探测包（与端口扫描类型相同，如 TCP SYN 到开放端口），等待 ICMP 时间超时（type 11）或目标响应。
- 每跳最多发送 3 次探测，超时时间 2×RTT。
- 记录每跳 IP、RTT，直到到达目标或 TTL 达到 30。

---

## 5. 端口扫描模块（rustmap-portscan）

### 5.1 支持的扫描技术（完整覆盖）

| 技术                | 选项 | 实现方式                                                     | 状态机/判定                                       |
| ------------------- | ---- | ------------------------------------------------------------ | ------------------------------------------------- |
| SYN 扫描            | -sS  | 构造 SYN 包，解析响应                                        | 表 5-1                                           |
| TCP Connect 扫描    | -sT  | `tokio::time::timeout` + `TcpStream::connect`，立即关闭      | 连接成功 → Open，失败 → Closed/Filtered         |
| UDP 扫描            | -sU  | UDP 包（可选负载），监听 ICMP 不可达                         | open\|filtered                                  |
| TCP Window 扫描     | -sW  | 构造 SYN，根据 RST 包窗口值非零判 Open                       | 类似 SYN                                        |
| TCP Maimon 扫描     | -sM  | 构造 FIN/ACK，响应 RST 判 Open\|Filtered                    | 类似 SYN                                        |
| TCP ACK 扫描        | -sA  | 构造 ACK，响应 RST 判 Unfiltered                             | 简单判定                                        |
| TCP NULL/FIN 扫描   | -sN/-sF | 无标志位 / FIN，响应 RST 判 Closed                           | 简单判定                                        |
| IP 协议扫描         | -sO  | 枚举 IP 协议号，构造空 IP 包                                 | 监听 ICMP 不可达                                |
| FTP Bounce 扫描     | -b   | FTP PORT 命令代理扫描                                        | 需 FTP 会话                                     |
| Idle 扫描           | -sI  | 利用僵尸机 IP ID 序列                                        | 移植 Nmap 算法                                  |
| SCTP INIT 扫描      | -sY  | SCTP INIT 包                                                 | 类似 SYN                                        |
| SCTP COOKIE-ECHO    | -sZ  | SCTP COOKIE_ECHO                                             | 类似 SYN                                        |

**端口状态枚举**：
```rust
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}
```

### 5.2 统一抽象：`PortScanTechnique` trait

```rust
#[async_trait]
pub trait PortScanTechnique: Send + Sync {
    async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
        engine: &dyn PacketEngine,
        rtt: &RttEstimator,
        retries: u8,
    ) -> PortState;
}
```

### 5.3 SYN 扫描状态机（细化）

| 当前状态   | 事件                    | 动作                       | 下一状态   | 输出状态     |
| ---------- | ----------------------- | -------------------------- | ---------- | ------------ |
| Initial    | 构造并发送SYN           | 存储seq，设置超时          | SentProbe  | -            |
| SentProbe  | 收到SYN/ACK             | 发送RST，记录RTT           | Done       | Open         |
| SentProbe  | 收到RST                 | 记录                       | Done       | Closed       |
| SentProbe  | 收到ICMP unreach (3)    | 检查code                   | Done       | Filtered     |
| SentProbe  | 超时                    | 重传计数 < max?            | Retransmit | -            |
| SentProbe  | 超时且重传已达上限      | 无                         | Done       | Filtered     |
| Retransmit | 重新发送SYN             | 超时时间翻倍               | SentProbe  | -            |

**重传退避**：`timeout = min(initial_timeout * 2^(retry-1), max_rtt_timeout)`。

### 5.4 UDP 扫描细化
- 发送空 UDP 包到目标端口，等待响应。
- **响应类型**：
  - UDP 包返回 → Open
  - ICMP 端口不可达 (type 3, code 3) → Closed
  - ICMP 其他不可达 (code 0,1,2,9,10,13) → Filtered
  - 无响应 → Open|Filtered
- 若 `--version-intensity` 较高，根据端口号发送常见协议探测数据（DNS、NTP、SNMP 等）。

### 5.5 IP 协议扫描细化
- 枚举协议号 0-255（可跳过已实现协议的探测）。
- 构造 IP 包，协议字段设为指定值，无上层数据（或空数据）。
- **响应类型**：
  - 收到相同协议的 IP 包 → Open
  - ICMP 协议不可达 (type 3, code 2) → Closed
  - ICMP 其他不可达或超时 → Filtered

### 5.6 空闲扫描 (Idle Scan) 算法移植
1. **探测僵尸机 IP ID**：发送 SYN/ACK 或 RST 包触发响应，解析 IP ID。
2. **伪造源 IP**：伪造 IP 包源地址为僵尸机，发送 SYN 包到目标端口。
3. **再次探测 IP ID**：若 IP ID 增加 2，则目标端口开放；若增加 1，则关闭或过滤。
4. **处理回绕**：考虑 16 位 IP ID 回绕，增量计算。

---

## 6. 操作系统指纹识别（rustmap-os）

### 6.1 测试序列
- 完整实现 T2–T7、IE、U1、TSeq 等 Nmap 标准测试集。
- 所有 TCP 测试包均携带 Nmap 标准选项（MSS、WScale、Timestamp、SACK）。

### 6.2 nmap-os-db 解析器
- 使用 `nom` 或手工解析，支持多行指纹。
- 指纹行格式：`Fingerprint <OS name>\n<Class ...>\n...<tests>`。
- 每个测试以 `TSeq`、`T1`、`T2` 等开头，后跟键值对。
- 存储结构：`HashMap<String, OsFingerprint>`，键为指纹名称。
- IPv6 指纹库：`nmap-os-db-ipv6` 类似解析。

### 6.3 匹配引擎
- **权重表**：硬编码为静态数组，从 Nmap 源码 `fprint_substr.c` 提取。
- **匹配过程**：对每个测试响应，计算与指纹库对应测试的**最长公共子串**长度，乘以权重，累加得分。
- **决策**：得分超过阈值直接判定，否则输出 guess（相似度前 5 的指纹及其百分比）。
- **`--osscan-limit`**：仅对至少开放一个 TCP 端口和一个关闭端口的主机执行。
- **`--osscan-guess`**：返回相似度前 5 的指纹及百分比。

---

## 7. 服务版本探测（rustmap-service）

### 7.1 nmap-service-probes 解析
- 文件格式：`Probe <protocol> <probename> <probestring>`，后跟多个 `match` 行。
- 正则表达式使用 `bstr::Regex`（字节正则），支持 Nmap 特殊语法：`%s` 插入端口，`%I` 插入 IP 等。
- 预编译所有正则表达式，按探针名索引，缓存于 `Lazy<HashMap<ProbeName, Vec<CompiledRegex>>>`。
- **NULL 探针**：空探测，等待 banner（连接建立后服务发送的第一批数据），超时 5s（可配置）。

### 7.2 探针执行引擎
1. **TCP 端口**：首先尝试 NULL 探针，若匹配则直接提取服务版本。
2. **探针选择**：根据端口号、服务猜测选择探针组（如 80 → "GetRequest"；443 → "SSLv3"、"TLS"）。
3. **强度控制**（`--version-intensity` 0–9）：
   - 强度 ≥7：发送所有探针。
   - 强度 ≤3：跳过 Nmap 标记为“稀有”（rarity > 7）的探针。
4. **并发**：同一主机多个探针可并行发送（需避免干扰），通过信号量控制。
5. **响应匹配**：对响应遍历匹配规则，一旦匹配则停止，提取服务名、版本、设备类型等信息。
6. **未匹配**：标记为 unknown。

### 7.3 SSL/TLS 检测
- 若端口为 443, 465, 993, 995 等或探测到 "SSL"、"TLS" 标志，启动 SSL 握手。
- 使用 `rustls` 作为客户端进行握手，获取证书链。
- 解析证书提取 `commonName` 和 `subjectAltName`。
- **`ssl-enum-ciphers` 等效逻辑**：实现为 Rust 代码，枚举服务器支持的加密套件和协议版本。

---

## 8. NSE 脚本引擎（rustmap-nse）

### 8.1 Lua API 实现标准

基于 `mlua`，实现 Nmap 7.94 官方脚本 API 子集：

**必须实现的 `nmap` 表函数**：
- `nmap.new_socket()` → userdata，包含 `connect`, `send`, `receive`, `close` 方法。
- `nmap.get_ports(host)` → 端口列表。
- `nmap.get_port_state(host, port)` → 获取端口状态。
- `nmap.set_port_state(host, port, state)` → 修改端口状态。
- `nmap.register_rule()` → 注册规则。
- `nmap.registry` → 全局 Lua 表，存储于 Rust 侧 `HashMap<String, Value>`，跨脚本共享。
- `nmap.this_host()`, `nmap.this_ip()` → 当前目标信息。
- `shortport` 模块：通过纯 Lua 实现，调用上述 API。
- DNS 解析：`nmap.resolve(name)` 调用 Rust 的 `lookup_host` 异步函数，阻塞协程。

**网络限制**：
- 所有 socket 操作通过 `ScanSession` 的包引擎转发，仅允许连接目标主机。
- 禁止访问本地文件系统。

### 8.2 沙箱实现
- **环境**：`mlua::Lua::sandbox(true)` 创建受限环境。
- **禁用模块**：`lua.load_from_std_lib(false)`，手动添加安全模块（`string`, `table`, `math`, `coroutine` 等）。
- **内存限制**：`mlua::Lua::set_memory_limit(10 * 1024 * 1024)`（需 feature）。
- **CPU 限制**：使用 `mlua::Lua::hook` 设置指令计数钩子，每 1000 条指令检查时间，超时 5s 则强制终止脚本。
- **子进程模式（备选）**：通过 `setrlimit(RLIMIT_CPU)` 限制 CPU 时间，通过 stdin/stdout 通信。

### 8.3 脚本获取与更新（Linux 专属）

- **仓库适配器**：
  ```rust
  pub struct NmapSvnRepository {
      base_url: String,
      http_client: reqwest::Client,
  }
  ```
- **自动更新机制**：
  - systemd 用户计时器：`rustmap-update-scripts.timer`，每周执行 `rustmap --script-update-all --quiet`。
  - 若 systemd 不可用，回退至 crontab 条目生成。
- **版本锁定**：
  - 脚本首行需包含 `-- @nse_version X.Y.Z`。
  - 引擎主版本 < 要求版本 → 拒绝加载。
- **原子切换**：
  - 新版本下载至 `/var/lib/rustmap/nse/tmp_rXXXXX`。
  - 下载完成后 `rename` 为 `rXXXXX`。
  - 原子替换符号链接 `current -> rXXXXX`。

### 8.4 脚本输出捕获
- 脚本的 `stdout`/`stderr` 通过 `mlua` 重定向到 Rust 侧缓冲区，最终合并到主机/端口输出结果。
- 支持 `--script-trace` 显示脚本网络收发详情，模拟 Nmap 的 `<script> -> ...` 输出。

---

## 9. 指纹库同步与版本管理（rustmap-fingerprint）

### 9.1 Linux 存储路径（MVCC）

```
/var/lib/rustmap/fingerprint/
├── osdb/
│   ├── r20260213_1/
│   │   └── nmap-os-db
│   └── current -> r20260213_1
├── probes/
│   ├── r20260213_1/
│   │   └── nmap-service-probes
│   └── current -> r20260213_1
└── ipv6_osdb/
    └── ...
```

**权限**：`root:rustmap 0755`，普通用户通过 `setgid` 组访问。

### 9.2 原子切换与回滚
- **原子切换**：使用 `symlink` 系统调用原子性：`rename(tmp_link, "current")`。
- **回滚机制**：更新前创建备份（硬链接），若更新失败或校验和不符，恢复符号链接。
- **日志记录**：`/var/log/rustmap/fp-update.log`。

### 9.3 自动更新调度
- systemd timer：每周二凌晨 3 点执行 `rustmap --fp-update-all --quiet`。
- 支持配置文件 `/etc/rustmap/fp-update.toml` 自定义更新源、代理。

---

## 10. 输出与报告模块（rustmap-output）

### 10.1 流式输出架构

```rust
pub trait OutputSink: Send + Sync {
    fn emit_host(&self, host: &HostResult) -> Result<()>;
    fn emit_port(&self, host_ip: IpAddr, port: &PortResult) -> Result<()>;
    fn flush(&self) -> Result<()>;
}
```

**实现细化**：
- **XmlSink**：基于 `xml::writer::EventWriter`，主机完成立即写入 `<host>`，严格遵循 `nmap.xsd` 顺序。
- **JsonLinesSink**：每端口一行 JSON 对象（也可主机完成后输出主机级 JSON）。
- **GrepableSink**：主机完成时拼接所有端口输出，格式 `Port: <proto> <port> <state> <service>`。
- **ScriptKiddieSink（-oS）**：模拟 Nmap 的“脚本小子”风格输出。
- **AllSink（-oA）**：同时写入三种格式。

**XML 必须包含字段**：
`<address>`, `<hostnames>`, `<ports>`, `<os>`, `<distance>`, `<uptime>`, `<tcpsequence>`, `<ipidsequence>`, `<tcptssequence>`。

**样式表**：支持 `--stylesheet` 嵌入 `xml-stylesheet` 处理指令。

### 10.2 交互式仪表盘
- **框架**：`ratatui` + `crossterm`，独立线程每秒刷新 10 次。
- **数据源**：`Arc<DashMap<IpAddr, HostSummary>>`，扫描每完成一个主机更新一次（仅存储摘要：状态、开放端口数等）。
- **键盘命令**：`p` 暂停/继续，`q` 优雅退出并保存会话，`v` 切换详细视图。
- **通信**：通过 `tokio::sync::mpsc` 通道向主线程发送命令。

---

## 11. 时序与性能控制

### 11.1 Nmap T0–T5 时序模板（同原文档）

| 模板 | min_rtt | max_rtt | init_rtt | max_parallel_hosts | max_parallel_ports | max_retries | host_group_size | max_rate (PPS) |
| ---- | ------- | ------- | -------- | ------------------ | ------------------ | ----------- | --------------- | -------------- |
| T0   | 100ms   | 5s      | 1s       | 1                  | 1                  | 10          | 16              | 10             |
| T1   | 100ms   | 2s      | 500ms    | 2                  | 4                  | 6           | 32              | 50             |
| T2   | 100ms   | 1.3s    | 400ms    | 4                  | 8                  | 4           | 64              | 200            |
| T3   | 100ms   | 1s      | 300ms    | 8                  | 16                 | 3           | 128             | 500            |
| T4   | 100ms   | 800ms   | 250ms    | 16                 | 32                 | 2           | 256             | 1000           |
| T5   | 50ms    | 500ms   | 150ms    | 32                 | 64                 | 1           | 512             | 5000           |

### 11.2 动态 RTT 估计器

```rust
pub struct RttEstimator {
    samples: VecDeque<Duration>,
    ema_alpha: f64,
    min_rtt: Duration,
    max_rtt: Duration,
}

impl RttEstimator {
    pub fn update(&mut self, rtt: Duration);
    pub fn timeout(&self) -> Duration; // max(avg + 2*stddev, min_rtt * 2)
}
```

- 滑动窗口 20 样本，指数移动平均（α=0.5）。
- 初始值取自模板或 `--initial-rtt-timeout`。

### 11.3 令牌桶速率限制
- 使用 `governor::RateLimiter`，配额 = `--max-rate` 或模板值。
- **粒度**：全局包发送限流（默认），也可按主机限流（`--host-rate`）。
- 发包前调用 `limiter.until_ready().await`。
- 支持 `--min-rate` 强制最低速率（忽略模板）。

### 11.4 并发控制
- **全局并发主机数**：`Semaphore::new(config.max_parallel_hosts)`。
- **每主机并发端口数**：`Semaphore::new(config.max_parallel_ports)`。
- TCP Connect 扫描并发：独立信号量，默认为 128。

---

## 12. 会话恢复（--resume）

### 12.1 SQLite 存储

数据库路径：`~/.local/share/rustmap/sessions/scan_<timestamp>.db`

**表结构**：
```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE hosts (
    ip TEXT PRIMARY KEY,
    status TEXT,
    last_scan_time INTEGER   -- unix timestamp
);
CREATE TABLE ports (
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service TEXT,
    version TEXT,
    PRIMARY KEY (ip, port, protocol)
);
```

- 每扫描完一个主机，插入/替换 `hosts` 和 `ports` 记录。
- 使用事务批处理，每 10 个主机 commit。
- Ctrl+C 自动保存当前进度。

### 12.2 恢复流程

1. 扫描开始前检查 `--resume <session-id>`（可以是文件路径或会话名称）。
2. 加载已完成主机、端口状态，从断点继续。
3. 输出时附加备注 `# Resumed from session ...`。

---

## 13. 测试策略（Linux 原生）

### 13.1 单元测试

- **MockEngine**：提供 `mpsc` 通道模拟收发包，无需 root 权限。
- **端口扫描**：对每种扫描技术，构造模拟响应序列，验证状态机转换和最终状态。
- **指纹匹配**：预置响应样本，验证得分和输出指纹。
- **BPF 生成器**：验证生成的过滤器逻辑正确，测试各种 `FilterSpec`。

### 13.2 集成测试

**自动化测试脚本**：`tests/integration.sh` 或 Python 驱动。

**对比测试**：
- 同时运行 `nmap` 和 `rustmap` 扫描同一靶机集。
- 使用 `lxml` 解析 XML 输出，比较主机数量、端口状态、服务名、OS 指纹等，允许误差（RTT、随机顺序）。
- 差异率目标 < 0.5%。

**网络模拟**：使用 `tc` 注入延迟、丢包、限速。

### 13.3 模糊测试

- 对 `nmap-os-db` 解析器 fuzz：`cargo fuzz` 目标解析任意二进制数据。
- 对 BPF 生成器 fuzz：生成任意 `FilterSpec` 并编译，验证 BPF 加载不 panic。
- 对包解析器 fuzz：畸形包输入，验证无内存安全漏洞。

### 13.4 性能基准

使用 `criterion` 对以下场景基准测试：

| 场景                         | Nmap 7.94      | Rustmap 目标   | 优化手段                         |
| ---------------------------- | -------------- | -------------- | -------------------------------- |
| 本地网络 SYN 扫描 65535 端口 | 45万 PPS (多核) | ≥80万 PPS (单核) | PACKET_MMAP + 零拷贝 + sendmmsg |
| 全互联网扫描（随机1k目标）   | 内存 ~200MB    | ≤50MB          | 无动态分配、流式处理             |
| 服务版本探测（-sV）          | 2.3倍SYN时间   | ≤1.5倍SYN时间  | 探针并行、响应复用               |

### 13.5 【新增】测试用靶机环境设计

#### 13.5.1 设计目标
构建一套可复现、自动化、覆盖广泛的操作系统与服务靶机环境，用于 Rustmap 与 Nmap 的功能对等验证、性能测试及稳定性测试。要求：
- 涵盖 Nmap 官方测试套件涉及的操作系统、服务、脆弱点。
- 支持 Linux、Windows、网络设备等常见系统指纹。
- 支持 IPv4 和 IPv6。
- 模拟网络延迟、丢包、限速等复杂场景。
- 可一键部署、重置，并自动运行对比测试。

#### 13.5.2 技术选型
- **容器化**：Docker + Docker Compose（Linux 靶机）。
- **Windows 靶机**：使用 Wine 运行轻量级服务，或通过 QEMU/KVM 运行 Windows 虚拟机（备用方案）。
- **网络模拟**：Linux `tc`（netem）在容器内或宿主机网桥设置。
- **配置管理**：Dockerfile 自定义镜像 + 环境变量。
- **自动化测试**：Python 脚本 + pytest，驱动 nmap 和 rustmap 并发扫描，对比输出。

#### 13.5.3 靶机清单

| 名称              | 操作系统/服务                     | 用途                         | 开放端口（示例）                     |
| ----------------- | --------------------------------- | ---------------------------- | ------------------------------------ |
| target-linux-1    | Ubuntu 22.04 LTS                 | 基础 Linux 指纹             | 22,80,443,3306,8080                 |
| target-linux-2    | CentOS 7                         | 老版本 Linux 指纹           | 21,25,111,514                       |
| target-linux-3    | Debian 11 (OpenWrt 模拟)         | 嵌入式 Linux 指纹           | 53,80,443                            |
| target-win-1      | Windows Server 2022 (Wine)       | Windows 指纹（部分）        | 445,3389,5985                       |
| target-win-2      | Windows 10 (Wine)                | 桌面 Windows 指纹           | 135,139,445                         |
| target-net-1      | FreeBSD 13.2                     | BSD 指纹                    | 22,80,443                            |
| target-net-2      | OpenBSD 7.4                      | OpenBSD 指纹                | 22,80                                |
| target-ipv6       | Ubuntu 22.04 IPv6                | IPv6 扫描测试               | 22,80 (IPv6 only)                   |
| target-service-1  | Nginx + MySQL + Redis           | 服务版本探测                | 80,443,3306,6379                    |
| target-service-2  | Apache Tomcat + SSH             | Web 服务                    | 8080,22                              |
| target-service-3  | DNS + SNMP + NTP                | UDP 服务探测                | 53,161,123                          |
| target-udp        | OpenDNS 模拟                    | UDP 端口扫描                | 53,161,123,500,4500                |
| target-ftp-bounce | vsftpd (允许FTP代理)            | FTP Bounce 扫描            | 21                                   |
| target-idle       | 僵尸机模拟（递增IP ID）         | Idle 扫描                  | 任意端口                             |
| target-ratelimit  | 限速服务（tc + iptables）       | 抗限速测试                  | 22,80,443                           |
| target-firewall   | 复杂防火墙（iptables规则）      | 过滤响应测试                | 部分端口开放，部分丢弃              |
| target-all-closed | 无开放端口                      | 扫描性能基线                | 无                                  |

#### 13.5.4 网络拓扑

```
宿主机（运行 rustmap/nmap 扫描器）
    │
    ├─ docker network: rustmap-bridge (172.20.0.0/24, fd00::/64)
    │    ├─ target-linux-1 (172.20.0.10, fd00::10)
    │    ├─ target-linux-2 (172.20.0.11)
    │    ├─ ...
    │    └─ target-idle   (172.20.0.20)
    │
    └─ (可选) QEMU 虚拟机网段（独立 bridge）
         └─ windows-vm (192.168.100.10)
```

所有 Linux 靶机基于同一基础镜像，通过环境变量配置启动的服务。网络延迟/丢包通过 `docker exec <容器> tc qdisc add dev eth0 root netem ...` 注入。

#### 13.5.5 自动化部署与测试

**部署脚本**（`tests/setup_targets.sh`）：
1. 构建基础镜像（安装 openssh-server、常用服务）。
2. 使用 docker-compose up -d 启动所有容器。
3. 为每个容器分配静态 IP（通过 docker network connect 并指定 IP）。
4. 配置 netem：`docker exec target-ratelimit tc qdisc add dev eth0 root netem delay 100ms loss 1%`。

**测试驱动**（`tests/run_compare.py`）：
- 参数：扫描类型（-sS, -sT, -sU, -O, -sV 等），目标列表（支持分组）。
- 并行运行 nmap 和 rustmap，采集 XML 输出。
- 使用 `lxml` 解析，比较主机数量、端口状态、服务名、OS 指纹等，允许误差。
- 生成差异报告，统计通过率。

**持续集成**：
- GitHub Actions 或本地 GitLab CI：启动服务，运行测试，上传报告。
- 定时任务：每周执行全量对比测试，捕获回归。

#### 13.5.6 靶机维护
- 所有 Dockerfile 存放在 `tests/docker/` 目录下。
- 基础镜像 `rustmap-target-base` 包含 systemd 模拟（使用 `docker-systemctl-replacement`）以便启动多个服务。
- Windows 虚拟机镜像使用 packer 构建，提供 vagrant box。

---

## 14. 工程交付物清单

### 14.1 代码库结构

```
rustmap/
├── Cargo.toml (workspace)
├── crates/
│   ├── rustmap-core/          # 会话、配置、错误类型
│   ├── rustmap-packet/        # 零拷贝引擎
│   ├── rustmap-target/        # 目标展开
│   ├── rustmap-ping/          # 主机发现
│   ├── rustmap-portscan/      # 端口扫描
│   ├── rustmap-os/            # OS指纹
│   ├── rustmap-service/       # 服务探测
│   ├── rustmap-nse/           # Lua脚本引擎
│   ├── rustmap-fingerprint/   # 指纹库管理
│   ├── rustmap-output/        # 输出格式化
│   ├── rustmap-cli/           # 命令行入口
│   └── rustmap-tui/           # 交互界面
├── tests/                     # 集成测试
│   ├── docker/                # 靶机Dockerfile
│   ├── docker-compose.yml     # 靶机编排
│   ├── setup_targets.sh       # 部署脚本
│   └── run_compare.py         # 对比测试驱动
├── benches/                   # 性能基准
├── nse-scripts/               # 内置脚本（来自Nmap）
├── systemd/                   # 服务单元文件
│   ├── rustmap-update-scripts.service
│   ├── rustmap-update-scripts.timer
│   ├── rustmap-update-fingerprint.service
│   └── rustmap-update-fingerprint.timer
├── selinux/                   # SELinux 策略模块（若启用）
└── docs/                      # 用户手册、开发者指南
```

### 14.2 文档产出

- **用户手册**（Markdown + man page）：
  - 安装（cargo install / .deb 包）
  - 权限配置（setcap cap_net_raw+ep）
  - 自动更新配置
  - 命令行详细参考
  - 典型用例
- **开发者文档**：
  - 模块架构图
  - 扩展新扫描类型指南
  - NSE 脚本编写教程
- **部署指南**：
  - DEB 包构建脚本
  - 静态链接二进制发布流程

---

## 15. 里程碑与开发阶段

| 阶段 | 时间 | 交付物                                                     | 备注                               |
| ---- | ---- | ---------------------------------------------------------- | ---------------------------------- |
| P0   | 2周  | rustmap-packet + rustmap-target + 基础 CLI，实现 SYN 扫描单目标，输出 XML | 可演示基础扫描                     |
| P1   | 3周  | 全部主机发现 + 所有 TCP 扫描 + UDP 扫描                   | 通过 TCP/IP 基础测试套件           |
| P2   | 2周  | OS 指纹 + 服务版本探测（基础）                            | 与 Nmap 对比误差 < 5%             |
| P3   | 3周  | NSE 引擎（加载+运行+沙箱）+ 常用脚本                      | 通过 Nmap 官方脚本测试集          |
| P4   | 2周  | 输出全格式 + 交互仪表盘 + 会话恢复                        | 交付 Beta 版                       |
| P5   | 2周  | 指纹库自动更新 + 打包 + 性能调优                          | 交付 RC 版，开放社区测试           |

---

品。
