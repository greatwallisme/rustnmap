# 5. 项目结构与模块划分

> **版本**: 1.0.0 (2.0 开发中)
> **最后更新**: 2026-02-17

---

## 5.0 RustNmap 2.0 项目概览

### 5.0.1 Crate 列表 (1.0 + 2.0)

| Crate | 用途 | 状态 |
|-------|------|------|
| `rustnmap-common` | 公共类型、工具函数、错误处理、ServiceDatabase | 1.0 |
| `rustnmap-net` | 原始套接字、数据包构造 | 1.0 |
| `rustnmap-packet` | PACKET_MMAP V2 零拷贝引擎 | 1.0 |
| `rustnmap-target` | 目标解析、主机发现 | 1.0 |
| `rustnmap-scan` | 端口扫描实现 (12 种扫描类型) | 1.0 |
| `rustnmap-fingerprint` | 服务/OS 指纹匹配、数据库加载 (MAC/RPC/协议) | 1.0 |
| `rustnmap-nse` | Lua 脚本引擎 (进程隔离) | 1.0 |
| `rustnmap-traceroute` | 网络路由追踪 | 1.0 |
| `rustnmap-evasion` | 防火墙/IDS 规避技术 | 1.0 |
| `rustnmap-cli` | 命令行界面 (lexopt 解析器) | 1.0 |
| `rustnmap-core` | 核心编排器、ScanSession DI 容器 | 1.0 |
| `rustnmap-output` | 输出格式化 (7 种格式) | 1.0 |
| `rustnmap-benchmarks` | 性能基准测试 | 1.0 |
| `rustnmap-stateless-scan` | Masscan 式无状态高速扫描 (SYN Cookie) | **2.0 NEW** |
| `rustnmap-scan-management` | 扫描持久化 (SQLite)、扫描对比、YAML 配置 | **2.0 NEW** |
| `rustnmap-vuln` | 漏洞情报 (CVE/CPE/EPSS/KEV) | **2.0 NEW** |
| `rustnmap-api` | REST API / Daemon 模式 (Axum) | **2.0 NEW** |
| `rustnmap-sdk` | Rust SDK (Builder API，支持本地和远程扫描) | **2.0 NEW** |

**总计**: 13 个 (1.0) + 5 个 (2.0 新增) = **18 个 Crate**

---

## 5.1 Cargo Workspace 结构

```
crates/
├── rustnmap-common/           # 公共类型、错误处理、ServiceDatabase
├── rustnmap-net/              # 原始套接字、数据包构造
├── rustnmap-packet/           # PACKET_MMAP V2 零拷贝引擎
│   └── src/ (engine, mmap, zero_copy, async_engine, bpf, stream)
├── rustnmap-target/           # 目标解析、主机发现
├── rustnmap-scan/             # 端口扫描实现 (12 种扫描类型)
├── rustnmap-fingerprint/      # 服务/OS 指纹匹配
│   └── src/database/ (mac, rpc, protocols, service/, os/)
├── rustnmap-nse/              # Lua 脚本引擎 (进程隔离)
│   ├── src/ (engine, libs, parser, process_executor)
│   └── src/bin/runner.rs      # rustnmap-nse-runner 独立进程
├── rustnmap-traceroute/       # 网络路由追踪
├── rustnmap-evasion/          # 防火墙/IDS 规避技术
├── rustnmap-output/           # 输出格式化 (7 种格式)
│   └── src/ (formatter, models, database_context)
├── rustnmap-core/             # 核心编排器、ScanSession DI 容器
│   └── src/ (orchestrator, session, timing)
├── rustnmap-cli/              # 命令行界面 (lexopt)
├── rustnmap-benchmarks/       # 性能基准测试
├── rustnmap-stateless-scan/   # 无状态高速扫描 (SYN Cookie)
├── rustnmap-scan-management/  # 扫描持久化、对比、YAML 配置
├── rustnmap-vuln/             # 漏洞情报 (CVE/CPE/EPSS/KEV)
├── rustnmap-api/              # REST API (Axum)
└── rustnmap-sdk/              # Rust SDK (Builder API)

data/                          # Nmap 兼容数据库文件
├── nmap-service-probes
├── nmap-os-db
├── nmap-mac-prefixes
├── nmap-rpc
└── nmap-payloads

scripts/                       # NSE 脚本库 (Nmap 兼容)
```

## 5.2 依赖关系图

### 5.2.1 实际内部依赖关系

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Internal Crate Dependencies                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  rustnmap-common          (无内部依赖 - 基础类型层)                 │
│     ^                                                               │
│     ├── rustnmap-net                                               │
│     │      ^                                                       │
│     │      ├── rustnmap-target                                     │
│     │      ├── rustnmap-evasion                                    │
│     │      └── rustnmap-scan ──> rustnmap-packet                   │
│     │                                                               │
│     ├── rustnmap-packet                                            │
│     │      ^                                                       │
│     │      └── rustnmap-scan                                       │
│     │                                                               │
│     ├── rustnmap-fingerprint ──> rustnmap-net, rustnmap-packet     │
│     │      ^                                                       │
│     │      └── rustnmap-output                                     │
│     │                                                               │
│     ├── rustnmap-nse ──> rustnmap-target                           │
│     │                                                               │
│     ├── rustnmap-traceroute ──> rustnmap-net                       │
│     │                                                               │
│     ├── rustnmap-vuln ──> rustnmap-output                          │
│     │      ^                                                       │
│     │      └── rustnmap-scan-management                            │
│     │                                                               │
│     └── rustnmap-core ──> common, net, packet, scan, target,       │
│            evasion, fingerprint, nse, traceroute, output           │
│            ^                                                        │
│            ├── rustnmap-cli ──> common, core, scan, target,        │
│            │       fingerprint, nse, output, evasion, vuln,        │
│            │       scan-management                                  │
│            │                                                        │
│            ├── rustnmap-api ──> core, output, scan-management      │
│            │                                                        │
│            ├── rustnmap-sdk ──> core, output, target, evasion,     │
│            │       common                                           │
│            │                                                        │
│            └── rustnmap-stateless-scan ──> core, packet, output    │
│                                                                     │
│  rustnmap-benchmarks ──> common, fingerprint, net, nse, packet,    │
│     scan, target                                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2.2 关键外部依赖

| 依赖 | 用途 |
|------|------|
| tokio | 异步运行时 |
| mlua | Lua 5.4 绑定 (NSE 脚本) |
| pnet | 数据包处理 |
| lexopt | CLI 参数解析 |
| serde/serde_json | 序列化 |
| regex | 正则匹配 |
| trust-dns | DNS 解析 |
| rustls/tokio-rustls | TLS/SSL |
| axum | REST API 框架 (2.0) |
| rusqlite | SQLite 数据库 (2.0) |
| reqwest | HTTP 客户端 (NVD API) |
| x509-parser | 证书解析 |

### 5.2.3 完整依赖链

```
rustnmap-cli ──> rustnmap-core ──> rustnmap-scan ──> rustnmap-net
                              │                       rustnmap-packet
                              │                       rustnmap-target
                              │                       rustnmap-evasion
                              ├──> rustnmap-nse ──> rustnmap-target
                              ├──> rustnmap-fingerprint ──> rustnmap-net
                              │                          rustnmap-packet
                              ├──> rustnmap-traceroute ──> rustnmap-net
                              └──> rustnmap-output ──> rustnmap-fingerprint

rustnmap-sdk ──> rustnmap-core (本地扫描)
             ──> rustnmap-output, rustnmap-target, rustnmap-evasion

rustnmap-api ──> rustnmap-core
             ──> rustnmap-output
             ──> rustnmap-scan-management ──> rustnmap-vuln ──> rustnmap-output
```

---

## 5.3 rustnmap-packet 详细结构 (PACKET_MMAP V2 重构)

> **重要**: 此 Crate 是性能优化的核心，需要完全重构以实现真正的 PACKET_MMAP V2 环形缓冲区。

### 5.3.1 文件结构 (重构后)

```
crates/rustnmap-packet/
├── Cargo.toml                     # 依赖配置
│   [dependencies]
│   rustnmap-common = { path = "../rustnmap-common" }
│   tokio = { version = "1.42", features = ["net", "io-util", "rt-multi-thread", "sync"] }
│   bytes = "1.9"
│   libc = "0.2"
│   socket2 = "0.5"
│   thiserror = "2.0"
│
├── src/
│   ├── lib.rs                     # 公开 API 导出
│   │   pub mod engine;
│   │   pub mod mmap;
│   │   pub mod async_engine;
│   │   pub mod bpf;
│   │   pub mod stream;
│   │   pub mod stats;
│   │   pub mod error;
│   │   pub mod sys;
│   │
│   ├── engine.rs                  # PacketEngine trait 定义
│   │   pub trait PacketEngine: Send + Sync
│   │   pub struct PacketBuffer { data: Bytes, len, timestamp, ... }
│   │   pub struct EngineStats { packets_received, packets_dropped, ... }
│   │
│   ├── mmap.rs                    # MmapPacketEngine 核心实现
│   │   pub struct MmapPacketEngine { fd, config, ring_ptr, ... }
│   │   pub struct RingConfig { block_count, block_size, frame_size }
│   │   pub struct Tpacket2Hdr { tp_status, tp_len, tp_snaplen, ... }
│   │   impl MmapPacketEngine:
│   │     - fn new(interface, config) -> Result<Self>
│   │     - fn setup_ring_buffer(&mut self) -> Result<()>
│   │     - fn mmap_ring(&mut self) -> Result<NonNull<u8>>
│   │     - fn current_frame_ptr(&self) -> *mut Tpacket2Hdr
│   │     - fn advance_frame(&mut self)
│   │     - fn try_recv(&mut self) -> Result<Option<PacketBuffer>>
│   │
│   ├── async_engine.rs            # AsyncPacketEngine (Tokio 集成)
│   │   pub struct AsyncPacketEngine { engine, async_fd, packet_tx, packet_rx }
│   │   impl AsyncPacketEngine:
│   │     - async fn new(interface, config) -> Result<Self>
│   │     - async fn start(&mut self) -> Result<()>
│   │     - async fn recv(&mut self) -> Result<Option<PacketBuffer>>
│   │     - async fn send(&self, packet) -> Result<usize>
│   │     - async fn stop(&mut self) -> Result<()>
│   │
│   ├── bpf.rs                     # BPF 过滤器
│   │   pub struct BpfFilter { instructions: Vec<sock_filter> }
│   │   pub struct BpfProgram { bf_len, bf_insns }
│   │   impl BpfFilter:
│   │     - fn compile(expr: &str) -> Result<Self>
│   │     - fn attach(&self, fd: i32) -> Result<()>
│   │     - fn tcp_dst_port(port: u16) -> Self
│   │     - fn udp_dst_port(port: u16) -> Self
│   │     - fn icmp() -> Self
│   │
│   ├── stream.rs                  # PacketStream (impl Stream)
│   │   pub struct PacketStream { engine: Arc<Mutex<AsyncPacketEngine>> }
│   │   impl Stream for PacketStream:
│   │     - fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<PacketBuffer>>
│   │
│   ├── stats.rs                   # 统计信息
│   │   pub struct EngineStats {
│   │     packets_received: AtomicU64,
│   │     packets_dropped: AtomicU64,
│   │     bytes_received: AtomicU64,
│   │     filter_accepts: AtomicU64,
│   │     filter_rejects: AtomicU64,
│   │   }
│   │
│   ├── error.rs                   # 错误类型定义
│   │   pub enum PacketError {
│   │     SocketCreation(io::Error),
│   │     MmapFailed(io::Error),
│   │     InvalidConfig(String),
│   │     InterfaceNotFound(String),
│   │     BpfError(String),
│   │     ChannelClosed,
│   │   }
│   │
│   └── sys/                       # Linux 系统调用封装
│       ├── mod.rs                 # 导出所有 sys 模块
│       ├── tpacket.rs             # TPACKET_V2 常量和结构
│       │   pub const TPACKET_V2: i32 = 2;
│       │   pub const TP_STATUS_KERNEL: u32 = 0;
│       │   pub const TP_STATUS_USER: u32 = 1;
│       │   pub const TP_STATUS_COPY: u32 = 2;
│       │   pub const TP_STATUS_LOSING: u32 = 4;
│       │   pub const TP_ALIGNMENT: usize = 16;
│       │
│       ├── if_packet.rs           # AF_PACKET 常量
│       │   pub const AF_PACKET: i32 = 17;
│       │   pub const ETH_P_ALL: u16 = 0x0003;
│       │   pub const ETH_P_IP: u16 = 0x0800;
│       │   pub const ETH_P_IPV6: u16 = 0x86DD;
│       │   pub const ETH_P_ARP: u16 = 0x0806;
│       │   pub const PACKET_MMAP: i32 = 8;
│       │   pub const PACKET_RX_RING: i32 = 5;
│       │   pub const PACKET_TX_RING: i32 = 7;
│       │   pub const PACKET_ADD_MEMBERSHIP: i32 = 1;
│       │   pub const PACKET_DROP_MEMBERSHIP: i32 = 2;
│       │
│       └── sock_addr.rs           # 套接字地址结构
│           pub struct SockaddrLl {
│             sll_family: u16,
│             sll_protocol: u16,
│             sll_ifindex: i32,
│             sll_hatype: u16,
│             sll_pkttype: u8,
│             sll_halen: u8,
│             sll_addr: [u8; 8],
│           }
│
└── tests/                         # 集成测试 (需要 root)
    ├── mmap_ring_test.rs          # 环形缓冲区测试
    ├── async_engine_test.rs       # 异步引擎测试
    └── bpf_filter_test.rs         # BPF 过滤器测试
```

### 5.3.2 关键 API 示例

```rust
use rustnmap_packet::{MmapPacketEngine, AsyncPacketEngine, RingConfig, BpfFilter};
use tokio_stream::StreamExt;

// 同步 API (底层)
fn sync_example() -> Result<(), PacketError> {
    let config = RingConfig::default();  // 2 blocks x 2MB
    let mut engine = MmapPacketEngine::new("eth0", config)?;

    // 设置 BPF 过滤器 (只接收 TCP 80 端口)
    let filter = BpfFilter::tcp_dst_port(80);
    engine.set_filter(&filter)?;

    engine.start()?;

    // 接收数据包
    while let Some(packet) = engine.recv()? {
        println!("Received {} bytes", packet.len);
    }

    engine.stop()?;
    Ok(())
}

// 异步 API (推荐)
#[tokio::main]
async fn async_example() -> Result<(), PacketError> {
    let config = RingConfig::default();
    let mut engine = AsyncPacketEngine::new("eth0", config).await?;

    engine.start().await?;

    // 使用 Stream trait
    let mut stream = engine.into_stream();
    while let Some(packet) = stream.next().await {
        match packet {
            Ok(pkt) => println!("Received {} bytes", pkt.len),
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    Ok(())
}
```

### 5.3.3 依赖关系

```
┌─────────────────────────────────────────────────────────────────────┐
│                   rustnmap-packet Dependencies                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  rustnmap-packet                                                    │
│       │                                                             │
│       ├──> rustnmap-common (类型定义)                               │
│       │                                                             │
│       ├──> tokio (异步运行时)                                       │
│       │     - net: AsyncFd 支持                                     │
│       │     - io-util: AsyncRead/Write                              │
│       │     - sync: mpsc channel                                    │
│       │                                                             │
│       ├──> bytes (零拷贝缓冲区)                                     │
│       │     - Bytes: 引用计数切片                                   │
│       │                                                             │
│       ├──> libc (系统调用)                                          │
│       │     - mmap/munmap                                           │
│       │     - socket/bind/setsockopt                                │
│       │     - AF_PACKET, TPACKET_V2                                 │
│       │                                                             │
│       ├──> socket2 (套接字封装)                                     │
│       │     - Type::RAW                                             │
│       │     - Protocol::from(ETH_P_ALL)                             │
│       │                                                             │
│       └──> thiserror (错误定义)                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3.4 性能目标

| 指标 | 当前 (recvfrom) | 目标 (PACKET_MMAP V2) | 提升 |
|------|-----------------|----------------------|------|
| 包/秒 (PPS) | ~50,000 | ~1,000,000 | 20x |
| CPU 使用率 | 80% (单核) | 30% (单核) | 2.7x |
| 内存拷贝 | 每包 1 次 | 零拷贝 | N/A |
| 系统调用 | 每包 1 次 | 批量 | ~100x |
| 丢包率 (T5) | ~30% | <1% | 30x |

