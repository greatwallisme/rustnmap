# 2. 系统架构设计

## 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           RustNmap Architecture                          │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                        CLI Interface Layer                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │  │
│  │  │  clap CLI   │  │  Config     │  │  Output Formatters          │ │  │
│  │  │  Parser     │  │  Manager    │  │  (Normal/XML/JSON/Grepable) │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Core Engine Layer                           │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Scan Orchestrator                         │  │  │
│  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────────┐  │  │  │
│  │  │  │ Scheduler │ │ Executor  │ │ State     │ │ Result      │  │  │  │
│  │  │  │           │ │           │ │ Manager   │ │ Aggregator  │  │  │  │
│  │  │  └───────────┘ └───────────┘ └───────────┘ └─────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Scan Modules Layer                         │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   Host     │ │   Port     │ │  Service   │ │      OS        │ │  │
│  │  │  Discovery │ │  Scanning  │ │  Detection │ │  Fingerprinting│ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │  Traceroute│ │   NSE      │ │   Vuln     │ │     NAT        │ │  │
│  │  │            │ │   Engine   │ │  Detection │ │  Traversal     │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                        Infrastructure Layer                        │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │    Raw     │ │   Packet   │ │   Async    │ │   Logging &    │ │  │
│  │  │  Socket    │ │   Builder  │ │   Runtime  │ │   Metrics      │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2.2 模块依赖关系

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Binary                      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      rustnmap-cli                           │
│  (命令行解析、配置加载、输出格式化)                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      rustnmap-core                          │
│  (扫描编排器、状态管理、结果聚合)                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐
│ rustnmap-scan │   │ rustnmap-nse  │   │rustnmap-finger│
│ (扫描模块)    │   │ (脚本引擎)    │   │ (指纹识别)    │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    rustnmap-net                             │
│  (原始套接字、数据包构造、异步网络)                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    rustnmap-common                          │
│  (类型定义、工具函数、错误处理)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2.3 核心抽象：ScanSession

基于 Deepseek 设计文档，所有功能模块通过 `ScanSession` 上下文交互，便于依赖注入、模拟测试和会话恢复。

### 2.3.1 ScanSession trait 定义

```rust
use std::sync::Arc;
use crate::common::{IpAddr, MacAddr, Target, PortState};
use crate::output::OutputSink;
use crate::fingerprint::FingerprintDatabase;
use crate::nse::ScriptRegistry;

/// 扫描会话上下文 (核心抽象)
pub struct ScanSession {
    /// 扫描配置
    pub config: ScanConfig,
    /// 目标集合 (线程安全)
    pub target_set: Arc<TargetSet>,
    /// 数据包引擎 (trait 化，可注入 MockEngine)
    pub packet_engine: Arc<dyn PacketEngine>,
    /// 输出接收器 (trait 化)
    pub output_sink: Arc<dyn OutputSink>,
    /// 指纹数据库 (线程安全)
    pub fingerprint_db: Arc<FingerprintDatabase>,
    /// NSE 脚本注册表 (线程安全)
    pub nse_registry: Arc<ScriptRegistry>,
    /// 扫描统计 (线程安全)
    pub stats: Arc<ScanStats>,
    /// 会话恢复存储 (可选)
    pub resume_store: Option<Arc<ResumeStore>>,
}

/// 扫描配置
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// 时序模板 (T0-T5)
    pub timing_template: TimingTemplate,
    /// 扫描类型 (SYN/CONNECT/UDP 等)
    pub scan_types: Vec<ScanType>,
    /// 端口范围
    pub port_spec: PortSpec,
    /// 并发主机数
    pub min_parallel_hosts: usize,
    pub max_parallel_hosts: usize,
    /// 并发端口数
    pub min_parallel_ports: usize,
    pub max_parallel_ports: usize,
    /// 速率限制 (PPS)
    pub min_rate: Option<u64>,
    pub max_rate: Option<u64>,
    /// 主机组大小
    pub host_group_size: usize,
}

/// 扫描统计 (线程安全)
pub struct ScanStats {
    /// 已完成主机数
    pub hosts_completed: AtomicUsize,
    /// 发现的开放端口总数
    pub open_ports: AtomicUsize,
    /// 发送的数据包总数
    pub packets_sent: AtomicU64,
    /// 接收的数据包总数
    pub packets_recv: AtomicU64,
    /// 开始时间
    pub start_time: std::time::Instant,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            hosts_completed: AtomicUsize::new(0),
            open_ports: AtomicUsize::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    /// 记录完成主机 (使用 Relaxed 内存序)
    #[inline]
    pub fn mark_host_complete(&self) {
        self.hosts_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 获取 PPS (每秒包数)
    pub fn pps(&self) -> u64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packets_sent.load(Ordering::Relaxed) as u64 / elapsed as u64
        } else {
            0
        }
    }
}
```

### 2.3.2 PacketEngine trait (可测试抽象)

```rust
/// 数据包引擎抽象 (支持依赖注入)
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// 发送单个数据包
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize, PacketError>;

    /// 批量发送数据包 (使用 sendmmsg)
    async fn send_batch(&self, pkts: &[PacketBuffer]) -> Result<usize, PacketError>;

    /// 接收数据包流
    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>>;

    /// 设置 BPF 过滤器
    fn set_bpf(&self, filter: &BpfProg) -> Result<(), PacketError>;

    /// 获取本机 MAC 地址
    fn local_mac(&self) -> Option<MacAddr>;

    /// 获取接口索引
    fn if_index(&self) -> libc::c_uint;
}

/// 数据包缓冲区
pub struct PacketBuffer {
    /// 数据 (使用 Bytes 零拷贝)
    pub data: bytes::Bytes,
    /// 长度
    pub len: usize,
    /// 时间戳
    pub timestamp: std::time::Duration,
    /// 协议
    pub protocol: u16,
}

/// BPF 过滤器程序
#[repr(C)]
pub struct BpfProg {
    pub bf_len: libc::c_ushort,
    pub bf_insns: *const libc::sock_bpf,
}

unsafe impl Send for BpfProg {}
unsafe impl Sync for BpfProg {}
```

### 2.3.3 依赖注入模式 (可测试性)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Mock 数据包引擎 (用于单元测试，无需 root)
    struct MockPacketEngine {
        send_tx: mpsc::Sender<PacketBuffer>,
        recv_rx: mpsc::Receiver<PacketBuffer>,
    }

    #[async_trait]
    impl PacketEngine for MockPacketEngine {
        async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize, PacketError> {
            self.send_tx.send(pkt).await.unwrap();
            Ok(pkt.len)
        }

        fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>> {
            Box::pin(futures::stream::unfold(
                self.recv_rx.clone(),
                |rx| async move {
                    rx.recv().await.map(|pkt| (pkt, rx))
                }
            ))
        }

        fn set_bpf(&self, _filter: &BpfProg) -> Result<(), PacketError> {
            Ok(())
        }

        fn local_mac(&self) -> Option<MacAddr> {
            Some(MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
        }

        fn if_index(&self) -> libc::c_uint {
            1
        }
    }

    /// 单元测试：无需 root 权限
    #[tokio::test]
    async fn test_scan_with_mock_engine() {
        let (tx, rx) = mpsc::channel(100);
        let mock = Arc::new(MockPacketEngine {
            send_tx: tx,
            recv_rx: rx,
        });

        let session = ScanSession {
            config: ScanConfig::default(),
            target_set: Arc::new(TargetSet::new()),
            packet_engine: mock.clone(),
            output_sink: Arc::new(MockOutputSink::new()),
            fingerprint_db: Arc::new(FingerprintDatabase::mock()),
            nse_registry: Arc::new(ScriptRegistry::empty()),
            stats: Arc::new(ScanStats::new()),
            resume_store: None,
        };

        // 测试扫描逻辑...
    }
}
```

---

