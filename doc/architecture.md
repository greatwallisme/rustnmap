# 2. 系统架构设计

> **版本**: 1.0.0 (2.0 开发中)
> **最后更新**: 2026-02-17

---

## 2.1 RustNmap 2.0 架构概览

RustNmap 2.0 从"端口扫描器"升级为"攻击面管理平台"，新增以下核心模块：

### 2.1.1 2.0 新增 Crate

| Crate | 用途 | 对应 Phase | 状态 |
|-------|------|-----------|------|
| `rustnmap-vuln` | 漏洞情报 (CVE/CPE 关联、EPSS/KEV) | Phase 2 (Week 5-7) | 待创建 |
| `rustnmap-api` | REST API / Daemon 模式 | Phase 5 (Week 12) | 待创建 |
| `rustnmap-sdk` | Rust SDK (Builder API) | Phase 5 (Week 12) | 待创建 |

### 2.1.2 2.0 新增功能模块

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        RustNmap 2.0 Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    API & SDK Layer (2.0 NEW)                       │  │
│  │  ┌─────────────────────┐  ┌─────────────────────────────────────┐ │  │
│  │  │   REST API (axum)   │  │      Rust SDK (Builder API)         │ │  │
│  │  │   POST /api/scans   │  │   Scanner::new().targets().run()    │ │  │
│  │  │   GET  /api/scans/1 │  │                                     │ │  │
│  │  └─────────────────────┘  └─────────────────────────────────────┘ │  │
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
│  │  │ Traceroute │ │   NSE      │ │  Vulnerability│ │  Evasion     │ │  │
│  │  │            │ │   Engine   │ │  (2.0 NEW)  │ │               │ │  │
│  │  └────────────┘ └────────────┘ └─────────────┘ └────────────────┘ │  │
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

---

## 2.2 整体架构图 (1.0 基线)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           RustNmap Architecture                          │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                        CLI Interface Layer                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │  │
│  │  │  lexopt CLI │  │  Config     │  │  Output Formatters          │ │  │
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

## 2.3 模块依赖关系

### 2.3.1 1.0 基线依赖图

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
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   rustnmap-output                           │
│  (输出格式化：Normal/XML/JSON/Grepable)                      │
└─────────────────────────────────────────────────────────────┘
```

### 2.3.2 2.0 新增依赖关系

```
                            ┌───────────────────────────────┐
                            │     rustnmap-sdk (2.0)        │
                            │   (稳定高层 Builder API)       │
                            └───────────────┬───────────────┘
                                            │ uses
                                            ▼
┌───────────────────────────────────────────────────────────────┐
│                     rustnmap-api (2.0)                        │
│   (REST API / Daemon 模式，基于 axum)                          │
│   POST /api/v1/scans, GET /api/v1/scans/{id}                 │
└───────────────────────────┬───────────────────────────────────┘
                            │ uses
                            ▼
┌───────────────────────────────────────────────────────────────┐
│                  rustnmap-vuln (2.0)                          │
│   (漏洞情报：CVE/CPE 关联、EPSS 评分、KEV 标记)                  │
│   - NVD API 集成                                               │
│   - 本地 SQLite 数据库                                          │
│   - EPSS/KEV聚合                                               │
└───────────────────────────┬───────────────────────────────────┘
                            │ uses
                            ▼
                    ┌────────────────┐
                    │ rustnmap-output │
                    │ (扩展 HostResult) │
                    └────────────────┘
```

### 2.3.3 完整依赖链 (1.0 + 2.0)

```
rustnmap-sdk (2.0)
    │
    └──> rustnmap-api (2.0)
             │
             ├──> rustnmap-core
             │        │
             │        ├──> rustnmap-scan
             │        ├──> rustnmap-nse
             │        ├──> rustnmap-fingerprint
             │        ├──> rustnmap-traceroute
             │        └──> rustnmap-evasion
             │
             ├──> rustnmap-vuln (2.0)
             │        │
             │        └──> rustnmap-output
             │
             └──> rustnmap-output
```
```

---

## 2.3 数据包引擎架构 (PACKET_MMAP V2 重构)

> **重要**: 当前 `rustnmap-packet` 使用 `recvfrom()` 系统调用，而非真正的 PACKET_MMAP 环形缓冲区。
> 这是导致 T5 Insane 扫描不稳定、UDP 扫描性能低下的根本原因。
> 本节描述基于 nmap 参考实现的完整架构重构方案。

### 2.3.1 当前问题诊断

| 问题 | 当前实现 | nmap 实现 | 影响 |
|------|---------|-----------|------|
| 包捕获方式 | `recvfrom()` 系统调用 | PACKET_MMAP V2 环形缓冲区 | 每包一次 syscall，开销大 |
| 缓冲区大小 | Socket 队列 (默认) | 4MB 环形缓冲区 | 高负载丢包 |
| 异步 I/O | `spawn_blocking` | nsock + epoll | 线程阻塞，效率低 |
| 零拷贝 | 无 (内存复制) | 有 (mmap) | CPU 和内存带宽浪费 |
| TPACKET 版本 | 声称 V3，实际未实现 | V2 (稳定性优先) | V3 在旧内核有 bug |

**nmap 版本协商策略** (参考 `reference/nmap/libpcap/pcap-linux.c:2974-3013`):
```c
// nmap 实际实现: 先尝试 V3，失败则回退 V2
// 但在 immediate mode 下直接使用 V2
if (!immediate_mode) {
    // 尝试 TPACKET_V3
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v3, sizeof(v3)) == 0) {
        // V3 设置成功，继续配置
    } else {
        // V3 失败，回退到 V2
        setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v2, sizeof(v2));
    }
} else {
    // immediate mode 直接使用 V2
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v2, sizeof(v2));
}
```

**RustNmap 架构决策**: 直接使用 V2，因为：
1. 扫描器通常需要 immediate mode（低延迟响应）
2. V2 在所有内核版本上稳定
3. nmap 在大多数情况下最终也使用 V2

**代码证据** (`crates/rustnmap-packet/src/lib.rs:764-765`):
```rust
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

### 2.3.2 新架构：分层设计

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Packet Engine Architecture (Redesigned)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Scanner Layer (rustnmap-scan)                       │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │  │
│  │  │ SYN Scanner │ │ UDP Scanner │ │Stealth Scan │ │  OS Fingerprint │  │  │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └────────┬────────┘  │  │
│  │         │               │               │                  │           │  │
│  │         └───────────────┴───────────────┴──────────────────┘           │  │
│  │                                   │                                    │  │
│  │                         dyn PacketEngine                               │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                  Async Integration Layer (NEW)                         │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    AsyncPacketEngine                             │  │  │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │  │
│  │  │  │ AsyncFd<Raw> │  │ mpsc Channel │  │  PacketStream        │   │  │  │
│  │  │  │  (Tokio)     │  │  (Backpress) │  │  (impl Stream)       │   │  │  │
│  │  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                   │                                    │  │
│  │                         PacketEngine trait                             │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                  Core Engine Layer (rustnmap-packet)                   │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                   MmapPacketEngine (NEW)                         │  │  │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │  │
│  │  │  │ RingBuffer   │  │ BlockManager │  │  FrameIterator       │   │  │  │
│  │  │  │ (mmap ptr)   │  │ (V2 Blocks)  │  │  (Zero-copy)         │   │  │  │
│  │  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                   BpfFilter (NEW)                                │  │  │
│  │  │  - Kernel-space packet filtering                                 │  │  │
│  │  │  - Compile BPF instructions from filter expression               │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│  ┌───────────────────────────────────▼───────────────────────────────────┐  │
│  │                     Linux Kernel Interface                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │  │
│  │  │ AF_PACKET    │  │ TPACKET_V2   │  │  PACKET_MMAP                 │ │  │
│  │  │ Socket       │  │ Ring Buffer  │  │  (4MB: 2 blocks x 2MB)       │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3.3 核心组件定义

#### PacketEngine Trait

```rust
use std::sync::Arc;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

/// 数据包引擎核心抽象
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// 启动引擎 (初始化环形缓冲区)
    async fn start(&mut self) -> Result<(), PacketError>;

    /// 接收单个数据包 (零拷贝)
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;

    /// 发送单个数据包
    async fn send(&self, packet: &[u8]) -> Result<usize, PacketError>;

    /// 停止引擎
    async fn stop(&mut self) -> Result<(), PacketError>;

    /// 设置 BPF 过滤器
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), PacketError>;

    /// 刷新缓冲区
    fn flush(&self) -> Result<(), PacketError>;

    /// 获取统计信息
    fn stats(&self) -> EngineStats;
}

/// 零拷贝数据包缓冲区
#[derive(Debug)]
pub struct PacketBuffer {
    /// 数据引用 (Bytes 实现零拷贝克隆)
    pub data: Bytes,
    /// 实际长度
    pub len: usize,
    /// 捕获时间戳
    pub timestamp: std::time::Instant,
    /// 协议类型
    pub protocol: u16,
    /// VLAN 标签 (可选)
    pub vlan_tci: Option<u16>,
}

/// 引擎统计信息
#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub filter_accepts: u64,
    pub filter_rejects: u64,
}
```

#### MmapPacketEngine 实现

```rust
use std::ptr::NonNull;
use libc::{mmap, munmap, PROT_READ, PROT_WRITE, MAP_SHARED};

/// TPACKET_V2 环形缓冲区配置
#[derive(Debug, Clone)]
pub struct RingConfig {
    /// 块数量 (推荐: 2)
    pub block_count: u32,
    /// 每块大小 (推荐: 2MB = 2097152)
    pub block_size: u32,
    /// 每帧大小 (推荐: TPACKET_ALIGNMENT = 512)
    pub frame_size: u32,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_count: 2,
            block_size: 2_097_152,  // 2MB per block
            frame_size: 512,         // TPACKET_ALIGNMENT
        }
    }
}

/// TPACKET_V2 头结构 (32 字节)
/// 参考: /usr/include/linux/if_packet.h:146-157
/// CRITICAL: tp_padding 是 [u8; 4]，不是 [u8; 8]
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,      // 帧状态 (TP_STATUS_*)
    pub tp_len: u32,         // 数据包长度
    pub tp_snaplen: u32,     // 捕获长度
    pub tp_mac: u16,         // MAC 头偏移
    pub tp_net: u16,         // 网络头偏移
    pub tp_sec: u32,         // 时间戳 (秒)
    pub tp_nsec: u32,        // 时间戳 (纳秒) - NOT tp_usec!
    pub tp_vlan_tci: u16,    // VLAN TCI
    pub tp_vlan_tpid: u16,   // VLAN TPID
    pub tp_padding: [u8; 4], // 填充 - NOT [u8; 8]!
}

/// PACKET_MMAP V2 引擎实现
pub struct MmapPacketEngine {
    /// 原始套接字文件描述符
    fd: i32,
    /// 环形缓冲区配置
    config: RingConfig,
    /// mmap 内存区域指针
    ring_ptr: NonNull<u8>,
    /// 环形缓冲区总大小
    ring_size: usize,
    /// 当前块索引
    current_block: u32,
    /// 当前帧索引
    current_frame: u32,
    /// 接口索引
    if_index: u32,
    /// 统计信息
    stats: EngineStats,
}

impl MmapPacketEngine {
    /// 创建新的 PACKET_MMAP 引擎
    pub fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        // 1. 创建 AF_PACKET 套接字
        // 2. 设置 TPACKET_V2 版本
        // 3. 配置环形缓冲区
        // 4. mmap 映射内存
        // 5. 绑定到网络接口
        // ...
    }

    /// 获取当前帧指针
    fn current_frame_ptr(&self) -> *mut Tpacket2Hdr {
        // 计算当前帧在环形缓冲区中的位置
        let block_offset = self.current_block as usize * self.config.block_size as usize;
        let frame_offset = self.current_frame as usize * self.config.frame_size as usize;
        unsafe {
            self.ring_ptr.as_ptr().add(block_offset + frame_offset)
                as *mut Tpacket2Hdr
        }
    }

    /// 等待帧可用
    fn wait_for_frame(&self, hdr: &Tpacket2Hdr) -> Result<(), PacketError> {
        // CRITICAL: 使用 Acquire 语义确保数据可见性
        // 来自 nmap 研究: __ATOMIC_ACQUIRE
        use std::sync::atomic::{AtomicU32, Ordering};
        loop {
            let status = unsafe {
                AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
                    .load(Ordering::Acquire)
            };
            if status & TP_STATUS_USER != 0 {
                return Ok(());
            }
            // 短暂让出 CPU
            std::hint::spin_loop();
        }
    }

    /// 释放帧回内核
    fn release_frame(&self, hdr: &mut Tpacket2Hdr) {
        // CRITICAL: 使用 Release 语义确保之前的读取完成
        // 来自 nmap 研究: __ATOMIC_RELEASE
        use std::sync::atomic::{AtomicU32, Ordering};
        unsafe {
            AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
                .store(TP_STATUS_KERNEL, Ordering::Release);
        }
    }
}

impl Drop for MmapPacketEngine {
    fn drop(&mut self) {
        // 清理 mmap 内存
        if !self.ring_ptr.is_null() {
            unsafe {
                munmap(self.ring_ptr.as_ptr() as *mut _, self.ring_size);
            }
        }
        // 关闭套接字
        if self.fd >= 0 {
            unsafe { libc::close(self.fd); }
        }
    }
}
```

#### AsyncPacketEngine 包装器

```rust
use tokio::io::{AsyncFd, AsyncFdReadyGuard, Interest};
use tokio::sync::mpsc::{channel, Sender, Receiver};
use std::os::unix::io::OwnedFd;

/// 异步数据包引擎 (Tokio 集成)
pub struct AsyncPacketEngine {
    /// 底层 MMAP 引擎
    engine: MmapPacketEngine,
    /// AsyncFd 用于非阻塞通知 (包装在 Arc 中以便共享)
    /// CRITICAL: AsyncFd<T> 不是 Clone，必须用 Arc 包装
    async_fd: std::sync::Arc<AsyncFd<OwnedFd>>,
    /// 数据包发送通道
    packet_tx: Sender<PacketBuffer>,
    /// 数据包接收通道
    packet_rx: Receiver<PacketBuffer>,
    /// 运行标志
    running: Arc<AtomicBool>,
}

impl AsyncPacketEngine {
    /// 创建异步引擎
    pub async fn new(interface: &str, config: RingConfig) -> Result<Self, PacketError> {
        let engine = MmapPacketEngine::new(interface, config)?;

        // CRITICAL: 不能使用 File::from_raw_fd(engine.fd)
        // 因为 engine 仍然持有 fd 所有权，会导致 double-close
        // 正确做法: 使用 libc::dup() 复制 fd，然后包装为 OwnedFd
        let async_fd = unsafe {
            // 复制 fd，避免所有权问题
            let dup_fd = libc::dup(engine.fd);
            if dup_fd < 0 {
                return Err(PacketError::FdDupFailed);
            }
            // OwnedFd 会在 drop 时自动关闭 fd
            let owned_fd = OwnedFd::from_raw_fd(dup_fd);
            AsyncFd::new(owned_fd)?
        };

        let (packet_tx, packet_rx) = channel(1024);

        Ok(Self {
            engine,
            async_fd: std::sync::Arc::new(async_fd),
            packet_tx,
            packet_rx,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 启动异步接收循环
    pub async fn start(&mut self) -> Result<(), PacketError> {
        self.running.store(true, Ordering::Release);
        self.engine.start()?;

        // 启动后台接收任务
        let running = self.running.clone();

        // CRITICAL: 不能将 &mut self.engine 裸指针传入 async block
        // 正确做法: 使用 Arc<Mutex<>> 或移动 engine 到 task
        let engine = std::sync::Arc::new(tokio::sync::Mutex::new(
            std::mem::replace(&mut self.engine, MmapPacketEngine::placeholder())
        ));
        // CRITICAL: AsyncFd 不是 Clone，必须使用 Arc 共享
        let async_fd = self.async_fd.clone();  // Arc::clone()
        let packet_tx = self.packet_tx.clone();

        tokio::spawn(async move {
            while running.load(Ordering::Acquire) {
                // 等待套接字可读
                let mut ready_guard = match async_fd.readable().await {
                    Ok(guard) => guard,
                    Err(_) => break,
                };

                // 批量读取数据包
                let mut engine_guard = engine.lock().await;
                while let Some(packet) = engine_guard.try_recv().unwrap_or(None) {
                    if packet_tx.send(packet).await.is_err() {
                        break;
                    }
                }
                drop(engine_guard);

                ready_guard.clear_ready_matching(Interest::READABLE);
            }
        });

        Ok(())
    }

    /// 异步接收数据包
    pub async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError> {
        self.packet_rx.recv().await.ok_or(PacketError::ChannelClosed)
    }
}
```

#### PacketStream 实现 (impl Stream)

**推荐模式: 使用 ReceiverStream 避免 busy-spin**

```rust
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::wrappers::ReceiverStream;

/// 数据包流 (基于 channel，避免 busy-spin)
///
/// CRITICAL: 不要在 poll_next 中无条件 wake_by_ref()
/// 这会导致 CPU 高频自唤醒（busy-spin）
/// 正确做法: 使用 channel 的 readiness 驱动唤醒
pub struct PacketStream {
    /// 使用 ReceiverStream 包装 channel receiver
    /// 当 channel 为空时，Stream 会正确地 Pending 而非自唤醒
    inner: ReceiverStream<Result<PacketBuffer, PacketError>>,
}

impl Stream for PacketStream {
    type Item = Result<PacketBuffer, PacketError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 委托给 ReceiverStream，它有正确的 readiness 语义
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl AsyncPacketEngine {
    /// 转换为 Stream
    ///
    /// 使用 channel 作为背压机制，避免 busy-spin
    #[must_use]
    pub fn into_stream(self) -> PacketStream {
        // 获取内部的 packet_rx channel receiver
        // 注意: 这需要 AsyncPacketEngine 暴露 packet_rx 的 getter
        // 或者使用 split() 模式分离 sender/receiver
        let packet_rx = self.packet_rx;
        PacketStream {
            inner: ReceiverStream::new(packet_rx),
        }
    }
}
```

**Cargo.toml 依赖:**
```toml
[dependencies]
futures = "0.3"       # REQUIRED: for Stream trait
tokio-stream = "0.1"  # REQUIRED: for ReceiverStream
```

#### Drop 实现安全顺序 (CRITICAL)

**MUST munmap BEFORE close fd - 顺序错误会导致资源泄漏**

```rust
impl Drop for MmapPacketEngine {
    fn drop(&mut self) {
        // 1. 首先取消 mmap 映射
        // SAFETY: ring_ptr 和 ring_size 在有效状态
        if !self.ring_ptr.is_null() {
            unsafe {
                // MUST come first - kernel expects mmap to be released before socket
                libc::munmap(self.ring_ptr.as_ptr() as *mut _, self.ring_size);
            }
            self.ring_ptr = NonNull::dangling(); // 防止 double-free
        }

        // 2. 然后关闭 socket
        // SAFETY: fd is valid and owned
        if self.fd >= 0 {
            unsafe {
                // MUST come second - after munmap
                libc::close(self.fd);
            }
            self.fd = -1; // 防止 double-close
        }
    }
}
```

**顺序错误后果:**
- 先 `close()` 后 `munmap()` 会导致 `EBADF` 错误
- 内核可能在 munmap 时访问已关闭的 fd
- 可能导致内存泄漏或 undefined behavior

### 2.3.4 网络波动处理架构

基于 nmap `timing.cc` 和 `scan_engine.cc` 的研究，实现完整的网络波动处理机制：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Network Volatility Handling Architecture                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        AdaptiveTiming (RFC 6298)                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  SRTT = (7/8) * SRTT + (1/8) * RTT                              │  │  │
│  │  │  RTTVAR = (3/4) * RTTVAR + (1/4) * |RTT - SRTT|                 │  │  │
│  │  │  Timeout = SRTT + 4 * RTTVAR                                    │  │  │
│  │  │  Timeout = clamp(Timeout, min_rtt, max_rtt)                     │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    CongestionController (TCP-like)                     │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ cwnd (拥塞窗口)  │  │ ssthresh (阈值)  │  │ Phase Detection      │ │  │
│  │  │                  │  │                  │  │ - Slow Start         │ │  │
│  │  │ Initial: 1       │  │ Initial: ∞       │  │ - Congestion Avoid   │ │  │
│  │  │ Min: 1           │  │ On drop: cwnd/2  │  │ - Recovery           │ │  │
│  │  │ Max: max_cwnd    │  │                  │  │                      │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ScanDelayBoost (动态延迟)                         │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  On high drop rate:                                              │  │  │
│  │  │    if timing_level < 4: delay = min(10000, max(1000, delay*10)) │  │  │
│  │  │    else: delay = min(1000, max(100, delay*2))                   │  │  │
│  │  │                                                                  │  │  │
│  │  │  Decay after good responses:                                     │  │  │
│  │  │    if good_responses > threshold: delay = max(default, delay/2) │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      RateLimiter (Token Bucket)                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  --min-rate: 保证最小发包速率                                     │  │  │
│  │  │  --max-rate: 限制最大发包速率                                     │  │  │
│  │  │  Tokens replenish at rate R per second                           │  │  │
│  │  │  Burst size = min_rate * burst_factor                            │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ErrorRecovery (ICMP 分类)                         │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ HOST_UNREACH     │  │ NET_UNREACH      │  │ PORT_UNREACH (UDP)   │ │  │
│  │  │ -> Mark Down     │  │ -> Reduce cwnd   │  │ -> Mark Closed       │ │  │
│  │  │                  │  │ -> Boost delay   │  │                      │ │  │
│  │  ├──────────────────┤  ├──────────────────┤  ├──────────────────────┤ │  │
│  │  │ ADMIN_PROHIBITED │  │ FRAG_NEEDED      │  │ TIMEOUT              │ │  │
│  │  │ -> Mark Filtered │  │ -> Set DF=0      │  │ -> Retry w/ backoff  │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3.5 时序模板参数对照表

| 参数 | T0 Paranoid | T1 Sneaky | T2 Polite | T3 Normal | T4 Aggressive | T5 Insane |
|------|-------------|-----------|-----------|-----------|---------------|-----------|
| `min_rtt_timeout` | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| `max_rtt_timeout` | 10s | 10s | 10s | 10s | 10s | 300ms |
| `initial_rtt` | 1s | 1s | 1s | 1s | 500ms | 250ms |
| `max_retries` | 10 | 10 | 10 | 10 | 6 | 2 |
| `scan_delay` | 5min | 15s | 400ms | 0ms | 0ms | 0ms |
| `max_parallelism` | 1 | 1 | 1 | dynamic | dynamic | dynamic |
| `min_host_group` | 1 | 1 | 1 | 1 | 1 | 1 |
| `max_host_group` | 1 | 1 | 1 | 100 | 100 | 256 |
| `min_rate` | 0 | 0 | 0 | 0 | 0 | 0 |
| `max_rate` | 0 | 0 | 0 | 0 | 0 | 0 |
| `cwnd_initial` | 1 | 1 | 1 | 1 | 1 | 1 |
| `cwnd_max` | 10 | 10 | 10 | dynamic | dynamic | dynamic |


### 2.3.7 性能优化实践 (2026-03-11)

#### 2.3.7.1 优化成果

经过系统性分析和优化，rustnmap 已达到并超越 nmap 的性能水平：

| 指标 | 初始状态 | 优化后 | nmap | 状态 |
|------|---------|--------|------|------|
| Fast Scan | 6.40s | 2.42s | 2.78s | ✅ 快 13% |
| 改进幅度 | - | 62% | - | ✅ 显著 |
| 准确度 | - | 100% | 100% | ✅ 完美 |
| 稳定性 | - | 2.39-2.48s | 2.38-4.22s | ✅ 更稳定 |

#### 2.3.7.2 关键优化措施

**优化 1: 拥塞窗口最小值保护** - 设置 cwnd 最小值为 10，防止崩溃到 1

**优化 2: 自适应重试限制** - 基于 max_successful_tryno 动态调整重试次数

**优化 3: 快速数据包排空** - 收到包后保持 1ms 超时，不增加到 10ms

**优化 4: 200ms 上限保护** - 添加等待阶段的 200ms 上限

详细信息见：`doc/modules/port-scanning.md` 第 3.2.6 节

### 2.3.6 文件结构规划

```
crates/rustnmap-packet/src/
├── lib.rs              # 公开 API 导出
├── engine.rs           # PacketEngine trait 定义
├── mmap.rs             # MmapPacketEngine 实现
│   ├── RingBuffer      # 环形缓冲区管理
│   ├── BlockManager    # TPACKET_V2 块管理
│   └── FrameIterator   # 零拷贝帧迭代器
├── async_engine.rs     # AsyncPacketEngine (Tokio 集成)
│   ├── AsyncFd 包装
│   └── Channel 分发
├── bpf.rs              # BPF 过滤器
│   ├── BpfFilter       # 过滤器结构
│   ├── compile()       # 编译表达式
│   └── attach()        # 附加到套接字
├── stream.rs           # PacketStream (impl Stream)
├── stats.rs            # EngineStats 统计
├── error.rs            # PacketError 错误类型
└── sys/
    ├── mod.rs          # Linux 系统调用封装
    ├── tpacket.rs      # TPACKET_V2 常量和结构
    └── if_packet.rs    # AF_PACKET 常量
```

---

## 2.4 核心抽象：ScanSession

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

---

## 2.5 Localhost 扫描限制与设计决策

> **状态**: 已知架构限制 | **优先级**: P0
> **分析日期**: 2026-03-08 | **相关文档**: `doc/modules/localhost-scanning.md`

### 2.5.1 问题描述

当扫描 `127.0.0.1` (localhost) 时，SYN 扫描无法正确识别端口状态，所有端口显示为 `filtered`。

**测试结果对比**:
```bash
$ nmap -sS -p 22 127.0.0.1
PORT   STATE SERVICE
22/tcp open   ssh          # ✅ 正确

$ rustnmap --scan-syn -p 22 127.0.0.1
PORT     STATE SERVICE
22/tcp  filtered ssh       # ❌ 错误
```

### 2.5.2 根本原因

#### 核心问题：响应路由不对称

```
发送路径:
  RustNmap (192.168.15.237) → SYN → 127.0.0.1:22
  ↓
响应路径:
  127.0.0.1:22 → SYN-ACK → 192.168.15.237 (外部 IP)
  ↓
路由决策:
  到 192.168.15.237 的响应通过 ens33 接口路由
  RustNmap 的 PACKET_MMAP 绑定到 lo 接口 → 永远看不到响应
```

**tcpdump 证据**:
```
192.168.15.237 > 127.0.0.1.22: Flags [S]     # 我们的 SYN
127.0.0.1.22 > 192.168.15.237: Flags [S.]   # SYN-ACK (注意目的地)
```

#### 技术细节

| 组件 | 当前行为 | 问题 |
|------|---------|------|
| `RawSocket` | 绑定到系统默认地址 | 源地址被内核设置为 192.168.15.237 |
| PACKET_MMAP | 绑定到 lo 接口 | 只能看到 lo 上的流量 |
| 路由表 | 127.0.0.1 → lo | 192.168.15.237 → ens33 |
| 响应目的地 | 192.168.15.237 | 不在 lo 接口上 |

### 2.5.3 设计决策

#### 决策：为 Localhost 创建专用的 RawSocket

**方案**: 修改 `TcpSynScanner` 架构，为 localhost 目标创建专用的 `RawSocket`，绑定到 `127.0.0.1`。

**理由**:
1. **功能完整性**: SYN 扫描应该对所有地址类型有效
2. **符合 nmap 标准**: nmap 在 Linux 上支持 localhost SYN 扫描
3. **技术正确性**: 正确的解决方案是修复根本原因

**架构影响**:

```rust
pub struct TcpSynScanner {
    // 主扫描 socket (用于远程目标)
    socket: RawSocket,

    // Localhost 专用 socket (绑定到 127.0.0.1)
    localhost_socket: Option<RawSocket>,

    // 配置
    local_addr: Ipv4Addr,
    config: ScanConfig,
}

impl TcpSynScanner {
    fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // 根据目标地址选择正确的 socket
        let socket = if dst_addr.is_loopback() {
            self.localhost_socket.as_ref().unwrap_or(&self.socket)
        } else {
            &self.socket
        };

        // 使用选定的 socket 发送数据包
        socket.send_packet(&packet, &dst_sockaddr)?;
        // ...
    }
}
```

### 2.5.4 实施计划

#### Phase 1: 扩展 RawSocket API

**文件**: `crates/rustnmap-net/src/lib.rs`

添加 `bind()` 方法：

```rust
impl RawSocket {
    /// 绑定 raw socket 到特定源地址
    ///
    /// # Arguments
    /// * `src_addr` - 可选的源地址
    ///
    /// # Errors
    /// 返回错误如果:
    /// - Socket 已经绑定
    /// - 无效地址
    /// - 权限拒绝
    pub fn bind(&self, src_addr: Option<Ipv4Addr>) -> io::Result<()> {
        // 实现 bind() 逻辑
    }
}
```

#### Phase 2: 修改 TcpSynScanner

**文件**: `crates/rustnmap-scan/src/syn_scan.rs`

1. 添加 `localhost_socket` 字段
2. 构造函数中创建并绑定 localhost socket
3. `send_syn_probe()` 中根据目标选择 socket

#### Phase 3: 验证测试

| 测试用例 | 预期结果 |
|---------|---------|
| 单端口 localhost | 端口状态正确 |
| 多端口 localhost | 混合状态正确 |
| 混合目标 (localhost + 远程) | 两者都正确 |
| 与 nmap 对比 | 结果一致 |

### 2.5.5 技术约束

#### PACKET_MMAP 限制

| 场景 | PACKET_MMAP | 原因 |
|------|------------|------|
| 远程 IP 扫描 | ✅ 正常 | 路由对称 |
| Localhost 扫描 | ❌ 受限 | 响应路由到外部接口 |

#### 参考实现

**nmap 源码**: `reference/nmap/libnetutil/netutil.cc:1916-1946`
```c
int islocalhost(const struct sockaddr_storage *ss) {
    // 检查 127.x.x.x
    if ((sin->sin_addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
        return 1;

    // 检查本地接口地址
    if (ipaddr2devname(dev, ss) != -1)
        return 1;

    return 0;
}
```

**nmap Windows 处理**: `reference/nmap/scan_engine.cc:2735-2739`
```c
#ifdef WIN32
  if (!o.have_pcap && scantype != CONNECT_SCAN &&
      Targets[0]->ifType() == devt_loopback) {
    // Windows 不支持对 localhost 的原始扫描，跳过
    return;
  }
#endif
```

### 2.5.6 替代方案 (降级)

如果实施复杂度过高，可以考虑降级方案：

**方案**: 检测 localhost 目标时，自动切换到 Connect 扫描

**位置**: `crates/rustnmap-core/src/orchestrator.rs`

```rust
// 扫描器选择逻辑
if targets.iter().any(|t| t.is_loopback()) && scantype == ScanType::Syn {
    log_warning("SYN scan on localhost not fully supported, using Connect scan");
    return TcpConnectScanner::new(config)?;
}
```

**缺点**: 失去 SYN 扫描的隐蔽性优势

---

## 2.6 架构更新历史

| 日期 | 变更内容 | 影响 |
|------|---------|------|
| 2026-03-08 | 添加 localhost 扫描限制章节 | 新增已知限制文档 |
| 2026-03-07 | 完成 PACKET_MMAP V2 实现 | Phase 5 完成 |
| 2026-03-07 | 修复 T5 多端口扫描拥塞控制 | 准确率 94.9% |
| 2026-02-17 | 初始架构设计 | 1.0 基线 |
```

---
