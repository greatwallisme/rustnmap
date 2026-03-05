# Task Plan: RustNmap Packet Capture Architecture Redesign

> **Created**: 2026-03-05
> **Updated**: 2026-03-05
> **Priority**: Critical
> **Status**: Phase 40 - Architecture Redesign

---

## Executive Summary

R RustNmap's packet capture implementation has fundamental deficiencies that prevent high-performance, stable scanning. This plan provides a complete architecture redesign to fix these issues at the root cause level, Instead of patching, the design leverages Rust's async capabilities and design patterns.



**The root problem is NOT T5 Insane timing - it is a fundamental limitation of the current `recvfrom`-based approach that cannot handle high packet rates.**


**Key findings from research:**
1. **No PACKET_MMAP implementation**: The `AfPacketEngine` uses `recvfrom()` instead of memory-mapped ring buffers
2. **No async integration**: Synchronous blocking calls prevent efficient async processing
3. **No BPF filtering in kernel**: Filters applied but not in kernel space
4. **Code duplication**: `SimpleAfPacket` is duplicated in scan modules
5. **Performance gaps**: T5 Insane scans are unreliable; UDP scans are 3x slower than nmap


**Reference:**
- nmap source code: `reference/nmap/` (especially `libpcap`, ` nsock`)
- libpcap documentation: https://www.tcpdump.org/manpages/pcap.3pcap.html
- Linux PACKET_MMAP: https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
- TPACKET V2/V3: https://www.kernel.org/doc/html/latest/networking/tpacket.html
- Rust async patterns: Tokio documentation
- Nmap book: "Network Scanning with Nmap" (https://nmap.org/book/)


**Goals:**
- 100% functional parity with nmap's packet capture
- True zero-copy using PACKET_MMAP V2 (following nmap's choice)
- High performance and stable under load
- event-driven async architecture using Tokio Async runtime
- Proper Rust design patterns for idioms

- Complete documentation with examples
- 100% test coverage
- Zero warnings, zero errors

 - benchmark validation against nmap

 **Non-goals:**
- Implementing V3 (unstable, nmap uses V2 for stability)
- Windows/macOS support (not needed - Linux-only implementation)
- Adding more dependencies (keep minimal)
- Major API changes (internal refactoring only)

 - **Implementation phases: 6 phases,- **Phase 1**: Core Infrastructure (rustnmap-packet)**
- **Phase 2: Async Integration (rustnmap-packet + rustnmap-scan)**
- **Phase 3: Scanner Migration (rustnmap-scan)**
- **Phase 4: Testing & Validation**
- **Phase 5: Documentation & Finalization**
- **Phase 6: Benchmarking & Optimization**
- **Success criteria:**
1. T5 Insane scan: 100% reliability (matching nmap)
2. Zero packet loss under high load
3. UDP scan: performance matches nmap (within 10%
4. All existing tests passing
5. No performance regression
6. All documentation complete and accurate
7. Code quality: zero clippy warnings

8. Memory safety: Miri validation (optional)

 **Dependencies:**
- `libc` - System calls
- `tokio` - Async runtime (v1.x)
- `bytes` - Zero-copy buffers
- `socket2` - Socket abstraction
- `thiserror` - Error handling
- `memmap2` - Memory mapping (optional)
- `pnet` - Packet construction (optional)
- `crossbeam-queue` - Lock-free queues (optional)


 **References:**
- `doc/modules/packet-engineering.md` - Detailed nmap architecture research
- `doc/architecture.md` - Overall system architecture
- `CLippy.toml` - Lint configuration
- `justfile` - Build commands
- `rust-guidelines` skill files

- `rust-concurrency` skill files
- `rust-design-patterns` skill files

---

## Network Volatility Handling (Critical Design Component)

Based on deep research of nmap's source code (`timing.cc`, `scan_engine.cc`, `nsock/`), the following mechanisms MUST be implemented to handle network fluctuations:

### 1. Adaptive RTT Estimation (RFC 2988)

**Status: Partially Implemented** (`crates/rustnmap-scan/src/timeout.rs`)

```
SRTT = (7/8) * SRTT + (1/8) * RTT
RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - RTT|
Timeout = SRTT + 4 * RTTVAR
```

**Gaps to Address:**
- Need `min_rtt_timeout` and `max_rtt_timeout` clamping (nmap: 100ms - 10000ms)
- Need `initial_rtt_timeout` per timing template
- Need proper `box()` function for clamping

### 2. TCP-like Congestion Control

**Status: Partially Implemented** (`crates/rustnmap-scan/src/ultrascan.rs`)

| Phase | Condition | cwnd Adjustment |
|-------|-----------|-----------------|
| Slow Start | cwnd < ssthresh | cwnd += slow_incr * scale |
| Congestion Avoidance | cwnd >= ssthresh | cwnd += ca_incr / cwnd * scale |
| Drop (Host) | Packet loss detected | cwnd = ssthresh / 2 |
| Drop (Group) | Group-level loss | cwnd = ssthresh / group_drop_divisor |

**Timing Template Defaults:**

| Template | cwnd | ssthresh | slow_incr | ca_incr |
|----------|------|----------|-----------|---------|
| T0 Paranoid | 1 | 1 | 1 | 0.01 |
| T1 Sneaky | 1 | 1 | 1 | 0.01 |
| T2 Polite | 3 | 30 | 1 | 0.05 |
| T3 Normal | 10 | 75 | 1 | 0.15 |
| T4 Aggressive | 20 | 300 | 1 | 0.30 |
| T5 Insane | 50 | 1000 | 1 | 0.50 |

### 3. Dynamic Scan Delay Boost

**Status: Needs Implementation**

When drop rate exceeds threshold, boost scan delay:

```rust
fn boost_scan_delay(&mut self) {
    let drop_ratio = dropped / (dropped + successful);
    if drop_ratio > DROP_THRESHOLD {
        // Exponential backoff on scan delay
        let new_delay = self.current_delay * 2;
        self.current_delay = new_delay.min(self.max_scan_delay);
    }
}
```

**Thresholds by Timing Level:**
- T0-T2: 0.25 (25% drop rate triggers boost)
- T3: 0.30 (30% drop rate)
- T4-T5: 0.40 (40% drop rate)

### 4. Rate Limiting (--max-rate / --min-rate)

**Status: Not Implemented**

```rust
pub struct RateLimiter {
    min_rate: Option<f64>,  // packets per second
    max_rate: Option<f64>,  // packets per second
    last_send: Instant,
    tokens: f64,            // Token bucket
}

impl RateLimiter {
    fn wait_if_needed(&mut self) {
        if let Some(max) = self.max_rate {
            let min_interval = Duration::from_secs_f64(1.0 / max);
            let elapsed = self.last_send.elapsed();
            if elapsed < min_interval {
                sleep(min_interval - elapsed);
            }
        }
    }
}
```

### 5. Error Recovery Mechanisms

| Error Type | nmap Behavior | Required Implementation |
|------------|---------------|------------------------|
| Host Unreachable | Mark host down, skip remaining ports | `HostState::Down` |
| Network Unreachable | Reduce cwnd, increase delay | Congestion response |
| Port Unreachable (UDP) | Mark closed | `PortState::Closed` |
| Admin Prohibited | Mark filtered | `PortState::Filtered` |
| Timeout | Retry up to max_retries | Exponential backoff |

### 6. Retry with Exponential Backoff

**Status: Partially Implemented**

```rust
fn calculate_retry_timeout(base: Duration, attempt: u8, timing: TimingTemplate) -> Duration {
    let multiplier = match timing {
        TimingTemplate::T0 => 2.0.powi(attempt as i32),  // Full exponential
        TimingTemplate::T5 => 1.0,                        // No backoff
        _ => 1.5.powi(attempt as i32),                   // Moderate backoff
    };
    base * multiplier as u32
}
```

### Implementation Tasks for Network Volatility

- [ ] Add `RateLimiter` struct with token bucket algorithm
- [ ] Implement `boost_scan_delay()` in all scanners
- [ ] Add `min_rtt_timeout` and `max_rtt_timeout` to timing config
- [ ] Implement proper error type classification (Host/Network/Port Unreachable)
- [ ] Add retry backoff configuration per timing template
- [ ] Create network condition detection (rate limiting, congestion)
- [ ] Add `--max-rate` and `--min-rate` CLI options
- [ ] Test under various network conditions (packet loss, latency, jitter)

---

## Phase 1: Core Infrastructure (Week 1-2)

### Goal
Implement true PACKET_MMAP V2 ring buffer in rustnmap-packet crate

### 1.1 核心数据结构 (2天)

- [ ] 创建 `src/syscall.rs` - 系统调用包装
  - [ ] 实现 `mmap()` 包装
  - [ ] 实现 `munmap()` 包装
  - [ ] 实现 `setsockopt()` 包装
  - [ ] 添加单元测试

- [ ] 创建 `src/tpacket.rs` - TPACKET 结构定义
  - [ ] 定义 `tpacket2_hdr` (48 bytes)
  - [ ] 定义 `tpacket_req` (V2 配置)
  - [ ] 定义 `tpacket_req3` (V3 参考)
  - [ ] 定义常量 (`TP_STATUS_KERNEL`, `TP_STATUS_USER`, etc.)
  - [ ] 添加单元测试

- [ ] 创建 `src/ring.rs` - Ring buffer 管理
  - [ ] 定义 `PacketRing` struct
  - [ ] 实现 `new()` - 创建 ring buffer
  - [ ] 实现 `get_frame()` - 获取帧
  - [ ] 实现 `release_frame()` - 释放帧
  - [ ] 实现 `Drop` trait
  - [ ] 添加单元测试

**CRITICAL: 内存序要求 (来自 nmap 研究)**

nmap 使用 C11 `__ATOMIC_ACQUIRE` / `__ATOMIC_RELEASE`:
```rust
use std::sync::atomic::{AtomicU32, Ordering};

// 检查帧是否可用 - 必须使用 Acquire
fn frame_is_available(hdr: &Tpacket2Hdr) -> bool {
    unsafe {
        AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
            .load(Ordering::Acquire) != TP_STATUS_KERNEL
    }
}

// 释放帧回内核 - 必须使用 Release
fn release_frame(hdr: &mut Tpacket2Hdr) {
    unsafe {
        AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
            .store(TP_STATUS_KERNEL, Ordering::Release);
    }
}
```

**NEVER 使用 SeqCst** - Acquire/Release 足够，SeqCst 有 5-10x 性能损失。
**NEVER 使用 Relaxed** - 对于 tp_status 字段，Relaxed 不保证数据可见性。

| Ordering | CPU 周期 | 适用场景 |
|----------|----------|----------|
| Relaxed | 1 | 仅计数器 (不适用于 tp_status) |
| Acquire/Release | 2-3 | 帧状态同步 (正确选择) |
| SeqCst | 5-10 | 全局顺序 (避免使用) |

### 1.2 Socket 初始化 (2天)

- [ ] 创建 `src/socket.rs` - Socket 创建和配置
  - [ ] 实现 `create_socket()` - AF_PACKET socket
  - [ ] 实现 `set_packet_version()` - 设置 TPACKET_V2
  - [ ] 实现 `bind_to_interface()` - 绑定接口
  - [ ] 实现 `get_interface_index()` - 获取接口索引
  - [ ] 添加单元测试

**CRITICAL: Socket 选项设置顺序 (来自 nmap 研究)**
```
1. socket(PF_PACKET, SOCK_RAW, ETH_P_ALL)
2. setsockopt(PACKET_VERSION, TPACKET_V2)  // 必须第一
3. setsockopt(PACKET_RESERVE, 4)           // 必须在 RX_RING 之前
4. setsockopt(PACKET_AUXDATA, 1)           // 可选
5. setsockopt(PACKET_RX_RING, &req)        // 环形缓冲区配置
6. mmap()
7. bind()
```
**错误顺序会导致 PACKET_RESERVE 被忽略！**

### 1.3 Ring Buffer 初始化 (2天)

- [ ] 实现 `setup_ring_buffer()` - 配置 PACKET_RX_RING
  - [ ] 实现 `mmap_ring()` - 内存映射
  - [ ] 实现 `munmap_ring()` - 取消映射
  - [ ] 实现错误处理 (`ENOMEM`, `EPERM`, `EINVAL`)
  - [ ] 添加单元测试

**CRITICAL: tpacket_req 字段计算 (来自 nmap 研究)**
```rust
// 帧大小计算
let netoff = TPACKET2_HDRLEN + 14 + RESERVE; // 48 + 14 + 4
let macoff = netoff - 14; // MAC 偏移
let frame_size = TPACKET_ALIGN(macoff + snaplen); // 对齐到 16 字节

// 块大小从页面大小开始翻倍
let mut block_size = page_size;
while block_size < frame_size { block_size *= 2; }

// 帧数和块数计算
let frame_nr = (buffer_size + frame_size - 1) / frame_size;
let frames_per_block = block_size / frame_size;
let block_nr = frame_nr / frames_per_block;
```

**CRITICAL: ENOMEM 恢复策略 (5% 迭代减少)**
```rust
// nmap 使用 5% 减少，而非固定重试
for _ in 0..MAX_RETRIES {
    match setsockopt(PACKET_RX_RING, &req) {
        Err(ENOMEM) => {
            req.tp_frame_nr = req.tp_frame_nr * 95 / 100; // 减少 5%
            // 重新计算 block_nr
        }
        result => return result,
    }
}
```

### 1.4 BPF 过滤器 (1天)

- [ ] 创建 `src/bpf.rs`
  - [ ] 定义 `BpfFilter` struct
  - [ ] 实现 `compile_bpf()` - 编译过滤器
  - [ ] 实现 `set_filter()` - 应用过滤器
  - [ ] 实现 `clear_filter()` - 清除过滤器
  - [ ] 预定义过滤器 (TCP, UDP, ICMP)
  - [ ] 添加单元测试

### 1.5 Async 包装 (2天)

- [ ] 创建 `src/async.rs`
  - [ ] 定义 `AsyncPacketEngine` struct
  - [ ] 实现 `AsyncFd` 包装
  - [ ] 实现 `recv_async()` - 异步接收
  - [ ] 实现 `recv_batch()` - 批量接收
  - [ ] 实现 `PacketStream` trait
  - [ ] 添加单元测试

### 1.6 集成和测试 (1天)

- [ ] 更新 `src/lib.rs` - Re-export 新 API
- [ ] 创建 `tests/integration_test.rs` - 集成测试
- [ ] 创建 `tests/stress_test.rs` - 压力测试
- [ ] 更新 `Cargo.toml` - 依赖版本锁定
- [ ] 文档完善

### Files to Create
- `crates/rustnmap-packet/src/syscall.rs` - 系统调用包装 (新)
- `crates/rustnmap-packet/src/tpacket.rs` - TPACKET 结构 (新)
- `crates/rustnmap-packet/src/ring.rs` - Ring buffer (新)
- `crates/rustnmap-packet/src/socket.rs` - Socket 操作 (新)
- `crates/rustnmap-packet/src/bpf.rs` - BPF 过滤器 (新)
- `crates/rustnmap-packet/src/async.rs` - Async 包装 (新)
- `crates/rustnmap-packet/tests/integration_test.rs` (新)
- `crates/rustnmap-packet/tests/stress_test.rs` (新)

### Files to Modify
- `crates/rustnmap-packet/src/lib.rs` - Re-export 新 API
- `crates/rustnmap-packet/Cargo.toml` - 更新依赖

### Success Criteria
- [ ] 所有 TPACKET_V2 结构定义完整
- [ ] `PacketRing::new()` 正确创建 socket 和映射 ring
- [ ] `AsyncPacketEngine::recv()` 异步返回数据包
- [ ] 所有单元测试通过 (覆盖率 >= 80%)
- [ ] 集成测试通过
- [ ] 文档完整且有示例
- [ ] Zero clippy warnings
- [ ] Miri 验证通过 (可选)

### Dependencies (版本锁定)
```toml
[dependencies]
libc = "0.2"
tokio = { version = "1.42", features = ["net", "io-util", "rt-multi-thread", "sync"] }
bytes = "1.9"
socket2 = "0.5"
thiserror = "2.0"
async-trait = "0.1"  # REQUIRED for PacketEngine trait

[dev-dependencies]
tokio-test = "0.4"
criterion = "0.5"
```

**CRITICAL: async-trait 依赖**
```rust
// 必须添加 async-trait = "0.1" 到 Cargo.toml
use async_trait::async_trait;

#[async_trait]  // REQUIRED macro
pub trait PacketEngine: Send + Sync {
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;
    // ...
}
```

### Estimated Time: 10 days (2 weeks)
### References:
- nmap source: `libpcap/pcap-linux.c`, `libpcap/pcap-common.c`
- Linux kernel: `include/uapi/linux/if_packet.h`
- `doc/modules/packet-engineering.md` - 技术规范
- `rust-concurrency` skill files


---

## Phase 2: Async Integration (Week 2-3)

### Goal
Build async packet capture pipeline with tokio integration

### 2.1 AsyncFd 包装 (2天)

- [ ] 创建 `src/async_fd.rs`
  - [ ] 实现 `AsyncFd<OwnedFd>` 包装
  - [ ] 实现 `wait_readable()` - 等待可读
  - [ ] 实现 `ready()` 检查
  - [ ] 夌持 `tokio::select!` 集成
  - [ ] 添加单元测试

### 2.2 PacketStream Trait (1天)

- [ ] 创建 `src/stream.rs`
  - [ ] 定义 `PacketStream` trait
  - [ ] 实现 `impl Stream for MmapPacketEngine`
  - [ ] 实现 `recv_batch()` - 批量接收
  - [ ] 添加单元测试

### 2.3 Channel 分发 (1天)

- [ ] 创建 `src/channel.rs`
  - [ ] 定义 `PacketChannel` struct
  - [ ] 实现 `create_channel()` - 创建分发器
  - [ ] 实现 `broadcast()` - 广播到多个消费者
  - [ ] 实现背压控制 (bounded channel)
  - [ ] 添加单元测试

### 2.4 Receiver Task (1天)

- [ ] 创建 `src/receiver.rs`
  - [ ] 定义 `AsyncReceiver` struct
  - [ ] 实现 `run()` - 主循环
  - [ ] 实现 `shutdown()` - 优雅关闭
  - [ ] 实现错误恢复
  - [ ] 添加单元测试

### 2.5 Scanner Integration (2天)

- [ ] 创建 `crates/rustnmap-scan/src/async_scan.rs`
  - [ ] 定义 `AsyncScanEngine` trait
  - [ ] 实现 `AsyncPacketSource` trait
  - [ ] 集成到 `ParallelScanEngine`
  - [ ] 添加单元测试

### Files to Create
- `crates/rustnmap-packet/src/async_fd.rs` - AsyncFd 包装
- `crates/rustnmap-packet/src/stream.rs` - Packet stream trait
- `crates/rustnmap-packet/src/channel.rs` - Channel utilities
- `crates/rustnmap-packet/src/receiver.rs` - Async receiver task
- `crates/rustnmap-scan/src/async_scan.rs` - Async scan integration

### Files to Modify
- `crates/rustnmap-packet/src/lib.rs` - Re-export new API
- `crates/rustnmap-scan/src/ultrascan.rs` - Add async support
- `crates/rustnmap-scan/src/lib.rs` - Re-export async APIs

### Success Criteria
- [ ] `AsyncFd` integration working with tokio select
- [ ] Non-blocking packet receive (no `spawn_blocking`)
- [ ] Channel-based distribution with backpressure
- [ ] Graceful shutdown handling
- [ ] All unit tests passing
- [ ] Performance >= synchronous `recvfrom` baseline
- [ ] Memory usage stable under load

### Estimated Time: 7 days
### Dependencies: tokio (net, io-util, sync), crossbeam-queue
### References:
- Tokio documentation: AsyncFd, mpsc channels
- nmap nsock: Event-driven architecture
- `rust-concurrency` skill: `async-io/async-network-programming.md`

---

## Phase 3: Scanner Migration (Week 3-4)

### Goal
Migrate all scanners to use new async engine, remove code duplication

### 3.1 AsyncScanEngine Trait (1天)

- [ ] 在 `src/scanner.rs` 定义 `AsyncScanEngine` trait
  - [ ] 定义 `async fn scan_port()`
  - [ ] 定义 `async fn scan_ports_batch()`
  - [ ] 定义 `fn bpf_filter()`
  - [ ] 定义 `fn timing_config()`
  - [ ] 添加默认实现
  - [ ] 添加单元测试

### 3.2 TcpSynScanner Migration (2天)

- [ ] 更新 `src/syn_scan.rs`
  - [ ] 实现 `AsyncScanEngine` trait
  - [ ] 移除 `SimpleAfPacket` 依赖
  - [ ] 使用 `AsyncPacketEngine`
  - [ ] 保留现有计时逻辑
  - [ ] 更新 BPF 过滤器生成
  - [ ] 添加单元测试
  - [ ] 添加集成测试

### 3.3 Stealth Scanners Migration (2天)

- [ ] 更新 `src/stealth_scans.rs`
  - [ ] 重构为共享的 `StealthScannerCore`
  - [ ] 实现 FIN/NULL/XMAS/ACK/Window/Maimon 扫描器
  - [ ] 移除重复的 `SimpleAfPacket`
  - [ ] 使用 `AsyncPacketEngine`
  - [ ] 保留 AdaptiveTiming 逻辑
  - [ ] 添加单元测试
  - [ ] 添加集成测试

### 3.4 UdpScanner Migration (2天)

- [ ] 更新 `src/udp_scan.rs`
  - [ ] 实现 `AsyncScanEngine` trait
  - [ ] 移除 `SimpleAfPacket` 依赖
  - [ ] 使用 `AsyncPacketEngine`
  - [ ] 优化 ICMP 接收逻辑
  - [ ] 添加单元测试
  - [ ] 添加集成测试

### 3.5 ParallelScanEngine Refactor (3天)

- [ ] 更新 `src/ultrascan.rs`
  - [ ] 重构为使用 `AsyncPacketEngine`
  - [ ] 实现异步发送/接收循环
  - [ ] 保留 CongestionControl 逻辑
  - [ ] 保留 AdaptiveTiming 逻辑
  - [ ] 移除 `spawn_blocking`
  - [ ] 添加单元测试
  - [ ] 添加集成测试

### 3.6 Cleanup (1天)

- [ ] 移除所有 `SimpleAfPacket` 定义
- [ ] 更新所有 re-exports
- [ ] 清理未使用代码
- [ ] 文档更新

### Files to Modify
- `crates/rustnmap-scan/src/scanner.rs` - Add AsyncScanEngine trait
- `crates/rustnmap-scan/src/syn_scan.rs` - Major refactor
- `crates/rustnmap-scan/src/stealth_scans.rs` - Major refactor
- `crates/rustnmap-scan/src/udp_scan.rs` - Major refactor
- `crates/rustnmap-scan/src/ultrascan.rs` - Major refactor
- `crates/rustnmap-scan/src/lib.rs` - Update exports
- `crates/rustnmap-scan/Cargo.toml` - Update dependencies

### Success Criteria
- [ ] All scan types implement AsyncScanEngine
- [ ] No `SimpleAfPacket` code remaining
- [ ] All existing tests pass
- [ ] New async tests added (coverage >= 80%)
- [ ] Performance >= current implementation (no regression)
- [ ] T5 Insane reliability >= 95%
- [ ] UDP scan performance within 20% of nmap

### Estimated Time: 11 days
### Dependencies: Phase 1, Phase 2
### References:
- Current scanner implementations
- nmap scan_engine.cc
- `rust-design-patterns` skill: Strategy pattern

---

## Phase 4: Testing & Validation (Week 5)

### Goal
Comprehensive testing and validation against nmap

### 4.1 Unit Tests Completion (2天)

- [ ] `rustnmap-packet` 测试
  - [ ] `syscall_test.rs` - 系统调用边界测试
  - [ ] `tpacket_test.rs` - 结构布局测试
  - [ ] `ring_test.rs` - Ring buffer 逻辑测试
  - [ ] `socket_test.rs` - Socket 操作测试
  - [ ] `bpf_test.rs` - BPF 过滤器测试
  - [ ] `async_test.rs` - Async 包装测试
  - [ ] 覆盖率目标: >= 85%

- [ ] `rustnmap-scan` 测试
  - [ ] `async_scan_test.rs` - 异步扫描测试
  - [ ] `timing_test.rs` - 计时逻辑测试
  - [ ] `congestion_test.rs` - 拥塞控制测试
  - [ ] 覆盖率目标: >= 80%

### 4.2 Integration Tests (2天)

- [ ] 创建 `tests/integration/`
  - [ ] `packet_engine_test.rs` - 端到端数据包测试
  - [ ] `scan_cycle_test.rs` - 完整扫描周期测试
  - [ ] `error_recovery_test.rs` - 错误恢复测试
  - [ ] `shutdown_test.rs` - 优雅关闭测试

- [ ] Mock Engine 设计
  - [ ] `MockPacketEngine` - 可预测的数据包
  - [ ] `MockSocket` - 模拟 socket 操作
  - [ ] 用于非 root 环境测试

### 4.3 Stress Tests (1天)

- [ ] 创建 `tests/stress/`
  - [ ] `high_rate_test.rs` - 高速率数据包测试
  - [ ] `long_running_test.rs` - 长时间运行测试
  - [ ] `memory_leak_test.rs` - 内存泄漏检测
  - [ ] `concurrent_access_test.rs` - 并发访问测试

### 4.4 Benchmark Suite (2天)

- [ ] 创建 `benchmarks/`
  - [ ] `packet_capture_bench.rs` - 数据包捕获基准
  - [ ] `async_vs_sync_bench.rs` - 异步 vs 同步对比
  - [ ] `scanner_bench.rs` - 扫描器性能基准
  - [ ] `timing_bench.rs` - 计时逻辑基准

### 4.5 Nmap Comparison Tests (1天)

- [ ] 创建 `tests/comparison/`
  - [ ] `tcp_syn_compare.rs` - TCP SYN 扫描对比
  - [ ] `stealth_compare.rs` - 隐秘扫描对比
  - [ ] `udp_compare.rs` - UDP 扫描对比
  - [ ] `timing_compare.rs` - 计时对比

- [ ] T5 Insane 可靠性测试
  - [ ] 100 次运行
  - [ ] 记录成功率
  - [ ] 分析失败模式

### Files to Create
- `crates/rustnmap-packet/tests/syscall_test.rs`
- `crates/rustnmap-packet/tests/tpacket_test.rs`
- `crates/rustnmap-packet/tests/ring_test.rs`
- `crates/rustnmap-packet/tests/socket_test.rs`
- `crates/rustnmap-packet/tests/bpf_test.rs`
- `crates/rustnmap-packet/tests/async_test.rs`
- `crates/rustnmap-scan/tests/async_scan_test.rs`
- `crates/rustnmap-scan/tests/timing_test.rs`
- `crates/rustnmap-scan/tests/congestion_test.rs`
- `tests/integration/packet_engine_test.rs`
- `tests/integration/scan_cycle_test.rs`
- `tests/integration/error_recovery_test.rs`
- `tests/integration/shutdown_test.rs`
- `tests/stress/high_rate_test.rs`
- `tests/stress/long_running_test.rs`
- `tests/stress/memory_leak_test.rs`
- `tests/stress/concurrent_access_test.rs`
- `benchmarks/packet_capture_bench.rs`
- `benchmarks/async_vs_sync_bench.rs`
- `benchmarks/scanner_bench.rs`
- `benchmarks/timing_bench.rs`
- `tests/comparison/tcp_syn_compare.rs`
- `tests/comparison/stealth_compare.rs`
- `tests/comparison/udp_compare.rs`
- `tests/comparison/timing_compare.rs`

### Success Criteria
- [ ] 100% unit test pass rate
- [ ] Integration tests pass (with root)
- [ ] T5 Insane: >= 95% reliability over 100 runs
- [ ] UDP scan: within 20% of nmap speed
- [ ] All stealth scans: within 25% of nmap speed
- [ ] No memory leaks (valgrind/miri clean)
- [ ] Benchmark suite runs successfully

### Estimated Time: 8 days
### Dependencies: Phase 1, Phase 2, Phase 3

---

## Phase 5: Documentation & Finalization (Week 6)

### Goal
Complete documentation, cleanup, and final review

### 5.1 API Documentation (2天)

- [ ] `rustnmap-packet` 文档
  - [ ] `PacketEngine` trait 文档
  - [ ] `MmapPacketEngine` 文档和示例
  - [ ] `AsyncPacketEngine` 文档和示例
  - [ ] `BpfFilter` 文档和示例
  - [ ] `PacketBuffer` 文档和示例
  - [ ] 错误类型文档

- [ ] `rustnmap-scan` 文档
  - [ ] `AsyncScanEngine` trait 文档
  - [ ] 所有扫描器更新文档
  - [ ] 计时配置文档
  - [ ] 错误处理文档

### 5.2 Architecture Documentation (2天)

- [ ] 更新 `doc/architecture.md`
  - [ ] 添加 PACKET_MMAP 组件图
  - [ ] 添加 Async 引擎架构图
  - [ ] 添加数据流图
  - [ ] 添加时序图

- [ ] 更新 `doc/structure.md`
  - [ ] 添加新文件到 crate 结构
  - [ ] 更新依赖关系图
  - [ ] 添加模块职责说明

- [ ] 更新 `doc/modules/packet-engineering.md`
  - [ ] 添加实现注意事项
  - [ ] 添加性能调优指南
  - [ ] 添加故障排除指南

### 5.3 Migration Guide (1天)

- [ ] 创建 `doc/migration-guide.md`
  - [ ] 从 `recvfrom` 迁移指南
  - [ ] API 兼容性说明
  - [ ] 常见问题解答
  - [ ] 代码示例

### 5.4 Code Cleanup (1天)

- [ ] 移除死代码
  - [ ] 运行 `cargo clippy` 并修复
  - [ ] 运行 `cargo fmt`
  - [ ] 检查并移除未使用的依赖
  - [ ] 检查并移除未使用的导入

### 5.5 Final Review (1天)

- [ ] 代码审查
  - [ ] 安全审查 (unsafe 块)
  - [ ] 并发审查 (原子操作)
  - [ ] 内存审查 (mmap 操作)
  - [ ] 错误处理审查

- [ ] 更新 `CHANGELOG.md`
- [ ] 更新 `README.md`
- [ ] 更新 `CLAUDE.md`

### Files to Update
- `doc/architecture.md` - Major update
- `doc/structure.md` - Major update
- `doc/modules/packet-engineering.md` - Add implementation notes
- `doc/migration-guide.md` - New file
- `CLAUDE.md` - Update architecture notes
- `doc/CHANGELOG.md` - Add v0.2.0 changes
- `README.md` - Update features list

### Success Criteria
- [ ] All public APIs documented with examples
- [ ] Architecture diagrams updated and accurate
- [ ] Migration guide complete and tested
- [ ] CHANGELOG updated for v0.2.0
- [ ] Zero dead code (clippy clean)
- [ ] Code review approved
- [ ] All unsafe blocks have SAFETY comments
- [ ] All atomic operations have memory ordering documented

### Estimated Time: 7 days
### Dependencies: Phase 1, Phase 2, Phase 3, Phase 4

---

## Phase 6: Benchmarking & Optimization (Ongoing)

### Goal
Validate performance, optimize hot paths, and ensure stability

### 6.1 Baseline Measurements (2天)

- [ ] 运行完整基准测试套件
  - [ ] TCP SYN 扫描 (T0-T5)
  - [ ] Stealth 扫描 (FIN/NULL/XMAS/ACK/Window/Maimon)
  - [ ] UDP 扫描
  - [ ] IP Protocol 扫描
  - [ ] 大规模端口扫描 (1000+ ports)

- [ ] 与 nmap 对比
  - [ ] 速度对比 (时间)
  - [ ] 准确性对比 (端口状态)
  - [ ] 内存使用对比
  - [ ] CPU 使用对比

### 6.2 Profiling (2天)

- [ ] 使用 `cargo-flamegraph` 分析
  - [ ] 识别热点路径
  - [ ] 分析内存分配
  - [ ] 分析系统调用开销

- [ ] 使用 `perf` 分析
  - [ ] CPU 缓存分析
  - [ ] 分支预测分析
  - [ ] 内存访问模式

### 6.3 Optimization (3天)

- [ ] 基于 profiling 结果优化
  - [ ] 减少内存分配
  - [ ] 优化热点路径
  - [ ] 减少系统调用

- [ ] Ring buffer 优化
  - [ ] 调整 block/frame 大小
  - [ ] 优化 poll 超时
  - [ ] 批量处理优化

- [ ] Async 优化
  - [ ] Channel 大小调优
  - [ ] 背压策略调优
  - [ ] 任务调度优化

### 6.4 Network Condition Testing (2天)

- [ ] 各种网络条件测试
  - [ ] 低延迟网络 (LAN)
  - [ ] 高延迟网络 (WAN)
  - [ ] 丢包网络 (模拟)
  - [ ] 拥塞网络 (模拟)
  - [ ] 带宽限制网络

- [ ] 网络波动恢复测试
  - [ ] 动态延迟变化
  - [ ] 突发丢包
  - [ ] 带宽波动

### 6.5 Performance Documentation (1天)

- [ ] 创建性能调优指南
  - [ ] Timing 模板选择
  - [ ] Ring buffer 配置
  - [ ] 网络条件适配
  - [ ] 资源使用优化

- [ ] 性能特性文档
  - [ ] 各扫描类型性能特征
  - [ ] 内存使用模式
  - [ ] CPU 使用模式
  - [ ] 网络带宽使用

### Performance Targets

| Scan Type | Current | Target | Nmap | Acceptance |
|-----------|---------|--------|------|------------|
| T5 Insane | ~60% reliable | >= 95% | 99%+ | >= 95% |
| TCP SYN (T3) | OK | OK | Baseline | Within 10% |
| UDP (T3) | 3x slower | Within 20% | Baseline | Within 20% |
| FIN (T3) | 1.36x faster | OK | Baseline | Within 25% |
| NULL (T3) | 0.79x | OK | Baseline | Within 25% |
| XMAS (T3) | 0.92x | OK | Baseline | Within 25% |
| ACK (T3) | 1.21x faster | OK | Baseline | Within 25% |
| Window (T3) | 0.85x | OK | Baseline | Within 25% |
| Maimon (T3) | 1.30x faster | OK | Baseline | Within 25% |

### Memory Targets

| Resource | Target | Measurement |
|----------|--------|-------------|
| Ring buffer | <= 4MB | `mmap` size |
| Heap allocation | <= 10MB | `valgrind --tool=massif` |
| Per-scan overhead | <= 1MB | Memory profiling |
| Memory leaks | 0 | `valgrind --leak-check=full` |

### Success Criteria
- [ ] All scan types within 25% of nmap speed
- [ ] T5 Insane: >= 95% reliability over 100 runs
- [ ] UDP: within 20% of nmap speed
- [ ] No packet loss under high load (stress test)
- [ ] Stable memory usage under load (no leaks)
- [ ] Graceful degradation under adverse network conditions

### Estimated Time: 10 days
### Dependencies: Phase 4
### Tools Required:
- `cargo-flamegraph`
- `perf`
- `valgrind`
- `tokio-console` (optional)

---

## Risk Assessment

### Technical Risks
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| PACKET_MMAP complexity | Medium | High | Start with V2, reference nmap |
| Async integration bugs | Medium | High | Comprehensive testing, use proven patterns |
| Performance regression | Low | Medium | Benchmark suite, CI gates |
| Memory safety issues | Low | High | Miri validation, careful unsafe code |
| Timing accuracy | Medium | Medium | Reference nmap timing.cc |

### Schedule Risks
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Scope creep | High | High | Strict phase boundaries |
| Testing delays | Medium | Medium | Parallel test development |
| Integration issues | Medium | High | Incremental integration |

---

## Rollback Plan
If critical issues arise:
1. **Phase 1-2 issues**: Revert to `recvfrom` implementation
2. **Phase 3 issues**: Keep old scanner code, use feature flags
3. **Phase 4 issues**: Extend testing phase, defer production use
4. **Complete failure**: Restore from git tag v0.1.0

---

## Approval Checklist
- [ ] Architecture design reviewed and approved
- [ ] Implementation phases approved
- [ ] Timeline acceptable
- [ ] Resources allocated
- [ ] Risk mitigation acceptable
- [ ] Success criteria defined
- [ ] Rollback plan reviewed

---

## References
- nmap source code: `reference/nmap/`
- libpcap documentation: https://www.tcpdump.org/manpages/pcap.3pcap.html
- Linux PACKET_MMAP: https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
- TPACKET V2/V3: https://www.kernel.org/doc/html/latest/networking/tpacket.html
- Tokio documentation: https://docs.rs/tokio/latest/tokio/
- Rust async patterns: `rust-concurrency` skill files
- Rust design patterns: `rust-design-patterns` skill files
- Project CLAUDE.md: `CLAUDE.md`
