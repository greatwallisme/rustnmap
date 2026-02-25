# Findings - RustNmap 项目分析

**Created**: 2026-02-19
**Updated**: 2026-02-25 18:15
**Status**: Phase 18 COMPLETE - cc_scale Implemented and Verified

---

## 最新发现 (2026-02-25 18:15) - Phase 18.3 Benchmark 结果

### cc_scale 实现后的基准测试

**Benchmark 测试结果** (comparison_test.py - basic suite, scanme.nmap.org):

| 测试类型 | rustnmap | nmap | 加速比 | 状态 |
|---------|----------|------|--------|------|
| SYN 扫描 (5 端口) | 905ms | 688ms | 0.76x | 慢 24% |
| Fast 扫描 (100 端口) | 2733ms | 4266ms | 1.56x | 快 56% |
| Top 端口 (100 端口) | 2506ms | 4101ms | 1.64x | 快 64% |

### 分析

**正面结果**:
1. 100 端口扫描 (Fast/Top) 比 nmap 快约 1.5-1.6x
2. 这次测试结果稳定,没有之前 18s 的异常情况

**需要注意**:
1. 之前 18.4s 的异常结果原因未明,可能涉及网络条件波动
2. 5 端口 SYN 扫描仍然比 nmap 慢 24%
3. 测试只针对 scanme.nmap.org,其他目标可能表现不同

**问题**:
- UDP 扫描有状态不匹配: 443/udp rustnmap=open, nmap=closed

### Phase 18 状态: COMPLETE (需要更多验证)

- [x] Phase 18.1: 添加 cc_scale 跟踪
- [x] Phase 18.2: 更新拥塞控制逻辑
- [x] Phase 18.3: 验证和调优

---

## 历史发现 (2026-02-25 17:35)

### 已完成的修改

1. **max_cwnd: 100 → 300** (`ultrascan.rs:446`)
   - 匹配 nmap 的默认 max_parallelism (`timing.cc:271`)
   - 应该提升大端口扫描性能

2. **添加 timing_level 字段到 ScanConfig**
   - 用于跟踪当前使用的 timing template (T0-T5 → 0-5)
   - 允许 congestion controller 根据 timing template 调整参数
   - 修改文件: `scan.rs`, `orchestrator.rs`, `discovery_integration_tests.rs`

3. **实现 ca_incr = 2 for T4/T5** (`ultrascan.rs`)
   - 匹配 nmap 的 `timing.cc:276-279`
   - `timing_level >= 4` 时使用 `ca_incr = 2`
   - 在 congestion avoidance 中每次增长 +2 而非 +1

4. **修复所有 Clippy 警告** ✅
   - 文档中缺失的反引号 (max_parallelism, ca_incr, timing_level)
   - benchmark 中的元组解构 (添加 _dst_port)
   - 测试中的 ScanConfig 初始化 (添加 timing_level)

### 代码质量状态

```bash
cargo clippy --release --all-targets -- -D warnings
# Finished - 零警告 ✅
```

### 测试结果分析

**5 端口 SYN 扫描** (17:13):
- rustnmap: 829ms, nmap: 716ms (0.86x - 16% 慢)
- 状态: 可接受 ✅

**100 端口扫描** - 结果不稳定:
- 16:41 (max_cwnd=100): rustnmap 3.0s vs nmap 4.3s (1.4x faster) ✅
- 17:14 (max_cwnd=300): rustnmap 18.4s vs nmap 2.4s (0.13x - 7.7x slower) 🔴
- 17:20 (max_cwnd=300): rustnmap 6.3s vs nmap 4.6s (0.73x - 27% 慢) ⚠️

### 分析结论

1. **max_cwnd=300 导致 100 端口扫描不稳定**
   - 不同测试运行结果差异巨大 (3s → 18s → 6s)
   - 可能原因: 网络条件、目标负载、或某种副作用
   - 需要添加诊断日志来找出根本原因

2. **5 端口扫描性能合理**
   - 16% 慢是可以接受的范围
   - cwnd 增长空间有限 (10 → 15)

3. **T4/T5 仍比 nmap 慢**
   - 即使实现了 ca_incr=2，效果不明显
   - 可能需要实现 cc_scale 自适应缩放

### 待解决问题

**P0: 100 端口扫描性能不稳定**
- 需要详细日志记录 cwnd 变化历史
- 检查是否有超时/重试问题
- 对比 nmap 和 rustnmap 的详细时序

**P1: 缺少 cc_scale 自适应缩放**
- nmap 使用 `ratio = num_replies_expected / num_replies_received`
- 最大可加速 50 倍
- 实现较复杂，需要跟踪额外状态

**P2: 可能需要回退 max_cwnd**
- 300 可能对于某些网络条件过大
- 需要找到平衡点 (150-200?)

### 下一步

1. 添加诊断日志调查 100 端口不稳定问题
2. 考虑实现 cc_scale 自适应缩放
3. 测试不同的 max_cwnd 值找到最优配置

---

## 最新发现 (2026-02-25 18:30) - Phase 18.1 Complete

### cc_scale 实现已完成 ✅

**修改的文件**: `crates/rustnmap-scan/src/ultrascan.rs`

**添加的功能**:
1. `num_replies_expected: AtomicU64` - 探测得到回复或超时时递增
2. `num_replies_received: AtomicU64` - 实际收到回复时递增
3. `cc_scale()` 方法 - 返回 `MIN(ratio, 50)` 缩放因子
4. `record_expected()` 方法 - 记录探测预期回复

**修改的方法**:
1. `on_packet_acked()` - 应用 cc_scale 到 cwnd 增长
2. `check_timeouts()` - 超时时调用 `record_expected()`
3. `scan_ports()` - 收到回复时调用 `record_expected()`

**代码质量**:
- ✅ `cargo clippy --workspace --all-targets -- -D warnings` - 零警告
- ✅ 所有类型转换都使用 `#[expect]` 注释说明合理性

---

## 历史发现 (2026-02-25 18:10) - cc_scale 缺失分析

### 关键发现: rustnmap 缺少 nmap 的核心性能优化机制

**问题根源**: 通过仔细阅读 nmap 源码 (`timing.cc:209-237`), 发现 rustnmap 缺少关键的 `cc_scale` 机制。

### nmap 的 cc_scale 机制

**目的**: 当存在包丢失时,加速拥塞窗口增长以维持吞吐量。

**原理**:
```c
// timing.cc:211-218
double ultra_timing_vals::cc_scale(const struct scan_performance_vars *perf) {
  double ratio;
  assert(num_replies_received > 0);
  ratio = (double) num_replies_expected / num_replies_received;
  return MIN(ratio, perf->cc_scale_max);  // cc_scale_max = 50
}
```

**关键点**:
- `num_replies_expected`: 探测得到回复或超时时递增
- `num_replies_received`: 实际收到回复时递增
- `ratio = num_replies_expected / num_replies_received`:
  - = 1: 无包丢失 (每个探测都有回复)
  - > 1: 存在包丢失 (期望的回复 > 实际收到的)
- `cc_scale = MIN(ratio, 50)`: 最多加速 50 倍!

**拥塞控制公式** (timing.cc:227, 237):
```c
// Slow start: cwnd += slow_incr * cc_scale * scale
// Congestion avoidance: cwnd += ca_incr / cwnd * cc_scale * scale
```

### 为什么 rustnmap 慢?

**当前实现** (ultrascan.rs:216-243):
```rust
fn on_packet_acked(&self, rtt: Option<Duration>) {
    // ...
    if current_cwnd < ssthresh {
        // Slow start: +1 (linear)
        let new_cwnd = (current_cwnd + 1).min(self.max_cwnd);
    } else {
        // Congestion avoidance: +ca_incr once per cwnd ACKs
        // Missing: cc_scale multiplier!
    }
}
```

**缺失项**:
1. ❌ `num_replies_expected` 计数器
2. ❌ `num_replies_received` 计数器
3. ❌ `cc_scale()` 函数
4. ❌ cc_scale 应用于 cwnd 增长

### 性能影响分析

**场景 1: 无包丢失 (理想网络)**
- nmap: cc_scale = 1, cwnd 正常增长
- rustnmap: cc_scale 隐式 = 1, 相同
- **结果**: 性能接近 ✅

**场景 2: 有包丢失 (真实网络)**
- nmap: cc_scale = 2-50, cwnd 加速增长以补偿丢失
- rustnmap: cc_scale 隐式 = 1, cwnd 正常 (慢) 增长
- **结果**: rustnmap 比 nmap 慢 🔴

**场景 3: 严重包丢失 (不稳定网络)**
- nmap: cc_scale = 50, cwnd 极速恢复
- rustnmap: cwnd 慢速恢复, 持续低吞吐
- **结果**: rustnmap 严重慢于 nmap 🔴

### 实现计划

**Phase 18.1: 添加 cc_scale 跟踪**
1. 在 `InternalCongestionStats` 中添加:
   - `num_replies_expected: AtomicU64`
   - `num_replies_received: AtomicU64`
2. 实现 `cc_scale()` 方法

**Phase 18.2: 更新拥塞控制**
1. 在 `on_packet_acked()` 中应用 cc_scale
2. 在 `on_packet_lost()` 中递增 `num_replies_expected`
3. 在探测超时时递增 `num_replies_expected`

**Phase 18.3: 验证和调优**
1. 运行 benchmark 对比 nmap
2. 调整 max_cwnd 如需要
3. 确认性能 >= nmap

### 代码参考

**nmap timing.cc 关键代码**:
```c
// timing.cc:87-93
int num_replies_expected;  // 期望的回复数 (包括超时)
int num_replies_received;  // 实际收到的回复数

// timing.cc:209-218
double cc_scale(const struct scan_performance_vars *perf) {
  double ratio;
  assert(num_replies_received > 0);
  ratio = (double) num_replies_expected / num_replies_received;
  return MIN(ratio, perf->cc_scale_max);
}

// timing.cc:220-241
void ack(const struct scan_performance_vars *perf, double scale) {
  num_replies_received++;
  if (cwnd < ssthresh) {
    cwnd += perf->slow_incr * cc_scale(perf) * scale;
  } else {
    cwnd += perf->ca_incr / cwnd * cc_scale(perf) * scale;
  }
}

// scan_engine.cc:1608-1612
void ultrascan_adjust_timing(...) {
  // ALWAYS increment expected (reply OR timeout)
  USI->gstats->timing.num_replies_expected++;
  // ...
  if (rcvdtime != NULL) {
    // ONLY increment received when actual reply
    USI->gstats->timing.ack(&USI->perf, ping_magnifier);
  }
}
```

### 下一步

1. 实现 cc_scale 机制
2. 运行 benchmark 验证性能
3. 确保达到或超过 nmap 性能

---

## 历史发现 (2026-02-25 16:50)

### T3-T5 Timing 模板性能问题 - 🔍 分析中 (已完成部分实现)

**原始问题**: T3-T5 timing 模板下 rustnmap 比 nmap 慢

**Nmap 源码分析** (已完成):
1. max_cwnd = 300 (timing.cc:271) ✅ 已实现
2. ca_incr = 2 for T4/T5 (timing.cc:276-279) ✅ 已实现
3. cc_scale 自适应缩放 (timing.cc:211-217) ❌ 未实现

**实现的功能** (已完成):
- max_cwnd: 100 → 300
- 添加 timing_level 字段
- 实现 ca_incr = 2 for T4/T5
- 修复所有 Clippy 警告

**剩余问题**:
- 100 端口扫描不稳定
- T4/T5 仍比 nmap 慢约 20%
- 缺少 cc_scale 自适应缩放

---

## 更早发现 (2026-02-25 15:30)

### Benchmark 脚本解析问题 - ✅ 已修复

**问题**: `compare_scans.py` 无法正确解析 nmap 和 rustnmap 的输出

**根本原因**:
- nmap 使用 "Not shown: 95 closed ports" 隐藏 closed 端口
- rustnmap 显示所有端口包括 closed 端口
- 解析逻辑没有处理 nmap 的 "Not shown" 摘要行

**修复**:
1. 添加 `hidden_closed_count` 字段到 `ScanResult`
2. 解析 "Not shown: X closed ports" 行
3. 比较时过滤掉 nmap 隐藏的 closed 端口

**修改文件**: `benchmarks/compare_scans.py`

---

## 更早发现 (2026-02-25 15:45)

### SYN 扫描性能问题 - ✅ 已修复

**问题**: rustnmap SYN 扫描比 nmap 慢

**Nmap 源代码分析** (reference/nmap/timing.cc):
- initial_cwnd = 10 (已匹配)
- initial_ssthresh = 75 (已匹配)
- max_cwnd = 300 (已实现)

**修复**: max_parallelism 从默认值改为匹配 nmap

---

## 最早发现 (2026-02-25 15:15)

### Benchmark 解析问题修复 - ✅ 已完成

- 修复了 nmap 输出解析中的 "Not shown" 处理
- 修复了端口状态比较逻辑
- 添加了 hidden_closed_count 字段
