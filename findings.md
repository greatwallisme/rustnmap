# Research Findings

> **Updated**: 2026-03-11 00:30
> **Status**: Work In Progress - NOT MEETING REQUIREMENTS

---

## IMPORTANT: 用户严格要求

1. **速度必须比nmap快** (ratio >= 0.95x) - 低于95%不可接受
2. **准确度必须与nmap完全相同** - 需要逐端口验证

**当前状态**: 均未达标

---

## CURRENT BENCHMARK RESULTS (2026-03-11)

### After Initial RTT Clamp Fix

| Test | rustnmap | nmap | Ratio | Status |
|------|----------|------|-------|--------|
| Fast Scan | 4728ms | 4000ms | **0.84x** | ❌ 未达标 (需>=0.95x) |
| Top Ports | 2130ms | 2567ms | **1.20x** | ✅ 达标 |
| Fast + Top Ports | 5078ms | 2171ms | **0.42x** | ❌ 严重未达标 |
| 准确度 | - | - | **未验证** | ❌ 必须验证 |

### Gap Analysis

**Fast Scan (4728ms vs 4000ms)**:
- 差距: 728ms (18% slower)
- 需要: 再快728ms才能达到nmap水平
- 要比nmap快: 需要达到 <3800ms

**Fast + Top Ports (5078ms vs 2171ms)**:
- 差距: 2907ms (60% slower)
- 这是严重问题，需要深入调查
- 原因未知

---

## ROOT CAUSE ANALYSIS

### Problem: Fast Scan Slow (6404ms vs nmap 3913ms)

**分析过程**:

1. **Memory Search** - 找到之前的优化记录
   - obs #3084-3088: 确认per-probe scan_delay被移除
   - obs #3086: Congestion control改为group scan behavior

2. **代码分析** - `ultrascan.rs`
   - `recommended_timeout()` 对第一个probe返回 `initial_rtt` (1000ms)
   - 这导致第一次timeout后cwnd崩溃

3. **诊断运行**
   - 96.6% 时间在等待
   - 373次迭代 (应该只有10-20次)
   - cwnd: 10 → 6 → 1 (stays at 1 for 150 iterations)

### Fix Applied

**修改**: `crates/rustnmap-scan/src/ultrascan.rs:195`
```rust
// Before:
self.initial_rtt.min(self.max_rtt)

// After:
self.initial_rtt.min(self.max_rtt).min(Duration::from_millis(200))
```

### Result: PARTIAL IMPROVEMENT ONLY

| Metric | Before | After | Required | Status |
|--------|--------|-------|----------|--------|
| Fast Scan | 6404ms | 4728ms | <3800ms | ❌ 仍慢18% |
| Improvement | - | 26% | - | 不足够 |

---

## UNRESOLVED ISSUES

### 1. Fast Scan Still Slow (0.84x)
- 当前: 4728ms
- 目标: <3800ms
- 差距: 928ms
- 原因: 未知，需要进一步调查

### 2. Fast + Top Ports Severely Slow (0.42x)
- 当前: 5078ms
- 目标: <2060ms
- 差距: 3018ms
- 原因: 未知，可能是不同的瓶颈

### 3. Accuracy Not Verified
- 必须逐端口对比rustnmap vs nmap结果
- 确保每个端口状态完全一致
- 这是用户强制要求

---

## NEXT INVESTIGATION NEEDED

### 1. 准确度验证 (CRITICAL)
```
运行相同扫描，对比每个端口结果:
- nmap -sS -F target
- rustnmap -sS -F target
- 逐端口对比STATE字段
```

### 2. Fast + Top Ports 深入分析
- 为什么比单独Fast Scan慢这么多?
- 是否有额外的开销?
- 检查端口列表生成逻辑

### 3. 进一步性能优化
- 分析剩余的728ms差距来自哪里
- 检查数据包发送速率
- 对比nmap的实际行为

---

## FILES MODIFIED

| File | Change | Status |
|------|--------|--------|
| `ultrascan.rs` | Initial RTT clamp | Committed |
| `comparison_test.sh` | Fixed CLI options | Committed |
| `task_plan.md` | Updated status | Updated |
| `progress.md` | Updated log | Updated |
| `findings.md` | This file | Updated |
