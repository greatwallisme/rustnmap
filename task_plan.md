# Task Plan: RustNmap Performance Optimization

> **Created**: 2026-03-10
> **Status**: Phase 1 Complete - Optimization Ineffective
> **Context**: Post-refactoring performance regression - root cause analysis needed

---

## Objective

系统性分析并修复 rustnmap 性能问题，确保至少达到 nmap 的 95% 性能。

**用户要求**:
- 不接受低于 95% 的性能
- 必须系统性分析根因
- 参考 nmap 实现方式
- 不允许猜测和表面修改

---

## Benchmark Results Summary

### Complete Test Results
- **Total Tests**: 39
- **Passed**: 38
- **Failed**: 0
- **Pass Rate**: 97.4%

### Critical Performance Issues (< 0.5x) - P0

| Test | rustnmap | nmap | Ratio | Issue |
|------|----------|------|-------|-------|
| IPv6 | 258ms | 47ms | **0.18x** | 5.5倍慢，最严重问题 |
| Fast Scan | 6352ms | 3913ms | **0.62x** | 1.6倍慢 |
| Fast + Top Ports | 5405ms | 2166ms | **0.40x** | 2.5倍慢 |
| Top Ports | 5525ms | 2540ms | **0.45x** | 2.2倍慢 |
| OS Detection | 25541ms | 11479ms | **0.44x** | 2.3倍慢 |
| Two Targets | 1643ms | 774ms | **0.47x** | 2.1倍慢 |

### Good Performance (> 1.0x)

| Test | rustnmap | nmap | Ratio | Notes |
|------|----------|------|-------|-------|
| Aggressive Scan | 14055ms | 30127ms | **2.14x** | 最快测试 ✅ |
| Version Detection | 7493ms | 9764ms | **1.30x** | ✅ |
| Connect Scan | 553ms | 671ms | **1.21x** | ✅ |
| Window Scan | 613ms | 733ms | **1.19x** | ✅ |
| T1 Sneaky | 75814ms | 90725ms | **1.19x** | ✅ |

### Acceptable Performance (0.8-1.0x)

| Test | rustnmap | nmap | Ratio |
|------|----------|------|-------|
| T4 Aggressive | 824ms | 830ms | **0.99x** | ✅ 接近目标 |
| XMAS Scan | 4465ms | 4423ms | **0.99x** | ✅ |
| NULL Scan | 4474ms | 4292ms | **0.95x** | ✅ 达标 |

### Sub-Optimal Performance (0.5-0.8x) - P1

| Test | rustnmap | nmap | Ratio | Notes |
|------|----------|------|-------|-------|
| SYN Scan | 865ms | 761ms | **0.87x** | 接近但未达标 |
| UDP Scan | 950ms | 732ms | **0.77x** | 需要优化 |
| T3 Normal | 870ms | 717ms | **0.82x** | 接近目标 |
| T4 | 862ms | 709ms | **0.82x** | 接近目标 |
| T5 Insane | 835ms | 708ms | **0.84x** | 接近目标 |

---

## Phase 1: Restore Single Target Optimization - ❌ INEFFECTIVE

**Status**: Complete but ineffective

**Action Taken**:
- 恢复了 `orchestrator.rs::run_host_discovery()` 中的单目标自动跳过逻辑

**Expected Results** (from historical obs #2049):
- 之前效果：620-650ms vs nmap 802-814ms（20-23% 更快）
- 预期消除 283ms (31%) 的主机发现开销

**Actual Results**:
- 优化前：~865ms
- 优化后：~825ms
- nmap baseline：~747ms
- **提升：仅40ms（4.6%），效果微弱**

**Root Cause Analysis**:
- 历史优化可能是在不同测试条件下得出的
- 当前测试显示主机发现可能不是主要瓶颈
- 需要重新分析真正的性能瓶颈位置

---

## Phase 2: Fast Scan Root Cause Analysis (P0) - IN PROGRESS

**Status**: Systematic debugging required

**Problem**:
- Fast Scan: 6352ms vs nmap 3913ms
- 差距：2439ms（62%差距）
- 两者都扫描100个端口

**Step 1: Verify Test Conditions** ✅
- nmap: 100 ports in 2.42s
- rustnmap: 100 ports in 6.11s
- 确认端口数量相同

**Step 2: Check Timing Templates**
- nmap Fast Scan 是否使用特殊 timing？
- rustnmap Fast Scan 是否有额外延迟？

**Step 3: Analyze Scan Loop**
- 参考 obs #2015: 63.3% 时间花在等待响应
- 参考 obs #2020: 413ms async 开销

**Investigation Needed**:
1. 检查 nmap Fast Scan 的 timing 配置
2. 对比 rustnmap 的 scan delay 设置
3. 分析数据包发送速率差异
4. 检查端口列表生成开销

---

## Phase 3: IPv6 Performance Investigation (P0)

**Status**: Pending

**Problem**:
- IPv6: 258ms vs nmap 47ms
- **5.5倍慢**，最严重问题

**Possible Causes**:
1. IPv6 socket 配置差异
2. DNS 解析延迟
3. 路由选择问题
4. 数据包封装开销

**Investigation Needed**:
1. 对比 IPv4 vs IPv6 扫描路径
2. 检查 socket 创建和配置
3. 分析网络层差异

---

## Phase 4: Multi-Target Optimization (P1)

**Status**: Pending

**Problem**:
- Two Targets: 1643ms vs nmap 774ms
- 2.1倍慢

**Possible Causes**:
1. 每个目标重复初始化
2. 串行 vs 并行处理
3. 扫描状态共享开销

---

## Historical Context

### Previous Optimization (obs #2049)
- **Date**: 2026-03-09
- **Change**: 单目标自动跳过主机发现
- **Effect**: 620-650ms vs nmap 802-814ms（20-23% 更快）
- **Status**: 当前恢复后效果不明显，可能测试条件不同

### Known Bottlenecks

| Bottleneck | Impact | Location | Status |
|------------|-------|----------|--------|
| Wait time | 63.3% (347ms/549ms) | Scan loop | obs #2015 |
| Host discovery | 282ms (31.7%) | Orchestrator | obs #2044 |
| Async overhead | 413ms | Setup/teardown | obs #2020 |

---

## Success Criteria

- [ ] **所有测试达到 >= 0.95x 性能**
- [ ] Fast Scan >= 0.95x
- [ ] Top Ports >= 0.95x
- [ ] IPv6 >= 0.95x
- [ ] SYN Scan >= 0.95x
- [ ] Two Targets >= 0.95x

---

## Error Log

| Error | Phase | Attempt | Resolution |
|-------|-------|--------|------------|
| Single target optimization ineffective | Phase 1 | Restored optimization | Only 40ms improvement, not root cause |
| Fast Scan 0.38x | Phase 2 | Pending | Root cause analysis needed |
| IPv6 0.18x | Phase 4 | Pending | Investigation needed |

---

## Next Actions

1. ❌ Phase 1 完成 - 但效果不佳
2. ✅ **Phase 2 ROOT CAUSE FOUND** - 初始RTT timeout太长 (1000ms)
3. ⏳ **Phase 2 修复进行中** - 实施修复
4. ⏳ Phase 4 待处理 - IPv6 严重性能问题
5. ⏳ Phase 3 待处理 - 多目标优化

---

## Implementation Log

### 2026-03-10 23:58 - Root Cause Identified
**Analysis Method**: Memory search + code analysis + diagnostic run
**Root Cause**: Initial probe timeout too long (1000ms) causing cascading cwnd collapse
**Evidence**:
- Memory observations #3084-3088 confirm per-probe scan_delay was removed
- Diagnostic: 96.6% wait time, 373 iterations, cwnd drops to 1 for 150 iterations
- Code: `recommended_timeout()` uses full `initial_rtt` (1000ms) for first probe

**Solution**: Clamp initial RTT to max 200ms for Fast Scan
