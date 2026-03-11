# Task Plan: RustNmap Performance Optimization

> **Created**: 2026-03-10
> **Status**: Phase 2 Partial Progress - NOT COMPLETE
> **Context**: Performance optimization - work in progress

---

## Objective

系统性分析并修复 rustnmap 性能问题。

**用户严格要求**:
1. **速度必须比nmap快** - 低于95%都是不可接受的
2. **准确度必须与nmap完全相同** - 必须逐端口对比验证

---

## Current Status - NOT MEETING REQUIREMENTS

### Latest Benchmark Results (2026-03-11)

| Test | rustnmap | nmap | Ratio | Status |
|------|----------|------|-------|--------|
| Fast Scan | 4728ms | 4000ms | **0.84x** | ❌ 未达标 (需>=0.95x) |
| Top Ports | 2130ms | 2567ms | **1.20x** | ✅ 达标 |
| Fast + Top Ports | 5078ms | 2171ms | **0.42x** | ❌ 严重未达标 |
| SYN Scan | 865ms | 761ms | **0.87x** | ❌ 未达标 |

### Critical Issues

1. **Fast Scan: 0.84x** - 比nmap慢16%，需要继续优化
2. **Fast + Top Ports: 0.42x** - 比nmap慢58%，严重问题
3. **准确度未验证** - 需要逐端口对比确认与nmap完全相同

---

## Phase 2: Fast Scan Optimization - IN PROGRESS (NOT COMPLETE)

### Analysis Completed
- Root cause identified: Initial RTT timeout (1000ms) caused cascading cwnd collapse
- Diagnostic data: 96.6% wait time, 373 iterations, cwnd=1 for 150 iterations

### Fix Applied
- Clamped initial RTT timeout to max 200ms
- Location: `crates/rustnmap-scan/src/ultrascan.rs:189-209`

### Results After Fix

| Metric | Before | After | Target | Status |
|--------|--------|-------|--------|--------|
| Fast Scan | 6404ms | 4728ms | <3800ms | ❌ 仍慢18% |
| Top Ports | 5525ms | 2130ms | <2440ms | ✅ 达标 |
| Fast + Top Ports | 5405ms | 5078ms | <2060ms | ❌ 仍慢60% |

### Current Gap Analysis

**Fast Scan (4728ms vs nmap 4000ms)**:
- 差距: 728ms (18%)
- 需要进一步优化

**Fast + Top Ports (5078ms vs nmap 2171ms)**:
- 差距: 2907ms (60%)
- 严重问题，需要深入调查

### Next Steps (NOT STARTED)

1. **准确度验证**:
   - 逐端口对比rustnmap vs nmap结果
   - 确保每个端口状态完全一致

2. **性能优化**:
   - 分析为什么Fast + Top Ports这么慢
   - 检查是否有其他瓶颈

3. **目标**:
   - Fast Scan: <3800ms (比nmap快5%)
   - Fast + Top Ports: <2060ms (比nmap快5%)

---

## Phase 3: IPv6 Performance - PENDING

**Problem**: IPv6: 258ms vs nmap 47ms (0.18x) - 5.5倍慢

---

## Phase 4: Multi-Target Optimization - PENDING

**Problem**: Two Targets: 1643ms vs nmap 774ms (0.47x) - 2.1倍慢

---

## Success Criteria - NOT MET

- [ ] **速度比nmap快** (ratio >= 0.95x)
  - [ ] Fast Scan >= 0.95x - 当前 0.84x ❌
  - [ ] Fast + Top Ports >= 0.95x - 当前 0.42x ❌
  - [ ] Top Ports >= 0.95x - 当前 1.20x ✅

- [ ] **准确度与nmap完全相同**
  - [ ] 逐端口对比验证 - 未完成 ❌

---

## Error Log

| Error | Status | Notes |
|-------|--------|-------|
| Initial RTT timeout fix insufficient | Partial | Improved but not meeting requirements |
| Fast + Top Ports severely slow | Not investigated | Needs deep analysis |
| Accuracy not verified | Not started | Critical requirement |

---

## Next Actions

1. ❌ Phase 2 未完成 - Fast Scan仍慢18%
2. ❌ 准确度未验证 - 必须逐端口对比
3. ⏳ Fast + Top Ports需要深入调查
4. ⏳ IPv6性能问题待处理
5. ⏳ 多目标优化待处理
