# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-26 11:21
**Status**: Phase 21 - 分析失败测试

---

## Phase 21: 分析 Benchmark 失败测试

### Benchmark 完整结果 (2026-02-26 11:15)

**总体**: 36/41 tests passed (87.8%), 5/41 tests failed

### 通过的测试套件
| Suite | Tests | Status |
|------|-------|--------|
| Basic Port Scans | 5/5 | ✅ ALL通过 |
| Service Detection | 3/3 | ✅ 所有通过 |
| OS Detection | 2/3 | ⚠️ 1失败 (OS Detection Limit) |
| Advanced Scans | 6/6 | ✅ 所有通过 |
| Timing Templates | 8/8 | ✅ 所有通过 |
| Multi-Target | 5/5 | ✅ 所有通过 |
| Output Formats | 3/4 | ⚠️ 1失败 (JSON Output) |

### 失败测试详情

#### 1. OS Detection Limit
- **状态**: FAIL
- **错误**: State mismatches (2 ports)
  - `31337/tcp: rustnmap=filtered, nmap=open`
  - `9929/tcp: rustnmap=filtered, nmap=open`
- **根因**: 可能是端口状态判断逻辑差异

#### 2. JSON Output
- **状态**: FAIL
- **错误**: nmap 不支持 JSON 输出
- **根因**: 这是测试本身有问题，nmap 没有 `-oX` 选项

#### 3. ACK Scan (Extended stealth scans)
- **状态**: FAIL
- **错误**: state mismatches (5 ports)
  - 所有端口: rustnmap=filtered, nmap=unfiltered
- **根因**: ACK 扫描状态判断逻辑错误

#### 4. Window Scan (extended stealth scans)
- **状态**: FAIL
- **错误**: state mismatches (5 ports)
  - 所有端口: rustnmap=filtered, nmap=closed
- **根因**: window 扫描状态判断逻辑错误

#### 5. Stealth with Decoys
- **状态**: FAIL
- **错误**: rustnmap 命令失败
- **根因**: 诱饵扫描功能实现问题

### 关键发现

1. **Basic Suite 全部通过**: SYN/Connect/UDP/Fast/Top Ports 性能都很好
2. **ACK/Window 扫描状态判断**: 应该返回 `unfiltered/closed`，但返回 `filtered`
3. **OS Detection Limit**: 2 个端口状态不匹配
4. **JSON Output**: nmap 不支持 JSON 格式（测试配置问题）

---

## Phase 20: 50-probe 批处理限制修复 - COMPLETE

### 修改文件

`crates/rustnmap-scan/src/ultrascan.rs`:
1. 添加 `first_measurement` 标志用于首次 RTT 直接设置
2. 添加 `BatchesSent` 批处理跟踪
3. 实现自适应等待时间计算
4. 修复批处理计数器重置逻辑

### 性能对比

| 测试类型 | Phase 19 | Phase 20 | Phase 21 |
|---------|---------|---------|---------|
| SYN Scan | 0.78x | **1.02x** | 1.02x |
| UDP Scan | 0.91x | **1.58x** | 1.58x |
| Fast Scan | 0.87x | **1.34x** | 1.34x |
| Top Ports | 0.49x | **1.44x** | 1.44x |

---

## 历史阶段

### Phase 19: Small Port Scan Optimization - FAILED (2026-02-26)
- 错误的优化方向导致性能下降
- SYN 和 Top Ports 性能严重退化
- 教训: 没有仔细研究 nmap 实现就盲目修改是错误的

### Phase 18: cc_scale Implementation - COMPLETE (2026-02-25)
- 添加了 cc_scale 自适应缩放机制
- 对某些场景有改进

### Phase 17: Bug investigation & Nmap Database Integration - COMPLETE
- nmap-services 数据库支持
- nmap-protocols 数据库支持
- AF_PACKET 集成修复
