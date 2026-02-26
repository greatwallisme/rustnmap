# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-26 14:36
**Status**: Phase 25 - 批量扫描修复完成，ACK/Window 性能超越 nmap

---

## Phase 23: 修复 ACK/Window 扫描状态判断 - CODE COMPLETE, BENCHMARK 待验证

### Bug 根因

ACK 和 Window 扫描器使用非阻塞 `recv_packet()` 而不是带超时的接收循环：
- `recv_packet()` 立即返回 None 如果没有数据
- 回退到 raw socket 无法接收 RST（内核 TCP 栈消耗）
- 结果：总是返回 `Filtered` 而不是正确判断

### 修复方案

为 ACK 和 Window 扫描器添加与 FIN 扫描器相同的接收循环：
1. 使用 `recv_packet_with_timeout()` 等待 RST 响应
2. 在循环中处理响应直到超时

### 修改文件

- `crates/rustnmap-scan/src/stealth_scans.rs`
  - `TcpAckScanner::send_ack_probe()` - 添加接收循环
  - `TcpWindowScanner::send_window_probe()` - 添加接收循环
  - 添加 `handle_icmp_response_with_match()` 函数

### 已完成的验证（仅手动测试）

```
# 手动测试 - 192.168.12.1
sudo ./target/release/rustnmap --scan-ack 192.168.12.1 -p 22,80,443
22/tcp  unfiltered ssh  ✅
80/tcp  unfiltered http ✅
443/tcp unfiltered https ✅

sudo nmap -sA -p 22,80,443 192.168.12.1
22/tcp  unfiltered ssh
80/tcp  unfiltered http
443/tcp unfiltered https
# 结果匹配！

# Window scan
sudo ./target/release/rustnmap --scan-window 192.168.12.1 -p 22,80,443
22/tcp  closed  ssh  ✅
80/tcp  closed  http ✅
443/tcp closed  https ✅

sudo nmap -sW -p 22,80,443 192.168.12.1
22/tcp  closed  ssh
80/tcp  closed  http
443/tcp closed  https
# 结果匹配！
```

### ⚠️ 未完成事项

1. **Benchmark 测试需要 sudo** - 必须使用 `sudo python3 benchmarks/comparison_test.py` 运行
2. **Top Ports 性能问题未修复** - 0.45x 性能差距仍然存在

---

## Phase 24: ACK/Window 修复验证 - COMPLETE

### 根因分析

ACK/Window 扫描需要 root 权限。之前的测试失败是因为没有使用 sudo。

| 权限 | 命令 | 结果 | 原因 |
|------|------|------|------|
| 无 sudo | `./target/release/rustnmap --scan-ack` | `open`/`closed` | 回退到 TCP Connect |
| 有 sudo | `sudo ./target/release/rustnmap --scan-ack` | `unfiltered` | 原始套接字正常 |

### 验证命令

```bash
# ACK Scan - 需要 sudo
sudo ./target/release/rustnmap --scan-ack -p 22,80 192.168.12.1
# 22/tcp  unfiltered ssh  ✅
# 80/tcp  unfiltered http ✅

# Window Scan - 需要 sudo
sudo ./target/release/rustnmap --scan-window -p 22,80 192.168.12.1
# 22/tcp  closed  ssh  ✅
# 80/tcp  closed  http ✅
```

### 结论

Phase 23 的修复是**正确的**。之前的测试失败是因为没有使用 sudo 权限运行。

---

## Phase 25: ACK/Window 批量扫描实现 - COMPLETE

### 问题

ACK 和 Window 扫描没有使用批量模式，导致：
1. 性能比 nmap 慢 3-7 倍
2. 远程目标部分端口返回错误状态

### 根本原因

1. `TcpAckScanner` 和 `TcpWindowScanner` 没有 `scan_ports_batch` 方法
2. Orchestrator 批量扫描列表不包含 `ScanType::TcpAck` 和 `ScanType::TcpWindow`
3. 响应匹配逻辑错误 - 使用响应目的端口而不是源端口

### 修复内容

1. **添加 `parse_tcp_response_with_window` 函数** (rustnmap-net/src/lib.rs)
   - 返回 TCP 窗口字段用于 Window 扫描

2. **添加 `TcpAckScanner::scan_ports_batch`** (stealth_scans.rs)
   - 批量发送所有 ACK 探测
   - 正确匹配 RST 响应 (使用响应源端口 = 目标端口)
   - RST → Unfiltered, 无响应 → Filtered

3. **添加 `TcpWindowScanner::scan_ports_batch`** (stealth_scans.rs)
   - 批量发送所有 ACK 探测
   - 解析 TCP 窗口字段
   - Window > 0 → Open, Window == 0 → Closed

4. **更新 Orchestrator** (orchestrator.rs)
   - 将 `ScanType::TcpAck` 和 `ScanType::TcpWindow` 添加到批量扫描列表
   - 添加对应的扫描器创建逻辑

### 测试结果

| 扫描类型 | rustnmap | nmap | 性能比 |
|---------|----------|------|--------|
| FIN Scan | 1636ms | 4162ms | **2.54x faster** |
| NULL Scan | 1593ms | 4575ms | **2.87x faster** |
| XMAS Scan | 1745ms | 4707ms | **2.70x faster** |
| MAIMON Scan | 1641ms | 4698ms | **2.86x faster** |
| **ACK Scan** | **697ms** | **733ms** | **1.05x faster** ✓ |
| Window Scan | 1546ms | 3358ms | **2.17x faster** |

### 遗留问题

1. **Decoy Scan** - 未实现 (`rustnmap exit=1`)
2. **Window Scan 状态不一致** - 偶尔显示 `filtered` 而不是 `closed`

---

## Phase 26: Top Ports 性能优化 - PENDING

### 问题

rustnmap Top Ports 比 nmap 慢 2.2x (0.45x)

### 需要调查

1. 检查 nmap 的 `--top-ports` 实现细节
2. 比较 rustnmap 和 nmap 扫描的端口数量
3. 检查批处理和并发设置

---

## Phase 26: Decoy Scan 实现 - PENDING

### 问题

`Stealth with Decoys` 测试失败，rustnmap exit=1

### 原因

Decoy 扫描功能未完全实现

---

## Phase 22: 深度分析测试日志警告和失败 - COMPLETE

### 问题分类

经过详细分析，测试日志中的警告和失败可分为以下几类：

#### 1. "Ports only in rustnmap" 警告 - **代码问题**

**根因**: rustnmap 输出所有端口（包括 closed），nmap 默认隐藏 closed 端口

**证据**:
```
# rustnmap 输出 - 显示所有端口
199/tcp  closed  smux
5051/tcp  closed  ida-agent
...

# nmap 输出 - 隐藏 closed 端口
Not shown: 95 closed ports
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  open     http
```

**测试脚本逻辑** (compare_scans.py:398-411):
- 尝试过滤 closed 端口
- 但 filtered 端口仍然显示差异

**解决方案**:
1. 修改 rustnmap 默认行为，隐藏 closed 端口（像 nmap 一样）
2. 或者添加 `--show-all` 选项让用户选择

#### 2. "Speed: 0.XXx slower" 警告 - **需要优化**

| 测试 | rustnmap | nmap | 比率 | 严重性 |
|-----|----------|------|------|--------|
| SYN Scan | 955ms | 881ms | 0.92x | 轻微 |
| Connect Scan | 699ms | 610ms | 0.87x | 轻微 |
| Top Ports | 5850ms | 2642ms | **0.45x** | 严重 |
| Two Targets | 2167ms | 771ms | **0.36x** | 严重 |

**Top Ports 慢的原因**:
- rustnmap 扫描更多端口（100个），nmap 可能优化了端口选择
- 需要分析 nmap 的 top ports 实现

#### 3. 状态判断失败 - **代码 Bug** (Phase 23 修复中)

| 扫描类型 | 问题 | nmap 参考代码 |
|---------|------|--------------|
| ACK Scan | filtered → 应为 unfiltered | scan_engine.cc:6672-6676 |
| Window Scan | filtered → 应为 closed | scan_engine.cc:6684-6686 |

#### 4. 功能未实现 - **功能缺失**

| 功能 | 状态 |
|-----|------|
| Stealth with Decoys (-D) | rustnmap exit=1 |
| JSON Output | nmap 不支持（测试配置问题） |

### 下一步行动

1. **P0**: 修复 ACK/Window 扫描状态判断逻辑 (Phase 23)
2. **P1**: 修复 rustnmap 默认隐藏 closed 端口
3. **P2**: 优化 Top Ports 性能
4. **P3**: 实现 Decoy 扫描功能

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
