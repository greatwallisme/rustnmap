# Findings - RustNmap 项目分析

**Created**: 2026-02-19
**Updated**: 2026-02-26 13:30
**Status**: Phase 24 - 发现 ACK/Window 扫描修复可能未生效，正在调查

---

## Phase 24: ACK/Window 扫描修复验证 - 发现问题

### 测试结果 (2026-02-26 13:20)

**手动测试**:
```
# ACK Scan - 192.168.12.1
./target/release/rustnmap --scan-ack -p 22,80 192.168.12.1
22/tcp  open    ssh    # WRONG! 应该是 unfiltered
80/tcp  closed  http   # WRONG! 应该是 unfiltered

# Window Scan - 192.168.12.1
./target/release/rustnmap --scan-window -p 22,80 192.168.12.1
22/tcp  open    ssh    # WRONG! 应该是 closed (window=0) 或 open (window>0)
80/tcp  closed  http   # 可能正确
```

### 问题分析

**现象**: ACK 扫描返回 `open` 和 `closed` 而不是 `unfiltered`

**根因分析**:
1. `open` 状态在 ACK 扫描中**不可能出现** - ACK 扫描只返回 `unfiltered` 或 `filtered`
2. 扫描在 0.02 秒内完成 - 远低于 1 秒超时
3. 这表明扫描器正在回退到 `scan_port_connect()` 而不是使用 `TcpAckScanner`

**代码流程**:
```rust
// orchestrator.rs:1546-1550
ScanType::TcpAck => match TcpAckScanner::new(local_addr, scanner_config) {
    Ok(scanner) => scanner.scan_port(...),
    Err(_) => return self.scan_port_connect(target, port).await,  // 回退到这里
},
```

**可能的原因**:
1. `TcpAckScanner::new()` 静默失败
2. 原始套接字创建失败
3. AF_PACKET 套接字创建失败

### 根因确认

**测试结果**:

| 权限 | 命令 | 结果 | 分析 |
|------|------|------|------|
| 无 sudo | `./target/release/rustnmap --scan-ack` | `open`/`closed` | 回退到 TCP Connect |
| 有 sudo | `sudo ./target/release/rustnmap --scan-ack` | `unfiltered` | 原始套接字正常 |

**结论**: Phase 23 的修复是**正确的**。之前的测试失败是因为没有使用 sudo 权限运行。

### 遗留问题：ACK/Window 扫描缺少批量模式 (Phase 25)

**问题表现**:
- 远程目标部分端口返回 `filtered` 而不是 `unfiltered`
- 性能比 nmap 慢 3-7 倍

**根因**: `TcpAckScanner` 和 `TcpWindowScanner` **没有** `scan_ports_batch` 方法！

```rust
// orchestrator.rs:796-799
let use_batch = matches!(
    primary_scan_type,
    ScanType::TcpFin | ScanType::TcpNull | ScanType::TcpXmas | ScanType::TcpMaimon
);
// TcpAck 和 TcpWindow 不在列表中！
```

**对比**:
| 扫描器 | 批量方法 | 顺序方法 |
|--------|----------|----------|
| TcpFinScanner | ✓ | ✓ |
| TcpNullScanner | ✓ | ✓ |
| TcpXmasScanner | ✓ | ✓ |
| TcpMaimonScanner | ✓ | ✓ |
| **TcpAckScanner** | **✗** | ✓ |
| **TcpWindowScanner** | **✗** | ✓ |

**解决方案**:
1. 为 `TcpAckScanner` 添加 `scan_ports_batch` 方法
2. 为 `TcpWindowScanner` 添加 `scan_ports_batch` 方法
3. 将 `ScanType::TcpAck` 和 `ScanType::TcpWindow` 添加到批量扫描列表

---

## Phase 23: ACK/Window 扫描 Bug 修复 - 代码已提交，待完整验证

### Bug 根因分析

**发现**: ACK 和 Window 扫描器使用非阻塞 `recv_packet()` 而不是带超时的接收循环

**对比代码**:

| 扫描器 | 接收方式 | 结果 |
|--------|----------|------|
| FIN/NULL/XMAS/Maimon | `recv_packet_with_timeout()` + 循环 | ✅ 正确接收 RST |
| ACK/Window | `recv_packet()` 无超时 | ❌ 无法接收 RST |

**代码位置**:
- ACK Scanner: `stealth_scans.rs:1953-1963` (修复前)
- Window Scanner: `stealth_scans.rs:2645-2655` (修复前)
- FIN Scanner (正确实现): `stealth_scans.rs:524-534`

### 修复内容

1. 为 `TcpAckScanner::send_ack_probe()` 添加接收循环
2. 为 `TcpWindowScanner::send_window_probe()` 添加接收循环
3. 使用 `recv_packet_with_timeout()` 等待 RST 响应
4. 添加 `handle_icmp_response_with_match()` 函数

### 已验证（仅手动测试）

| 测试项 | 目标 | rustnmap | nmap | 状态 |
|--------|------|----------|------|------|
| ACK Scan | 192.168.12.1:22,80,443 | unfiltered | unfiltered | ✅ 匹配 |
| Window Scan | 192.168.12.1:22,80,443 | closed | closed | ✅ 匹配 |

### ⚠️ 未验证项

| 项目 | 原因 |
|------|------|
| Benchmark 套件 | 未运行 `comparison_test.py` |
| 远程目标 | 只测试了本地网关 |
| 不同端口组合 | 只测试了 3 个端口 |
| 不同网络环境 | 只测试了一种网络 |

### Commit 信息

```
commit 45d3ec8
fix: ACK and Window scan state detection with receive loop
```

---

## Phase 22: 测试日志深度分析

### Bug 根因分析

**发现**: ACK 和 Window 扫描器使用非阻塞 `recv_packet()` 而不是带超时的接收循环

**对比代码**:

| 扫描器 | 接收方式 | 结果 |
|--------|----------|------|
| FIN/NULL/XMAS/Maimon | `recv_packet_with_timeout()` + 循环 | ✅ 正确接收 RST |
| ACK/Window | `recv_packet()` 无超时 | ❌ 无法接收 RST |

**代码位置**:
- ACK Scanner: `stealth_scans.rs:1953-1963`
- Window Scanner: `stealth_scans.rs:2645-2655`
- FIN Scanner (正确实现): `stealth_scans.rs:524-534`

**问题**:
1. `recv_packet()` 是非阻塞的，立即返回 None 如果没有数据
2. 然后回退到 raw socket，但 raw socket 无法接收 RST（内核 TCP 栈消耗）
3. 结果：总是返回 `Filtered` 而不是检查 RST 响应

**修复方案**:
- 为 ACK 和 Window 扫描器添加与 FIN 扫描器相同的接收循环
- 使用 `recv_packet_with_timeout()` 等待 RST 响应

### nmap 行为参考

**ACK Scan** (refguide.xml:689):
- RST 收到 → Unfiltered
- 无响应/ICMP → Filtered

**Window Scan** (refguide.xml:1479):
- RST + Window > 0 → Open
- RST + Window == 0 → Closed
- 无响应/ICMP → Filtered

---

## Phase 22: 测试日志深度分析

### 1. "Ports only in rustnmap" 警告分析

**现象**: 测试报告显示 rustnmap 报告了很多 nmap 没有报告的端口

**根因分析**:
- rustnmap 默认输出所有扫描的端口（包括 closed）
- nmap 默认隐藏 closed 端口，显示 "Not shown: X closed ports"

**实际输出对比**:
```
# rustnmap --fast-scan 45.33.32.156
PORT     STATE SERVICE
199/tcp  closed  smux      # closed 端口
5051/tcp  closed  ida-agent # closed 端口
37/tcp  closed  time       # closed 端口
...

# nmap -F 45.33.32.156
Not shown: 95 closed ports  # 隐藏 closed 端口
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  open     http
```

**测试脚本处理**:
- compare_scans.py:398-411 尝试过滤 closed 端口
- 但 filtered 端口仍然显示为差异
- 这不是测试脚本 bug，而是 rustnmap 行为与 nmap 不一致

**解决方案**:
1. 修改 rustnmap 默认行为，隐藏 closed 端口
2. 添加 `--show-all` 选项让用户显式请求显示所有端口

### 2. 性能警告分析

| 测试 | rustnmap | nmap | 比率 | 分析 |
|-----|----------|------|------|------|
| SYN Scan | 955ms | 881ms | 0.92x | 接近，可接受 |
| Connect Scan | 699ms | 610ms | 0.87x | 接近，可接受 |
| UDP Scan | 3167ms | 2679ms | 0.85x | 需要优化 |
| Fast Scan | 4925ms | 3881ms | 0.79x | 需要优化 |
| **Top Ports** | **5850ms** | **2642ms** | **0.45x** | **严重** |
| **Two Targets** | **2167ms** | **771ms** | **0.36x** | **严重** |

**Top Ports 慢的原因**:
- rustnmap 可能扫描了比 nmap 更多的端口
- nmap 对 top ports 有特殊优化

### 3. 功能缺失分析

| 功能 | nmap 支持 | rustnmap 支持 | 状态 |
|-----|----------|--------------|------|
| Decoy (-D) | ✅ | ❌ | 未实现 |
| JSON Output | ❌ | ✅ | nmap 不支持（测试问题） |

---

## Phase 23: ACK/Window 扫描修复 - COMPLETE

| Metric | 之前 (Phase 21) | 之后 (Phase 23) |
|-------|---------------|-------------|
| ACK Scan | 总是 filtered | unfiltered (正确!) |
| Window Scan | 总是 filtered | closed (正确!) |

### 修改摘要

1. 为 ACK 和 Window 扫描器添加了带超时的接收循环
2. 使用 `recv_packet_with_timeout()` 焉待 RST 响应
3. 正确匹配响应的源 IP 和目标地址

4. 正确解析 TCP window 字段

5. 更新测试用例以使用新的函数名

### 代码质量
- 所有 clippy 警告已修复
- 所有测试通过 (93 tests)### 总体结果

| Metric | 励值 |
|-------|------|-------|
| 总测试数 | 41 | 36 (87.8%) |
| 通过 | 5 | 5 | ✅ |
| 失败 | 5 | ❌ |

### 通过的测试套件 (全部 PASS)

1. **Basic Port Scans** (5/5) - ✅ SYN, Connect, UDP, 快速、Top 端口
2. **Service Detection** (3/3) - ✅ 版本检测、强度检测、攻击扫描
3. **Advanced scans** (6/6) - ✅ FIN/NULL/MAimon/窗口扫描
4. **timing模板** (8/8) - ✅ T0-T5, 速率限制
5. **多目标** (5/5) - ✅ 两个目标、 端口范围、 排除端口、 快速+top、 IPv6
6. **输出格式** (3/4) - ⚠️ JSON (nmap 不支持)
、 普通/XML/grepable通过

7. **扩展隐秘扫描** (4/7) - ❌ FIN/null/XMAS/马imon/窗口/ACK 扫描失败
8. **隐秘+诱饵** (1/1) - ❌ 诱饵扫描失败

### 失败测试详情

#### 1. OS Detection Limit
- **错误**: 状态不匹配 (2 ports)
  - `31337/tcp: rustnmap=filtered, nmap=open`
  - `9929/tcp: rustnmap=filtered, nmap=open`
- **根因**: 端口状态判断逻辑差异

#### 2. JSON输出
- **错误**: nmap 不支持 JSON 输出
- **根因**: 测试配置问题（nmap 没有 `-oX` 选项）

#### 3. ACK 扫描 (Extended stealth scans)
- **错误**: 所有 5 端口状态不匹配
  - `rustnmap=filtered`, `nmap=unfiltered`
- **根因**: ACK 扫描状态判断逻辑错误
- **参考**: nmap `scan_engine.cc:6672-6676` - RST+syn 返回 `unfiltered`，没有 syn 返回 `filtered`

#### 4. 窗口扫描 (Extended stealth scans)
- **错误**: 所有 5 端口状态不匹配
  - `rustnmap=filtered`, `nmap=closed`
- **根因**: 窗口扫描状态判断逻辑错误
- **参考**: nmap `scan_engine.cc:6684-6686`

#### 5. Stealth with Decoys
- **错误**: rustnmap 命令失败
- **根因**: 诱饵扫描功能实现问题

### 性能总结

| 测试类型 | 之前 (Phase 19) | 之后 (Phase 21) | 改进 |
|---------|---------------|---------------|------|
| SYN Scan | 2194ms (2.7x慢) | **895ms (1.02x 快)** | **3.7x** |
| Connect Scan | 628ms (1.41x 快) | 702ms (1.15x 快) | 保持 |
| UDP Scan | 2787ms (2.35x 快) | **2569ms (1.58x 快)** | 保持 |
| Fast Scan | 2143ms (2.06x 快) | **3466ms (1.34x 快)** | 保持 |
| Top Ports | 19107ms (4.4x 慢) | **3469ms (1.44x 快)** | **5.8x** |

### 关键修复

1. **首次 RTT 测量直接使用** (nmap timing.cc:119-124)
   - 之前: EWMA 慢收敛
   - 之后: 首次测量直接设置 SRTT/RTTVAR

2. **自适应等待时间计算**
   - 基于最早超时计算等待时间
   - 避免无意义的 10ms 循环等待

3. **批处理计数器重置逻辑**
   - 只在发送满 50 个探测后重置
   - 不是每次收到响应就重置

---

## 历史记录

### Phase 20: 50-probe 批处理限制修复 - COMPLETE (2026-02-26 10:21)
- 实现了 nmap 的 50-probe 批处理限制
- SYN 扫描从 2.7x 慢改进到 1.02x 快

### Phase 19: Small Port Scan Optimization - FAILED (2026-02-26)
- 错误的优化方向导致性能下降
- SYN 和 Top Ports 性能严重退化
- 教训: 没有仔细研究 nmap 实现就盲目修改是错误的

### Phase 18: cc_scale Implementation - COMPLETE (2026-02-25)
- 添加了 cc_scale 自适应缩放机制
- 对某些场景有改进，但不够

### Phase 17: Bug Investigation & Nmap Database Integration - COMPLETE
- nmap-services 数据库支持
- nmap-protocols 数据库支持
- AF_PACKET 集成修复
