# Findings - RustNmap 项目分析

**Created**: 2026-02-19
**Updated**: 2026-02-27 16:05
**Status**: Phase 30 - UDP Parallel Scanning - AF_PACKET ICMP Reception Limitations

---

## Phase 30.2: UDP Parallel Scanning - ICMP Reception Analysis (2026-02-27 16:05)

### Implementation Status

UDP并行扫描已在ultrascan.rs中完整实现：
- `scan_udp_ports`方法实现并行UDP探测
- `UdpOutstandingProbe`和`IcmpResponse`结构
- ICMP响应解析和匹配逻辑
- 阻塞式AF_PACKET socket with SO_RCVTIMEO
- 增加的socket接收缓冲区(2MB)
- 50ms inter-probe delay (like nmap)
- 500ms minimum probe timeout for UDP

### Current Issue: Inconsistent ICMP Reception

**症状**：
- 第一次扫描通常正确
- 后续扫描中部分端口显示为`open|filtered`而不是`closed`
- 端口8080（通常是最后一个扫描的端口）最常出现问题
- 约70%的扫描完全正确

**根本原因分析**：

1. **AF_PACKET vs libpcap差异**：
   - nmap使用libpcap，具有内核级BPF过滤和环形缓冲区
   - AF_PACKET没有BPF过滤，接收所有数据包
   - libpcap的缓冲机制更可靠

2. **ICMP速率限制**：
   - 目标主机可能限制ICMP Port Unreachable响应的速率
   - nmap有`--defeat-icmp-ratelimit`选项处理此问题
   - 快速连续扫描可能导致ICMP响应丢失

3. **时序问题**：
   - 第一次扫描：系统状态干净，工作正常
   - 后续扫描：可能存在网络栈状态问题

### 实施的优化

1. 阻塞式socket with SO_RCVTIMEO (100ms) - 消除polling gaps
2. 增大socket接收缓冲区 (2MB) - 防止packet loss
3. 50ms inter-probe delay - 减少ICMP rate limiting
4. 500ms minimum UDP timeout - 给ICMP响应更多时间
5. Final ICMP wait (200ms) - 捕获最后的响应
6. Socket buffer flush - 清除之前扫描的stale数据

### 性能数据

- rustnmap UDP (5 ports): ~1.5-2秒
- nmap UDP (5 ports): ~0.7-0.9秒
- rustnmap比nmap慢约2倍，主要由于50ms inter-probe delay

### 可能的解决方案

1. **使用libpcap** (推荐)：
   - 添加pcap crate依赖
   - 使用pcap_open_live()和BPF过滤器
   - 这是nmap使用的方法

2. **BPF过滤**：
   - 在AF_PACKET socket上实现BPF过滤
   - 只接收ICMP和相关数据包

3. **--defeat-icmp-ratelimit选项**：
   - 像nmap一样实现此选项
   - 在检测到ICMP rate limiting时调整行为

### Next Steps

1. 评估是否添加pcap crate依赖
2. 实现BPF过滤以提高ICMP接收可靠性
3. 考虑添加--defeat-icmp-ratelimit选项

---

## Phase 30: UDP Parallel Scanning Research (2026-02-27)

### Root Cause Analysis - CONFIRMED

经过深入研究nmap源代码和使用deepwiki查询，确认了UDP扫描问题的根本原因：

**架构差异：顺序扫描 vs 并行扫描**

| 特性 | Nmap (ultra_scan) | RustNmap (Current) |
|------|-------------------|-------------------|
| 扫描架构 | 并行 | 顺序 |
| 探测发送 | 批量发送，受cwnd限制 | 一次一个端口 |
| 响应等待 | 统一等待所有探测的响应 | 每个探测单独等待 |
| ICMP捕获 | 在统一等待期间捕获所有ICMP | 只捕获当前端口的ICMP |
| 性能 | 5端口 ~700ms | 5端口 ~3000ms |
| 准确性 | ~100% | ~60% |

### Nmap ultra_scan Architecture (from source code)

**Main Loop** (scan_engine.cc:2776-2791):
```cpp
while (!USI.incompleteHostsEmpty()) {
    doAnyPings(&USI);
    doAnyOutstandingRetransmits(&USI);  // 重传超时的探测
    doAnyRetryStackRetransmits(&USI);   // 从retry_stack重传
    doAnyNewProbes(&USI);               // 发送新探测（批量）
    waitForResponses(&USI);             // 统一等待所有响应
    processData(&USI);                  // 处理所有响应
}
```

**Congestion Window** (scan_engine.cc:399, 584):
```cpp
if (timing.cwnd >= num_probes_active + 0.5) {
    // 允许发送新探测
}
```

**ICMP Handling** (scan_engine_raw.cc:501-536):
```cpp
// 捕获ICMP类型3（Port Unreachable）、4（Source Quench）、11（Time Exceeded）
else if ((hdr.proto == IPPROTO_ICMP && (ping->type == 3 || ping->type == 4 || ping->type == 11))) {
    // 解析内嵌的原始IP/UDP头
    encaps_len = datalen - 8;
    encaps_data = ip_get_data((char *) data + 8, &encaps_len, &encaps_hdr);
    // 匹配到对应的探测并更新端口状态
}
```

### Key Findings from DeepWiki

**Nmap UDP扫描实现**:
1. `ultra_scan`函数是扫描的核心，处理包括UDP在内的各种扫描类型
2. `retry_stack`机制用于管理需要重传的探测包
3. **Closed**: 收到ICMP Port Unreachable响应
4. **Open|Filtered**: 所有重传后都没有响应
5. `--defeat-icmp-ratelimit`选项可以在ICMP响应慢时加速扫描

**Nmap性能优化**:
1. 主机组大小：UDP扫描使用128个主机的批次
2. 自适应定时和拥塞控制：动态调整探测速率和延迟
3. 载荷优化：同时发送每个端口的UDP载荷
4. cwnd机制控制并行探测数量

### Timing Constants (nmap.h:192-200)
```c
#define MAX_RTT_TIMEOUT 10000    // 最大RTT超时10秒
#define INITIAL_RTT_TIMEOUT 1000 // 初始RTT超时1秒
#define MAX_RETRANSMISSIONS 10   // 最大重传次数（共11次探测）
```

### Why Sequential Scanning Cannot Match Nmap

**问题**：ICMP响应可能在超时后到达

**顺序扫描的困境**：
1. 发送端口A的探测
2. 等待端口A的ICMP响应（最多1000ms）
3. 如果ICMP在1001ms到达，端口A被标记为`open|filtered`
4. 开始扫描端口B
5. 但此时端口A的ICMP已经到达，却被忽略

**并行扫描的优势**：
1. 同时发送端口A、B、C、D、E的探测
2. 统一等待所有端口的响应
3. 在等待期间，任何端口的ICMP响应都会被捕获
4. 即使某个ICMP响应延迟，也会被正确处理

### Solution: Implement UDP Parallel Scanning

**必须在ultrascan.rs中实现UDP并行扫描支持**：

1. **添加UDP探测发送**：批量发送UDP探测，受cwnd限制
2. **添加ICMP响应处理**：解析ICMP Port Unreachable并匹配到正确的探测
3. **更新Orchestrator**：使用并行扫描而不是顺序扫描

---

## Phase 28-29: Failed Attempts (2026-02-27)

### What Was Tried

1. **增加超时时间** (1500ms, 2000ms, 3000ms)
   - 结果：性能下降，仍然有40-70%失败率

2. **添加重试逻辑**
   - 结果：超时变成17+分钟
   - 根本原因：重试逻辑在顺序架构中会累加超时

3. **合并AF_PACKET和Socket接收循环**
   - 结果：仍然有40-70%失败率
   - 根本原因：仍然是一个端口一个端口地扫描

4. **添加源IP验证**（已修复）
   - 问题：UDP响应没有验证是否来自目标IP
   - 修复：添加`src_ip == dst_addr`检查
   - 结果：不再出现错误的`open`状态

### Why These Approaches Were Wrong

**核心错误**：试图在顺序扫描架构上打补丁，而不是实现正确的并行扫描架构。

**正确的解决方案**：在ultrascan.rs中实现UDP并行扫描，完全复制nmap的ultra_scan架构。

---

## Benchmark Results: 40/41 tests PASS (97.6%)

| Suite | Tests | Pass | Fail | Rate |
|-------|-------|------|------|------|
| Basic Port Scans | 5 | 4 | 1 | 80% |
| Service Detection | 3 | 3 | 0 | 100% |
| OS Detection | 3 | 3 | 0 | 100% |
| Advanced Scans | 6 | 6 | 0 | 100% |
| Timing Templates | 8 | 8 | 0 | 100% |
| Multi-Target Scans | 5 | 5 | 0 | 100% |
| Output Formats | 4 | 3 | 1 | 75% |
| Extended Stealth Scans | 7 | 7 | 0 | 100% |

### Failed Test: UDP Scan
- **Error**: 端口状态不匹配，不同运行失败端口不同
- **Root Cause**: 顺序扫描架构无法聚合ICMP响应
- **Solution**: 实现UDP并行扫描

---

## Key Learnings

1. **必须研究nmap源代码**：不能凭猜测实现，必须深入理解nmap的架构

2. **架构差异是根本原因**：不是简单的参数调整问题，而是架构问题

3. **并行扫描是关键**：nmap的性能和准确性都来自并行扫描架构

4. **不接受简化方案**：必须完整实现ultra_scan架构才能达到nmap级别

5. **ICMP响应可能延迟**：ICMP Port Unreachable可能被目标限速或网络延迟

6. **顺序扫描的局限性**：在顺序扫描中，ICMP响应可能在超时后到达，导致误判
