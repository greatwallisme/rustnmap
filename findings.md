# Findings - RustNmap 项目分析

**Created**: 2026-02-19
**Updated**: 2026-02-26 11:21
**Status**: Phase 21 - 分析失败测试

---

## Phase 21: Benchmark 完整测试结果

### 总体结果

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
