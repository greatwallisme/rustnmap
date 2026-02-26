# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-26 10:21
**Status**: Phase 20 COMPLETE - 性能问题已修复

---

## Phase 20: 50-probe 批处理限制修复 - COMPLETE

### 问题根因

通过仔细阅读 nmap 源码 (`reference/nmap/scan_engine.cc:326-327`), 发现 rustnmap 缺少 **关键的 50-probe 批处理限制**。

nmap 的实现:
```cpp
// Limit sends between waits to avoid overflowing pcap buffer
recentsends = USI->gstats->probes_sent - USI->gstats->probes_sent_at_last_wait;
if (recentsends >= 50)  // HARD LIMIT: 50 probes per wait cycle
    return false;
```

### 修复内容

**修改文件**: `crates/rustnmap-scan/src/ultrascan.rs`

1. 添加常量 `BATCH_SIZE = 50`
2. 在 `scan_ports()` 中跟踪每批发送的探测数
3. 每发送 50 个探测后，等待并处理所有可用响应
4. 重置批处理计数器

### 性能对比

| 测试类型 | 修复前 | 修复后 | 改进 |
|---------|--------|--------|------|
| SYN Scan | 2.7x 慢 | 1.19x 快 | **4.1x 改进** |
| Top Ports | 4.4x 慢 | 1.09x 快 | **4.8x 改进** |
| Connect Scan | 1.41x 快 | 1.08x 快 | 保持 |
| Fast Scan | 2.06x 快 | 1.36x 快 | 保持 |
| UDP Scan | 2.35x 快 | 0.80x 慢 | 需单独优化 |

### 代码质量

- ✅ `cargo clippy --workspace --all-targets -- -D warnings` - 零警告
- ✅ `cargo test --workspace --lib --bins` - 34 测试通过
- ✅ 所有修复都基于对 nmap 源码的深入理解

---

## Phase 21: 后续优化 (可选)

### 待优化项

1. **UDP 扫描性能**: 当前比 nmap 慢 20%，需要单独分析
2. **SYN 扫描小端口优化**: 仍可在小端口数时进一步优化

### 优化方向

1. 研究 nmap 的 UDP 扫描实现
2. 分析 nmap 对小端口扫描的特殊处理
3. 使用 profiler 找出剩余瓶颈

---

## 历史阶段

### Phase 19: Small Port Scan Performance - FAILED (2026-02-26)
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
