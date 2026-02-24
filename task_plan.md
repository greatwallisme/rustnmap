# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-24 17:56
**Status**: Phase 17 - Bug Investigation & Fixes
**Goal**: Fix MAC address output, FIN scan accuracy

---

## 当前阶段

Phase 17: Bug Investigation & Fixes - IN PROGRESS

### 待解决问题

1. **MAC 地址输出缺失** (MEDIUM)
   - 现象: rustnmap 不显示目标 MAC 地址，nmap 显示
   - 根因: 基础设施存在但未连接 (`HostResult.mac` 始终为 `None`)
   - 文件: `orchestrator.rs`, `mac.rs`

3. **FIN 扫描端口状态不准确** (LOW)
   - 现象: rustnmap 显示 `open|filtered`, nmap 显示 `closed`
   - 影响: 80 端口状态判断差异

---

## Phase 16: Decoy Scan Integration - COMPLETE

**目标**: 实现 CLI `-D` 参数与扫描引擎的集成

**状态**: 功能完成 (2026-02-24)

**修复说明**: 添加 `create_decoy_scheduler()` 辅助函数，确保 `scan_port()` 函数也将 decoy 配置传递给所有隐身扫描器。

### 实现总结

1. **修改 Stealth Scanners** (`crates/rustnmap-scan/src/stealth_scans.rs`)
   - 为 TcpFinScanner, TcpNullScanner, TcpXmasScanner, TcpMaimonScanner 添加 `decoy_scheduler` 字段
   - 添加 `with_decoy()` 构造函数
   - 修改 `scan_ports_batch()` 支持多源发送

2. **修改 Orchestrator** (`crates/rustnmap-core/src/orchestrator.rs`)
   - 从 `evasion_config` 创建 `DecoyScheduler`
   - 传递给扫描器构造函数

3. **添加依赖** (`crates/rustnmap-scan/Cargo.toml`)
   - 添加 `rustnmap-evasion` 依赖

### 关键实现逻辑

对于每个端口，发送 N 个探测（每个 decoy + 真实 IP），仅跟踪真实 IP 的响应：

```rust
if let Some(scheduler) = &self.decoy_scheduler {
    scheduler.reset();
    while let Some(src_ip) = scheduler.next_source() {
        // 发送探测
        let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, ...);
        self.socket.send_packet(&packet, &addr)?;

        // 仅跟踪真实 IP 的探测
        if scheduler.is_real_ip(&src_ip) {
            outstanding.insert((*dst_port, src_port), ...);
        }
    }
}
```

### 测试验证

```bash
# 构建
cargo build --release  # PASS

# 测试
cargo test --package rustnmap-scan --package rustnmap-core  # 168 tests PASS

# Clippy
cargo clippy -- -D warnings  # PASS
```

### 使用方法

```bash
# Decoy 扫描
sudo ./target/release/rustnmap -sF -D 192.168.1.100,192.168.1.101 192.168.1.1
```

---

## Phase 17: Bug Investigation & Fixes (当前阶段)

**目标**: 修复 MAC 地址输出、FIN 扫描准确性问题

**状态**: IN PROGRESS

### 问题清单

| 优先级 | 问题 | 状态 | 备注 |
|--------|------|------|------|
| HIGH | Decoy Scan 验证失败 | ✅ 已修复 (2026-02-24) | evasion_config 现已正确传递 |
| MEDIUM | MAC 地址输出缺失 | 🔍 待实现 | 需要 ARP 处理逻辑 |
| LOW | FIN 扫描状态不准确 | 🔍 待调查 | RST 响应处理 |

### 调查计划

#### Step 1: MAC 地址实现

1. 分析 nmap MAC 地址获取逻辑
2. 在 `orchestrator.rs` 添加 ARP 请求发送
3. 解析 ARP 响应并填充 `HostResult.mac`

#### Step 2: FIN 扫描调试

1. 对比 rustnmap 和 nmap 的 tcpdump 输出
2. 检查 RST 响应是否被正确接收
3. 验证端口状态判断逻辑

---

## 历史阶段

### Phase 15: P0/P1 优化修复 - COMPLETE

... (保留原有内容)
