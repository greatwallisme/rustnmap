# Task Plan: TCP Window Scan (-sW) Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Status**: COMPLETE
> **Created**: 2026-02-14
> **Completed**: 2026-02-14
> **Goal**: 严格对照 doc/modules/port-scanning.md 实现 TCP Window Scan (-sW)

---

## Goal

实现 TCP Window Scan (-sW)，这是一种类似于 ACK 扫描的技术，但通过检查 RST 响应中的 TCP Window 字段来区分开放和关闭的端口。

## Background

根据设计文档 `doc/modules/port-scanning.md` 和 Nmap 参考：

### TCP Window Scan 工作原理

1. **发送探测**: 发送带有 ACK 标志的 TCP 包到目标端口
2. **端口状态判断**:
   - **RST + Window > 0** -> Port **Closed** (某些系统如 HP-UX 等)
   - **RST + Window = 0** -> Port **Open** (某些系统)
   - **No response/ICMP** -> Port **Filtered**

3. **适用场景**:
   - 某些系统（如 HP-UX, AIX）在 RST 包中设置非零窗口大小
   - 可以用来绕过简单的防火墙规则

### Port State Mapping

| Response | Window Field | State |
|----------|--------------|-------|
| RST | > 0 | Closed |
| RST | = 0 | Open |
| No response/ICMP | N/A | Filtered |

---

## Phases

### Phase 1: 更新 TCP 响应解析器以提取 Window 字段

**Files**: `crates/rustnmap-net/src/lib.rs`

**Tasks**:
- [x] 验证 `parse_tcp_response_full` 函数已包含 TCP Window 字段
- [x] `TcpResponse` 结构体已包含 `window: u16` 字段

**Status**: COMPLETE

---

### Phase 2: 实现 TcpWindowScanner

**Files**: `crates/rustnmap-scan/src/stealth_scans.rs`

**Tasks**:
- [x] 添加 `TcpWindowScanner` 结构体定义
- [x] 实现 `new()` 构造函数
- [x] 实现 `scan_port_impl()` 方法
- [x] 实现 `send_window_probe()` 方法（发送 ACK 探测）
- [x] 实现端口状态判断逻辑（基于 Window 字段）
- [x] 实现 `PortScanner` trait

**Status**: COMPLETE

---

### Phase 3: 更新模块导出

**Files**: `crates/rustnmap-scan/src/lib.rs`

**Tasks**:
- [x] 在 re-exports 中添加 `TcpWindowScanner`
- [x] 更新文档注释

**Status**: COMPLETE

---

### Phase 4: 添加单元测试

**Files**: `crates/rustnmap-scan/src/stealth_scans.rs`

**Tasks**:
- [x] 添加 `test_window_scanner_creation()` 测试
- [x] 添加 `test_window_scanner_requires_root()` 测试
- [x] 添加 `test_window_handle_icmp()` 测试
- [x] 验证端口状态判断逻辑

**Status**: COMPLETE

---

### Phase 5: 验证实现

**Tasks**:
- [x] 运行 `cargo build` 确保编译通过
- [x] 运行 `cargo clippy -- -D warnings` 确保零警告
- [x] 运行 `cargo test` 确保所有测试通过
- [x] 运行 `cargo fmt` 确保代码格式正确

**Status**: COMPLETE

---

## Implementation Summary

### 实现细节

`TcpWindowScanner` 的核心实现逻辑：

```rust
impl TcpWindowScanner {
    fn send_window_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // 1. 发送 ACK 探测（与 ACK 扫描相同）
        let packet = TcpPacketBuilder::new(...)
            .ack_flag()
            .build();

        // 2. 使用 parse_tcp_response_full 解析响应
        if let Some(tcp_resp) = parse_tcp_response_full(&recv_buf[..len]) {
            // 3. 检查 RST 标志和 Window 字段
            if (tcp_resp.flags & tcp_flags::RST) != 0 {
                if tcp_resp.window > 0 {
                    return Ok(PortState::Closed);  // Window > 0 = Closed
                }
                return Ok(PortState::Open);        // Window = 0 = Open
            }
        }
        ...
    }
}
```

### 关键设计决策

1. **复用现有基础设施**: 使用现有的 `parse_tcp_response_full()` 函数获取 TCP Window 字段
2. **遵循现有模式**: 实现模式与 `TcpAckScanner` 一致，保持一致性
3. **正确的端口状态映射**: 严格遵循 Nmap 的 Window Scan 行为定义

---

## Files Modified

| File | Action | Description |
|------|--------|-------------|
| `crates/rustnmap-scan/src/stealth_scans.rs` | Edit | 添加 TcpWindowScanner 实现和测试 |
| `crates/rustnmap-scan/src/lib.rs` | Edit | 添加 re-export 和更新文档 |

---

## Quality Verification

| Check | Command | Status |
|-------|---------|--------|
| Build | `cargo build -p rustnmap-scan` | PASS |
| Clippy | `cargo clippy -p rustnmap-scan -- -D warnings` | PASS (zero warnings) |
| Tests | `cargo test -p rustnmap-scan` | PASS (44 tests) |
| Format | `cargo fmt -p rustnmap-scan` | PASS |

---

## Test Results

### New Tests Added

| Test | Status |
|------|--------|
| `test_window_scanner_creation` | PASS |
| `test_window_scanner_requires_root` | PASS |
| `test_window_handle_icmp` | PASS |

### All Tests Summary

```
running 44 tests
...
test stealth_scans::tests::test_window_scanner_creation ... ok
test stealth_scans::tests::test_window_scanner_requires_root ... ok
test stealth_scans::tests::test_window_handle_icmp ... ok
...
test result: ok. 44 passed; 0 failed; 0 ignored
```

---

## Conclusion

TCP Window Scan (-sW) 已成功实现，严格遵循了设计文档 `doc/modules/port-scanning.md` 的要求。实现包括：

1. **完整的扫描器结构** `TcpWindowScanner`
2. **正确的端口状态判断逻辑** 基于 RST 响应中的 Window 字段
3. **完整的单元测试** 覆盖创建、权限和 ICMP 处理
4. **零编译警告** 符合项目质量标准

---
