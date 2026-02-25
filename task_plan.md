# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-25
**Status**: Phase 17 - Bug Investigation & Nmap Database Integration - COMPLETE
**Goal**: Fix MAC address output, FIN scan accuracy, integrate nmap-services/protocols/rpc databases

---

## 当前阶段

Phase 17: Bug Investigation & Nmap Database Integration - COMPLETE

### 完成工作 (2026-02-25)

1. **nmap-services 数据库支持** ✅
   - 创建 `crates/rustnmap-fingerprint/src/database/services.rs`
   - 实现 `ServiceDatabase` 解析 `nmap-services` 格式
   - 提供 `port_to_service(port, protocol)` 查询接口
   - 集成到 DatabaseUpdater
   - 集成到 CLI 启动加载

2. **nmap-protocols 数据库支持** ✅
   - 创建 `crates/rustnmap-fingerprint/src/database/protocols.rs`
   - 实现 `ProtocolDatabase` 解析 `nmap-protocols` 格式
   - 提供 `protocol_number_to_name(num)` 查询接口
   - 集成到 DatabaseUpdater
   - 集成到 CLI 启动加载

3. **nmap-rpc 数据库支持** ✅
   - 创建 `crates/rustnmap-fingerprint/src/database/rpc.rs`
   - 实现 `RpcDatabase` 解析 `nmap-rpc` 格式
   - 提供 `rpc_number_to_name(num)` 查询接口
   - 集成到 DatabaseUpdater
   - 集成到 CLI 启动加载

4. **nmap-mac-prefixes 集成** ✅
   - 在 `FingerprintDatabase` 中添加 `mac_prefix_db` 字段
   - 实现 `mac_db()` 和 `load_mac_db()` 方法
   - 在 orchestrator 中集成 MAC 厂商查找
   - 所有扫描路径 (parallel, batch, sequential, two-phase) 都添加了 MAC 地址和厂商查找
   - 集成到 CLI 启动加载

### 待解决问题

1. **FIN 扫描端口状态不准确 - ✅ 已修复并测试通过** (LOW)
   - 现象：rustnmap 显示 `open|filtered`, nmap 显示 `closed`
   - 影响：80 端口状态判断差异
   - **根本原因**：
     - AF_PACKET 使用非阻塞模式，立即返回 `Ok(None)` 并回退到 raw socket
     - `parse_tcp_response()` 未返回 destination port，导致无法正确匹配 RST 响应
   - **2026-02-25 已修复**：
     - 添加 `recv_packet_with_timeout()` 方法，使用 `poll()` 等待数据 (200ms 超时)
     - 更新 `parse_tcp_response()` 返回 destination port
     - 更新响应匹配逻辑，使用 destination port 匹配 RST
     - 文件：
       - `crates/rustnmap-scan/src/stealth_scans.rs`
       - `crates/rustnmap-net/src/lib.rs`
   - **✅ 测试通过**：关闭端口正确显示 `closed`
     - rustnmap: `80/tcp closed`
     - nmap: `80/tcp closed`

---

## 实现总结

### 修改的文件

1. **rustnmap-fingerprint/src/database/services.rs** - 新建
   - 实现 `ServiceDatabase` 和 `ServiceEntry`
   - 解析 `nmap-services` 格式 (service port/protocol frequency)
   - 支持 TCP/UDP/SCTP 协议

2. **rustnmap-fingerprint/src/database/protocols.rs** - 新建
   - 实现 `ProtocolDatabase` 和 `ProtocolEntry`
   - 解析 `nmap-protocols` 格式 (name number)

3. **rustnmap-fingerprint/src/database/rpc.rs** - 新建
   - 实现 `RpcDatabase` 和 `RpcEntry`
   - 解析 `nmap-rpc` 格式 (name number aliases...)

4. **rustnmap-fingerprint/src/database/mod.rs** - 更新
   - 导出新的数据库模块

5. **rustnmap-fingerprint/src/database/updater.rs** - 更新
   - 添加 `NMAP_SERVICES_URL`, `NMAP_PROTOCOLS_URL`, `NMAP_RPC_URL`
   - 在 `CustomUrls` 中添加新字段
   - 添加 `update_services()`, `update_protocols()`, `update_rpc()` 方法
   - 在 `update_all()` 中调用新方法

6. **rustnmap-fingerprint/src/lib.rs** - 更新
   - 更新文档，添加新数据库支持
   - 导出新的数据库类型

7. **rustnmap-core/src/session.rs** - 更新
   - 在 `FingerprintDatabase` 中添加 `mac_prefix_db` 字段
   - 添加 `mac_db()`, `is_mac_db_loaded()`, `set_mac_db()`, `load_mac_db()` 方法

8. **rustnmap-core/src/orchestrator.rs** - 更新
   - 在 parallel scan 路径中添加 MAC 厂商查找
   - 在 batch scan 路径中添加 MAC 厂商查找
   - 在 sequential scan 路径中添加 MAC 地址和厂商查找
   - 在 two-phase scan 路径中添加 MAC 地址和厂商查找

9. **rustnmap-scan/src/stealth_scans.rs** - 更新 (2026-02-25, **✅ 已修复并测试**)
   - 添加 `SimpleAfPacket` 结构体 (L2 数据包捕获)
   - 添加 `recv_packet_with_timeout()` 方法 (使用 `poll()` 实现超时)
   - 添加 `create_packet_socket()` 和 `get_interface_for_ip()` 辅助函数
   - 所有 6 个 stealth scanners 添加 `packet_socket` 字段
   - 更新所有构造函数创建 AF_PACKET socket
   - 更新所有接收循环优先使用 AF_PACKET (200ms 超时)，回退到 raw socket
   - 修正 RST 响应匹配逻辑 (使用 destination port)
   - 目的：绕过内核 TCP 栈以接收 RST 响应，修复 FIN 扫描端口状态

10. **rustnmap-net/src/lib.rs** - 更新 (2026-02-25)
    - 更新 `parse_tcp_response()` 返回 destination port
    - 新签名: `Option<(u8, u32, u32, u16, u16, Ipv4Addr)>`
    - 添加 `_dst_port` 和 `resp_dst_port` 参数

11. **rustnmap-scan/src/syn_scan.rs** - 更新 (2026-02-25)
    - 适配新的 `parse_tcp_response()` 签名

12. **rustnmap-scan/src/ultrascan.rs** - 更新 (2026-02-25)
    - 适配新的 `parse_tcp_response()` 签名

13. **rustnmap-traceroute/src/tcp.rs** - 更新 (2026-02-25)
    - 适配新的 `parse_tcp_response()` 签名

14. **rustnmap-target/src/discovery.rs** - 更新 (2026-02-25)
    - 适配新的 `parse_tcp_response()` 签名

### 测试验证

```bash
# 构建
cargo build --release  # PASS, zero warnings

# 单元测试
cargo test --release  # 600+ tests PASS

# Clippy
cargo clippy -- -D warnings  # PASS

# AF_PACKET 功能测试 (✅ 通过)
sudo ./target/release/rustnmap --scan-fin -p 22,80,443,8080 192.168.12.1
# 结果: 80/tcp closed (与 nmap 一致, 修复前显示 open|filtered)

# Nmap 对比
sudo nmap -sF -p 80,443,22,8080 192.168.12.1
# 结果: 80/tcp closed ✅ 匹配
```

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

对于每个端口，发送 N 个探测 (每个 decoy + 真实 IP),仅跟踪真实 IP 的响应:

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

## 历史阶段

### Phase 15: P0/P1 优化修复 - COMPLETE

... (保留原有内容)
