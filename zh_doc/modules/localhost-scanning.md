# Localhost 扫描技术分析

> **创建日期**: 2026-03-08
> **状态**: 设计决策文档
> **优先级**: P0 - 架构限制

---

## 问题概述

RustNmap 在扫描 `127.0.0.1` (localhost) 时，所有端口显示为 `filtered` 状态，而 nmap 能正确识别 `open`/`closed` 状态。

**测试命令**:
```bash
nmap -sS -p 22 127.0.0.1
# 结果: 22/tcp open ssh

rustnmap --scan-syn -p 22 127.0.0.1
# 结果: 22/tcp filtered ssh  (错误)
```

---

## 根本原因分析

### 问题流程

```
1. 用户执行: rustnmap --scan-syn -p 22 127.0.0.1
2. TcpSynScanner 创建 RawSocket (绑定到系统默认地址 192.168.15.237)
3. TcpSynScanner 创建 PacketEngine (绑定到 ens33 接口)
4. 发送 SYN 探测: src=192.168.15.237, dst=127.0.0.1
5. 目标响应 SYN-ACK: src=127.0.0.1, dst=192.168.15.237
6. **关键问题**: 响应的目的地址是 192.168.15.237 (外部 IP)
7. **路由决策**: 192.168.15.237 的响应通过 ens33 接口路由
8. **捕获失败**: 绑定到 lo 的 PacketEngine 永远看不到这个响应
9. **结果**: 超时 → filtered 状态
```

### tcpdump 证据

```
# 实际捕获的包
192.168.15.237.60554 > 127.0.0.1.22: Flags [S]     # 我们的 SYN 探测
127.0.0.1.22 > 192.168.15.237.60554: Flags [S.]   # SYN-ACK 响应
192.168.15.237.60554 > 127.0.0.1.22: Flags [R]     # 内核 TCP 栈 RST
```

**关键发现**: SYN-ACK 的**目的地是外部 IP**，而非 127.0.0.1！

### 技术原因

#### 1. Raw Socket 源地址绑定

`TcpSynScanner` 中的 `RawSocket` 创建方式：

```rust
// crates/rustnmap-scan/src/syn_scan.rs:71
let socket = RawSocket::with_protocol(6)?;
```

**问题**: RawSocket 没有绑定到特定的源地址。当发送数据包时，内核根据以下规则选择源地址：
1. Socket 绑定的本地地址（如果已绑定）
2. 路由表确定的出口接口地址
3. 对于到 127.0.0.1 的数据包，内核使用主接口地址（192.168.15.237）

#### 2. PACKET_MMAP 接口绑定

我们创建的 `localhost_engine` 绑定到了 `lo` 接口：

```rust
// 代码正确检测到了 loopback 接口
[DEBUG] Found loopback interface: lo
[DEBUG] Using loopback interface: lo
```

**但是**：响应的目的地址是 192.168.15.237，所以响应通过 ens33 路由，而非 lo。

#### 3. 内核路由行为

Linux 内核对本地通信的决策：
- 源地址: 192.168.15.237 (主接口地址)
- 目的地址: 127.0.0.1 (loopback)
- **路由决策**: 到 127.0.0.1 的包通过 lo 发送
- **响应路由**: 到 192.168.15.237 的包通过主接口（ens33）接收

这就是关键问题所在！

---

## nmap 的处理方式

### nmap 源码分析

**文件**: `reference/nmap/libnetutil/netutil.cc:1916-1946`

```c
int islocalhost(const struct sockaddr_storage *ss) {
  // 检查是否是 127.x.x.x
  if ((sin->sin_addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return 1;

  // 检查是否匹配本地接口地址
  if (ipaddr2devname(dev, ss) != -1)
    return 1;

  return 0;
}
```

### Windows 平台的处理

**文件**: `reference/nmap/scan_engine.cc:2735-2739`

```c
#ifdef WIN32
  if (!o.have_pcap && scantype != CONNECT_SCAN &&
      Targets[0]->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n",
             scantype2str(scantype), Targets[0]->NameIP());
    return;
  }
#endif
```

**关键发现**: nmap 在 Windows 上**明确跳过**对 localhost 的原始套接字扫描，因为在某些平台上不支持。

---

## 解决方案

### 方案 A: Raw Socket 绑定到 Loopback (正确方案)

修改 `TcpSynScanner` 为 localhost 目标创建专用的 RawSocket，绑定到 127.0.0.1。

#### 实现结构

```rust
pub struct TcpSynScanner {
    // 现有字段
    local_addr: Ipv4Addr,
    socket: RawSocket,

    // 新增字段
    localhost_socket: Option<RawSocket>,  // 专用于 localhost 扫描
    is_local_addr_loopback: bool,          // 标记 local_addr 是否为 loopback
}
```

#### 修改发送逻辑

```rust
fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
    // 检测是否为 localhost 目标
    let is_localhost_target = dst_addr.is_loopback();

    // 选择正确的 socket
    let socket = if is_localhost_target {
        self.localhost_socket.as_ref().unwrap_or(&self.socket)
    } else {
        &self.socket
    };

    // 发送数据包
    socket.send_packet(&packet, &dst_sockaddr)?;
    // ...
}
```

#### 构造函数修改

```rust
pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
    // 创建主 RawSocket
    let socket = RawSocket::with_protocol(6)?;

    // 如果 local_addr 本身就是 loopback，直接使用
    // 否则创建专用的 localhost socket
    let localhost_socket = if !local_addr.is_loopback() {
        // 创建绑定到 127.0.0.1 的 socket
        let lo_socket = RawSocket::with_protocol(6)?;
        lo_socket.bind(Some(Ipv4Addr::new(127, 0, 0, 1)))?;
        Some(lo_socket)
    } else {
        None
    };

    Ok(Self {
        local_addr,
        socket,
        localhost_socket,
        // ...
    })
}
```

**优点**:
- 完整解决根本原因
- 保持 SYN 扫描的所有功能
- 符合 nmap 设计哲学

**缺点**:
- 需要维护两个 RawSocket
- 架构复杂度增加

### 方案 B: 使用 Connect 扫描 (降级方案)

检测到 localhost 目标时，降级使用 `TcpConnectScanner` 而非 `TcpSynScanner`。

#### 实现位置

在 `crates/rustnmap-core/src/orchestrator.rs` 中的扫描器选择逻辑：

```rust
// 检测 localhost 目标
let has_localhost = targets.iter().any(|t| {
    matches!(t.ip, IpAddr::V4(addr) if addr.is_loopback())
});

// 如果有 localhost 目标且使用 SYN 扫描，警告并使用 Connect 扫描
if has_localhost && scantype == ScanType::Syn {
    log_warning("SYN scan against localhost not supported, using Connect scan instead");
    return TcpConnectScanner::new(config)?.scan_targets(targets);
}
```

**优点**:
- 实现简单
- 避免 PACKET_MMAP 限制
- 与 nmap 某些平台行为一致

**缺点**:
- 失去 SYN 扫描的隐蔽性
- 功能降级

---

## 设计决策

### 决策: 实施方案 A (Raw Socket 绑定)

**理由**:
1. **功能完整性**: SYN 扫描应该对所有目标有效，包括 localhost
2. **符合 nmap 标准**: nmap 在 Linux 上支持对 localhost 的 SYN 扫描
3. **技术正确性**: 正确的解决方案是修复根本原因，而非绕过

### 实施计划

#### Phase 1: 修改 RawSocket

**文件**: `crates/rustnmap-net/src/lib.rs`

添加 `bind()` 方法到 `RawSocket`：

```rust
impl RawSocket {
    /// Binds the raw socket to a specific source address.
    ///
    /// # Arguments
    ///
    /// * `src_addr` - Optional source address to bind to
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Socket is already bound
    /// - Invalid address
    /// - Permission denied
    pub fn bind(&self, src_addr: Option<Ipv4Addr>) -> io::Result<()> {
        // 实现 bind 逻辑
    }
}
```

#### Phase 2: 修改 TcpSynScanner

**文件**: `crates/rustnmap-scan/src/syn_scan.rs`

1. 添加 `localhost_socket` 字段
2. 修改构造函数创建 localhost socket
3. 修改 `send_syn_probe()` 使用正确的 socket

#### Phase 3: 测试验证

1. 单端口 localhost 测试
2. 多端口 localhost 测试
3. 混合目标测试（localhost + 远程）
4. 与 nmap 结果对比

---

## 技术约束

### PACKET_MMAP 限制

PACKET_MMAP V2 在 Linux 上的已知限制：

| 场景 | PACKET_MMAP 行为 | 原因 |
|------|------------------|------|
| 扫描远程 IP | 正常工作 | 路由对称，发送和接收在同一接口 |
| 扫描 127.0.0.1 | 失败 | 响应路由到外部接口，不在 lo 上 |
| 绑定到 lo 接口 | 只能看到 lo 流量 | 其他接口的包不会出现在 lo |

### 内核路由表

```
# 查看路由表
ip route get 127.0.0.1
# 127.0.0.1 dev lo scope link

ip route get 192.168.15.237
# 192.168.15.237 dev ens33 scope link
```

这解释了为什么响应到 192.168.15.237 的包会走 ens33 而不是 lo。

---

## 测试用例

### 测试 1: 单端口 Localhost

```bash
# 应该显示 open
rustnmap --scan-syn -p 22 127.0.0.1
# 期望: 22/tcp open ssh
```

### 测试 2: 多端口 Localhost

```bash
# 应该显示混合状态
rustnmap --scan-syn -p 22,80,443 127.0.0.1
# 期望: 22/tcp open, 80/tcp closed, 443/tcp closed
```

### 测试 3: 混合目标

```bash
# 同时扫描 localhost 和远程目标
rustnmap --scan-syn -p 22 127.0.0.1 45.33.32.156
# 期望: 两个目标都能正确扫描
```

---

## 参考文档

### 内核文档

- `man 7 packet` - PACKET socket 使用
- `man 7 raw` - Raw socket 使用
- `man ip-route` - 路由表操作

### nmap 参考

- `reference/nmap/libnetutil/netutil.cc` - 接口检测
- `reference/nmap/scan_engine.cc` - 扫描引擎
- `reference/nmap/libpcap/pcap-linux.c` - PACKET_MMAP 实现

---

## 更新历史

| 日期 | 变更 | 作者 |
|------|------|------|
| 2026-03-08 | 创建文档，记录 localhost 扫描完整技术分析 | Claude |
