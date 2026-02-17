# 无状态扫描模块 (rustnmap-stateless-scan)

> **版本**: 2.0.0 (开发中)
> **对应 Phase**: Phase 4 (Week 10-11)
> **优先级**: P1

---

## 概述

无状态扫描模块实现类似 masscan 的高速扫描能力，通过加密 Cookie 编码源端口和序列号，无需维护连接状态表即可匹配响应。这是 RustNmap 2.0 性能飞跃的核心组件。

---

## 功能特性

### 1. 无状态 SYN 扫描

- 无需维护连接状态表
- 发送和接收完全解耦
- 理论上可达到线速扫描

### 2. Cookie 编码

- 使用加密 Cookie 编码源端口
- Cookie 编码序列号
- 无需状态表即可验证响应

### 3. 高速率扫描

- 目标速率：1000 万 PPS (包/秒)
- 适用于大规模网络资产发现
- 支持 Rate 限制

### 4. 实验特性标志

- 通过 `--fast` 或 `-F2` 选项启用
- 默认禁用（需要显式启用）
- 仅支持 SYN 扫描模式

---

## 工作原理

### 传统有状态扫描

```
发送线程                          接收线程
   │                                │
   ├──> 发送 SYN (src_port=12345)   │
   │    记录状态表 {12345 -> target} │
   │                                │
   │              SYN-ACK <─────────┤
   │                                │
   ├──> 查找状态表 [12345]          │
   │    匹配到 target               │
   │    发送 RST                    │
```

### 无状态扫描

```
发送线程                          接收线程
   │                                │
   ├──> 计算 Cookie = HMAC(key, target_ip)
   ├──> src_port = Cookie >> 16     │
   ├──> seq_num = Cookie & 0xFFFF   │
   ├──> 发送 SYN (src_port, seq)    │
   │    (无状态记录)                │
   │                                │
   │              SYN-ACK <─────────┤
   │              (携带 src_port,   │
   │               ack_num = seq+1) │
   │                                │
   │                                ├──> 接收 SYN-ACK
   │                                ├──> 重建 Cookie
   │                                │   = (src_port << 16) | (ack_num - 1)
   │                                ├──> 验证 Cookie = HMAC(key, target_ip)
   │                                │   匹配 -> 端口开放
   │                                │   不匹配 -> 丢弃
```

---

## 核心算法

### Cookie 生成

```rust
use blake3::Hasher;

/// 无状态扫描 Cookie 生成器
pub struct StatelessCookie {
    /// 加密密钥（随机生成）
    key: [u8; 32],
}

impl StatelessCookie {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        Self { key }
    }

    /// 为 target IP 生成 Cookie
    pub fn generate(&self, target: IpAddr, timestamp: u64) -> Cookie {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        hasher.update(&target.octets());
        hasher.update(&timestamp.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // 源端口：使用 hash 的高 16 位（排除特权端口）
        let source_port = 1024 + ((u16::from_le_bytes([hash_bytes[0], hash_bytes[1]]) % 64511) as u16);

        // 序列号：使用 hash 的低 32 位
        let sequence_num = u32::from_le_bytes([
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7],
        ]);

        Cookie {
            source_port,
            sequence_num,
            timestamp,
        }
    }

    /// 验证接收的响应
    pub fn verify(&self, target: IpAddr, source_port: u16, ack_num: u32, max_age: Duration) -> VerifyResult {
        // 重建序列号
        let sequence_num = ack_num - 1;

        // 验证时间窗口（防止重放攻击）
        let current_time = current_timestamp();
        let cookie_timestamp = extract_timestamp(sequence_num);

        if current_time - cookie_timestamp > max_age.as_secs() {
            return VerifyResult::Expired;
        }

        // 重新计算并验证 Cookie
        let expected = self.generate(target, cookie_timestamp);
        if expected.source_port == source_port && expected.sequence_num == sequence_num {
            VerifyResult::Valid
        } else {
            VerifyResult::Invalid
        }
    }
}

/// Cookie 结构
pub struct Cookie {
    pub source_port: u16,
    pub sequence_num: u32,
    pub timestamp: u64,
}

/// 验证结果
pub enum VerifyResult {
    Valid,
    Invalid,
    Expired,
}
```

### 发送器

```rust
/// 无状态 SYN 发送器
pub struct StatelessSender {
    socket: RawSocket,
    cookie_gen: StatelessCookie,
    rate_limiter: RateLimiter,
    targets: Vec<Target>,
}

impl StatelessSender {
    /// 创建发送器
    pub fn new(config: StatelessConfig) -> Result<Self>;

    /// 发送 SYN 包（无状态）
    pub async fn send_syn(&self, target: IpAddr, port: u16) -> Result<()> {
        // 生成 Cookie
        let cookie = self.cookie_gen.generate(target, current_timestamp());

        // 构建 SYN 包
        let mut packet = TcpPacket::new();
        packet.set_source(self.local_ip);
        packet.set_destination(target);
        packet.set_source_port(cookie.source_port);
        packet.set_dest_port(port);
        packet.set_seq(cookie.sequence_num);
        packet.set_syn(true);

        // 发送
        self.socket.send(packet.build()).await?;
        self.rate_limiter.tick().await;

        Ok(())
    }

    /// 批量发送（优化性能）
    pub async fn send_batch(&self, targets: &[(IpAddr, u16)]) -> Result<usize> {
        let mut packets = Vec::with_capacity(targets.len());

        for &(target, port) in targets {
            let cookie = self.cookie_gen.generate(target, current_timestamp());
            let mut packet = TcpPacket::new();
            packet.set_source(self.local_ip);
            packet.set_destination(target);
            packet.set_source_port(cookie.source_port);
            packet.set_dest_port(port);
            packet.set_seq(cookie.sequence_num);
            packet.set_syn(true);
            packets.push(packet.build());
        }

        // 批量发送（使用 sendmmsg）
        let sent = self.socket.send_batch(packets).await?;
        for _ in 0..sent {
            self.rate_limiter.tick().await;
        }

        Ok(sent)
    }
}
```

### 接收器

```rust
/// 无状态 SYN 接收器
pub struct StatelessReceiver {
    socket: RawSocket,
    cookie_gen: StatelessCookie,
    results_tx: mpsc::Sender<ScanResult>,
}

impl StatelessReceiver {
    /// 创建接收器
    pub fn new(config: StatelessConfig, results_tx: mpsc::Sender<ScanResult>) -> Self;

    /// 接收并验证响应
    pub async fn recv_loop(&self) -> Result<()> {
        loop {
            // 接收数据包
            let packet = self.socket.recv().await?;

            // 解析 TCP 头
            let tcp = TcpPacket::parse(&packet)?;

            // 仅处理 SYN-ACK
            if !tcp.get_syn() || !tcp.get_ack() {
                continue;
            }

            let target = tcp.get_source();
            let source_port = tcp.get_source_port();
            let ack_num = tcp.get_ack();

            // 验证 Cookie
            match self.cookie_gen.verify(target, source_port, ack_num, Duration::from_secs(30)) {
                VerifyResult::Valid => {
                    // 端口开放
                    let result = ScanResult {
                        ip: target,
                        port: tcp.get_dest_port(),
                        state: PortState::Open,
                    };
                    self.results_tx.send(result).await?;

                    // 发送 RST 关闭连接
                    self.send_rst(target, source_port, ack_num).await?;
                }
                VerifyResult::Invalid => {
                    // Cookie 不匹配，可能是伪造响应
                    continue;
                }
                VerifyResult::Expired => {
                    // Cookie 过期，可能是重放攻击
                    continue;
                }
            }
        }
    }

    /// 发送 RST 包
    async fn send_rst(&self, target: IpAddr, source_port: u16, ack_num: u32) -> Result<()> {
        let mut packet = TcpPacket::new();
        packet.set_source(self.local_ip);
        packet.set_destination(target);
        packet.set_source_port(0);  // 任意端口
        packet.set_dest_port(source_port);
        packet.set_seq(ack_num);
        packet.set_ack(0);
        packet.set_rst(true);

        self.socket.send(packet.build()).await?;
        Ok(())
    }
}
```

---

## 架构设计

### 模块结构

```
rustnmap-stateless/
├── src/
│   ├── lib.rs           # 公共 API
│   ├── cookie.rs        # Cookie 生成与验证
│   ├── sender.rs        # 无状态发送器
│   ├── receiver.rs      # 无状态接收器
│   ├── rate_limiter.rs  # 速率限制器
│   └── config.rs        # 配置管理
└── tests/
    └── integration.rs   # 集成测试
```

### 扫描流程

```
                    ┌─────────────────┐
                    │  Scanner::fast() │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌────────────────┐ ┌───────────┐ ┌───────────┐
    │StatelessSender │ │ Receiver  │ │RateLimiter│
    │ (发送 SYN 包)    │ │(接收 SYN-ACK)│ │ (限流)    │
    └───────┬────────┘ └─────┬─────┘ └─────┬─────┘
            │                │             │
            │                │             │
            └────────────────┼─────────────┘
                             │
                             ▼
                   ┌─────────────────┐
                   │  Results Channel │
                   │  (mpsc::Sender)  │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ OutputSink      │
                   │ (流式输出结果)   │
                   └─────────────────┘
```

---

## CLI 选项

### 启用无状态扫描

```bash
# 基本用法
rustnmap --fast -p 1-65535 192.168.1.0/8

# 或者使用 -F2（区别于 -F 快速扫描）
rustnmap -F2 -p 1-10000 10.0.0.0/8

# 设置发送速率（包/秒）
rustnmap --fast --rate 1000000 -p 80,443 192.168.1.0/24

# 仅发现开放端口（不进行服务检测）
rustnmap --fast --ports-only -p 1-1000 192.168.1.0/24
```

### 两阶段扫描

```bash
# 阶段 1：无状态快速发现
rustnmap --fast -p 1-65535 192.168.1.0/24 -oG fast-results.gnmap

# 阶段 2：精细分析（仅针对发现的开放端口）
rustnmap -iL open-ports.txt -sV -sC -O 192.168.1.0/24
```

---

## 性能优化

### 批处理发送

```rust
/// 使用 sendmmsg 批量发送
pub async fn send_batch_optimized(&self, packets: &[TcpPacket]) -> Result<usize> {
    // 准备 iovec 数组
    let mut iovs: Vec<libc::iovec> = packets
        .iter()
        .map(|pkt| libc::iovec {
            iov_base: pkt.data().as_ptr() as *mut libc::c_void,
            iov_len: pkt.data().len(),
        })
        .collect();

    // 准备 mmsghdr 数组
    let mut msgs: Vec<libc::mmsghdr> = iovs
        .iter_mut()
        .map(|iov| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut _,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        })
        .collect();

    // 批量发送
        unsafe {
        libc::sendmmsg(
            self.socket_fd,
            msgs.as_mut_ptr(),
            msgs.len() as libc::c_uint,
            0,
        )
    };

    Ok(sent as usize)
}
```

### 零拷贝接收

```rust
/// 使用 PACKET_MMAP V3 零拷贝接收
pub struct ZeroCopyReceiver {
    ring: PacketRing,
}

impl ZeroCopyReceiver {
    pub async fn recv_next(&mut self) -> Result<Option<&TcpPacket>> {
        // 直接从 ring buffer 获取引用，无需拷贝
        let slot = self.ring.next_slot().await?;
        if let Some(slot) = slot {
            let packet = TcpPacket::parse(slot.data())?;
            Ok(Some(packet))
        } else {
            Ok(None)
        }
    }
}
```

---

## 安全考虑

### 1. Cookie 密钥保护

```rust
/// 安全密钥生成
fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    // 使用系统 RNG
    getrandom::getrandom(&mut key).expect("Failed to generate random key");
    key
}

/// 密钥轮换（每 24 小时）
pub struct KeyRotator {
    current_key: [u8; 32],
    previous_key: [u8; 32],
    last_rotation: Instant,
    rotation_interval: Duration,
}
```

### 2. 重放攻击防护

- Cookie 包含时间戳
- 验证时间窗口（默认 30 秒）
- 过期 Cookie 自动拒绝

### 3. 速率限制

```rust
/// Token Bucket 限流器
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,  // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub async fn acquire(&mut self) {
        while self.tokens < 1.0 {
            self.refill();
            tokio::time::sleep(Duration::from_micros(10)).await;
        }
        self.tokens -= 1.0;
    }
}
```

---

## 与 RETHINK.md 对齐

| 章节 | 对应内容 |
|------|---------|
| 4.2.3 无状态扫描 | 加密 Cookie 编码、stateless SYN |
| 12.3 Phase 4 | 性能主干优化（Week 10-11） |
| 14.5 Phase 4-5 | 扫描主循环改造 |

---

## 依赖关系

```toml
[dependencies]
# 加密
blake3 = "1"
getrandom = "0.2"

# 异步
tokio = { version = "1", features = ["full"] }

# 内部依赖
rustnmap-common = { path = "../rustnmap-common" }
rustnmap-net = { path = "../rustnmap-net" }
rustnmap-packet = { path = "../rustnmap-packet" }
```

---

## 测试

### 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation() {
        let cookie_gen = StatelessCookie::new();
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        let cookie1 = cookie_gen.generate(target, 1000);
        let cookie2 = cookie_gen.generate(target, 1000);

        // 相同 target 和 timestamp 应生成相同 Cookie
        assert_eq!(cookie1.source_port, cookie2.source_port);
        assert_eq!(cookie1.sequence_num, cookie2.sequence_num);
    }

    #[test]
    fn test_cookie_verification() {
        let cookie_gen = StatelessCookie::new();
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        let cookie = cookie_gen.generate(target, 1000);

        // 验证应成功
        let result = cookie_gen.verify(
            target,
            cookie.source_port,
            cookie.sequence_num + 1,  // ack_num = seq + 1
            Duration::from_secs(30),
        );
        assert!(matches!(result, VerifyResult::Valid));
    }
}
```

---

## 下一步

1. **Week 10**: 实现 Cookie 生成和验证算法
2. **Week 10**: 实现无状态发送器和接收器
3. **Week 11**: 集成速率限制和批量发送
4. **Week 11**: 编写集成测试和性能基准

---

## 参考链接

- [masscan 原理](https://github.com/robertdavidgraham/masscan)
- [TCP Cookie TCP (RFC 6013)](https://datatracker.ietf.org/doc/html/rfc6013)
- [BLAKE3 哈希函数](https://docs.rs/blake3)
