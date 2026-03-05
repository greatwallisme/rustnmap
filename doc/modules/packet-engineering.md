# TPACKET_V2 Structures定义

> **Reference**: Linux kernel `include/uapi/linux/if_packet.h`
> **Note**: These must to be added to rustnmap-packet crate!
> **nmap Reference**: `reference/nmap/libpcap/pcap-linux.c`

---

## nmap 实现研究 (Critical Implementation Details)

> **IMPORTANT**: These details are from actual nmap source code analysis.
> Do NOT deviate from these patterns without explicit justification.

### Socket 选项设置顺序 (CRITICAL)

**必须严格按照以下顺序设置 socket 选项，否则会导致失败:**

```rust
// 1. 创建 AF_PACKET socket
let fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))?;

// 2. 设置 TPACKET 版本 (MUST come first)
let version = TPACKET_V2 as i32;
setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, size_of::<i32>())?;

// 3. 设置 PACKET_RESERVE (MUST come BEFORE PACKET_RX_RING)
let reserve: u32 = 4; // VLAN_TAG_LEN
setsockopt(fd, SOL_PACKET, PACKET_RESERVE, &reserve, size_of::<u32>())?;

// 4. 设置 PACKET_AUXDATA (可选，用于获取辅助数据)
let auxdata: i32 = 1;
setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &auxdata, size_of::<i32>())?;

// 5. 配置环形缓冲区 (PACKET_RX_RING)
setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, size_of::<tpacket_req>())?;

// 6. mmap 映射
let ring_ptr = mmap(null_mut(), ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)?;

// 7. 绑定到接口
bind(fd, &sockaddr_ll, size_of::<sockaddr_ll>())?;
```

**错误顺序会导致的问题:**
- `PACKET_RESERVE` 在 `PACKET_RX_RING` 之后设置会被忽略
- `PACKET_VERSION` 必须在所有 TPACKET 相关操作之前设置

### tpacket_req 字段计算公式

```rust
/// 计算 tpacket_req 字段 (基于 nmap libpcap 实现)
fn calculate_tpacket_req(snaplen: u32, buffer_size: usize) -> tpacket_req {
    // 1. 计算帧大小
    // netoff = TPACKET2_HDRLEN + ethernet_header (14) + reserve (4)
    let netoff = TPACKET2_HDRLEN as u32 + 14 + RESERVE;
    let maclen = 14u32; // Ethernet header
    let macoff = netoff - maclen;
    let frame_size = TPACKET_ALIGN(macoff + snaplen);

    // 2. 计算块大小 (从页面大小开始，翻倍直到 >= frame_size)
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
    let mut block_size = page_size;
    while block_size < frame_size {
        block_size *= 2;
    }

    // 3. 计算帧数量
    let frame_nr = (buffer_size + frame_size as usize - 1) / frame_size as usize;

    // 4. 计算每个块的帧数
    let frames_per_block = block_size / frame_size;

    // 5. 计算块数量
    let block_nr = (frame_nr / frames_per_block as usize) as u32;

    tpacket_req {
        tp_block_size: block_size,
        tp_block_nr: block_nr,
        tp_frame_size: frame_size,
        tp_frame_nr: frame_nr as u32,
    }
}

const fn TPACKET_ALIGN(x: u32) -> u32 {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

const TPACKET_ALIGNMENT: u32 = 16;
const TPACKET2_HDRLEN: u32 = 48; // sizeof(tpacket2_hdr)
const RESERVE: u32 = 4; // VLAN_TAG_LEN
```

### ENOMEM 恢复策略 (5% 迭代减少)

**nmap 使用 5% 迭代减少策略，而非固定重试:**

```rust
/// 配置环形缓冲区，带 ENOMEM 恢复
fn setup_ring_buffer_with_retry(fd: i32, mut req: tpacket_req) -> Result<()> {
    const MAX_RETRIES: u32 = 10;

    for attempt in 0..MAX_RETRIES {
        match setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, size_of::<tpacket_req>()) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                // 减少 5% 帧数量 (nmap 策略)
                req.tp_frame_nr = req.tp_frame_nr * 95 / 100;

                // 重新计算块数量
                let frames_per_block = req.tp_block_size / req.tp_frame_size;
                req.tp_block_nr = req.tp_frame_nr / frames_per_block;

                if req.tp_block_nr == 0 {
                    return Err(PacketError::InsufficientMemory);
                }

                log::warn!(
                    "ENOMEM on attempt {}, reducing frames to {}",
                    attempt + 1,
                    req.tp_frame_nr
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    Err(PacketError::RingBufferSetupFailed)
}
```

### 内存序要求 (CRITICAL)

**nmap 使用 C11 原子操作，对应 Rust:**

```c
// nmap 原始代码 (pcap-linux.c:135-138)
#define packet_mmap_acquire(pkt) \
    (__atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_release(pkt) \
    (__atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))
```

**Rust 等效实现:**

```rust
use std::sync::atomic::{AtomicU32, Ordering};

/// 检查帧是否可用 (用户空间拥有)
/// SAFETY: 必须使用 Acquire 语义确保看到完整的数据
fn frame_is_available(hdr: &Tpacket2Hdr) -> bool {
    // 对应 nmap 的 __ATOMIC_ACQUIRE
    unsafe {
        AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
            .load(Ordering::Acquire) != TP_STATUS_KERNEL
    }
}

/// 释放帧回内核
/// SAFETY: 必须使用 Release 语义确保之前的读取完成
fn release_frame(hdr: &mut Tpacket2Hdr) {
    // 对应 nmap 的 __ATOMIC_RELEASE
    unsafe {
        AtomicU32::from_ptr(std::ptr::addr_of!((*hdr).tp_status))
            .store(TP_STATUS_KERNEL, Ordering::Release);
    }
}
```

**性能基准 (来自 rust-concurrency skill):**
| Ordering | CPU 周期 | 适用场景 |
|----------|----------|----------|
| Relaxed | 1 | 仅计数器 |
| Acquire/Release | 2-3 | 生产者-消费者同步 |
| SeqCst | 5-10 | 全局顺序 (避免使用) |

**NEVER 使用 SeqCst** - 对于环形缓冲区，Acquire/Release 足够且性能更好。

### 帧指针数组初始化

**mmap 后必须构建帧指针数组:**

```rust
/// 初始化帧指针数组
/// 基于 nmap pcap-linux.c:3434-3453
fn init_frame_pointers(
    mmap_ptr: *mut u8,
    req: &tpacket_req,
) -> Vec<NonNull<Tpacket2Hdr>> {
    let total_frames = req.tp_frame_nr as usize;
    let frame_size = req.tp_frame_size as usize;

    let mut frames = Vec::with_capacity(total_frames);

    for i in 0..total_frames {
        let offset = i * frame_size;
        // SAFETY: offset is within mmap region
        let frame_ptr = unsafe { NonNull::new_unchecked(mmap_ptr.add(offset) as *mut Tpacket2Hdr) };
        frames.push(frame_ptr);
    }

    frames
}
```

### VLAN 标签重构逻辑

**nmap 在需要时移动数据以插入 VLAN 标签:**

```rust
/// 重构带有 VLAN 标签的数据包
/// 基于 nmap pcap-linux.c:4321-4336
fn reconstruct_vlan_packet(
    hdr: &Tpacket2Hdr,
    raw: &[u8],
) -> Option<Cow<'_, [u8]>> {
    const VLAN_TAG_LEN: usize = 4;
    const TP_STATUS_VLAN_VALID: u32 = 0x10;

    // 检查是否有有效 VLAN 标签
    if hdr.tp_vlan_tci == 0 && (hdr.tp_status & TP_STATUS_VLAN_VALID) == 0 {
        return None; // 无 VLAN 标签
    }

    // 需要移动数据以插入 VLAN 标签
    let mac_offset = hdr.tp_mac as usize;
    let mac_len = 14; // Ethernet header length
    let payload_len = hdr.tp_len as usize - mac_len;

    let mut packet = vec![0u8; hdr.tp_len as usize + VLAN_TAG_LEN];

    // 复制 MAC 头 (目标 + 源 MAC)
    packet[..mac_offset].copy_from_slice(&raw[..mac_offset]);

    // 插入 VLAN 标签 (TPID + TCI)
    let tpid = if hdr.tp_vlan_tpid != 0 { hdr.tp_vlan_tpid } else { 0x8100 };
    packet[mac_offset..mac_offset + 2].copy_from_slice(&tpid.to_be_bytes());
    packet[mac_offset + 2..mac_offset + 4].copy_from_slice(&hdr.tp_vlan_tci.to_be_bytes());

    // 复制剩余载荷
    packet[mac_offset + VLAN_TAG_LEN..].copy_from_slice(&raw[mac_offset..]);

    Some(Cow::Owned(packet))
}
```

### breakloop 模式 (可中断阻塞)

**nmap 使用 eventfd 实现可中断的 poll:**

```rust
use tokio::io::{AsyncFd, Interest};
use std::os::unix::io::AsRawFd;

/// 可中断的数据包接收器
pub struct InterruptibleReceiver {
    /// 数据包 socket 的 AsyncFd
    packet_fd: AsyncFd<OwnedFd>,
    /// 用于中断的 eventfd
    breakloop_fd: AsyncFd<OwnedFd>,
    /// 运行标志
    running: Arc<AtomicBool>,
}

impl InterruptibleReceiver {
    /// 等待数据包或中断信号
    pub async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError> {
        loop {
            // 同时等待 socket 可读或 breakloop 信号
            tokio::select! {
                // 数据包到达
                result = self.packet_fd.readable() => {
                    result?;
                    let mut guard = self.packet_fd.try_io(Interest::READABLE, |fd| {
                        // 从环形缓冲区读取数据包
                        self.try_recv_from_ring()
                    })?;
                    return guard.map(|opt| opt);
                }

                // breakloop 信号
                _ = self.breakloop_fd.readable() => {
                    // 清除 eventfd
                    let mut buf = [0u8; 8];
                    unsafe {
                        libc::read(
                            self.breakloop_fd.as_raw_fd(),
                            buf.as_mut_ptr().cast(),
                            8
                        );
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// 请求中断阻塞操作
    pub fn break_loop(&self) -> Result<()> {
        let buf: u64 = 1;
        unsafe {
            libc::write(
                self.breakloop_fd.as_raw_fd(),
                &buf as *const u64 as *const libc::c_void,
                8
            );
        }
        Ok(())
    }
}
```

## TPACKET_V2 Header Structure (32 bytes)

> **CRITICAL**: 结构体总大小是 **32 字节**，不是 48 字节。
> `tp_padding` 是 `[u8; 4]`，不是 `[u8; 8]`。

```c
/// tpacket2_hdr from Linux if_packet.h
/// 参考: /usr/include/linux/if_packet.h:146-157
#[repr(C)]
pub struct __tpacket2_hdr {
    pub tp_status: u32,      // Frame status (4 bytes)
    pub tp_len: u32,         // Packet length (4 bytes)
    pub tp_snaplen: u32,     // Captured length (4 bytes)
    pub tp_mac: u16,         // MAC header offset (2 bytes)
    pub tp_net: u16,         // Network header offset (2 bytes)
    pub tp_sec: u32,         // Timestamp seconds (4 bytes)
    pub tp_nsec: u32,        // Timestamp nanoseconds (4 bytes) - NOT tp_usec!
    pub tp_vlan_tci: u16,    // VLAN TCI (2 bytes)
    pub tp_vlan_tpid: u16,   // VLAN TPID (2 bytes)
    pub tp_padding: [u8; 4], // Padding (4 bytes) - NOT [u8; 8]!
}  // Total: 4+4+4+2+2+4+4+2+2+4 = 32 bytes
```

**CRITICAL 修正**:
1. V2 头使用 `tp_nsec` (纳秒)，不是 `tp_usec` (微秒)
2. `tp_padding` 是 `[u8; 4]`，不是 `[u8; 8]`
3. 结构体总大小是 **32 字节**，不是 48 字节

这是 Linux 内核 `/usr/include/linux/if_packet.h:146-157` 的准确定义。

---

## mmap Flags 说明

| Flag | 说明 |
|------|------|
| `PROT_READ` | 允许读取包数据 |
| `PROT_WRITE` | 允许写入数据 |
| `MAP_SHARED` | 共享内存 (推荐) |
| `MAP_PRIVATE` | 私有 COW (不推荐) |
| `MAP_LOCKED` | 锁定内存 (不推荐) |
| `MAP_POPULATE` | 预填充 (不推荐) |

**推荐配置**:
```rust
let ring_ptr = unsafe {
    mmap(
        std::ptr::null_mut(),
        ring_size,
        PROT::PROT_READ | PROT::PROT_WRITE, MAP_SHARED,
        fd,
        0
    )
};
```

---

## 错误处理目录

| 错误类型 | 处理方式 |
|------|------|
| `EAGAIN` | 重试操作 |
| `ENOMEM` | 减小缓冲区 |
| `EPERM` | 权限检查 |
| `EINTR` | 信号处理 |

---

## 测试策略

### 单元测试要求
- 每个公共函数必须有测试
- 边界条件测试
- 错误路径测试
- 并发安全测试

```

cargo test -p rustnmap-packet --lib
```


### 测试覆盖率要求
- 每个公共函数: >=1 测试
- 每个错误路径: >=1 测试
- 边界条件: >=2 测试
- 总体覆盖率: >=80%

---

## 依赖版本锁定

```toml
[dependencies]
libc = "0.2"
tokio = { version = "1.42", features = ["net", "io-util", "rt-multi-thread", "sync"] }
bytes = "1.9"
socket2 = "0.5"
thiserror = "2.0"
async-trait = "0.1"  # REQUIRED: PacketEngine trait 必须使用

[dev-dependencies]
tokio-test = "0.4"  # For async testing
criterion = "0.5"  # For benchmarking
```

**CRITICAL: async-trait 依赖**

`PacketEngine` trait 必须使用 `async-trait` 宏:

```rust
use async_trait::async_trait;

#[async_trait]  // REQUIRED
pub trait PacketEngine: Send + Sync {
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;
    async fn send(&self, packet: &[u8]) -> Result<usize, PacketError>;
}
```

不使用 `async-trait` 会导致 trait 方法无法作为 trait object 使用 (`Box<dyn PacketEngine>`)。

---

## 错误处理目录

| 错误类型 | errno | 处理方式 |
|---------|-------|----------|
| `EAGAIN` | 11 | 重试操作 |
| `ENOMEM` | 12 | 减小缓冲区 |
| `EPERM` | 1 | 权限检查 |
| `EINTR` | 4 | 信号处理 |
| `EINVAL` | 22 | 参数检查 |
| `ENODEV` | 19 | 设备不存在 |
| `ENETDOWN` | 100 | 网络关闭 |
| `ENETUNREACH` | 101 | 网络不可达 |
| `EHOSTUNREACH` | 113 | 主机不可达 |

---

## 迁移指南

### 从 recvfrom 迁移到 PACKET_MMAP

**旧代码:**
```rust
// Before: Using recvfrom
let mut buf = [0u8; 65535];
let len = socket.recvfrom(&mut buf)?;
let packet = &buf[..len];
```

**新代码:**
```rust
// After: Using PACKET_MMAP
let engine = MmapPacketEngine::new("eth0", config)?;
let packet = engine.recv_async().await?;
```

### API 兼容性

`PacketEngine` trait 允许渐进迁移:

```rust
// Old scanners can be updated incrementally
pub trait PacketEngine: Send + Sync {
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;
    // ...
}

// New async scanners
impl AsyncScanner for TcpSynScanner {
    async fn scan(&mut self, engine: &mut dyn PacketEngine) -> Result<ScanResult, ScanError>;
}
```

---

## 参考资源

1. **Linux 内核文档**
   - https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
   - https://www.kernel.org/doc/html/latest/networking/tpacket.html

2. **nmap 源代码**
   - `reference/nmap/libpcap/pcap-linux.c`
   - `reference/nmap/nsock/src/`

3. **Rust 资源**
   - Tokio 文档: https://docs.rs/tokio/latest/tokio/
   - bytes 文档: https://docs.rs/bytes/latest/bytes/

4. **社区资源**
   - https://github.com/libpnet/libpnet (参考实现)
   - https://github.com/brutal-smooth/jni-rs (FFI 参考)
