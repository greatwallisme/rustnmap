## 3.11 并发模型设计

基于 Rust 并发编程指南 (rust-concurrency) 和 Deepseek 设计文档的并发模型。

### 3.11.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RustNmap Concurrency Model                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Main Thread (CLI)                           │   │
│  │                    - 配置解析                                   │   │
│  │                    - 输出协调                                   │   │
│  │                    - 进度显示                                   │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            │                                       │
│  ┌─────────────────────────▼───────────────────────────────────────┐   │
│  │                  Scan Orchestrator (async)                     │   │
│  │                  - 目标分组调度                               │   │
│  │                  - 时序控制 (T0-T5)                          │   │
│  │                  - 速率限制                                   │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            │                                       │
│        ┌───────────────────┼───────────────────┐                    │
│        │                   │                   │                    │
│  ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐        │
│  │ Packet    │    │  NSE      │    │  Service  │        │
│  │ Engine    │    │  Engine   │    │  Detect   │        │
│  │ Thread    │    │  Pool     │    │  Pool     │        │
│  │ Pool      │    │           │    │           │        │
│  │ (Work-    │    │ (Work-    │    │ (Fixed)   │        │
│  │  Stealing) │    │  Stealing) │    │           │        │
│  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘        │
│        │                 │                   │                 │
│        └─────────────────┴───────────────────┘                 │
│                            │                                   │
│  ┌─────────────────────────▼─────────────────────────────────────┐   │
│  │              Zero-Copy Packet Queues                       │   │
│  │              - MPSC (多生产者单消费者)                      │   │
│  │              - Lock-free Ring Buffer                         │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.11.2 内存序指南

基于 `rust-concurrency/atomic/memory-ordering.md`:

#### 核心原则

| 场景 | 内存序 | 说明 |
|--------|---------|------|
| 简单计数器 | `Relaxed` | 只需原子性，不涉及同步 |
| 生产者-消费者标志 | `Release/Acquire` | 生产者用Release，消费者用Acquire |
| 状态机转换 | `AcqRel` | CAS操作需要同时保证 |
| 全局一致性需求 | `SeqCst` | 代价高，仅在必要时使用 |

#### 数据包队列内存序

```rust
use std::sync::atomic::{AtomicUsize, Ordering};

/// MPSC 无锁队列 (多生产者单消费者)
pub struct PacketQueue {
    /// 写入索引 (多生产者竞争)
    write_idx: AtomicUsize,
    /// 读取索引 (仅消费者修改)
    read_idx: AtomicUsize,
    /// 环形缓冲区
    buffer: Vec<Option<PacketBuffer>>,
    /// 容量
    capacity: usize,
}

impl PacketQueue {
    /// 生产者入队 (Release 语义)
    pub fn push(&self, packet: PacketBuffer) -> Result<(), PacketError> {
        // 获取当前写入位置
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed);

        if idx - self.load_read(Ordering::Acquire) >= self.capacity {
            // 队列满，回滚
            self.write_idx.fetch_sub(1, Ordering::Relaxed);
            return Err(PacketError::QueueFull);
        }

        let pos = idx % self.capacity;
        self.buffer[pos] = Some(packet);

        // Release 语义: 确保数据写入完成后再更新可见性
        atomic::fence(Ordering::Release);
        Ok(())
    }

    /// 消费者出队 (Acquire 语义)
    pub fn pop(&self) -> Option<PacketBuffer> {
        let read = self.read_idx.load(Ordering::Acquire);
        let write = self.write_idx.load(Ordering::Acquire);

        if read == write {
            return None;  // 队列空
        }

        let pos = read % self.capacity;
        let packet = self.buffer[pos].take()?;

        // Acquire 语义: 确保看到之前所有 Release 操作
        self.read_idx.fetch_add(1, Ordering::Acquire);
        Some(packet)
    }

    /// 获取读取位置 (仅消费者调用)
    #[inline]
    fn load_read(&self, ordering: Ordering) -> usize {
        self.read_idx.load(ordering)
    }
}
```

### 3.11.3 工作窃取线程池

基于 `rust-concurrency/threading/work-stealing.md`:

```rust
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::task::Wake;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// 工作窃取线程池
pub struct WorkStealingPool {
    /// 每个线程的本地队列
    workers: Vec<Arc<Mutex<VecDeque<Job>>>>,
    /// 工作线程句柄
    handles: Vec<thread::JoinHandle<()>>,
    /// 线程数
    num_workers: usize,
}

impl WorkStealingPool {
    /// 创建新的工作窃取池
    pub fn new(num_workers: usize) -> Self {
        let mut workers = Vec::with_capacity(num_workers);
        let mut handles = Vec::with_capacity(num_workers);

        for id in 0..num_workers {
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            workers.push(Arc::clone(&queue));

            let all_queues = workers.clone();
            let handle = thread::spawn(move || {
                Worker {
                    id,
                    local_queue: queue,
                    all_queues,
                }.run();
            });

            handles.push(handle);
        }

        Self {
            workers,
            handles,
            num_workers,
        }
    }

    /// 提交任务到指定线程
    pub fn submit_to(&self, worker_id: usize, job: Job) {
        if worker_id < self.num_workers {
            let mut queue = self.workers[worker_id].lock().unwrap();
            queue.push_back(job);
        }
    }

    /// 提交任务到随机线程 (负载均衡)
    pub fn submit(&self, job: Job) {
        let worker_id = fastrand::usize(0..self.num_workers);
        self.submit_to(worker_id, job);
    }
}

struct Worker {
    id: usize,
    local_queue: Arc<Mutex<VecDeque<Job>>>,
    all_queues: Vec<Arc<Mutex<VecDeque<Job>>>>,
}

impl Worker {
    fn run(&self) {
        loop {
            // 1. 尝试从本地队列获取任务
            if let Some(job) = self.try_local_job() {
                job();
                continue;
            }

            // 2. 本地队列为空，尝试窃取任务
            if let Some(job) = self.try_steal_job() {
                job();
                continue;
            }

            // 3. 没有任务，yield
            std::hint::spin_loop();
        }
    }

    fn try_local_job(&self) -> Option<Job> {
        let mut queue = self.local_queue.lock().unwrap();
        queue.pop_front()  // 从头部获取
    }

    fn try_steal_job(&self) -> Option<Job> {
        // 随机选择其他队列进行窃取
        let num_workers = self.all_queues.len();
        let start = (self.id + 1) % num_workers;

        for i in 0..num_workers {
            let target_id = (start + i) % num_workers;
            if target_id == self.id {
                continue;  // 不从自己队列窃取
            }

            if let Some(job) = self.steal_from_queue(target_id) {
                return Some(job);
            }
        }
        None
    }

    fn steal_from_queue(&self, target_id: usize) -> Option<Job> {
        let mut queue = self.all_queues[target_id].lock().unwrap();
        queue.pop_back()  // 从尾部窃取
    }
}
```

### 3.11.4 死锁预防

基于 `rust-concurrency/sync/mutex-rwlock.md`:

#### 全局锁顺序定义

```rust
/// 全局锁顺序 (避免死锁)
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum LockOrder {
    SessionConfig = 0,     // 配置锁
    TargetSet = 1,          // 目标集合锁
    PacketEngine = 2,        // 包引擎锁
    PortList = 3,           // 端口列表锁
    Results = 4,             // 结果锁
    Output = 5,              // 输出锁
}

/// 有序锁包装器
pub struct OrderedMutex<T> {
    order: LockOrder,
    inner: Mutex<T>,
}

impl<T> OrderedMutex<T> {
    pub fn new(order: LockOrder, value: T) -> Self {
        Self {
            order,
            inner: Mutex::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<T> {
        self.inner.lock().unwrap()
    }
}

/// 正确的锁定顺序示例
fn scan_host_with_port_check(
    session: &OrderedMutex<ScanSession>,
    ports: &OrderedMutex<PortList>,
) {
    // 总是按照 LockOrder 顺序获取锁
    let _s1 = session.lock();  // SessionConfig < PortList
    let _s2 = ports.lock();
    // ... 扫描逻辑
}
```

### 3.11.5 热路径内存分配策略

基于 Deepseek 设计和 rust-guidelines:

#### 禁止动态分配的场景

```rust
/// 热路径：数据包接收循环
/// ❌ 错误：使用 Vec 动态分配
pub fn recv_packet_bad() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(65535);  // 堆分配
    // ... 填充数据
    buffer
}

/// ✅ 正确：使用栈上数组或预分配池
pub struct PacketPool {
    buffers: Box<[u8; 65535 * 256]>,  // 预分配 16MB
    free_list: AtomicUsize,
}

impl PacketPool {
    pub fn get_buffer(&self) -> &mut [u8] {
        let idx = self.free_list.fetch_add(1, Ordering::Relaxed);
        let base = idx % 256;
        &mut self.buffers[base * 65535..(base + 1) * 65535]
    }
}
```

#### 零拷贝数据包传递

```rust
use bytes::{Bytes, BytesMut};

/// 零拷贝数据包引用
pub struct ZeroCopyPacket {
    /// 使用 Bytes 引用计数，避免拷贝
    data: Bytes,
    timestamp: std::time::Instant,
}

impl ZeroCopyPacket {
    /// 从 PACKET_MMAP 区域创建 (无拷贝)
    pub unsafe fn from_mmap_ptr(
        ptr: *const u8,
        len: usize,
        timestamp: std::time::Instant,
    ) -> Self {
        // Bytes::from_raw_parts 不拷贝数据
        Self {
            data: Bytes::from_raw_parts(ptr as *const u8, len),
            timestamp,
        }
    }

    /// 克隆只增加引用计数
    pub fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),  // 引用计数 +1，无数据拷贝
            timestamp: self.timestamp,
        }
    }
}
```

### 3.11.6 时序模板并发控制

```rust
/// Nmap T0-T5 时序模板并发参数
#[derive(Debug, Clone)]
pub struct TimingTemplate {
    pub min_parallelism: usize,
    pub max_parallelism: usize,
    pub min_rtt_ms: u64,
    pub max_rtt_ms: u64,
    pub init_rtt_ms: u64,
    pub host_timeout_ms: u64,
    pub max_retries: u8,
}

/// 时序模板定义 (与 Nmap 一致)
pub const TEMPLATES: &[TimingTemplate] = &[
    TimingTemplate {  // T0: Paranoid
        min_parallelism: 1,
        max_parallelism: 1,
        min_rtt_ms: 100,
        max_rtt_ms: 5000,
        init_rtt_ms: 1000,
        host_timeout_ms: 120000,
        max_retries: 10,
    },
    TimingTemplate {  // T1: Sneaky
        min_parallelism: 1,
        max_parallelism: 2,
        min_rtt_ms: 100,
        max_rtt_ms: 2000,
        init_rtt_ms: 500,
        host_timeout_ms: 120000,
        max_retries: 6,
    },
    // ... T2-T5
];

/// 令牌桶速率限制器
pub struct TokenBucket {
    tokens: AtomicU64,
    capacity: u64,
    last_update: AtomicU64,
    rate: u64,  // tokens per second
}

impl TokenBucket {
    pub fn try_acquire(&self, tokens: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 恢复令牌
        let last = self.last_update.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);
        if elapsed > 0 {
            let add = elapsed * self.rate;
            let current = self.tokens.load(Ordering::Relaxed);
            let new = std::cmp::min(current + add, self.capacity);
            self.tokens.store(new, Ordering::Relaxed);
            self.last_update.store(now, Ordering::Relaxed);
        }

        // 消耗令牌
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < tokens {
                return false;
            }
            if self.tokens.compare_exchange_weak(
                current,
                current - tokens,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return true;
            }
        }
    }
}
```

---
