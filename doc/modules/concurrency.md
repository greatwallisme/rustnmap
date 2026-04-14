## 3.11 Concurrency Model Design

### 3.11.1 Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RustNmap Concurrency Model                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Main Thread (CLI)                           │   │
│  │                    - Configuration parsing                    │   │
│  │                    - Output coordination                      │   │
│  │                    - Progress display                         │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            │                                       │
│  ┌─────────────────────────▼───────────────────────────────────────┐   │
│  │                  Scan Orchestrator (async)                     │   │
│  │                  - Target group scheduling                    │   │
│  │                  - Timing control (T0-T5)                     │   │
│  │                  - Rate limiting                              │   │
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
│  │              - MPSC (Multi-Producer Single-Consumer)        │   │
│  │              - Lock-free Ring Buffer                         │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.11.2 Memory Ordering Guidelines

Based on `rust-concurrency/atomic/memory-ordering.md`:

#### Core Principles

| Scenario | Memory Ordering | Description |
|----------|-----------------|-------------|
| Simple counter | `Relaxed` | Only atomicity needed, no synchronization involved |
| Producer-consumer flag | `Release/Acquire` | Producer uses Release, consumer uses Acquire |
| State machine transition | `AcqRel` | CAS operations require both guarantees |
| Global consistency requirement | `SeqCst` | High cost, use only when necessary |

#### Packet Queue Memory Ordering

```rust
use std::sync::atomic::{AtomicUsize, Ordering};

/// MPSC lock-free queue (Multi-Producer Single-Consumer)
pub struct PacketQueue {
    /// Write index (contended by multiple producers)
    write_idx: AtomicUsize,
    /// Read index (modified by consumer only)
    read_idx: AtomicUsize,
    /// Ring buffer
    buffer: Vec<Option<PacketBuffer>>,
    /// Capacity
    capacity: usize,
}

impl PacketQueue {
    /// Producer enqueue (Release semantics)
    pub fn push(&self, packet: PacketBuffer) -> Result<(), PacketError> {
        // Get current write position
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed);

        if idx - self.load_read(Ordering::Acquire) >= self.capacity {
            // Queue full, rollback
            self.write_idx.fetch_sub(1, Ordering::Relaxed);
            return Err(PacketError::QueueFull);
        }

        let pos = idx % self.capacity;
        self.buffer[pos] = Some(packet);

        // Release semantics: ensure data write completes before updating visibility
        atomic::fence(Ordering::Release);
        Ok(())
    }

    /// Consumer dequeue (Acquire semantics)
    pub fn pop(&self) -> Option<PacketBuffer> {
        let read = self.read_idx.load(Ordering::Acquire);
        let write = self.write_idx.load(Ordering::Acquire);

        if read == write {
            return None;  // Queue empty
        }

        let pos = read % self.capacity;
        let packet = self.buffer[pos].take()?;

        // Acquire semantics: ensure all prior Release operations are visible
        self.read_idx.fetch_add(1, Ordering::Acquire);
        Some(packet)
    }

    /// Get read position (consumer only)
    #[inline]
    fn load_read(&self, ordering: Ordering) -> usize {
        self.read_idx.load(ordering)
    }
}
```

### 3.11.3 Work-Stealing Thread Pool

Based on `rust-concurrency/threading/work-stealing.md`:

```rust
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::task::Wake;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Work-stealing thread pool
pub struct WorkStealingPool {
    /// Per-thread local queues
    workers: Vec<Arc<Mutex<VecDeque<Job>>>>,
    /// Worker thread handles
    handles: Vec<thread::JoinHandle<()>>,
    /// Number of workers
    num_workers: usize,
}

impl WorkStealingPool {
    /// Create a new work-stealing pool
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

    /// Submit a job to a specific thread
    pub fn submit_to(&self, worker_id: usize, job: Job) {
        if worker_id < self.num_workers {
            let mut queue = self.workers[worker_id].lock().unwrap();
            queue.push_back(job);
        }
    }

    /// Submit a job to a random thread (load balancing)
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
            // 1. Try to get a task from local queue
            if let Some(job) = self.try_local_job() {
                job();
                continue;
            }

            // 2. Local queue empty, try to steal a task
            if let Some(job) = self.try_steal_job() {
                job();
                continue;
            }

            // 3. No tasks available, yield
            std::hint::spin_loop();
        }
    }

    fn try_local_job(&self) -> Option<Job> {
        let mut queue = self.local_queue.lock().unwrap();
        queue.pop_front()  // Take from front
    }

    fn try_steal_job(&self) -> Option<Job> {
        // Randomly select other queues to steal from
        let num_workers = self.all_queues.len();
        let start = (self.id + 1) % num_workers;

        for i in 0..num_workers {
            let target_id = (start + i) % num_workers;
            if target_id == self.id {
                continue;  // Don't steal from own queue
            }

            if let Some(job) = self.steal_from_queue(target_id) {
                return Some(job);
            }
        }
        None
    }

    fn steal_from_queue(&self, target_id: usize) -> Option<Job> {
        let mut queue = self.all_queues[target_id].lock().unwrap();
        queue.pop_back()  // Steal from back
    }
}
```

### 3.11.4 Deadlock Prevention

Based on `rust-concurrency/sync/mutex-rwlock.md`:

#### Global Lock Ordering Definition

```rust
/// Global lock ordering (to prevent deadlocks)
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum LockOrder {
    SessionConfig = 0,     // Configuration lock
    TargetSet = 1,          // Target set lock
    PacketEngine = 2,        // Packet engine lock
    PortList = 3,           // Port list lock
    Results = 4,             // Results lock
    Output = 5,              // Output lock
}

/// Ordered mutex wrapper
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

/// Correct lock ordering example
fn scan_host_with_port_check(
    session: &OrderedMutex<ScanSession>,
    ports: &OrderedMutex<PortList>,
) {
    // Always acquire locks in LockOrder sequence
    let _s1 = session.lock();  // SessionConfig < PortList
    let _s2 = ports.lock();
    // ... scan logic
}
```

### 3.11.5 Hot Path Memory Allocation Strategy

Based on Deepseek design and rust-guidelines:

#### Scenarios Where Dynamic Allocation Is Prohibited

```rust
/// Hot path: packet receive loop
/// Wrong: using Vec for dynamic allocation
pub fn recv_packet_bad() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(65535);  // Heap allocation
    // ... fill data
    buffer
}

/// Correct: use stack-allocated array or pre-allocated pool
pub struct PacketPool {
    buffers: Box<[u8; 65535 * 256]>,  // Pre-allocate 16MB
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

#### Zero-Copy Packet Passing

```rust
use bytes::{Bytes, BytesMut};

/// Zero-copy packet reference
pub struct ZeroCopyPacket {
    /// Use Bytes reference counting to avoid copies
    data: Bytes,
    timestamp: std::time::Instant,
}

impl ZeroCopyPacket {
    /// Create from PACKET_MMAP region (no copy)
    pub unsafe fn from_mmap_ptr(
        ptr: *const u8,
        len: usize,
        timestamp: std::time::Instant,
    ) -> Self {
        // Bytes::from_raw_parts does not copy data
        Self {
            data: Bytes::from_raw_parts(ptr as *const u8, len),
            timestamp,
        }
    }

    /// Clone only increments reference count
    pub fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),  // Reference count +1, no data copy
            timestamp: self.timestamp,
        }
    }
}
```

### 3.11.6 Timing Template Concurrency Control

```rust
/// Nmap T0-T5 timing template concurrency parameters
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

/// Timing template definitions (consistent with Nmap)
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

/// Token bucket rate limiter
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

        // Replenish tokens
        let last = self.last_update.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);
        if elapsed > 0 {
            let add = elapsed * self.rate;
            let current = self.tokens.load(Ordering::Relaxed);
            let new = std::cmp::min(current + add, self.capacity);
            self.tokens.store(new, Ordering::Relaxed);
            self.last_update.store(now, Ordering::Relaxed);
        }

        // Consume tokens
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
