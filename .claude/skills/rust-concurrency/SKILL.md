---
name: rust-concurrency
description: |
    Production-grade Rust concurrency: threads, atomics, async/await, lock-free data structures, memory ordering, ABA problem, executor design, NUMA, work-stealing, deadlock prevention. Use when: building high-concurrency systems, implementing lock-free algorithms, debugging race conditions, optimizing async runtimes, or handling synchronization primitives.
allowed-tools: Read, Write, Edit, Bash, Grep, Glob, Task, mcp__Bocha__bocha_web_search, mcp__Context7__*, mcp__rust-analyzer__*, mcp__Sequential__sequentialthinking
---

# Rust并发编程指南

## NEVER DO THESE

1. **NEVER** 在不知道内存序含义时使用SeqCst - 5-10x性能损失
2. **NEVER** 在持有锁时进行耗时操作 - 导致所有线程阻塞
3. **NEVER** 无条件使用try_lock循环自旋 - CPU空转浪费
4. **NEVER** 假设relaxed atomic能同步任何数据 - 架构相关
5. **NEVER** 在不理解ABA问题时实现无锁结构 - 概率性崩溃
6. **NEVER** 在无锁结构中假设单线程内存模型 - 必须考虑happens-before关系
7. **NEVER** 使用AtomicBool::load(Ordering::SeqCst)作为简单标志 - Release/Acquire足够

## 并发设计思维原则

在实现并发系统前,问自己:

### 1. 正确性优先
- 数据竞争是否已证明不可能发生?(通过类型系统验证)
- 死锁场景是否已枚举并预防?(锁顺序、超时机制)
- 所有panic路径是否已处理?(join结果检查)

### 2. 性能瓶颈定位
- 瓶颈在锁竞争、内存带宽还是CPU缓存?(先测量再优化)
- 是否有profiling数据支持优化方向?(cargo-flamegraph、criterion)
- 优化后性能提升是否超过复杂度增加的代价?

### 3. 复杂度代价
- 无锁算法的正确性证明成本是否值得?(考虑使用crossbeam)
- 是否有更简单的替代方案?(Mutex通常足够)
- 团队是否有能力维护此复杂度?

### 4. 可测试性
- 如何测试并发正确性?(loom模型检查、miri数据竞争检测)
- 是否使用了静态分析工具?(clippy lint、锁依赖分析)
- 是否有压力测试验证稳定性?

### 5. 优雅降级
- 当并发原语失败时,是否有降级方案?(fallback to Mutex)
- 是否有限流/背压机制防止资源耗尽?
- 错误是否可传播而非静默丢失?

## 并发方案决策树

### 线程 vs 异步
| 场景 | 推荐方案 | 加载文档 |
|------|---------|---------|
| CPU密集型计算 | 线程池 | `threading/work-stealing.md` |
| I/O密集型操作 | 异步运行时 | `runtime/executor-design.md` |
| 混合负载 | 线程池 + 异步 | 两者都加载 |

### 同步原语选择
| 需求 | 首选 | 备选 |
|------|------|------|
| 简单计数器 | AtomicU64 | Mutex<u64> |
| 读多写少 | RwLock | Atomic + sharding |
| 复杂临界区 | Mutex | - |
| 无阻塞需求 | Lock-free结构 | 考虑crossbeam |

### 无锁方案选择
| 场景 | 推荐方案 | 原因 |
|------|---------|------|
| 高频小操作 | 无锁队列 | 锁开销占主导 |
| 低频大操作 | Mutex | 正确性更易保证 |
| 不确定 | 先用Mutex,有证据再优化 | 过早优化是万恶之源 |

## 按需加载专题

### 同步原语

**MANDATORY** - 在使用锁前阅读 [`sync/mutex-rwlock.md`](./sync/mutex-rwlock.md) 重点关注死锁预防部分(第528行起)

**场景检测**:
- 用户提到"死锁"、"deadlock"、"锁顺序" → 加载此文件
- 用户提到"Mutex"、"RwLock"、"锁竞争" → 加载此文件

**Do NOT load** - `atomic/` 目录除非明确需要原子操作

---

### 内存序模型

**MANDATORY** - 在使用任何原子操作前,必须阅读 [`atomic/memory-ordering.md`](./atomic/memory-ordering.md) 完整内容(~240行)

**场景检测**:
- 用户提到"原子"、"atomic"、"compare_exchange" → 加载此文件
- 用户提到"内存序"、"memory ordering"、"happens-before" → 加载此文件
- 用户提到"Acquire"、"Release"、"SeqCst" → 加载此文件

**Do NOT load**:
- 除非用户提到"ABA问题",否则不要加载 `atomic/aba-problem.md`

---

### 无锁数据结构

**MANDATORY** - 在实现无锁队列/栈前,必须阅读 [`datastructures/lockfree-queue.md`](./datastructures/lockfree-queue.md)

**场景检测**:
- 用户提到"无锁"、"lock-free"、"无阻塞" → 加载此文件
- 用户提到"MPMC"、"SPSC"、"Michael-Scott" → 加载此文件
- 用户提到"CAS"、"compare_exchange" → 加载此文件

**配合加载**:
- 如果涉及指针复用,同时加载 `atomic/aba-problem.md`

---

### 工作窃取线程池

**MANDATORY** - 在实现任务调度器前,必须阅读 [`threading/work-stealing.md`](./threading/work-stealing.md)

**场景检测**:
- 用户提到"线程池"、"thread pool"、"工作窃取" → 加载此文件
- 用户提到"work-stealing"、"任务调度"、"NUMA" → 加载此文件
- 用户提到"负载均衡"、"CPU利用率" → 加载此文件

**Do NOT load**:
- 除非用户明确需要NUMA优化,否则跳过第189行起的NUMA部分

---

### 异步运行时设计

**MANDATORY** - 在设计执行器前,必须阅读 [`runtime/executor-design.md`](./runtime/executor-design.md)

**场景检测**:
- 用户提到"执行器"、"executor"、"Future" → 加载此文件
- 用户提到"异步运行时"、"async runtime" → 加载此文件
- 用户提到"任务调度"、"task scheduler" → 加载此文件

**配合加载**:
- 如果涉及Future实现细节,同时加载 `async/future-trait.md`

---

### 并发调试

**MANDATORY** - 在调试竞态条件时,阅读 [`debugging/concurrent-bugs.md`](./debugging/concurrent-bugs.md)

**场景检测**:
- 用户提到"竞态"、"race condition"、"数据竞争" → 加载此文件
- 用户提到"并发bug"、"死锁"、"并发调试" → 加载此文件
- 用户提到"loom"、"miri"、"ThreadSanitizer" → 加载此文件

---

### 异步I/O操作

**MANDATORY** - 在实现异步文件/网络操作时阅读 [`async-io/async-file-operations.md`](./async-io/async-file-operations.md) 或 [`async-io/async-network-programming.md`](./async-io/async-network-programming.md)

**场景检测**:
- 用户提到"异步文件"、"async file"、"Tokio fs" → 加载 async-file-operations.md
- 用户提到"异步网络"、"async network"、"TcpListener/ TcpStream" → 加载 async-network-programming.md

---

### 并发模式

**MANDATORY** - 在设计并发架构时阅读 [`patterns/concurrent-patterns.md`](./patterns/concurrent-patterns.md)

**场景检测**:
- 用户提到"并发模式"、"并发架构"、"生产者消费者" → 加载此文件
- 用户提到"工作池"、"pipeline"、"fan-out/fan-in" → 加载此文件

**配合加载**:
- 如果涉及错误处理,同时加载 `patterns/error-handling.md`

---

### 性能优化

**MANDATORY** - 当用户提到性能优化时,阅读:
- [`performance/cache-optimization.md`](./performance/cache-optimization.md) - 缓存行优化、伪共享
- [`performance/numa-programming.md`](./performance/numa-programming.md) - NUMA架构编程

**场景检测**:
- "性能优化"、"性能瓶颈"、"cache miss"、"NUMA"、"缓存对齐"、"伪共享"

---

### 并发HashMap

**MANDATORY** - 在实现并发HashMap时阅读 [`datastructures/concurrent-map.md`](./datastructures/concurrent-map.md)

**场景检测**:
- 用户提到"并发HashMap"、"分段锁"、"concurrent hash map"、"sharding" → 加载此文件

**配合加载**:
- 如果涉及无锁实现,同时加载 `datastructures/lockfree-queue.md`

---

### 内存回收策略

**MANDATORY** - 在实现无锁数据结构时阅读 [`datastructures/memory-reclamation.md`](./datastructures/memory-reclamation.md)

**场景检测**:
- 用户提到"内存回收"、"hazard pointer"、"epoch"、"RCU" → 加载此文件
- 用户提到"延迟释放"、"安全释放内存" → 加载此文件

---

### 压力测试

**MANDATORY** - 在验证并发系统稳定性时阅读 [`testing/stress-testing.md`](./testing/stress-testing.md)

**场景检测**:
- 用户提到"压力测试"、"压测"、"负载测试"、"模糊测试" → 加载此文件
- 用户提到"并发测试"、"fuzz testing"、"稳定性测试" → 加载此文件

---

## 代码模板

### 线程池
- [`templates/thread-pools/thread-pool-basic.rs`](./templates/thread-pools/thread-pool-basic.rs) - 基础实现
- [`templates/thread-pools/thread-pool-work-stealing.rs`](./templates/thread-pools/thread-pool-work-stealing.rs) - 工作窃取

### 异步编程
- [`templates/async/simple-executor.rs`](./templates/async/simple-executor.rs) - 简单执行器
- [`templates/async/async-runtime-config.rs`](./templates/async/async-runtime-config.rs) - 运行时配置

### 原子操作
- [`templates/atomic/versioned-pointer.rs`](./templates/atomic/versioned-pointer.rs) - ABA问题解决方案

## 测试与调试工具

- [`tools/testing/async-test-framework.md`](./tools/testing/async-test-framework.md) - 异步测试
- [`tools/analysis/contention-analyzer.rs`](./tools/analysis/contention-analyzer.rs) - 锁竞争分析
