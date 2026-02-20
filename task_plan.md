# Task Plan

**Created**: 2026-02-19
**Status**: active
**Goal**: RustNmap 项目持续开发与完善

---

## 当前任务

### Task: Async/Await 优化审查与改进 ✅ COMPLETE
**创建时间**: 2026-02-20
**完成时间**: 2026-02-20
**目标**: 审查已完成异步优化的代码，识别遗漏和改进点

#### 发现摘要
- **严重问题**: 1 个 (block_on 在 orchestrator) ✅ 已修复
- **高优先级**: 2 个 (混合 API、Std 锁在异步上下文) ✅ 已修复
- **中优先级**: 4 个 (blocking_lock、低效 sleep、混合连接扫描) ✅ 已修复

#### 进度状态
1. ✅ `rustnmap-core/src/orchestrator.rs` - block_on 已移除
2. ✅ `rustnmap-nse/src/libs/stdnse.rs` - std RwLock 已替换为 tokio RwLock
3. ✅ `rustnmap-vuln/src/database.rs` - 转换为 tokio-rusqlite
4. ✅ `rustnmap-vuln/src/client.rs` - 已更新为 async API
5. ✅ `rustnmap-vuln/src/cve.rs` - 已更新为 async API
6. ✅ `rustnmap-vuln/src/epss.rs` - 已更新为 async API
7. ✅ `rustnmap-vuln/src/kev.rs` - 已更新为 async API

#### 修复详情

**rustnmap-vuln 完整 async 转换**:
- `database.rs`: 使用 `tokio-rusqlite` 替代 `rusqlite` + `Mutex`
- `cve.rs`: `CveEngine::get_cve()` 转换为 async
- `epss.rs`: 所有 `EpssEngine` 方法转换为 async
- `kev.rs`: 所有 `KevEngine` 方法转换为 async
- `client.rs`: 已是 async，更新测试为 `#[tokio::test]`

**rustnmap-nse stdnse 修复**:
- `get_script_args()` Lua 回调使用 `block_in_place` + `Handle::block_on()`
- 测试更新为 `#[tokio::test(flavor = "multi_thread")]`

---

### Task: Async/Await 性能优化 ✅ COMPLETE
**完成时间**: 2026-02-20
**目标**: 全工作空间异步/等待性能优化，解决阻塞异步运行时的同步操作

#### 实现结果
- **7 个阶段全部完成**: P0-P3 优先级全覆盖
- **修改文件**: 15 个文件
- **关键改进**:
  - 阻塞 sleep → tokio::time::sleep
  - TCP Connect 异步化
  - 文件 I/O 异步化
  - 自旋循环指数退避
  - CPU 循环 yield 点
  - 异步上下文 Mutex 一致性
- **测试**: 553 测试通过
- **质量**: 零编译警告，零 Clippy 警告

---

### Task: rustnmap-packet 模块实现 ✅ COMPLETE
**完成时间**: 2026-02-19
**目标**: 严格按照 `doc/modules/raw-packet.md` 设计文档完成 rustnmap-packet 模块

#### 实现结果
- **文件**: `crates/rustnmap-packet/src/lib.rs` (1,152 行)
- **组件**:
  - `PacketError` - 完整错误类型
  - `RingConfig` - 环形缓冲区配置
  - `PacketBuffer` - 零拷贝缓冲区
  - `AfPacketEngine` - AF_PACKET 套接字引擎
- **测试**: 16/16 通过
- **质量**: 零编译警告，零 Clippy 警告

---

## 项目整体状态

### 完成度: 99%

| Phase | 完成度 | 状态 |
|-------|--------|------|
| Phase 1: Infrastructure | 100% | ✅ 全部完成 |
| Phase 2: Core Scanning | 100% | ✅ 全部完成 |
| Phase 3: Advanced Features | 100% | ✅ 全部完成 |
| Phase 4: Integration | 100% | ✅ 全部完成 |
| 2.0 New Features | 100% | ✅ 全部完成 |

---

## 待办事项

### P2 - 用户体验改进
- [ ] 为所有 18 个 crate 添加 README.md 文件
- [ ] 添加更多使用示例到文档注释
- [ ] 添加性能特性文档

### P3 - 可维护性改进
- [ ] 拆分 rustnmap-net/lib.rs (1,851 行) 为独立模块
- [ ] 添加架构图到 crate README
- [ ] 统一错误处理模式

---

## 已完成任务

### 2026-02-20: Async/Await 性能优化
- **Phase 1 (P0)**: 关键阻塞修复 - sleep、TCP Connect、NSE 网络
- **Phase 2 (P1)**: 热路径文件 I/O - Session、脚本加载、输出
- **Phase 3 (P1)**: 网络操作 - FTP Bounce、NSE nmap 库
- **Phase 4 (P1)**: 数据库操作 - SQLite 异步化
- **Phase 5 (P2)**: CPU 密集型任务 - 指数退避、yield 点
- **Phase 6 (P2)**: 配置/设置 I/O - CLI 输出、Profile 操作
- **Phase 7 (P3)**: 同步原语一致性 - 异步 Mutex

### 2026-02-19: Clippy 零警告修复
- 修复所有基本 clippy 警告
- 修复所有 pedantic 级别警告
- 修复编译错误

### 2026-02-19: 项目完成度审阅
- 全面审阅 18 个 crate
- 对比设计文档与实际实现
- 生成完成度报告

### 2026-02-19: rustnmap-packet 模块实现
- 实现 PACKET_MMAP V3 零拷贝引擎
- 添加完整测试和文档

---

## 代码质量标准

**零容忍政策**:
- ✅ 零编译警告
- ✅ 零 Clippy 警告 (包括 pedantic)
- ✅ 代码格式化一致 (cargo fmt)
- ✅ 所有测试通过

**验证命令**:
```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## 错误记录

| 时间 | 错误 | 解决方案 |
|------|------|----------|
| 2026-02-20 | vuln cve/epss/kev 模块调用 async 方法没有 await | 将这些模块的所有方法转换为 async |
| 2026-02-20 | NSE get_script_args 测试失败 (竞态条件) | 使用 block_in_place 替代创建新 runtime，测试改为 multi_thread flavor |
| 2026-02-20 | vacuum() 返回类型错误 (Result<usize> vs Result<()>) | 在 .call() 闭包中显式返回 Ok(()) |
