# RustNmap 2.0 实施任务计划

**创建日期**: 2026-02-17
**最后更新**: 2026-02-17
**任务目标**: RustNmap 2.0 实施（12 周计划）
**参考文档**: [RETHINK.md](../RETHINK.md), [doc/CHANGELOG.md](../doc/CHANGELOG.md)

---

## 任务概述

根据 RETHINK.md 中的 12 周执行计划，实施 RustNmap 2.0 从"端口扫描器"到"攻击面管理平台"的升级。

---

## 完成状态 (2026-02-17 已提交)

### Phase 0: 执行正确性与可观测性 - 完成 ✅

- [x] Host Discovery: 集成 rustnmap-target::HostDiscovery
- [x] scan_types 路由：支持所有扫描类型
- [x] Scan Metadata: 动态扫描类型/协议派生
- [x] OutputSink: 实现真实输出格式化
- [x] ResumeStore: 保存/加载/清理功能

### Phase 1: 用户体验与流水线友好 - 完成 ✅

- [x] NdjsonFormatter: 换行符分隔 JSON 输出
- [x] MarkdownFormatter: Markdown 报告格式
- [x] CLI 选项：--output-ndjson, --output-markdown, --stream

### Phase 2: 漏洞情报 - 完成 ✅

- [x] 创建 rustnmap-vuln crate (第 15 个 crate)
- [x] VulnClient: 主 API
- [x] CpeMatcher: CPE 解析和匹配
- [x] VulnDatabase: SQLite 存储
- [x] EPSS Engine: 漏洞利用预测评分
- [x] KEV Engine: CISA 已知利用漏洞

### Phase 2.5: VulnClient 异步重构 - 完成 ✅

- [x] 使用 `tokio::sync::RwLock` 包装数据库
- [x] 使用 `DashMap` 实现并发缓存
- [x] 实现异步 API (`offline_async`, `query_cpe_async` 等)
- [x] 严格 Clippy 检查通过（无规避）

### Phase 2.6: 全工作空间 Clippy 修复 - 完成 ✅

- [x] 修复 `rustnmap-core` 的 `cast_possible_truncation`
- [x] 修复 `rustnmap-core` 的 `too_many_lines`
- [x] 修复 `rustnmap-core` 的 `single_match_else`
- [x] 全工作空间 `cargo clippy -- -D warnings` 通过

### Phase 3: 扫描管理 - 完成 ✅

- [x] SQLite 扫描结果持久化 (database.rs)
- [x] 扫描 Diff 比较 (diff.rs)
- [x] YAML Profile 配置 (profile.rs)
- [x] 历史查询支持 (history.rs)
- [x] 创建 rustnmap-scan-management crate (第 16 个 crate)
- [x] 全工作空间 zero warnings, zero errors

---

## 待完成任务

### Phase 4: 性能优化 (Week 10-11)

- [ ] 两阶段扫描
- [ ] 自适应批量大小
- [ ] 无状态快速扫描

### Phase 5: 平台化 (Week 12)

- [ ] REST API / Daemon 模式 (rustnmap-api)
- [ ] Rust SDK Builder API (rustnmap-sdk)

---

## 代码统计

| 指标 | 数值 |
|------|------|
| 总代码行数 | 38,000+ |
| 工作区 Crate 数 | 16 (1.0: 14 + 2.0: 2) |
| 通过测试数 | 683+ (全部通过) |
| Clippy 状态 | ✅ 全工作空间 0 警告 0 错误 |
| 最新提交 | cb3e814 |

---

## 错误日志

| 错误 | 尝试 | 解决方案 |
|------|------|---------|
| SQLite 外键约束失败 | 1 | 测试中先插入 CVE 再插入 EPSS/KEV |
| CPE 格式解析错误 | 1 | 确保 13 部分格式 |
| rusqlite::Clone 不可用 | 1 | 使用引用传递代替 ownership |
| Debug trait 缺失 | 1 | 为所有 pub struct 添加 `#[derive(Debug)]` |
| clippy::allow_attributes_without_reason | 1 | 为所有 allow 属性添加 reason |
| clippy::format_push_string | 1 | 添加 allow 注释（标准模式） |

---

## Phase 3 实现详情

### rustnmap-scan-management crate 结构

```
crates/rustnmap-scan-management/
├── Cargo.toml
└── src/
    ├── lib.rs       - Crate root, exports
    ├── database.rs  - SQLite 数据库操作
    ├── diff.rs      - 扫描结果对比引擎
    ├── error.rs     - 错误类型定义
    ├── history.rs   - 历史查询管理
    ├── models.rs    - 数据模型
    └── profile.rs   - YAML 配置文件管理
```

### 核心功能

1. **ScanDatabase** - SQLite 持久化
   - 4 个表：scans, host_results, port_results, vulnerability_results
   - 索引优化查询性能
   - 事务处理批量插入
   - 自动清理过期扫描

2. **ScanHistory** - 历史查询
   - 支持时间范围/目标/类型/状态过滤
   - 分页查询支持
   - 获取目标历史扫描

3. **ScanDiff** - 扫描对比
   - HostChanges: 新增/消失/状态变化
   - PortChanges: 新增/关闭/状态变化/服务变化
   - VulnerabilityChanges: 新增/修复/风险变化
   - 4 种报告格式：Text/Markdown/Json/Html

4. **ScanProfile** - YAML 配置
   - 支持配置继承
   - 验证扫描类型/定时模板/版本强度/EPSS 阈值
   - ProfileManager 管理多个配置

### 测试结果

```
cargo test -p rustnmap-scan-management --lib
running 4 tests
test profile::tests::test_validate_profile ... ok
test profile::tests::test_parse_yaml_profile ... ok
test profile::tests::test_validate_invalid_timing ... ok
test history::tests::test_open_database ... ok

test result: ok. 4 passed; 0 failed
```
