# RustNmap 2.0 文档更新任务计划

**创建日期**: 2026-02-17
**任务目标**: 完成 RustNmap 2.0 所有文档更新
**参考文档**: [RETHINK.md](../RETHINK.md), [doc/CHANGELOG.md](../doc/CHANGELOG.md)

---

## 任务概述

根据 RETHINK.md 中的 12 周执行计划，更新 `doc/` 目录下的所有文档，以反映 RustNmap 2.0 从"端口扫描器"到"攻击面管理平台"的升级。

---

## 完成状态 (2026-02-17)

### Phase 0: 文档基线标记 - 完成

- [x] 为所有 1.0 用户文档添加版本标记
- [x] 创建 `doc/CHANGELOG.md`
- [x] 更新 `doc/README.md` 添加 2.0 路线图

### Phase 1: 核心架构更新 - 完成

- [x] 更新 `doc/architecture.md` - 添加 2.0 新 crate 和依赖图
- [x] 更新 `doc/structure.md` - 从 14 个 crate 扩展到 17 个

### Phase 2: 新增模块文档 - 完成

- [x] 创建 `doc/modules/vulnerability.md` - 漏洞情报模块
- [x] 创建 `doc/modules/rest-api.md` - REST API 模块
- [x] 创建 `doc/modules/sdk.md` - Rust SDK 模块
- [x] 创建 `doc/modules/scan-management.md` - 扫描管理模块
- [x] 创建 `doc/modules/stateless-scan.md` - 无状态扫描模块

---

## 完成总结

### 已完成的文档更新

| Phase | 文档 | 操作 | 新增行数 |
|-------|------|------|---------|
| Phase 0 | 12 个用户文档 | 添加 v1.0 版本标记 | - |
| Phase 0 | `doc/CHANGELOG.md` | 新建 | ~200 |
| Phase 0 | `doc/README.md` | 更新 2.0 路线图 | ~50 |
| Phase 1 | `doc/architecture.md` | 添加 2.0 架构 | ~150 |
| Phase 1 | `doc/structure.md` | 更新 crate 列表 | ~100 |
| Phase 2 | `doc/modules/vulnerability.md` | 新建 | ~500 |
| Phase 2 | `doc/modules/rest-api.md` | 新建 | ~450 |
| Phase 2 | `doc/modules/sdk.md` | 新建 | ~400 |
| Phase 2 | `doc/modules/scan-management.md` | 新建 | ~450 |
| Phase 2 | `doc/modules/stateless-scan.md` | 新建 | ~400 |
| **总计** | **19 个文档** | **-** | **~2,700 行** |

---

## 后续工作

根据 RETHINK.md 的 12 周计划，以下文档更新将在对应 Phase 代码完成后进行：

| Phase | 周次 | 待更新文档 | 触发条件 |
|-------|------|-----------|---------|
| Phase 1 | Week 3-4 | `doc/manual/options.md`, `doc/manual/output-formats.md` | 流式输出、NDJSON 完成后 |
| Phase 2 | Week 5-7 | `doc/manual/html-report.md` | HTML/SARIF 报告完成后 |
| Phase 3 | Week 8-9 | `doc/manual/profiles.md` | YAML Profile 完成后 |
| Phase 4 | Week 10-11 | `doc/modules/port-scanning.md` 更新 | 两阶段扫描完成后 |
| Phase 5 | Week 12 | `doc/architecture.md` 最终版 | REST API、SDK 完成后 |

---

## 验证标准

1. [x] 所有新增文档无拼写错误
2. [x] 文档链接无断链
3. [ ] 示例命令可实际执行 (待代码实现后验证)
4. [x] CHANGELOG.md 已更新

---

## 错误日志

| 错误 | 尝试 | 解决方案 |
|------|------|---------|
| 无 | - | 本次任务顺利完成 |
