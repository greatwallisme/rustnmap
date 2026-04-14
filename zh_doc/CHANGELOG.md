# RustNmap 2.0 Changelog / 变更日志

> **RustNmap 2.0 文档变更记录**

本文档追踪 RustNmap 2.0 开发过程中的所有文档变更。

---

## Version 2.0.0 (In Development / 开发中)

**目标发布日期**: TBD

### 新增功能 / New Features

#### 2026-03-10: CLI Migration to lexopt ✅

| 变更 | 状态 | 文档影响 |
|------|------|---------|
| 从 clap 迁移到 lexopt | ✅ 完成 | 已更新 `architecture.md`, `structure.md` |
| 新增 CLI 模块文档 | ✅ 完成 | 新增 `modules/cli.md` |
| 复合短选项支持 (-sS -sV -sC) | ✅ 完成 | 更新相关选项文档 |
| 输出格式复合选项 (-oN/-oX/-oG/-oA) | ✅ 完成 | 更新输出格式文档 |
| 二进制文件大小减少 12% | ✅ 完成 | 更新性能指标 |

**重要变更:**
- 移除依赖: `clap = { version = "4.5", features = ["derive", "wrap_help", "cargo"] }`
- 新增依赖: `lexopt = "0.3"`
- 新增文件: `crates/rustnmap-cli/src/help.rs` (手动帮助系统, 170 行)
- 重构文件: `crates/rustnmap-cli/src/args.rs` (~1100 行重写)

**Nmap 兼容性提升:**
- ✅ `-sS -sV -sC -T4` 完全兼容
- ✅ `-oN file`, `-oX file`, `-oG file`, `-oA basename` 完全兼容
- ✅ `-Pn` 主机发现选项完全兼容
- ✅ 所有 T0-T5 时序模板完全兼容

**详细文档:** 见 `LEXOPT_MIGRATION_COMPLETE.md` 和 `doc/modules/cli.md`

#### Phase 0: 基线修复 (Week 1-2)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| Host Discovery 真正落地 | 待开始 | 更新 `modules/host-discovery.md` |
| `scan_types` 执行链路贯通 | 待开始 | 更新 `modules/port-scanning.md` |
| OutputSink 接入输出系统 | 待开始 | 更新 `modules/output.md`, `manual/output-formats.md` |
| ResumeStore 最小可用版 | 待开始 | 新增 `--resume` 选项文档 |

#### Phase 1: 用户体验与流水线友好 (Week 3-4)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| 流式输出（Host 级） | 待开始 | 新增 `--stream` 选项文档 |
| NDJSON Pipeline 输出 | 待开始 | 更新 `manual/output-formats.md` |
| Shell 补全脚本 | 待开始 | 更新 `manual/options.md` |
| Markdown 报告 | 待开始 | 新增 `-oM` 选项文档 |

#### Phase 2: 漏洞情报主链路 (Week 5-7)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| CVE/CPE 关联引擎 | 待开始 | 新增 `modules/vulnerability.md` |
| EPSS/KEV 聚合与风险排序 | 待开始 | 更新 `manual/options.md` |
| HTML 报告 | 待开始 | 新增 `manual/html-report.md` |
| SARIF 格式 | 待开始 | 更新 `manual/output-formats.md` |

#### Phase 3: 扫描管理能力 (Week 8-9)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| 扫描结果持久化（SQLite） | 待开始 | 新增 `modules/scan-management.md` |
| 扫描 Diff | 待开始 | 新增 `--diff` 选项文档 |
| 配置即代码（YAML Profile） | 待开始 | 新增 `manual/profiles.md` |
| `--history` 查询能力 | 待开始 | 更新 `manual/options.md` |

#### Phase 4: 性能主干优化 (Week 10-11)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| 两阶段扫描（发现 + 精扫） | 待开始 | 更新 `modules/port-scanning.md` |
| 自适应批量大小 | 待开始 | 更新 `modules/concurrency.md` |
| 无状态快速扫描（实验特性） | 待开始 | 新增 `modules/stateless-scan.md` |

#### Phase 5: 平台化最小闭环 (Week 12)

| 功能 | 状态 | 文档影响 |
|------|------|---------|
| REST API / Daemon（最小集） | 待开始 | 新增 `modules/rest-api.md` |
| Rust SDK（稳定 Builder API） | 待开始 | 新增 `modules/sdk.md` |

---

## 文档状态追踪 / Documentation Status

### 核心文档 / Core Documentation

| 文档 | 1.0 状态 | 2.0 更新 | 负责人 |
|------|---------|---------|--------|
| `README.md` | 已标记 | 待更新 | - |
| `architecture.md` | 当前 | 待更新 | - |
| `structure.md` | 当前 | 待更新 | - |
| `user-guide.md` | 已标记 | 待更新 | - |

### 用户手册 / User Manual

| 文档 | 1.0 状态 | 2.0 更新 | 负责人 |
|------|---------|---------|--------|
| `manual/README.md` | 已标记 | 待更新 | - |
| `manual/options.md` | 已标记 | 待更新 | - |
| `manual/quick-reference.md` | 已标记 | 待更新 | - |
| `manual/scan-types.md` | 已标记 | 待更新 | - |
| `manual/output-formats.md` | 已标记 | 待更新 | - |
| `manual/nse-scripts.md` | 已标记 | 待更新 | - |
| `manual/exit-codes.md` | 已标记 | 待更新 | - |
| `manual/environment.md` | 已标记 | 待更新 | - |
| `manual/configuration.md` | 已标记 | 待更新 | - |

### 模块文档 / Module Documentation

| 文档 | 1.0 状态 | 2.0 更新 | 负责人 |
|------|---------|---------|--------|
| `modules/host-discovery.md` | 当前 | 待更新 | - |
| `modules/port-scanning.md` | 当前 | 待更新 | - |
| `modules/service-detection.md` | 当前 | 待更新 | - |
| `modules/os-detection.md` | 当前 | 待更新 | - |
| `modules/nse-engine.md` | 当前 | 待更新 | - |
| `modules/traceroute.md` | 当前 | 待更新 | - |
| `modules/evasion.md` | 当前 | 待更新 | - |
| `modules/output.md` | 当前 | 待更新 | - |
| `modules/target-parsing.md` | 当前 | 待更新 | - |
| `modules/raw-packet.md` | 当前 | 待更新 | - |
| `modules/concurrency.md` | 当前 | 待更新 | - |

### 新增文档（2.0）/ New Documentation (2.0)

| 文档 | 主题 | 状态 | 负责人 |
|------|------|------|--------|
| `modules/vulnerability.md` | 漏洞情报模块 | 待创建 | - |
| `modules/rest-api.md` | REST API 模块 | 待创建 | - |
| `modules/sdk.md` | Rust SDK 模块 | 待创建 | - |
| `modules/scan-management.md` | 扫描管理模块 | 待创建 | - |
| `modules/stateless-scan.md` | 无状态扫描模块 | 待创建 | - |
| `manual/profiles.md` | 配置即代码指南 | 待创建 | - |
| `manual/html-report.md` | HTML 报告指南 | 待创建 | - |

---

## 版本标记说明 / Version Marking

在 RustNmap 2.0 开发期间，所有 1.0 文档已添加版本标记横幅：

```markdown
> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的功能。2.0 版本开发中，详见 [CHANGELOG.md](CHANGELOG.md)。
```

当 2.0 功能完成后，相应文档的版本标记将更新为：

```markdown
> **版本**: 2.0.0
> **状态**: 此文档描述 RustNmap 2.0.0 的功能。
```

---

## 相关链接 / Related Links

- [RETHINK.md](../RETHINK.md) - RustNmap 2.0 进化路线图
- [Project README](../README.md) - 项目概览
- [GitHub Repository](https://github.com/greatwallisme/rust-nmap) - 代码仓库

---

**Last Updated**: 2026-02-17
