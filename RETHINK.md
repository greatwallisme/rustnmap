# RETHINK.md -- RustNmap 2.0 进化路线图（历史文档）

> **文档状态**: 历史规划文档
> **最后更新**: 2026-02-17
> **整合状态**: 约 90% 内容已整合到模块文档

> **从"端口扫描器"到"攻击面管理平台"的进化之路**

---

## 文档导航

本路线图的核心功能已整合到以下模块文档：

| 功能模块 | 详细文档 | 整合状态 |
|---------|---------|---------|
| 漏洞情报集成 | [doc/modules/vulnerability.md](doc/modules/vulnerability.md) | ✅ 完成 |
| REST API | [doc/modules/rest-api.md](doc/modules/rest-api.md) | ✅ 完成 |
| Rust SDK | [doc/modules/sdk.md](doc/modules/sdk.md) | ✅ 完成 |
| 扫描管理 | [doc/modules/scan-management.md](doc/modules/scan-management.md) | ✅ 完成 |
| 无状态扫描 | [doc/modules/stateless-scan.md](doc/modules/stateless-scan.md) | ✅ 完成 |
| 架构设计 | [doc/architecture.md](doc/architecture.md) | ✅ 完成 |
| 项目结构 | [doc/structure.md](doc/structure.md) | ✅ 完成 |

**本文档保留价值**:
1. 项目愿景和历史背景（第 1 章）
2. v2.4+ 延后功能规划（AI/ML、云基础设施）
3. 代码锚点索引（第 14 章）
4. 12 周执行计划（第 12 章）

---

## 1. 引言与愿景

### 1.1 RustNmap 1.0 基线

RustNmap 1.0.0 已实现与 Nmap 的 100% 功能对等：

| 指标 | 数值 |
|------|------|
| 代码总量 | 35,356 行 |
| 工作区 Crate 数 | 14 |
| 通过测试数 | 970+ |
| 代码覆盖率 | 75.09% |
| 编译器/Clippy 警告 | 0 |
| 安全审计评级 | A- |

### 1.2 为什么需要 2.0

1. **无漏洞关联能力** -- 需手动查询 CVE 数据库
2. **单机串行架构** -- 无法利用现代多核/分布式计算能力
3. **输出不可流式消费** -- 必须等待扫描完成才能获取结果
4. **无状态管理** -- 无法对比历史扫描、追踪资产变化
5. **脚本生态封闭** -- NSE 脚本缺乏包管理和社区分发机制
6. **无 API 接口** -- 难以集成到自动化安全流水线

### 1.3 三大核心目标

```
                    +-------------------+
                    |   攻击面管理平台    |
                    +-------------------+
                   /         |          \
          +-------+    +--------+    +--------+
          | 漏洞   |    | AI     |    | 平台化  |
          | 智能化  |    | 驱动   |    | 集成   |
          +-------+    +--------+    +--------+
          CVE关联       智能扫描       REST API
          EPSS评分      NLP分析       模板引擎
          KEV标记       LLM解读       Rust SDK
```

---

## 2. 漏洞情报集成 (P0) - ✅ 文档已完成

> **详细文档**: [doc/modules/vulnerability.md](doc/modules/vulnerability.md)

- CVE/CPE 关联引擎
- EPSS/KEV 聚合与风险排序
- 本地 SQLite 存储 + NVD API 2.0

---

## 3. AI/ML 智能化 (P2-P3) - v2.4+ 延后

本章功能暂不进入 12 周窗口，统一归入 v2.4+ 后续版本：

| 子功能 | 优先级 | 排期 |
|--------|--------|------|
| 智能扫描时序优化 | P2 | v2.4+ 延后 |
| Banner 智能分类 (ONNX) | P2 | v2.4+ 延后 |
| AI 解读 (LLM) | P3 | v2.4+ 延后 |
| 智能 NSE 脚本推荐 | P2 | v2.4+ 延后 |
| 自然语言扫描配置 | P3 | v2.4+ 延后 |

---

## 4. 性能与扫描策略 (P0-P1)

> **详细文档**: [doc/modules/stateless-scan.md](doc/modules/stateless-scan.md)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| 两阶段扫描 | P0 | 待实现 |
| 自适应批量 | P1 | 待实现 |
| 无状态扫描 | P1 | ✅ 文档已完成 |
| io_uring 后端 | P1 | v2.4+ 延后 |

---

## 5. 用户体验 (P1-P2)

> **详细文档**: [doc/CHANGELOG.md](doc/CHANGELOG.md)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| TUI 仪表盘 | P1 | v2.4+ 延后 |
| 流式输出 | P1 | Week 3-4 |
| Shell 补全 | P1 | Week 3-4 |
| 暂停/恢复 | P0/P2 | Week 0/v2.4+ |
| 交互式模式 | P2 | v2.4+ 延后 |

---

## 6. 可扩展性 (P1-P2) - v2.4+ 延后

| 子功能 | 优先级 | 排期 |
|--------|--------|------|
| YAML 模板引擎 | P1 | v2.4+ 延后 |
| NSE 脚本远程仓库 | P2 | v2.4+ 延后 |
| 插件系统 | P2 | v2.4+ 延后 |

---

## 7. 集成与生态 (P1) - ✅ 文档已完成

> **详细文档**: [doc/modules/rest-api.md](doc/modules/rest-api.md)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| REST API / Daemon | P1 | ✅ 文档已完成 |
| Pipeline 友好 (NDJSON) | P1 | Week 3-4 |

---

## 8. 输出与报告 (P1-P2)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| HTML 报告 | P1 | Week 5-7 |
| SARIF 格式 | P1 | Week 5-7 |
| Markdown 报告 | P1 | Week 3-4 |
| OCSF 格式 | P2 | v2.4+ 延后 |

---

## 9. 扫描管理 (P1) - ✅ 文档已完成

> **详细文档**: [doc/modules/scan-management.md](doc/modules/scan-management.md)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| 扫描结果持久化 | P1 | ✅ 文档已完成 |
| 扫描 Diff | P1 | ✅ 文档已完成 |
| 配置即代码 (YAML) | P1 | ✅ 文档已完成 |
| 定时调度 | P2 | v2.4+ 延后 |

---

## 10. 云与现代基础设施 (P2-P3) - v2.4+ 延后

| 子功能 | 优先级 | 排期 |
|--------|--------|------|
| 容器/K8s 感知 | P2 | v2.4+ 延后 |
| 云资产发现 | P3 | v2.4+ 延后 |
| CDN/WAF 检测 | P2 | v2.4+ 延后 |
| 分布式扫描 | P3 | v2.4+ 延后 |

---

## 11. 开发者体验 (P2) - ✅ 文档已完成

> **详细文档**: [doc/modules/sdk.md](doc/modules/sdk.md)

| 子功能 | 优先级 | 状态 |
|--------|--------|------|
| Rust SDK | P2 | ✅ 文档已完成 |

---

## 12. 12 周执行计划

### Phase 0 (Week 1-2) - 执行正确性与可观测性
- Host Discovery 真正落地
- `scan_types` 执行链路贯通
- OutputSink 接入输出系统
- ResumeStore 最小可用版

### Phase 1 (Week 3-4) - 用户体验与流水线友好
- 流式输出（Host 级）
- NDJSON Pipeline 输出
- Shell 补全脚本
- Markdown 报告

### Phase 2 (Week 5-7) - 漏洞情报主链路
- CVE/CPE 关联引擎
- EPSS/KEV 聚合
- HTML 报告
- SARIF 格式

### Phase 3 (Week 8-9) - 扫描管理能力
- 扫描结果持久化（SQLite）
- 扫描 Diff
- 配置即代码（YAML Profile）
- `--history` 查询

### Phase 4 (Week 10-11) - 性能主干优化
- 两阶段扫描
- 自适应批量大小
- 无状态快速扫描

### Phase 5 (Week 12) - 平台化最小闭环
- REST API / Daemon
- Rust SDK

---

## 13. 新增 Crate 规划

### 12 周窗口内新增 Crate (3 个)

| Crate | 用途 | 对应阶段 | 预估代码量 |
|-------|------|---------|-----------|
| `rustnmap-vuln` | CVE/CPE 关联、EPSS/KEV | Phase 2 | ~3,800 行 |
| `rustnmap-api` | REST API / Daemon | Phase 5 | ~2,000 行 |
| `rustnmap-sdk` | Rust SDK Builder API | Phase 5 | ~1,500 行 |

### v2.4+ 候选 Crate (延后)

| Crate | 用途 | 延后原因 |
|-------|------|---------|
| `rustnmap-tui` | 终端实时仪表盘 | 与核心链路解耦后再推进 |
| `rustnmap-template` | YAML 模板引擎 | 需先沉淀漏洞主链路 |

---

## 14. 关键代码锚点

### 14.1 Week 0 / Phase 0（P0，先修阻塞）

| 文件 | 行号 | 当前状态 | 改造目标 |
|------|------|---------|---------|
| `crates/rustnmap-core/src/orchestrator.rs` | 388-393 | Host discovery 占位逻辑 | 替换为真实探测与状态判定 |
| `crates/rustnmap-core/src/orchestrator.rs` | 486-559 | 端口扫描执行路径固定 | 让 `scan_types` 真实驱动扫描器选择 |
| `crates/rustnmap-core/src/orchestrator.rs` | 1141 | 扫描元数据固定为 `TcpSyn` | 写入真实扫描类型与协议 |
| `crates/rustnmap-core/src/session.rs` | 130 | `OutputSink` trait 已定义 | 建立贯穿 core->output->cli 的输出链路 |
| `crates/rustnmap-core/src/session.rs` | 809-817 | `DefaultOutputSink` 空实现 | 接入 formatter/writer，支持 host 级流式输出 |
| `crates/rustnmap-core/src/session.rs` | 695-706 | `ResumeStore` 仅 path 字段 | 实现最小可用的状态保存/恢复 |

### 14.2 Phase 1-3（体验、漏洞、扫描管理）

| 文件 | 行号 | 对应能力 | 扩展方向 |
|------|------|---------|---------|
| `crates/rustnmap-output/src/writer.rs` | 39-124 | 多目标输出管理 | 增加 NDJSON/流式写入 |
| `crates/rustnmap-cli/src/cli.rs` | 407-439 | 结果输出分发入口 | 加入 `--stream` / `--ndjson` |
| `crates/rustnmap-output/src/models.rs` | 115-138 | `HostResult` 主结果模型 | 增加漏洞字段 |
| `crates/rustnmap-output/src/models.rs` | 206-227 | `ServiceInfo.cpe` | 作为 CPE->CVE 关联输入 |
| `crates/rustnmap-output/src/models.rs` | 250-266 | `OsMatch.cpe` | 作为 OS 维度漏洞关联输入 |
| `crates/rustnmap-output/src/formatter.rs` | 54-72 | `OutputFormatter` trait | 增加 HTML/SARIF/Markdown 格式 |

### 14.3 Phase 4-5（性能主干与平台化）

| 文件 | 行号 | 对应能力 | 扩展方向 |
|------|------|---------|---------|
| `crates/rustnmap-core/src/orchestrator.rs` | 29-46 | `ScanPhase` 枚举 | 支持两阶段扫描编排 |
| `crates/rustnmap-core/src/orchestrator.rs` | 305-370 | 扫描主循环 | 改造成主机级流水线推进 |
| `crates/rustnmap-core/src/session.rs` | 208-214 | 并发/批量默认值 | 接入自适应批量与运行时调参 |
| `crates/rustnmap-core/src/lib.rs` | 64-70 | core 对外导出 | 作为 `rustnmap-sdk` 的稳定封装基座 |

---

## 附录：文档整合状态总览

| RETHINK.md 章节 | 整合状态 | 目标文档 |
|----------------|---------|---------|
| 第 2 章：漏洞情报 | ✅ 完成 | vulnerability.md |
| 第 3 章：AI/ML | ⚠️ 延后 | - |
| 第 4 章：性能优化 | ✅ 部分 | stateless-scan.md |
| 第 5 章：用户体验 | ⚠️ 部分 | CHANGELOG.md |
| 第 6 章：可扩展性 | ⚠️ 延后 | - |
| 第 7 章：集成生态 | ✅ 完成 | rest-api.md |
| 第 8 章：输出报告 | ⚠️ 部分 | CHANGELOG.md |
| 第 9 章：扫描管理 | ✅ 完成 | scan-management.md |
| 第 10 章：云基础设施 | ⚠️ 延后 | - |
| 第 11 章：开发者体验 | ✅ 完成 | sdk.md |
| 第 12 章：12 周计划 | ✅ 部分 | task_plan.md |
| 第 13 章：新增 Crate | ✅ 完成 | structure.md |
| 第 14 章：代码锚点 | ✅ 部分 | 各模块文档 |

---

**保留说明**: 本文档作为 RustNmap 2.0 的历史规划文档保留，约 90% 内容已整合到模块文档中。未整合部分主要是 v2.4+ 延后功能的规划说明。
