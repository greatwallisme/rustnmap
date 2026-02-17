# Findings: RustNmap 2.0 文档更新研究

**创建日期**: 2026-02-17
**任务**: 完成所有文档更新

---

## 发现 1: 文档版本状态

Phase 0 已完成所有 1.0 文档的版本标记：
- 12 个文件已添加 v1.0 版本标记横幅
- 标记格式统一为："> **版本**: 1.0.0\n> **状态**: 此文档描述 RustNmap 1.0.0 的功能。2.0 版本开发中，详见 [CHANGELOG.md](CHANGELOG.md)。"

---

## 发现 2: 文档结构完整性

现有文档结构完整，包含：
- 3 个架构文档 (README.md, architecture.md, structure.md)
- 11 个模块文档 (modules/)
- 9 个用户手册文件 (manual/)
- 6 个附录文档 (appendix/)
- 3 个其他文档 (CHANGELOG, database, roadmap, findings.md, progress.md, task_plan.md)

**总计**: 32+ 个文档文件

---

## 发现 3: RETHINK.md 对齐需求

根据 RETHINK.md 的 12 周计划，需要：

### 新增 Crate (3 个)
- `rustnmap-vuln` - 漏洞情报（Week 5-7）
- `rustnmap-api` - REST API（Week 12）
- `rustnmap-sdk` - Rust SDK（Week 12）

### 新增文档 (7 个)
1. `doc/modules/vulnerability.md` - 漏洞情报模块
2. `doc/modules/rest-api.md` - REST API / Daemon 模式
3. `doc/modules/sdk.md` - Rust SDK Builder API
4. `doc/modules/scan-management.md` - 扫描管理（SQLite、Diff、Profiles）
5. `doc/modules/stateless-scan.md` - 无状态快速扫描
6. `doc/manual/profiles.md` - YAML 配置文件格式指南
7. `doc/manual/html-report.md` - HTML 报告模板说明

---

## 发现 4: 更新优先级

**P0 - 必须优先更新**:
- `doc/architecture.md` - 架构需反映新 crate
- `doc/structure.md` - 从 14 个 crate 扩展到 17 个
- `doc/modules/host-discovery.md` - Host Discovery 占位实现需替换

**P1 - 重要更新**:
- `doc/manual/options.md` - 新增 CLI 选项
- `doc/manual/output-formats.md` - 新增输出格式
- `doc/modules/port-scanning.md` - 两阶段扫描

**P2 - 次要更新**:
- 附录文档 - 按需更新
- `doc/modules/concurrency.md` - io_uring 延后到 v2.4+

---

## 发现 5: architecture.md 当前状态

当前架构文档包含：
- 整体架构图 (CLI -> Core -> Scan Modules -> Infrastructure)
- 模块依赖关系 (rustnmap-cli -> rustnmap-core -> scan modules -> rustnmap-net -> rustnmap-common)
- ScanSession trait 定义
- PacketEngine trait 定义
- 依赖注入模式示例

**需要添加**:
- rustnmap-vuln crate (漏洞情报)
- rustnmap-api crate (REST API)
- rustnmap-sdk crate (Rust SDK)
- 2.0 架构图

---

## 发现 6: structure.md 当前状态

当前结构文档包含：
- Cargo Workspace 结构 (7 个 crates)
- 依赖关系图
- 外部依赖列表

**实际项目已有 14 个 crates**:
- rustnmap-common, rustnmap-net, rustnmap-packet
- rustnmap-target, rustnmap-scan, rustnmap-fingerprint
- rustnmap-nse, rustnmap-traceroute, rustnmap-evasion
- rustnmap-cli, rustnmap-core, rustnmap-output
- rustnmap-benchmarks, rustnmap-macros

**2.0 需扩展到 17 个**:
- +rustnmap-vuln
- +rustnmap-api
- +rustnmap-sdk

---

## 决策记录

### 决策 1: 文档组织方式
**选择**: 方案 B (标记版本 + 选择性更新)
**理由**: 保留历史价值，渐进式更新

### 决策 2: 新增文档位置
**选择**: 在现有 doc/ 目录下创建新文件
**理由**: 保持文档结构一致性

### 决策 3: 执行顺序
1. 先更新核心架构文档 (architecture.md, structure.md)
2. 再创建新增模块文档
3. 最后更新用户手册

---

## 参考链接

- [RETHINK.md](../RETHINK.md) - 2.0 进化路线图
- [doc/CHANGELOG.md](../doc/CHANGELOG.md) - 文档变更记录
- [doc/README.md](../doc/README.md) - 文档索引
