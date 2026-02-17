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
- [x] scan_types 路由: 支持所有扫描类型
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

---

## 待完成任务

### Phase 3: 扫描管理 (Week 8-9)

- [ ] SQLite 扫描结果持久化
- [ ] 扫描 Diff 比较
- [ ] YAML Profile 配置
- [ ] --history 查询支持

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
| 总代码行数 | 35,356+ |
| 工作区 Crate 数 | 15 (1.0: 14 + 2.0: 1) |
| 通过测试数 | 106+ (core: 47 + output: 28 + vuln: 31) |
| 最新提交 | cb3e814 |

---

## 错误日志

| 错误 | 尝试 | 解决方案 |
|------|------|---------|
| SQLite 外键约束失败 | 1 | 测试中先插入 CVE 再插入 EPSS/KEV |
| CPE 格式解析错误 | 1 | 确保 13 部分格式 |
| rusqlite::Clone 不可用 | 1 | 使用引用传递代替 ownership |
