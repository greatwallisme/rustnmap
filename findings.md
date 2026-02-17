# Findings: RustNmap 2.0 实施研究

**创建日期**: 2026-02-17
**最后更新**: 2026-02-17
**任务**: RustNmap 2.0 Phase 0, 1, 2 实施

---

## 发现 1: Phase 0 占位实现分析

Phase 0 有 5 个占位实现需要修复：

1. **Host Discovery** (orchestrator.rs:388-393)
   - 问题：直接将所有主机标记为"Up"，无实际探测
   - 解决：集成 rustnmap-target::HostDiscovery
   - 状态：✅ 完成

2. **scan_types 路由** (orchestrator.rs:486-559)
   - 问题：忽略配置，始终使用 TCP SYN 扫描
   - 解决：根据 config.scan_types 路由到不同扫描器
   - 状态：✅ 完成

3. **Scan Metadata** (orchestrator.rs:1141)
   - 问题：硬编码为 TcpSyn
   - 解决：从配置动态派生
   - 状态：✅ 完成

4. **OutputSink** (session.rs:809-817)
   - 问题：空实现，不输出任何内容
   - 解决：集成 rustnmap-output 格式化器
   - 状态：✅ 完成

5. **ResumeStore** (session.rs:695-706)
   - 问题：只存储路径，无保存/加载功能
   - 解决：实现 JSON 序列化/反序列化
   - 状态：✅ 完成

---

## 发现 2: Phase 1 输出格式需求

新增输出格式：

1. **NDJSON** (Newline Delimited JSON)
   - 用途：流水线处理，每行一个 JSON 对象
   - 实现：NdjsonFormatter
   - 文件扩展名：.ndjson

2. **Markdown**
   - 用途：人类可读报告
   - 实现：MarkdownFormatter
   - 包含：扫描信息、统计、主机表格、脚本、OS 匹配

3. **CLI 选项**
   - `--output-ndjson FILE`: NDJSON 输出
   - `--output-markdown FILE`: Markdown 输出
   - `--stream`: 流式输出模式

---

## 发现 3: Phase 2 漏洞情报架构

### 数据库设计

```sql
-- CVE 表
CREATE TABLE cve (
    id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_base REAL,
    cvss_v3_vector TEXT,
    published_at TEXT,
    modified_at TEXT
);

-- CPE 匹配表
CREATE TABLE cpe_match (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    cpe_23_uri TEXT NOT NULL,
    version_start_excluding TEXT,
    version_end_excluding TEXT,
    vulnerable INTEGER,
    FOREIGN KEY (cve_id) REFERENCES cve(id)
);

-- EPSS 评分表
CREATE TABLE epss (
    cve_id TEXT PRIMARY KEY,
    epss_score REAL,
    percentile REAL,
    date TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve(id)
);

-- KEV 目录表
CREATE TABLE kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    date_added TEXT,
    required_action TEXT,
    due_date TEXT,
    notes TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve(id)
);
```

### 风险评分公式

```
risk_priority = (cvss_v3 * 5.0) + (epss_score * 30.0) + (is_kev ? 20.0 : 0.0)
```

- CVSS 贡献：最高 50 分 (CVSS 10.0 * 5.0)
- EPSS 贡献：最高 30 分 (EPSS 1.0 * 30.0)
- KEV 奖励：20 分 (如果在 KEV 目录中)
- 最高分：100 分

---

## 发现 4: 实施挑战与解决方案

### SQLite 外键约束

**问题**: EPSS 和 KEV 表有 CVE 外键约束，测试失败

**解决方案**: 测试中先插入 CVE，再插入 EPSS/KEV

```rust
// 先插入 CVE
let cve = CveEntry { id: "CVE-2024-1234".to_string(), ... };
db.insert_cve(&cve).unwrap();

// 再插入 EPSS
let epss = EpssRecord { cve_id: "CVE-2024-1234".to_string(), ... };
db.insert_epss(&epss).unwrap();
```

### CPE 格式验证

**问题**: CPE 必须有 13 个部分

**解决方案**: 解析时验证部分数量

```rust
let parts: Vec<&str> = cpe_str.split(':').collect();
if parts.len() < 13 {
    return Err(VulnError::cpe("expected 13 parts"));
}
```

### rusqlite Connection 不可 Clone

**问题**: VulnDatabase 需要在多个 Engine 之间共享

**解决方案**: 使用引用传递而不是所有权

```rust
// 修改前
pub struct EpssEngine { db: VulnDatabase }

// 修改后
pub struct EpssEngine; // 无状态工具

impl EpssEngine {
    pub fn get_score(db: &VulnDatabase, cve_id: &str) -> Result<...>
}
```

---

## 决策记录

### 决策 1: 漏洞情报工作模式

**选择**: 优先实现离线模式

**理由**:
- 不需要 API 密钥
- 无速率限制
- 更适合本地扫描场景

**延后**: NVD API 在线模式、EPSS/KEV 自动下载

### 决策 2: 风险评分权重

**CVSS 50%**: 基础严重性
**EPSS 30%**: 利用可能性
**KEV 20%**: 实际利用证据

**理由**: CVSS 是基础，但实际利用风险 (EPSS+KEV) 更重要

---

## 测试结果

| Crate | 测试数 | 状态 |
|-------|--------|------|
| rustnmap-core | 47 | ✅ 通过 |
| rustnmap-output | 28 | ✅ 通过 |
| rustnmap-vuln | 31 | ✅ 通过 |
| **总计** | **106** | ✅ 通过 |

---

## 参考链接

- [RETHINK.md](../RETHINK.md) - 2.0 路线图
- [phase0_findings.md](../phase0_findings.md) - Phase 0 详细分析
- [doc/modules/vulnerability.md](../doc/modules/vulnerability.md) - 漏洞情报设计
