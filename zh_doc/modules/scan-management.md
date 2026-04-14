# 扫描管理模块 (rustnmap-scan-management)

> **版本**: 2.0.0 (开发中)
> **对应 Phase**: Phase 3 (Week 8-9)
> **优先级**: P1

---

## 概述

扫描管理模块提供扫描结果的持久化存储、历史查询、结果对比（Diff）和配置文件管理功能。这是 RustNmap 2.0 从一次性扫描工具升级为持续性安全监控平台的关键组件。

---

## 功能特性

### 1. 扫描结果持久化

- 使用 SQLite 存储历史扫描结果
- 支持按时间、目标、扫描类型查询
- 自动清理过期数据（可选）

### 2. 扫描结果 Diff

- 对比两次扫描结果的差异
- 识别新增主机、消失主机
- 识别端口变化、服务版本变化
- 识别新增漏洞

### 3. 扫描历史查询

- 按时间范围查询
- 按目标查询
- 按扫描类型查询
- 导出历史记录

### 4. 配置即代码 (YAML Profiles)

- YAML 格式配置文件
- 支持继承和覆盖
- 版本控制和复用

---

## 数据库设计

### Schema

```sql
-- 扫描任务表
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    command_line TEXT,
    target_spec TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    options_json TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    created_by TEXT,
    profile_name TEXT
);

-- 主机结果表
CREATE TABLE IF NOT EXISTS host_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    ip_addr TEXT NOT NULL,
    hostname TEXT,
    mac_addr TEXT,
    status TEXT NOT NULL,
    os_match TEXT,
    os_accuracy INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    UNIQUE(scan_id, ip_addr)
);

-- 端口结果表
CREATE TABLE IF NOT EXISTS port_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    service_version TEXT,
    cpe TEXT,
    reason TEXT,
    FOREIGN KEY (host_id) REFERENCES host_results(id),
    UNIQUE(host_id, port, protocol)
);

-- 漏洞结果表
CREATE TABLE IF NOT EXISTS vulnerability_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    cvss_v3 REAL,
    epss_score REAL,
    is_kev BOOLEAN DEFAULT FALSE,
    affected_cpe TEXT,
    FOREIGN KEY (host_id) REFERENCES host_results(id)
);

-- 索引
CREATE INDEX idx_scans_started_at ON scans(started_at);
CREATE INDEX idx_scans_target ON scans(target_spec);
CREATE INDEX idx_host_results_ip ON host_results(ip_addr);
CREATE INDEX idx_port_results_state ON port_results(state);
CREATE INDEX idx_vulnerability_cve ON vulnerability_results(cve_id);
CREATE INDEX idx_vulnerability_kev ON vulnerability_results(is_kev);
```

---

## 核心 API

### ScanHistory (历史查询)

```rust
/// 扫描历史管理器
pub struct ScanHistory {
    db: Arc<SqliteConnection>,
}

impl ScanHistory {
    /// 打开或创建数据库
    pub async fn open(db_path: &Path) -> Result<Self>;

    /// 保存扫描结果
    pub async fn save_scan(&self, result: &ScanResult) -> Result<String>;

    /// 查询扫描列表
    pub async fn list_scans(&self, filter: ScanFilter) -> Result<Vec<ScanSummary>>;

    /// 获取扫描详情
    pub async fn get_scan(&self, id: &str) -> Result<ScanResult>;

    /// 获取目标的历史扫描
    pub async fn get_target_history(&self, target: &str) -> Result<Vec<ScanSummary>>;

    /// 删除过期扫描
    pub async fn prune_old_scans(&self, retention_days: u32) -> Result<usize>;
}

/// 扫描过滤器
pub struct ScanFilter {
    /// 时间范围开始
    pub since: Option<DateTime<Utc>>,

    /// 时间范围结束
    pub until: Option<DateTime<Utc>>,

    /// 目标过滤
    pub target: Option<String>,

    /// 扫描类型过滤
    pub scan_type: Option<ScanType>,

    /// 状态过滤
    pub status: Option<ScanStatus>,

    /// 每页数量
    pub limit: Option<usize>,

    /// 偏移量
    pub offset: Option<usize>,
}
```

### ScanDiff (结果对比)

```rust
/// 扫描对比工具
pub struct ScanDiff {
    before: ScanResult,
    after: ScanResult,
}

impl ScanDiff {
    /// 创建对比
    pub fn new(before: ScanResult, after: ScanResult) -> Self;

    /// 从数据库加载并对比
    pub async fn from_history(
        history: &ScanHistory,
        before_id: &str,
        after_id: &str
    ) -> Result<Self>;

    /// 获取主机变化
    pub fn host_changes(&self) -> HostChanges;

    /// 获取端口变化
    pub fn port_changes(&self) -> PortChanges;

    /// 获取漏洞变化
    pub fn vulnerability_changes(&self) -> VulnerabilityChanges;

    /// 生成对比报告
    pub fn generate_report(&self, format: DiffFormat) -> String;
}

/// 主机变化
pub struct HostChanges {
    /// 新增主机
    pub added: Vec<IpAddr>,

    /// 消失主机
    pub removed: Vec<IpAddr>,

    /// 状态变化的主机
    pub status_changed: Vec<HostStatusChange>,
}

/// 端口变化
pub struct PortChanges {
    /// 每个主机的端口变化
    pub by_host: HashMap<IpAddr, HostPortChanges>,
}

pub struct HostPortChanges {
    /// 新增端口
    pub added: Vec<PortChange>,

    /// 关闭端口
    pub removed: Vec<PortChange>,

    /// 状态变化的端口
    pub state_changed: Vec<PortChange>,

    /// 服务版本变化的端口
    pub service_changed: Vec<PortChange>,
}

/// 漏洞变化
pub struct VulnerabilityChanges {
    /// 新增漏洞
    pub added: Vec<VulnChange>,

    /// 修复漏洞
    pub fixed: Vec<VulnChange>,

    /// 风险变化的漏洞
    pub risk_changed: Vec<VulnChange>,
}
```

### ScanProfile (配置管理)

```rust
/// 扫描配置模板
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanProfile {
    /// 配置名称
    pub name: String,

    /// 配置描述
    pub description: Option<String>,

    /// 目标列表
    pub targets: Vec<String>,

    /// 排除目标
    #[serde(default)]
    pub exclude: Vec<String>,

    /// 扫描配置
    pub scan: ScanConfig,

    /// 输出配置
    pub output: OutputConfig,

    /// 继承的配置文件
    #[serde(rename = "extends")]
    pub extends_from: Option<String>,
}

/// 扫描配置
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanConfig {
    /// 扫描类型
    #[serde(rename = "type")]
    pub scan_type: String,

    /// 端口范围
    pub ports: Option<String>,

    /// 服务检测
    #[serde(default)]
    pub service_detection: bool,

    /// OS 检测
    #[serde(default)]
    pub os_detection: bool,

    /// NSE 脚本
    #[serde(default)]
    pub scripts: Vec<String>,

    /// 漏洞扫描
    #[serde(default)]
    pub vulnerability_scan: bool,

    /// 时序模板
    #[serde(default = "default_timing")]
    pub timing: String,
}

impl ScanProfile {
    /// 从文件加载
    pub fn from_file(path: &Path) -> Result<Self>;

    /// 保存到文件
    pub fn save(&self, path: &Path) -> Result<()>;

    /// 从字符串解析
    pub fn from_yaml(yaml: &str) -> Result<Self>;

    /// 验证配置
    pub fn validate(&self) -> Result<()>;

    /// 应用默认值
    pub fn with_defaults(mut self) -> Self;
}
```

---

## CLI 选项

### 历史查询

```bash
# 列出所有扫描
rustnmap --history

# 列出最近的扫描
rustnmap --history --limit 10

# 按时间范围查询
rustnmap --history --since 2026-01-01 --until 2026-02-01

# 按目标查询
rustnmap --history --target 192.168.1.10

# 查看扫描详情
rustnmap --history --scan-id scan_001
```

### 扫描对比

```bash
# 对比两次扫描
rustnmap --diff scan_20240101.xml scan_20240201.xml

# 从数据库对比
rustnmap --diff --from-history scan_001 scan_002

# 生成详细报告
rustnmap --diff scan_001 scan_002 --format markdown --output diff.md

# 仅显示漏洞变化
rustnmap --diff scan_001 scan_002 --vulns-only
```

### 配置文件

```bash
# 使用配置文件扫描
rustnmap --profile scan-profiles/weekly-internal.yaml

# 列出可用配置
rustnmap --list-profiles

# 验证配置文件
rustnmap --validate-profile scan-profiles/weekly-internal.yaml

# 创建配置模板
rustnmap --generate-profile > my-scan.yaml
```

---

## 使用示例

### 保存扫描结果

```rust
use rustnmap_sdk::{Scanner, ScanHistory};

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = Scanner::new()?;

    // 执行扫描
    let result = scanner
        .targets(["192.168.1.0/24"])
        .syn_scan()
        .service_detection(true)
        .run()
        .await?;

    // 保存到数据库
    let history = ScanHistory::open("~/.rustnmap/scans.db").await?;
    let scan_id = history.save_scan(&result).await?;

    println!("Scan saved with ID: {}", scan_id);

    Ok(())
}
```

### 对比扫描结果

```rust
use rustnmap_sdk::{ScanHistory, ScanDiff, DiffFormat};

#[tokio::main]
async fn main() -> Result<()> {
    let history = ScanHistory::open("~/.rustnmap/scans.db").await?;

    // 获取最近两次扫描
    let scans = history.list_scans(ScanFilter {
        target: Some("192.168.1.0/24".to_string()),
        limit: Some(2),
        ..Default::default()
    }).await?;

    if scans.len() < 2 {
        println!("Need at least 2 scans for comparison");
        return Ok(());
    }

    // 加载并对比
    let before = history.get_scan(&scans[1].id).await?;
    let after = history.get_scan(&scans[0].id).await?;

    let diff = ScanDiff::new(before, after);

    // 输出对比报告
    let host_changes = diff.host_changes();
    println!("=== Host Changes ===");
    println!("Added: {:?}", host_changes.added);
    println!("Removed: {:?}", host_changes.removed);

    let vuln_changes = diff.vulnerability_changes();
    println!("\n=== Vulnerability Changes ===");
    println!("New vulnerabilities: {}", vuln_changes.added.len());
    for vuln in &vuln_changes.added {
        println!("  - {} (CVSS {})", vuln.cve_id, vuln.new_cvss);
    }

    Ok(())
}
```

### 使用配置文件

```rust
use rustnmap_sdk::{Scanner, ScanProfile};

#[tokio::main]
async fn main() -> Result<()> {
    // 加载配置文件
    let profile = ScanProfile::from_file("scan-profiles/weekly-internal.yaml")?;

    // 验证配置
    profile.validate()?;

    // 执行扫描
    let scanner = Scanner::new()?;
    let result = scanner
        .from_profile(profile)
        .run()
        .await?;

    println!("Scan completed: {} hosts up", result.statistics.hosts_up);

    Ok(())
}
```

---

## 配置文件示例

### 内网周扫描

```yaml
# scan-profiles/weekly-internal.yaml
name: 内网周扫描
description: 每周内网安全基线检查
targets:
  - 192.168.0.0/16
  - 10.0.0.0/8
exclude:
  - 10.0.0.1  # 网关，跳过
scan:
  type: syn
  ports: "1-10000"
  service_detection: true
  os_detection: true
  scripts: ["default", "vuln"]
  timing: T3
output:
  formats: [json, html, sarif]
  directory: /var/lib/rustnmap/reports/
  save_to_history: true
```

### 快速端口扫描

```yaml
# scan-profiles/quick-scan.yaml
name: 快速扫描
description: 快速检查常见端口
targets: []  # 从命令行指定
scan:
  type: syn
  ports: "21,22,23,25,80,443,3306,3389,5432,8080"
  service_detection: false
  os_detection: false
  timing: T4
output:
  formats: [normal]
```

### 全面漏洞扫描

```yaml
# scan-profiles/full-vuln-scan.yaml
name: 全面漏洞扫描
description: 完整的漏洞检测扫描
targets: []  # 从命令行指定
scan:
  type: syn
  ports: "1-65535"
  service_detection: true
  version_intensity: 7
  os_detection: true
  scripts:
    - default
    - vuln
    - exploit
  vulnerability_scan: true
  epss_threshold: 0.3
  timing: T3
output:
  formats: [json, sarif, html]
  save_to_history: true
```

---

## 对比报告格式

### Markdown 格式示例

```markdown
# 扫描结果对比报告

**对比**: scan_20240101 -> scan_20240201
**生成时间**: 2026-02-17

## 主机变化

### 新增主机 (2)
- 192.168.1.50 (首次发现)
- 192.168.1.51 (首次发现)

### 消失主机 (1)
- 192.168.1.30 (上次在线，本次未响应)

## 端口变化

### 192.168.1.10
- 新增端口: 8443/tcp (open)
- 服务变更: 80/tcp (nginx 1.18.0 -> nginx 1.24.0)

### 192.168.1.15
- 关闭端口: 21/tcp (closed)

## 漏洞变化

### 新增漏洞 (1)
- CVE-2024-XXXXX (CVSS 8.1) - 192.168.1.10

## 统计

| 指标 | 上次 | 本次 | 变化 |
|------|------|------|------|
| 在线主机 | 45 | 46 | +1 |
| 开放端口 | 123 | 124 | +1 |
| 高危漏洞 | 5 | 6 | +1 |
```

---

## 性能优化

### 批量插入

```rust
/// 批量保存扫描结果（事务处理）
pub async fn save_scan_batch(&self, result: &ScanResult) -> Result<String> {
    let mut tx = self.db.begin().await?;

    // 保存扫描元数据
    let scan_id = save_scan_metadata(&mut tx, result).await?;

    // 批量保存主机
    for host in &result.hosts {
        let host_id = save_host(&mut tx, scan_id, host).await?;

        // 批量保存端口
        save_ports_batch(&mut tx, host_id, &host.ports).await?;

        // 批量保存漏洞
        save_vulnerabilities_batch(&mut tx, host_id, &host.vulnerabilities).await?;
    }

    tx.commit().await?;
    Ok(scan_id)
}
```

### 查询优化

```sql
-- 使用覆盖索引
CREATE INDEX idx_port_results_covering
ON port_results(host_id, state, port, protocol);

-- 使用物化视图（SQLite 用表模拟）
CREATE TABLE IF NOT EXISTS mv_host_summary AS
SELECT
    scan_id,
    ip_addr,
    COUNT(*) as port_count,
    SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_port_count
FROM host_results
JOIN port_results ON host_results.id = port_results.host_id
GROUP BY scan_id, ip_addr;
```

---

## 与 RETHINK.md 对齐

| 章节 | 对应内容 |
|------|---------|
| 9.2.1 扫描 Diff | 结果对比功能 |
| 9.2.2 结果持久化 | SQLite 存储 |
| 9.2.4 配置即代码 | YAML Profiles |
| 12.3 Phase 3 | 扫描管理能力（Week 8-9） |
| 14.2 Phase 1-3 | OutputSink 与持久化集成 |

---

## 下一步

1. **Week 8**: 实现 SQLite 数据库 Schema 和保存逻辑
2. **Week 8**: 实现历史查询 API
3. **Week 9**: 实现 Diff 引擎和报告生成
4. **Week 9**: 实现 YAML Profile 解析和验证

---

## 参考链接

- [SQLite 文档](https://www.sqlite.org/docs.html)
- [Serde YAML](https://docs.rs/serde_yaml)
- [SQLx (可选替代)](https://docs.rs/sqlx)
