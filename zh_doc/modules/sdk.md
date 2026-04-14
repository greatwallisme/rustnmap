# Rust SDK 模块 (rustnmap-sdk)

> **版本**: 2.0.0 (开发中)
> **对应 Phase**: Phase 5 (Week 12)
> **优先级**: P2

---

## 概述

Rust SDK 为 Rust 开发者提供稳定、高层次的 API，使其能够在自己的项目中轻松集成 RustNmap 的扫描能力。SDK 采用 Builder 模式，提供流畅的链式调用体验。

---

## 快速开始

### 基本扫描

```rust
use rustnmap_sdk::{Scanner, ScanResult};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // 创建扫描器
    let scanner = Scanner::new()?;

    // 发起扫描
    let result: ScanResult = scanner
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .syn_scan()
        .service_detection(true)
        .run()
        .await?;

    // 处理结果
    for host in &result.hosts {
        println!("{}: {} open ports", host.ip, host.ports.len());
        for port in &host.ports {
            if port.state == "open" {
                println!("  Port {}: {}", port.port, port.service.as_ref().map(|s| &s.name).unwrap_or(&"unknown".to_string()));
            }
        }
    }

    Ok(())
}
```

### 漏洞扫描

```rust
use rustnmap_sdk::{Scanner, VulnOptions};

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = Scanner::new()?;

    let result = scanner
        .targets(["192.168.1.1"])
        .ports("1-65535")
        .syn_scan()
        .service_detection(true)
        .vulnerability_scan(VulnOptions::default())
        .run()
        .await?;

    // 输出高危漏洞
    for host in &result.hosts {
        for vuln in host.high_risk_vulnerabilities() {
            println!("{}: {} (CVSS {}, KEV: {})",
                host.ip, vuln.cve_id, vuln.cvss_v3, vuln.is_kev);
        }
    }

    Ok(())
}
```

---

## Builder API

### ScannerBuilder

```rust
/// 扫描器构建器
pub struct ScannerBuilder {
    targets: Vec<String>,
    ports: Option<String>,
    scan_type: ScanType,
    timing: Timing,
    options: ScanOptions,
}

impl ScannerBuilder {
    /// 设置目标
    pub fn targets<T: IntoIterator<Item = S>, S: Into<String>>(mut self, targets: T) -> Self;

    /// 设置端口
    pub fn ports<S: Into<String>>(mut self, ports: S) -> Self;

    /// 设置端口列表
    pub fn port_list(mut self, ports: Vec<u16>) -> Self;

    /// SYN 扫描 (需要 root)
    pub fn syn_scan(mut self) -> Self;

    /// Connect 扫描 (无需 root)
    pub fn connect_scan(mut self) -> Self;

    /// UDP 扫描
    pub fn udp_scan(mut self) -> Self;

    /// 服务检测
    pub fn service_detection(mut self, enable: bool) -> Self;

    /// OS 检测
    pub fn os_detection(mut self, enable: bool) -> Self;

    /// 漏洞扫描
    pub fn vulnerability_scan(mut self, options: VulnOptions) -> Self;

    /// 时序模板
    pub fn timing(mut self, template: TimingTemplate) -> Self;

    /// 自定义超时
    pub fn timeout(mut self, duration: Duration) -> Self;

    /// 构建并执行扫描
    pub async fn run(self) -> Result<ScanResult>;
}
```

### ScanOptions

```rust
/// 扫描选项
pub struct ScanOptions {
    /// 服务检测
    pub service_detection: bool,

    /// OS 检测
    pub os_detection: bool,

    /// 漏洞扫描选项
    pub vuln_options: Option<VulnOptions>,

    /// NSE 脚本
    pub scripts: Vec<String>,

    /// traceroute
    pub traceroute: bool,

    /// 自定义配置
    pub custom: HashMap<String, serde_json::Value>,
}

/// 漏洞扫描选项
pub struct VulnOptions {
    /// 仅在线模式 (使用 NVD API)
    pub online_only: bool,

    /// EPSS 阈值
    pub epss_threshold: f32,

    /// 仅 KEV 漏洞
    pub kev_only: bool,
}
```

---

## 结果处理

### ScanResult

```rust
/// 扫描结果
pub struct ScanResult {
    /// 扫描 ID
    pub id: String,

    /// 扫描状态
    pub status: ScanStatus,

    /// 开始时间
    pub started_at: DateTime<Utc>,

    /// 结束时间
    pub completed_at: Option<DateTime<Utc>>,

    /// 主机列表
    pub hosts: Vec<HostResult>,

    /// 统计信息
    pub statistics: ScanStatistics,

    /// 扫描配置
    pub config: ScanConfig,
}

impl ScanResult {
    /// 获取所有开放端口
    pub fn all_open_ports(&self) -> Vec<(&HostResult, &PortResult)>;

    /// 获取高危主机 (有 KEV 漏洞或 CVSS >= 7.0)
    pub fn high_risk_hosts(&self) -> Vec<&HostResult>;

    /// 按服务过滤主机
    pub fn hosts_with_service(&self, service: &str) -> Vec<&HostResult>;

    /// 导出为 JSON
    pub fn to_json(&self) -> Result<String>;

    /// 导出为 XML
    pub fn to_xml(&self) -> Result<String>;
}
```

### HostResult

```rust
/// 主机结果
pub struct HostResult {
    /// IP 地址
    pub ip: IpAddr,

    /// 主机名
    pub hostname: Option<String>,

    /// MAC 地址
    pub mac: Option<MacAddr>,

    /// 状态
    pub status: HostStatus,

    /// 端口列表
    pub ports: Vec<PortResult>,

    /// OS 匹配
    pub os: Option<OsMatch>,

    /// 漏洞列表
    pub vulnerabilities: Vec<VulnInfo>,

    /// Traceroute 结果
    pub traceroute: Option<TracerouteResult>,
}

impl HostResult {
    /// 获取开放端口
    pub fn open_ports(&self) -> Vec<&PortResult>;

    /// 获取高危漏洞
    pub fn high_risk_vulnerabilities(&self) -> Vec<&VulnInfo>;

    /// 判断是否有指定服务
    pub fn has_service(&self, service: &str) -> bool;
}
```

### PortResult

```rust
/// 端口结果
pub struct PortResult {
    /// 端口号
    pub port: u16,

    /// 协议
    pub protocol: Protocol,

    /// 状态
    pub state: PortState,

    /// 服务信息
    pub service: Option<ServiceInfo>,

    /// 脚本结果
    pub scripts: Vec<ScriptResult>,
}

/// 服务信息
pub struct ServiceInfo {
    /// 服务名称
    pub name: String,

    /// 产品名称
    pub product: Option<String>,

    /// 版本号
    pub version: Option<String>,

    /// 额外信息
    pub extra_info: Option<String>,

    /// CPE 标识符
    pub cpe: Vec<String>,
}
```

---

## 流式 API

### 进度订阅

```rust
use rustnmap_sdk::{Scanner, ScanEvent};
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = Scanner::new()?;

    // 创建扫描任务
    let mut scan = scanner
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .syn_scan()
        .create_task()
        .await?;

    // 订阅事件流
    let mut events = scan.events();

    while let Some(event) = events.next().await {
        match event {
            ScanEvent::Progress { completed, total, percentage } => {
                println!("Progress: {}/{} ({:.1}%)", completed, total, percentage);
            }
            ScanEvent::HostFound(host) => {
                println!("Host found: {}", host.ip);
            }
            ScanEvent::PortFound(port) => {
                println!("  Port {}: {}", port.port, port.state);
            }
            ScanEvent::Vulnerability(vuln) => {
                println!("  [!] Vulnerability: {} (CVSS {})", vuln.cve_id, vuln.cvss_v3);
            }
            ScanEvent::Completed(result) => {
                println!("Scan completed: {} hosts up", result.hosts.iter().filter(|h| h.status == HostStatus::Up).count());
                break;
            }
            ScanEvent::Error(e) => {
                eprintln!("Scan error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
```

---

## 配置管理

### 从文件加载配置

```rust
use rustnmap_sdk::{Scanner, ScanProfile};

#[tokio::main]
async fn main() -> Result<()> {
    // 从 YAML 文件加载配置
    let profile = ScanProfile::from_file("scan-profiles/weekly-internal.yaml")?;

    let scanner = Scanner::new()?;
    let result = scanner
        .from_profile(profile)
        .run()
        .await?;

    Ok(())
}
```

### 配置文件格式

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
```

---

## 错误处理

### ScanError

```rust
/// 扫描错误
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("无效的目标：{0}")]
    InvalidTarget(String),

    #[error("权限不足：{0}")]
    PermissionDenied(String),

    #[error("网络错误：{0}")]
    NetworkError(#[from] std::io::Error),

    #[error("扫描超时：{0:?}")]
    Timeout(Duration),

    #[error("扫描被取消：{0}")]
    Cancelled(String),

    #[error("API 错误：{0}")]
    ApiError(String),
}

// 使用示例
async fn run_scan() -> Result<(), ScanError> {
    let scanner = Scanner::new()?;

    // 检查权限
    if !scanner.has_required_privileges() {
        return Err(ScanError::PermissionDenied(
            "SYN scan requires root privileges".to_string()
        ));
    }

    let result = scanner
        .targets(["192.168.1.1"])
        .syn_scan()
        .run()
        .await?;

    Ok(())
}
```

---

## 与 API 集成

### 远程扫描 (通过 rustnmap-api)

```rust
use rustnmap_sdk::{RemoteScanner, ApiConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // 配置远程 API
    let config = ApiConfig {
        base_url: "http://localhost:8080".to_string(),
        api_key: "your_api_key".to_string(),
    };

    // 创建远程扫描器
    let scanner = RemoteScanner::new(config)?;

    // 创建扫描任务
    let task = scanner
        .create_scan()
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .submit()
        .await?;

    println!("Scan task created: {}", task.id);

    // 轮询状态
    loop {
        let status = scanner.get_status(&task.id).await?;
        println!("Progress: {:.1}%", status.progress.percentage);

        if status.status == ScanStatus::Completed {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // 获取结果
    let result = scanner.get_results(&task.id).await?;
    println!("Found {} hosts up", result.statistics.hosts_up);

    Ok(())
}
```

---

## 测试

### 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_builder() {
        let scanner = Scanner::new().unwrap();
        let builder = scanner
            .targets(["127.0.0.1"])
            .ports("22,80")
            .syn_scan();

        // 验证构建器状态
        assert_eq!(builder.targets, vec!["127.0.0.1"]);
        assert_eq!(builder.ports, Some("22,80".to_string()));
        assert_eq!(builder.scan_type, ScanType::Syn);
    }

    #[tokio::test]
    async fn test_scan_result_serialization() {
        let result = ScanResult::mock();
        let json = result.to_json().unwrap();

        assert!(json.contains("\"hosts\""));
        assert!(json.contains("\"statistics\""));
    }
}
```

---

## 依赖关系

```toml
[dependencies]
# 内部依赖
rustnmap-core = { path = "../rustnmap-core" }
rustnmap-output = { path = "../rustnmap-output" }

# 异步
tokio = { version = "1", features = ["full"] }
futures = "0.3"
async-stream = "0.3"

# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# 工具
thiserror = "1"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }

# HTTP (远程扫描)
reqwest = { version = "0.11", features = ["json"] }
```

---

## 最佳实践

### 1. 资源管理

```rust
// 正确：使用 Result 传播错误
async fn scan_network(target: &str) -> Result<ScanResult> {
    let scanner = Scanner::new()?;
    let result = scanner
        .targets([target])
        .syn_scan()
        .run()
        .await?;
    Ok(result)
}

// 错误：忽略错误
async fn bad_scan(target: &str) {
    let scanner = Scanner::new().unwrap();  // 可能 panic
    let _ = scanner.targets([target]).run().await;  // 忽略错误
}
```

### 2. 并发控制

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

// 限制并发扫描数
let semaphore = Arc::new(Semaphore::new(3));

let tasks: Vec<_> = targets
    .iter()
    .map(|target| {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        async move {
            let result = Scanner::new()?
                .targets([target])
                .syn_scan()
                .run()
                .await?;
            drop(permit);  // 释放许可证
            Ok::<_, ScanError>(result)
        }
    })
    .collect();

let results = futures::future::join_all(tasks).await;
```

### 3. 结果缓存

```rust
use moka::future::Cache;

struct CachedScanner {
    scanner: Scanner,
    cache: Cache<String, ScanResult>,
}

impl CachedScanner {
    async fn scan(&self, target: &str) -> Result<ScanResult> {
        // 检查缓存
        if let Some(cached) = self.cache.get(target).await {
            return Ok(cached);
        }

        // 执行扫描
        let result = self.scanner
            .targets([target])
            .syn_scan()
            .run()
            .await?;

        // 缓存结果 (TTL: 1 小时)
        self.cache.insert(target.to_string(), result.clone()).await;

        Ok(result)
    }
}
```

---

## 与 RETHINK.md 对齐

| 章节 | 对应内容 |
|------|---------|
| 11.2 Library API | Rust SDK Builder API |
| 12.3 Phase 5 | 平台化最小闭环（Week 12） |
| 13.1 新增 Crate | rustnmap-sdk |
| 14.3 Phase 4-5 | core 作为 SDK 的封装基座 |

---

## 下一步

1. **Week 12**: 实现 ScannerBuilder 和核心 API
2. **Week 12**: 实现 ScanResult 和结果处理
3. **Week 12**: 实现流式事件订阅
4. **Week 12**: 编写示例和文档

---

## 参考链接

- [Builder Pattern in Rust](https://rust-lang.github.io/api-guidelines/type-safety.html#builder-type-constructs-a-many-argument-constructor-c-builder)
- [Tokio Async Programming](https://tokio.rs/tokio/tutorial)
- [Serde Serialization](https://serde.rs/)
