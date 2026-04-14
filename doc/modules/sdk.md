# Rust SDK Module (rustnmap-sdk)

> **Version**: 2.0.0 (in development)
> **Corresponding Phase**: Phase 5 (Week 12)
> **Priority**: P2

---

## Overview

The Rust SDK provides Rust developers with a stable, high-level API to easily integrate RustNmap's scanning capabilities into their own projects. The SDK uses the Builder pattern, offering a fluent chained-calling experience.

---

## Quick Start

### Basic Scan

```rust
use rustnmap_sdk::{Scanner, ScanResult};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create scanner
    let scanner = Scanner::new()?;

    // Initiate scan
    let result: ScanResult = scanner
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .syn_scan()
        .service_detection(true)
        .run()
        .await?;

    // Process results
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

### Vulnerability Scan

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

    // Output high-risk vulnerabilities
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
/// Scanner builder
pub struct ScannerBuilder {
    targets: Vec<String>,
    ports: Option<String>,
    scan_type: ScanType,
    timing: Timing,
    options: ScanOptions,
}

impl ScannerBuilder {
    /// Set targets
    pub fn targets<T: IntoIterator<Item = S>, S: Into<String>>(mut self, targets: T) -> Self;

    /// Set ports
    pub fn ports<S: Into<String>>(mut self, ports: S) -> Self;

    /// Set port list
    pub fn port_list(mut self, ports: Vec<u16>) -> Self;

    /// SYN scan (requires root)
    pub fn syn_scan(mut self) -> Self;

    /// Connect scan (no root required)
    pub fn connect_scan(mut self) -> Self;

    /// UDP scan
    pub fn udp_scan(mut self) -> Self;

    /// Service detection
    pub fn service_detection(mut self, enable: bool) -> Self;

    /// OS detection
    pub fn os_detection(mut self, enable: bool) -> Self;

    /// Vulnerability scan
    pub fn vulnerability_scan(mut self, options: VulnOptions) -> Self;

    /// Timing template
    pub fn timing(mut self, template: TimingTemplate) -> Self;

    /// Custom timeout
    pub fn timeout(mut self, duration: Duration) -> Self;

    /// Build and execute scan
    pub async fn run(self) -> Result<ScanResult>;
}
```

### ScanOptions

```rust
/// Scan options
pub struct ScanOptions {
    /// Service detection
    pub service_detection: bool,

    /// OS detection
    pub os_detection: bool,

    /// Vulnerability scan options
    pub vuln_options: Option<VulnOptions>,

    /// NSE scripts
    pub scripts: Vec<String>,

    /// traceroute
    pub traceroute: bool,

    /// Custom configuration
    pub custom: HashMap<String, serde_json::Value>,
}

/// Vulnerability scan options
pub struct VulnOptions {
    /// Online-only mode (uses NVD API)
    pub online_only: bool,

    /// EPSS threshold
    pub epss_threshold: f32,

    /// KEV vulnerabilities only
    pub kev_only: bool,
}
```

---

## Result Processing

### ScanResult

```rust
/// Scan result
pub struct ScanResult {
    /// Scan ID
    pub id: String,

    /// Scan status
    pub status: ScanStatus,

    /// Start time
    pub started_at: DateTime<Utc>,

    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,

    /// Host list
    pub hosts: Vec<HostResult>,

    /// Statistics
    pub statistics: ScanStatistics,

    /// Scan configuration
    pub config: ScanConfig,
}

impl ScanResult {
    /// Get all open ports
    pub fn all_open_ports(&self) -> Vec<(&HostResult, &PortResult)>;

    /// Get high-risk hosts (with KEV vulnerabilities or CVSS >= 7.0)
    pub fn high_risk_hosts(&self) -> Vec<&HostResult>;

    /// Filter hosts by service
    pub fn hosts_with_service(&self, service: &str) -> Vec<&HostResult>;

    /// Export as JSON
    pub fn to_json(&self) -> Result<String>;

    /// Export as XML
    pub fn to_xml(&self) -> Result<String>;
}
```

### HostResult

```rust
/// Host result
pub struct HostResult {
    /// IP address
    pub ip: IpAddr,

    /// Hostname
    pub hostname: Option<String>,

    /// MAC address
    pub mac: Option<MacAddr>,

    /// Status
    pub status: HostStatus,

    /// Port list
    pub ports: Vec<PortResult>,

    /// OS match
    pub os: Option<OsMatch>,

    /// Vulnerability list
    pub vulnerabilities: Vec<VulnInfo>,

    /// Traceroute result
    pub traceroute: Option<TracerouteResult>,
}

impl HostResult {
    /// Get open ports
    pub fn open_ports(&self) -> Vec<&PortResult>;

    /// Get high-risk vulnerabilities
    pub fn high_risk_vulnerabilities(&self) -> Vec<&VulnInfo>;

    /// Check if a specific service is present
    pub fn has_service(&self, service: &str) -> bool;
}
```

### PortResult

```rust
/// Port result
pub struct PortResult {
    /// Port number
    pub port: u16,

    /// Protocol
    pub protocol: Protocol,

    /// State
    pub state: PortState,

    /// Service information
    pub service: Option<ServiceInfo>,

    /// Script results
    pub scripts: Vec<ScriptResult>,
}

/// Service information
pub struct ServiceInfo {
    /// Service name
    pub name: String,

    /// Product name
    pub product: Option<String>,

    /// Version number
    pub version: Option<String>,

    /// Extra information
    pub extra_info: Option<String>,

    /// CPE identifiers
    pub cpe: Vec<String>,
}
```

---

## Streaming API

### Progress Subscription

```rust
use rustnmap_sdk::{Scanner, ScanEvent};
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = Scanner::new()?;

    // Create scan task
    let mut scan = scanner
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .syn_scan()
        .create_task()
        .await?;

    // Subscribe to event stream
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

## Configuration Management

### Loading Configuration from File

```rust
use rustnmap_sdk::{Scanner, ScanProfile};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration from YAML file
    let profile = ScanProfile::from_file("scan-profiles/weekly-internal.yaml")?;

    let scanner = Scanner::new()?;
    let result = scanner
        .from_profile(profile)
        .run()
        .await?;

    Ok(())
}
```

### Configuration File Format

```yaml
# scan-profiles/weekly-internal.yaml
name: Weekly Internal Network Scan
description: Weekly internal network security baseline check
targets:
  - 192.168.0.0/16
  - 10.0.0.0/8
exclude:
  - 10.0.0.1  # Gateway, skip
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

## Error Handling

### ScanError

```rust
/// Scan error
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Scan timeout: {0:?}")]
    Timeout(Duration),

    #[error("Scan cancelled: {0}")]
    Cancelled(String),

    #[error("API error: {0}")]
    ApiError(String),
}

// Usage example
async fn run_scan() -> Result<(), ScanError> {
    let scanner = Scanner::new()?;

    // Check privileges
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

## Integration with API

### Remote Scan (via rustnmap-api)

```rust
use rustnmap_sdk::{RemoteScanner, ApiConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Configure remote API
    let config = ApiConfig {
        base_url: "http://localhost:8080".to_string(),
        api_key: "your_api_key".to_string(),
    };

    // Create remote scanner
    let scanner = RemoteScanner::new(config)?;

    // Create scan task
    let task = scanner
        .create_scan()
        .targets(["192.168.1.0/24"])
        .ports("1-1000")
        .submit()
        .await?;

    println!("Scan task created: {}", task.id);

    // Poll status
    loop {
        let status = scanner.get_status(&task.id).await?;
        println!("Progress: {:.1}%", status.progress.percentage);

        if status.status == ScanStatus::Completed {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Get results
    let result = scanner.get_results(&task.id).await?;
    println!("Found {} hosts up", result.statistics.hosts_up);

    Ok(())
}
```

---

## Testing

### Unit Tests

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

        // Verify builder state
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

## Dependencies

```toml
[dependencies]
# Internal dependencies
rustnmap-core = { path = "../rustnmap-core" }
rustnmap-output = { path = "../rustnmap-output" }

# Async
tokio = { version = "1", features = ["full"] }
futures = "0.3"
async-stream = "0.3"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# Utilities
thiserror = "1"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }

# HTTP (remote scan)
reqwest = { version = "0.11", features = ["json"] }
```

---

## Best Practices

### 1. Resource Management

```rust
// Correct: use Result to propagate errors
async fn scan_network(target: &str) -> Result<ScanResult> {
    let scanner = Scanner::new()?;
    let result = scanner
        .targets([target])
        .syn_scan()
        .run()
        .await?;
    Ok(result)
}

// Wrong: ignore errors
async fn bad_scan(target: &str) {
    let scanner = Scanner::new().unwrap();  // May panic
    let _ = scanner.targets([target]).run().await;  // Ignore errors
}
```

### 2. Concurrency Control

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

// Limit concurrent scans
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
            drop(permit);  // Release permit
            Ok::<_, ScanError>(result)
        }
    })
    .collect();

let results = futures::future::join_all(tasks).await;
```

### 3. Result Caching

```rust
use moka::future::Cache;

struct CachedScanner {
    scanner: Scanner,
    cache: Cache<String, ScanResult>,
}

impl CachedScanner {
    async fn scan(&self, target: &str) -> Result<ScanResult> {
        // Check cache
        if let Some(cached) = self.cache.get(target).await {
            return Ok(cached);
        }

        // Execute scan
        let result = self.scanner
            .targets([target])
            .syn_scan()
            .run()
            .await?;

        // Cache result (TTL: 1 hour)
        self.cache.insert(target.to_string(), result.clone()).await;

        Ok(result)
    }
}
```

---

## Alignment with RETHINK.md

| Section | Corresponding Content |
|---------|----------------------|
| 11.2 Library API | Rust SDK Builder API |
| 12.3 Phase 5 | Platform minimal closed loop (Week 12) |
| 13.1 New Crate | rustnmap-sdk |
| 14.3 Phase 4-5 | core as the foundation layer for SDK encapsulation |

---

## Next Steps

1. **Week 12**: Implement ScannerBuilder and core API
2. **Week 12**: Implement ScanResult and result processing
3. **Week 12**: Implement streaming event subscription
4. **Week 12**: Write examples and documentation

---

## Reference Links

- [Builder Pattern in Rust](https://rust-lang.github.io/api-guidelines/type-safety.html#builder-type-constructs-a-many-argument-constructor-c-builder)
- [Tokio Async Programming](https://tokio.rs/tokio/tutorial)
- [Serde Serialization](https://serde.rs/)
