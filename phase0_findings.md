# Phase 0 Findings: Execution Correctness & Observability

**Created**: 2026-02-17
**Status**: Analysis Complete

---

## Analysis of Code Anchors

### 1. Host Discovery Placeholder (orchestrator.rs:388-393)

**Current State**:
```rust
// Host discovery implementation will be integrated with rustnmap-target discovery module
// Initial implementation marks hosts as up to allow scan pipeline progression
let mut state_guard = state.write().await;
let host_state = state_guard.host_state(target.ip);
host_state.status = HostStatus::Up;
host_state.discovery_method = Some("initial".to_string());
```

**Problem**: Host discovery is a no-op that just marks all hosts as "Up" without actual probing.

**Required Fix**: Integrate with `rustnmap-target` discovery module to perform real host discovery using:
- ARP Ping (local network)
- ICMP Echo
- TCP SYN/ACK Ping (ports 80, 443, 22)
- UDP Ping

**Integration Point**: Use `rustnmap_target::discover::HostDiscoverer` for discovery.

---

### 2. scan_types Execution Path (orchestrator.rs:486-559)

**Current State**:
```rust
// Try to create TCP SYN scanner (requires root)
match TcpSynScanner::new(local_addr, scanner_config) {
    Ok(scanner) => {
        // ... always uses TCP SYN regardless of scan_types config
        match scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp) {
            // ...
        }
    }
    Err(_) => {
        // Fallback to TCP Connect
        self.scan_port_connect(target, port).await
    }
}
```

**Problem**: The `scan_types` configuration is ignored. Always performs TCP SYN scan (or Connect fallback).

**Required Fix**: Route to appropriate scanner based on `self.session.config.scan_types`:
- `ScanType::TcpSyn` -> TCP SYN scanner
- `ScanType::TcpConnect` -> TCP Connect scanner
- `ScanType::Udp` -> UDP scanner
- `ScanType::Fin` -> FIN scanner
- `ScanType::Null` -> NULL scanner
- `ScanType::Xmas` -> XMAS scanner
- etc.

**Integration Point**: Use `rustnmap_scan::scanner::ScanExecutor` trait with different scanner implementations.

---

### 3. Scan Metadata Fixed to TcpSyn (orchestrator.rs:1141)

**Current State**:
```rust
let metadata = rustnmap_output::models::ScanMetadata {
    // ...
    scan_type: rustnmap_output::models::ScanType::TcpSyn,  // Always TcpSyn!
    protocol: rustnmap_output::models::Protocol::Tcp,
};
```

**Problem**: Scan type is hardcoded to `TcpSyn` regardless of actual scan performed.

**Required Fix**: Derive scan type from `self.session.config.scan_types`:
```rust
let primary_scan_type = self.session.config.scan_types.first().copied().unwrap_or(ScanType::TcpSyn);
let metadata = rustnmap_output::models::ScanMetadata {
    // ...
    scan_type: match primary_scan_type {
        ScanType::TcpSyn => rustnmap_output::models::ScanType::TcpSyn,
        ScanType::TcpConnect => rustnmap_output::models::ScanType::TcpConnect,
        // ... map all types
    },
    protocol: match primary_scan_type {
        ScanType::Udp => rustnmap_output::models::Protocol::Udp,
        ScanType::Sctp => rustnmap_output::models::Protocol::Sctp,
        _ => rustnmap_output::models::Protocol::Tcp,
    },
};
```

---

### 4. OutputSink Trait Definition (session.rs:130)

**Current State**:
```rust
#[async_trait]
pub trait OutputSink: Send + Sync {
    async fn output_host(&self, result: &HostResult) -> Result<()>;
    async fn output_scan_result(&self, result: &ScanResult) -> Result<()>;
    async fn flush(&self) -> Result<()>;
}
```

**Status**: Trait definition is correct and sufficient.

**Required Integration**: The trait needs a real implementation that:
1. Buffers output for batch writing
2. Supports multiple output formats (normal, XML, JSON, grepable)
3. Supports streaming output (host-by-host)
4. Writes to files specified in output config

---

### 5. DefaultOutputSink Empty Implementation (session.rs:809-817)

**Current State**:
```rust
impl OutputSink for DefaultOutputSink {
    async fn output_host(&self, _result: &HostResult) -> Result<()> {
        // Console output implementation pending integration with output formatters
        Ok(())  // Does nothing!
    }

    async fn output_scan_result(&self, _result: &ScanResult) -> Result<()> {
        // Console output implementation pending integration with output formatters
        Ok(())  // Does nothing!
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}
```

**Problem**: The implementation is a no-op. Results are never output.

**Required Fix**: Integrate with `rustnmap-output` formatters:
```rust
pub struct DefaultOutputSink {
    config: OutputConfig,
    formatter: Box<dyn OutputFormatter>,
    writer: OutputWriter,
}

impl OutputSink for DefaultOutputSink {
    async fn output_host(&self, result: &HostResult) -> Result<()> {
        let formatted = self.formatter.format_host(result)?;
        self.writer.write_host(&formatted).await?;
        if self.config.stream {
            self.writer.flush().await?;
        }
        Ok(())
    }
    // ...
}
```

---

### 6. ResumeStore Minimal Implementation (session.rs:695-706)

**Current State**:
```rust
pub struct ResumeStore {
    #[allow(dead_code)]
    path: std::path::PathBuf,
}

impl ResumeStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}
```

**Problem**: Only stores the path, no actual resume functionality.

**Required Fix**: Implement state save/restore:
```rust
pub struct ResumeStore {
    path: std::path::PathBuf,
}

impl ResumeStore {
    pub fn save(&self, state: &ResumeState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<ResumeState>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&self.path)?;
        let state = serde_json::from_str(&json)?;
        Ok(Some(state))
    }

    pub fn cleanup(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

pub struct ResumeState {
    pub completed_hosts: Vec<IpAddr>,
    pub current_phase: ScanPhase,
    pub scanned_ports: HashMap<IpAddr, Vec<u16>>,
}
```

---

## Phase 0 Implementation Tasks

### Task 0.1: Replace Host Discovery Placeholder
**File**: `crates/rustnmap-core/src/orchestrator.rs`
**Lines**: 388-393
**Action**: Integrate `rustnmap_target::discover::HostDiscoverer`

### Task 0.2: Fix scan_types Execution Path
**File**: `crates/rustnmap-core/src/orchestrator.rs`
**Lines**: 486-559
**Action**: Route to appropriate scanner based on `config.scan_types`

### Task 0.3: Fix Scan Metadata
**File**: `crates/rustnmap-core/src/orchestrator.rs`
**Line**: 1141
**Action**: Derive scan type from config

### Task 0.4: Implement OutputSink Integration
**File**: `crates/rustnmap-core/src/session.rs`
**Lines**: 809-817
**Action**: Integrate with `rustnmap-output` formatters

### Task 0.5: Implement ResumeStore
**File**: `crates/rustnmap-core/src/session.rs`
**Lines**: 695-706
**Action**: Add save/load/cleanup methods with `ResumeState` struct

---

## Dependencies

| Crate | Purpose | Status |
|-------|---------|--------|
| rustnmap-target | Host discovery | Available |
| rustnmap-scan | Port scanners | Available |
| rustnmap-output | Output formatters | Available |
| rustnmap-common | Common types | Available |
| serde_json | Resume state serialization | In workspace deps |
| tokio | Async runtime | In workspace deps |

---

## Testing Strategy

1. **Unit Tests**: Test individual components (scanner routing, output formatting)
2. **Integration Tests**: Test full scan pipeline with different scan types
3. **Manual Tests**: Run actual scans against test hosts

```bash
# Build and test
cargo test -p rustnmap-core

# Run integration test
cargo test -p rustnmap-core --test integration_scan

# Manual scan test (requires sudo)
sudo cargo run -- -sS -p 1-100 192.168.1.1
```

---

## Success Criteria

1. [ ] Host discovery performs real probing (not just marking hosts as up)
2. [ ] `scan_types` config correctly routes to appropriate scanners
3. [ ] Scan metadata reflects actual scan type performed
4. [ ] Output is actually written (not no-op)
5. [ ] Resume/restore works for interrupted scans
6. [ ] All existing tests still pass
7. [ ] Zero clippy warnings
