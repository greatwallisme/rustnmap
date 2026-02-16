# rustnmap-core

Core scan orchestrator for RustNmap network scanner.

## Purpose

Central orchestration layer that coordinates all scanning phases: discovery, port scanning, service detection, OS detection, and NSE script execution.

## Key Components

### Scan Orchestration

- `ScanOrchestrator` - Main orchestrator coordinating all phases
- `ScanPipeline` - Configurable scan phase pipeline
- `ScanPhase` - Individual scan phases (Discovery, PortScan, ServiceDetect, etc.)

### State Management

- `ScanState` - Current scan state machine
- `ScanProgress` - Progress tracking with percentage
- `HostState` - Per-host scan state
- `PortScanState` - Per-port scan state

### Timing and Congestion Control

- `AdaptiveTiming` - RTT-based rate adjustment
- `CongestionController` - TCP-like congestion control
- `RateLimiter` - Min/max rate enforcement

### Session Context

- `ScanSession` - Dependency injection container
- `ScanConfig` - Complete scan configuration
- `ScanStats` - Runtime statistics

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-net | Network primitives |
| rustnmap-packet | Packet engine |
| rustnmap-target | Target/discovery |
| rustnmap-scan | Port scanning |
| rustnmap-fingerprint | Service/OS detection |
| rustnmap-nse | Script engine |
| rustnmap-traceroute | Route tracing |
| rustnmap-evasion | Evasion techniques |
| rustnmap-output | Output formatting |
| tokio | Async runtime |
| dashmap/papaya | Concurrent hash maps |

## Testing

```bash
cargo test -p rustnmap-core
```

## Usage

```rust
use rustnmap_core::{ScanOrchestrator, ScanConfig};

let config = ScanConfig::new()
    .with_targets("192.168.1.0/24")
    .with_ports("1-1000")
    .with_syn_scan();

let orchestrator = ScanOrchestrator::new(config)?;
let results = orchestrator.run().await?;
```

## Architecture

```
ScanOrchestrator
├── ScanPipeline
│   ├── DiscoveryPhase
│   ├── PortScanPhase
│   ├── ServiceDetectPhase
│   ├── OsDetectPhase
│   └── ScriptPhase
├── ScanState
└── AdaptiveTiming
```
