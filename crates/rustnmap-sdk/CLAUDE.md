# rustnmap-sdk

Builder API for programmatic RustNmap usage.

## Purpose

Provides a Rust SDK with builder-pattern API for running scans programmatically. Supports both local scanning (direct engine) and remote scanning (via rustnmap-api REST server).

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `ScanBuilder` | `builder.rs` | Builder pattern for scan configuration |
| `RemoteClient` | `remote.rs` | Client for rustnmap-api REST server |
| `Profile` | `profile.rs` | Reusable scan profile definitions |
| `SdkModels` | `models.rs` | SDK-specific result types |

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-core | Scan orchestration |
| rustnmap-output | Output formatting |
| rustnmap-target | Target parsing |
| rustnmap-evasion | Evasion config |
| rustnmap-common | Common types |
| reqwest | Remote API client |

## Testing

```bash
cargo test -p rustnmap-sdk
```

## Usage

```rust
use rustnmap_sdk::ScanBuilder;

let results = ScanBuilder::new()
    .targets("192.168.1.0/24")
    .ports("22,80,443")
    .syn_scan()
    .service_detection()
    .run()
    .await?;
```
