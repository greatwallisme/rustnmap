# rustnmap-fingerprint

Service and OS fingerprinting for RustNmap.

## Purpose

Service version detection, OS fingerprinting via TCP/IP stack quirks, and TLS certificate analysis.

## Key Components

### Service Detection

- `ServiceDetector` - Main service detection engine
- `ProbeDatabase` - nmap-service-probes parser
- `MatchRule` - Pattern matching for banners
- `ServiceInfo` - Detected service metadata

### OS Detection

- `OsDetector` - OS fingerprinting engine
- `FingerprintDatabase` - nmap-os-db parser
- `Fingerprint` - TCP/IP stack behavior analysis
- `OsMatch` - OS detection result with confidence

### TLS/SSL Detection

- `TlsDetector` - TLS handshake and certificate parsing
- `CertificateInfo` - X.509 certificate analysis
- `TlsVersion` - SSL/TLS version detection

### Database Updates

- `DatabaseUpdater` - Download latest Nmap databases
- `MacPrefixDatabase` - MAC vendor lookup

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-net | Network operations |
| rustnmap-common | Common types |
| tokio-rustls, rustls | TLS operations |
| x509-parser | Certificate parsing |
| reqwest | Database downloads |
| regex | Pattern matching |

## Testing

```bash
cargo test -p rustnmap-fingerprint
```

## Usage

```rust
use rustnmap_fingerprint::ServiceDetector;

let detector = ServiceDetector::new()
    .with_probes_from_file("nmap-service-probes")?;
let info = detector.detect(target, 80).await?;
```

## Database Files

- `nmap-service-probes` - Service detection probes
- `nmap-os-db` - OS fingerprints
- `nmap-mac-prefixes` - MAC vendor mappings
