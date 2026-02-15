# Findings: Phase 4 SSL/TLS Detection Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Created**: 2026-02-14
> **Purpose**: SSL/TLS detection and certificate parsing implementation

---

## Overview

TLS/SSL detection module provides comprehensive analysis of encrypted connections, including version detection, cipher suite identification, and X.509 certificate parsing.

## TLS Detection Features

### 1. TLS Version Detection

Supported TLS versions:
- SSL 3.0
- TLS 1.0
- TLS 1.1
- TLS 1.2
- TLS 1.3

Detection is performed by attempting handshake with highest version and observing negotiated version via rustls.

### 2. Certificate Parsing

Extracted certificate information:
- **Subject**: Certificate subject name (CN, O, OU, etc.)
- **Issuer**: Certificate issuer name
- **Serial Number**: Certificate serial number as hex string
- **Subject Alternative Names (SANs)**: DNS names and IP addresses
- **Validity Period**: Not before/after timestamps
- **Signature Algorithm**: OID of signature algorithm
- **Public Key Info**: Algorithm identifier
- **SHA-256 Fingerprint**: Certificate fingerprint

### 3. Security Indicators

- **Self-signed detection**: Subject == Issuer comparison
- **Expiry detection**: Current time vs not_after comparison
- **Days until expiry**: Calculated from validity period
- **Chain depth**: Number of certificates in chain

### 4. ALPN Protocol Detection

Detects application-layer protocols negotiated via ALPN:
- h2 (HTTP/2)
- http/1.1
- Other custom protocols

## Implementation Details

### Dependencies

| Crate | Purpose |
|-------|---------|
| tokio-rustls | Async TLS connections |
| rustls | TLS implementation |
| x509-parser | X.509 certificate parsing |
| ring | SHA-256 fingerprint calculation |

### Architecture

```rust
pub struct TlsDetector {
    timeout: Duration,
    verify_certificates: bool,
}

pub struct TlsInfo {
    version: TlsVersion,
    cipher_suite: String,
    certificate: Option<CertificateInfo>,
    chain_depth: usize,
    alpn_protocol: Option<String>,
    is_self_signed: bool,
    is_expired: bool,
    days_until_expiry: Option<i64>,
}
```

### Common TLS Ports

The detector includes a helper for common TLS ports:
- 443: HTTPS
- 465: SMTPS
- 636: LDAPS
- 993: IMAPS
- 995: POP3S
- 3389: RDP
- 8443: HTTPS Alternate
- 990-994: Various SSL services

## Certificate Parsing

### X.509 Parsing with x509-parser

```rust
match X509Certificate::from_der(cert_der) {
    Ok((_, cert)) => {
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        // ... extract other fields
    }
}
```

### SAN Extraction

Subject Alternative Names are extracted from the certificate extensions:
- DNSName entries → domain names
- IPAddress entries → IP addresses

### Fingerprint Calculation

SHA-256 fingerprint calculated using ring crate:
```rust
let hash = ring::digest::digest(&ring::digest::SHA256, cert_der);
```

## Testing

| Test | Description |
|------|-------------|
| test_tls_info_new | Basic TLS info creation |
| test_tls_version_display | Version formatting |
| test_tls_detector_new | Detector configuration |
| test_is_tls_port | Common port detection |
| test_tls_info_builder | Builder pattern |

## Security Considerations

1. **Certificate Verification Disabled**: The detector uses a custom certificate verifier that accepts all certificates (for fingerprinting purposes only)
2. **No Certificate Pinning**: The detector does not verify certificate chains against trust stores
3. **Information Gathering Only**: All TLS data is for service identification, not security validation

## Future Enhancements

- Certificate transparency log checking
- Weak cipher suite detection
- SSL/TLS vulnerability scanning (Heartbleed, POODLE, etc.)
- Certificate chain validation
- OCSP stapling detection

---

## Reference

- Nmap service detection: `doc/modules/service-detection.md`
- rustls documentation: https://docs.rs/rustls
- x509-parser documentation: https://docs.rs/x509-parser

---

## Phase 4.3: Database Update Implementation

### Overview

Implemented automatic database update mechanism for Nmap fingerprint databases.

### Components

#### 1. DatabaseUpdater

Located in `crates/rustnmap-fingerprint/src/database/updater.rs`:

```rust
let updater = DatabaseUpdater::new();
let result = updater.update_all("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
```

Features:
- Downloads from Nmap SVN repository
- Backup before update (optional)
- Atomic file replacement
- Custom URL support

#### 2. MacPrefixDatabase

Located in `crates/rustnmap-fingerprint/src/database/mac.rs`:

```rust
let db = MacPrefixDatabase::load_from_file("nmap-mac-prefixes").await?;
let vendor = db.lookup("00:00:0C:12:34:56");
```

Features:
- Parses Nmap MAC prefix format
- Multiple MAC address format support
- Detects private/random MACs
- Detects locally administered/multicast

### Database Sources

| Database | URL |
|----------|-----|
| nmap-service-probes | https://svn.nmap.org/nmap/nmap-service-probes |
| nmap-os-db | https://svn.nmap.org/nmap/nmap-os-db |
| nmap-mac-prefixes | https://svn.nmap.org/nmap/nmap-mac-prefixes |

---

*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*
