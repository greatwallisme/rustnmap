# Task Plan: Remove #[ignore] Attributes from Tests

> **Project**: RustNmap - Rust Network Mapper
> **Status**: COMPLETE
> **Created**: 2026-02-13
> **Updated**: 2026-02-13
> **Goal**: Remove `#[ignore]` attributes since development runs under root account

---

## Goal

移除所有测试上的 `#[ignore]` 属性，因为项目开发在 root 账户下进行，所有需要 root/CAP_NET_RAW 权限的测试都应该直接运行。

---

## Analysis

### Files with #[ignore] Attributes (NOW REMOVED)

| # | File | # of Ignored Tests | Status |
|---|------|-------------------|--------|
| 1 | `crates/rustnmap-core/tests/udp_scan_test.rs` | 5 | REMOVED |
| 2 | `crates/rustnmap-core/tests/tcp_scan_test.rs` | 4 | REMOVED |
| 3 | `crates/rustnmap-core/tests/scan_target_test.rs` | 5 | REMOVED |
| 4 | `crates/rustnmap-target/tests/host_discovery_test.rs` | 8 | REMOVED |
| 5 | `crates/rustnmap-fingerprint/tests/os_detection_test.rs` | 1 | REMOVED |
| 6 | `crates/rustnmap-target/src/discovery.rs` | 2 | REMOVED |

**Total**: 26 `#[ignore]` attributes removed

---

## Phases

### Phase 1: Remove #[ignore] from UDP Scan Tests

**File**: `crates/rustnmap-core/tests/udp_scan_test.rs`

- Updated module doc comment
- Removed `#[ignore = "requires root/CAP_NET_RAW privileges"]` from:
  - `test_udp_scanner_creation`
  - `test_udp_scan_port`
  - `test_udp_scan_wrong_protocol`
  - `test_udp_scan_ipv6_target`
  - `test_udp_scan_performance`

**Status**: COMPLETE

---

### Phase 2: Remove #[ignore] from TCP Scan Tests

**File**: `crates/rustnmap-core/tests/tcp_scan_test.rs`

- Updated module doc comment
- Removed `#[ignore = "requires root/CAP_NET_RAW privileges"]` from:
  - `test_syn_scan_open_ports`
  - `test_syn_scan_closed_ports_filtered`
  - `test_syn_scan_mixed_ports`
  - `test_syn_scan_performance`

**Status**: COMPLETE

---

### Phase 3: Remove #[ignore] from Scan Target Tests

**File**: `crates/rustnmap-core/tests/scan_target_test.rs`

- Removed `--include-ignored` comment from file header
- Removed `#[ignore]` from:
  - `test_syn_scan_target`
  - `test_connect_scan_target`
  - `test_udp_scan_target`
  - `test_icmp_ping_target`
  - `test_os_detection_target`

**Status**: COMPLETE

---

### Phase 4: Remove #[ignore] from Host Discovery Tests

**File**: `crates/rustnmap-target/tests/host_discovery_test.rs`

- Updated module doc comment
- Removed `#[ignore = "requires root/CAP_NET_RAW privileges"]` from:
  - `test_tcp_syn_ping_localhost`
  - `test_tcp_ack_ping_localhost`
  - `test_icmp_ping_localhost`
  - `test_icmp_timestamp_ping_localhost`
  - `test_arp_ping_localhost`
  - `test_host_discovery_tcp_ping`
  - `test_host_discovery_icmp`
  - `test_discovery_ipv6_returns_unknown`

**Status**: COMPLETE

---

### Phase 5: Remove #[ignore] from OS Detection Tests

**File**: `crates/rustnmap-fingerprint/tests/os_detection_test.rs`

- Updated module doc comment
- Removed `#[ignore = "Requires root privileges and a listening service on port 80"]` from:
  - `test_os_detection_localhost`

**Status**: COMPLETE

---

### Phase 6: Remove #[ignore] from Discovery Doc Tests

**File**: `crates/rustnmap-target/src/discovery.rs`

- Removed `#[ignore = "Requires root privileges"]` from:
  - `test_tcp_syn_ping_discover_localhost` (line 1002)
  - `test_icmp_ping_discover_localhost` (line 1021)

**Status**: COMPLETE

---

### Phase 7: Update Documentation

- Updated test file headers to remove "marked with #[ignore]" notes
- Removed references to `--include-ignored` flag

**Status**: COMPLETE

---

### Phase 8: Verify All Tests Pass

Run full test suite:
```bash
cargo test --all
```

**Status**: PENDING VERIFICATION

---

## Files Modified

| File | Changes |
|------|---------|
| `crates/rustnmap-core/tests/udp_scan_test.rs` | Removed 5 `#[ignore]` attributes, updated doc comment |
| `crates/rustnmap-core/tests/tcp_scan_test.rs` | Removed 4 `#[ignore]` attributes, updated doc comment |
| `crates/rustnmap-core/tests/scan_target_test.rs` | Removed 5 `#[ignore]` attributes, updated header comment |
| `crates/rustnmap-target/tests/host_discovery_test.rs` | Removed 8 `#[ignore]` attributes, updated doc comment |
| `crates/rustnmap-fingerprint/tests/os_detection_test.rs` | Removed 1 `#[ignore]` attribute, updated doc comment |
| `crates/rustnmap-target/src/discovery.rs` | Removed 2 `#[ignore]` attributes from doc tests |

---

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Remove all #[ignore] attributes | Development runs under root account |
| Keep privilege check logic | Tests gracefully skip if no privileges available |
| Update documentation | Remove references to --include-ignored |

---

## Project Context

**Technology Stack**:
- Rust 1.85+
- Root/CAP_NET_RAW required for raw socket operations

**Required Privileges**:
- All privileged tests now run directly (root account assumed)

