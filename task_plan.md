# Task Plan: Fix API & SDK Module Issues

## Goal

Fix all 25 issues identified in the rustnmap-api and rustnmap-sdk audit across both crates.

## Current Phase

Phase 1: Quick Fixes (in progress)

## Phases

### Phase 1: Quick SDK/API Fixes (non-breaking, low-risk)
- [ ] L-02: Add `#[must_use]` on `Scanner::run()` and `ScannerBuilder::run()`
- [ ] L-03: Fix `Scanner::default()` unwrap panic
- [ ] L-05: Handle Queued in ScanStatus From conversion
- [ ] M-06: Fix cancel_scan response to use ApiResponse wrapper
- **Status:** in_progress

### Phase 2: Port & Validation Fixes
- [ ] C-03: Fix `port_list()` to use `PortSpec::List` instead of `PortSpec::Top(N)`
- [ ] M-04: Fix `parse_port_spec` to handle comma-separated ports
- [ ] M-05: Add port validation in `validate_request`
- **Status:** pending

### Phase 3: Dead Code & Dependency Cleanup
- [ ] L-01: Clean up dead AuthMiddleware struct
- [ ] M-01: Remove unused `once_cell` from rustnmap-api
- [ ] M-02: Remove unused `reqwest` from rustnmap-api
- [ ] M-03: Remove unused `futures-util` and `async-stream` from rustnmap-sdk
- **Status:** pending

### Phase 4: High-Severity Fixes
- [ ] H-01: Fix `vulnerability_scan()` silent no-op
- [ ] H-02: Fix `get_scan_results` 404 for pending scans
- [ ] H-03: Add `sctp_init` to profile.rs, handle missing core types
- **Status:** pending

### Phase 5: Security & XML Fix
- [ ] M-07: Fix manual XML injection vulnerability in `to_xml()`
- **Status:** pending

### Phase 6: Background Scan Runner (Critical)
- [ ] C-01: Add background task runner that picks up queued scans
- [ ] C-02: Fix SSE stream termination with timeout
- **Status:** pending

### Phase 7: Verification
- [ ] `cargo clippy -p rustnmap-api -p rustnmap-sdk -- -D warnings` (0 warnings)
- [ ] `cargo test -p rustnmap-api -p rustnmap-sdk` (all pass)
- [ ] `cargo fmt --all -- --check` (clean)
- **Status:** pending

## Decisions

| Decision | Rationale |
|----------|-----------|
| H-04 type duplication: document only | Moving shared types to rustnmap-common is a larger refactor, separate task |
| sctp_cookie/idle: keep in VALID_SCAN_TYPES | Will error at scan time via runner; removing would break API compatibility |
| C-01 background runner: implement last | Depends on having clean codebase first; most complex change |
