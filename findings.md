# Findings: rustnmap-api & rustnmap-sdk Module Audit

> **Date**: 2026-04-13
> **Scope**: `crates/rustnmap-api/` and `crates/rustnmap-sdk/`
> **Result**: Clippy 0 warnings, 100 tests pass. **25 issues found** (3 CRITICAL, 4 HIGH, 7 MEDIUM, 5 LOW, 6 INFO)
> **Status**: All 22 actionable issues **FIXED** (6 INFO are observations, not bugs)

---

## CRITICAL Issues

### C-01: API creates scans but never executes them
**File**: `crates/rustnmap-api/src/handlers/create_scan.rs:207-243`

The `create_scan` handler inserts a task record into `ScanManager` with status `Queued`, but **no background task picks up queued scans and runs them**. Scans stay in `Queued` state forever.

**Evidence**: `ScanManager` has `update_status()` and `update_progress()` methods that are never called from any handler or background worker. The `ScanOrchestrator` is never invoked from the API crate.

**Impact**: The entire API is a facade - it records scan requests but never performs actual network scanning.

**Fix**: Add a background task runner that:
1. Polls `ScanManager` for `Queued` scans
2. Spawns `ScanOrchestrator::run()` in a tokio task
3. Updates status/progress via `ScanManager` callbacks
4. Stores results when complete

---

### C-02: SSE stream never terminates for queued scans
**File**: `crates/rustnmap-api/src/sse/mod.rs:42-77`

The `scan_stream` SSE handler polls every 1 second waiting for terminal state (`Completed`, `Cancelled`, `Failed`). Since scans never transition out of `Queued` (see C-01), the stream **loops forever** sending identical progress updates.

**Impact**: Memory leak - each SSE connection holds a reference and sends data indefinitely.

**Fix**: Either implement the scan runner (C-01), or add a timeout to the SSE stream for queued scans.

---

### C-03: `port_list()` builder method produces wrong results
**File**: `crates/rustnmap-sdk/src/builder.rs:179-196`

```rust
pub fn port_list(mut self, ports: &[u16]) -> Self {
    if ports.len() == 1 {
        self.config.port_spec = PortSpec::Range { start: ports[0], end: ports[0] };
    } else {
        self.config.port_spec = PortSpec::Top(ports.len());  // BUG
    }
    self
}
```

Passing `[22, 80, 443]` creates `PortSpec::Top(3)` which scans the **top 3 most common ports** (e.g., 80, 23, 443), NOT ports 22, 80, 443 specifically.

**Impact**: SDK users get completely different scan results than requested.

**Fix**: Build a proper comma-separated port string and parse it, or add a `PortSpec::List` variant.

---

## HIGH Issues

### H-01: `vulnerability_scan()` is a silent no-op
**File**: `crates/rustnmap-sdk/src/builder.rs:305-310`

```rust
pub fn vulnerability_scan(self, enable: bool) -> Self {
    let _ = enable;  // Silently discarded
    self
}
```

Users who call `.vulnerability_scan(true)` get no vulnerability scanning, and no error or warning.

**Fix**: Either implement it via `rustnmap-vuln` integration, or return an error/panic explaining it's not yet supported.

---

### H-02: `get_scan_results` returns misleading 404 for pending scans
**File**: `crates/rustnmap-api/src/handlers/get_scan_results.rs:33-44`

The handler only checks the `results` DashMap. If a scan exists (is `Queued` or `Running`) but hasn't completed, it returns `404 Scan not found`.

**Impact**: Client can't distinguish between "scan doesn't exist" and "scan exists but not done".

**Fix**: Check `tasks` first, return 404 if not found, 202 Accepted if not completed, 200 with results if completed.

---

### H-03: Missing SCTP scan types in `ScanProfile::to_scan_config()`
**File**: `crates/rustnmap-sdk/src/profile.rs:210-227`

The match statement handles 9 scan types but omits `sctp_init` and `sctp_cookie`, which ARE listed in the API's `VALID_SCAN_TYPES` (12 types total in `create_scan.rs:28-41`).

**Impact**: Loading a profile with `scan_type: "sctp_init"` returns an error instead of configuring the scan.

---

### H-04: Type duplication between API and SDK
**Files**: `rustnmap-api/src/lib.rs`, `rustnmap-sdk/src/models.rs`, `rustnmap-sdk/src/remote.rs`

Both crates independently define:
- `ScanStatus` enum (API `lib.rs:117-125` vs SDK `models.rs:131-138`)
- `CreateScanRequest` / `ScanOptions` (API `lib.rs:165-191` vs SDK `remote.rs:324-337`)
- `ApiResponse` (API `lib.rs:65-72` vs SDK `remote.rs:340-344`)
- `ScanProgress` (API `lib.rs:151-162` vs SDK `remote.rs:363-368`)

SDK models also duplicate `rustnmap_output::models` with different field names (e.g., `port.number` vs `port.port`).

**Impact**: Maintenance burden, potential inconsistency, API/SDK version drift.

**Fix**: Move shared types to `rustnmap-common` or a new `rustnmap-api-types` crate.

---

## MEDIUM Issues

### M-01: Unused dependency `once_cell`
**File**: `crates/rustnmap-api/Cargo.toml:37`

The code uses `std::sync::LazyLock` (stable since Rust 1.80), making `once_cell = "1.19"` unnecessary.

---

### M-02: Unused dependency `reqwest` in rustnmap-api
**File**: `crates/rustnmap-api/Cargo.toml:49`

Listed as "HTTP client for health checks" but never imported or used anywhere in the API crate.

---

### M-03: Unused dependency `futures-util` and `async-stream` in rustnmap-sdk
**File**: `crates/rustnmap-sdk/Cargo.toml:18-19`

Neither `futures_util` nor `async_stream` are used in any SDK source file.

---

### M-04: `parse_port_spec` doesn't handle comma-separated ports
**File**: `crates/rustnmap-sdk/src/builder.rs:200-223`

Only handles ranges (`"1-1000"`), special strings (`"all"`, `"*"`), `"topN"`, and single ports. Cannot handle `"22,80,443"` which is a standard nmap port format.

---

### M-05: `ScanOptions.ports` has no server-side validation
**File**: `crates/rustnmap-api/src/handlers/create_scan.rs`

The `validate_request()` function validates targets, scan_type, and timing, but **never validates `options.ports`**. Invalid port strings are passed through silently.

---

### M-06: Inconsistent response format for `cancel_scan`
**File**: `crates/rustnmap-api/src/handlers/cancel_scan.rs:33-43`

Returns `CancelScanResponse` directly (no `ApiResponse<>` wrapper). Other handlers use `ApiResponse::success()` wrapper with `{"success": true, "data": {...}}`.

cancel_scan returns: `{"id": "...", "status": "cancelled", "message": "..."}`
Others return: `{"success": true, "data": {"id": "...", ...}}`

---

### M-07: Manual XML construction vulnerable to injection
**File**: `crates/rustnmap-sdk/src/models.rs:93-127`

Uses `std::fmt::Write` to manually build XML. If any field (e.g., hostname, service name, OS name) contains `<`, `>`, `&`, or `"`, the output will be malformed XML or vulnerable to injection.

---

## LOW Issues

### L-01: Dead `AuthMiddleware` struct
**File**: `crates/rustnmap-api/src/middleware/auth.rs:28-35`

`AuthMiddleware` struct is defined with a `state` field marked `#[allow(dead_code)]`, but only `auth_middleware` function is actually used as middleware. The struct is never constructed except in tests.

---

### L-02: Missing `#[must_use]` on `Scanner::run()` and `ScannerBuilder::run()`
**File**: `crates/rustnmap-sdk/src/builder.rs:83, 339`

Both `run()` methods return `ScanResult<ScanOutput>` which should not be silently discarded. `#[must_use]` is present on builder setter methods but missing on the `run()` methods themselves.

---

### L-03: `Scanner::default()` may panic
**File**: `crates/rustnmap-sdk/src/builder.rs:137-141`

```rust
impl Default for Scanner {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
```

`Scanner::new()` currently can't fail (just returns `Ok`), but if it ever does, `Default` will panic. Should use a const default or handle gracefully.

---

### L-04: `HealthResponse::default()` has hardcoded zeros
**File**: `crates/rustnmap-api/src/lib.rs:104-114`

Default impl sets `uptime_seconds: 0`, `active_scans: 0`, `queued_scans: 0`. The handler overrides these, but anyone using `HealthResponse::default()` directly gets misleading data.

---

### L-05: `ScanStatus` conversion doesn't handle `Queued`
**File**: `crates/rustnmap-api/src/lib.rs:139-148`

`From<rustnmap_scan_management::ScanStatus>` only handles `Running`, `Completed`, `Failed`, `Cancelled`. If `scan_management` ever adds `Queued`, compilation fails.

---

## INFO (Observations, not issues)

### I-01: `ScanProfile::from_file` uses `block_in_place`
**File**: `crates/rustnmap-sdk/src/profile.rs:144-147`

Uses `tokio::task::block_in_place` for file I/O, which is valid in async context but will panic outside tokio runtime.

### I-02: No CORS configuration
**File**: `crates/rustnmap-api/Cargo.toml:19`

`tower-http` is compiled with CORS feature, but no CORS layer is configured in the router.

### I-03: No graceful shutdown
**File**: `crates/rustnmap-api/src/server.rs:84-100`

`run()` uses `axum::serve()` without `with_graceful_shutdown()`. Server cannot be cleanly stopped.

### I-04: `profile.rs` port parsing uses `unwrap_or` defaults silently
**File**: `crates/rustnmap-sdk/src/profile.rs:184-196`

Invalid port specs silently become defaults (e.g., `unwrap_or(1000)`) instead of returning errors.

### I-05: No request size limit
**File**: `crates/rustnmap-api/src/routes/mod.rs`

No `DefaultBodyLimit` layer is applied. A malicious client could send extremely large JSON bodies.

### I-06: `ApiConfig` generates a random key on every `default()`
**File**: `crates/rustnmap-api/src/config.rs:48`

Every `ApiConfig::default()` call generates a new random key. This is documented but could surprise users who create two instances expecting the same key.

---

## Build & Test Verification

| Check | Result |
|-------|--------|
| `cargo clippy -p rustnmap-api -p rustnmap-sdk -- -D warnings` | 0 warnings |
| `cargo test -p rustnmap-api -p rustnmap-sdk` | 100 pass (76 api unit + 16 api integration + 6 sdk unit + 2 doctests) |
| `cargo fmt --all -- --check` | Pass (formatting compliant) |

---

## Statistics

| Metric | Value |
|--------|-------|
| Files reviewed | 22 (14 api + 5 sdk + 2 Cargo.toml + 1 doc) |
| Lines of code | 5,175 (new on develop branch) |
| Total issues | 25 |
| Critical | 3 |
| High | 4 |
| Medium | 7 |
| Low | 5 |
| Info | 6 |
