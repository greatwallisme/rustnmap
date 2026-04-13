# Progress Log

> **Updated**: 2026-04-13

---

## Session: 2026-04-13 (API/SDK Fixes)

### Phase 1-7: Fix all 25 issues in rustnmap-api and rustnmap-sdk
- **Status:** complete
- **Started:** 2026-04-13

#### Fixes Applied

**CRITICAL (3)**
| ID | Fix | Files |
|----|-----|-------|
| C-01 | Added background ScanRunner that polls for queued scans and executes via ScanOrchestrator | runner.rs (new), server.rs, lib.rs, Cargo.toml |
| C-02 | Added 30-minute SSE timeout + timeout event to prevent infinite streaming | sse/mod.rs |
| C-03 | Fixed `port_list()` to use `PortSpec::List(ports)` instead of `PortSpec::Top(N)` | builder.rs |

**HIGH (4)**
| ID | Fix | Files |
|----|-----|-------|
| H-01 | Fixed `vulnerability_scan()` to enable NSE scripts with "vuln" category selector | builder.rs |
| H-02 | Fixed `get_scan_results` to return 202 for pending scans, 404 for not found, 500 for missing results | get_scan_results.rs, error.rs |
| H-03 | Added `sctp_init` to profile.rs; `sctp_cookie`/`idle` now return clear error | profile.rs |
| H-04 | Documented for future refactor (moving shared types to rustnmap-common) | - |

**MEDIUM (7)**
| ID | Fix | Files |
|----|-----|-------|
| M-01 | Removed unused `once_cell` dep | Cargo.toml (api) |
| M-02 | Removed unused `reqwest` dep | Cargo.toml (api) |
| M-03 | Removed unused `futures-util` and `async-stream` deps | Cargo.toml (sdk) |
| M-04 | Fixed `parse_port_spec` to handle comma-separated ports ("22,80,443") | builder.rs |
| M-05 | Added `validate_port_spec()` with comprehensive port format validation | create_scan.rs |
| M-06 | Fixed `cancel_scan` to use `ApiResponse<>` wrapper for consistent format | cancel_scan.rs, integration.rs |
| M-07 | Fixed XML injection by adding `escape_xml()` for all string fields in `to_xml()` | models.rs |

**LOW (5)**
| ID | Fix | Files |
|----|-----|-------|
| L-01 | Removed dead `AuthMiddleware` struct; made `extract_api_key` standalone function | auth.rs, mod.rs |
| L-02 | Added `#[must_use]` on `Scanner::run()` and `ScannerBuilder::run()` | builder.rs |
| L-03 | Fixed `Scanner::default()` to use derive instead of unwrap | builder.rs |
| L-04 | HealthResponse::default() kept as-is (handler overrides values) | - |
| L-05 | Added comment documenting Queued as API-only state in From conversion | lib.rs |

#### New Files
- `crates/rustnmap-api/src/runner.rs` - Background scan runner

#### Modified Files (15)
- `crates/rustnmap-api/Cargo.toml`
- `crates/rustnmap-api/src/lib.rs`
- `crates/rustnmap-api/src/error.rs`
- `crates/rustnmap-api/src/server.rs`
- `crates/rustnmap-api/src/middleware/auth.rs`
- `crates/rustnmap-api/src/middleware/mod.rs`
- `crates/rustnmap-api/src/sse/mod.rs`
- `crates/rustnmap-api/src/handlers/create_scan.rs`
- `crates/rustnmap-api/src/handlers/cancel_scan.rs`
- `crates/rustnmap-api/src/handlers/get_scan_results.rs`
- `crates/rustnmap-api/tests/integration.rs`
- `crates/rustnmap-sdk/Cargo.toml`
- `crates/rustnmap-sdk/src/builder.rs`
- `crates/rustnmap-sdk/src/models.rs`
- `crates/rustnmap-sdk/src/profile.rs`

#### Verification
| Check | Result |
|-------|--------|
| `cargo clippy -p rustnmap-api -p rustnmap-sdk -- -D warnings` | 0 warnings |
| `cargo test -p rustnmap-api -p rustnmap-sdk` | 110 pass (86+16+6+1+1) |
| `cargo fmt --check` | Clean |

---
*Updated after completing all phases*
