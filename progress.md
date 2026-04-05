# Progress: NSE Script Compatibility Testing

> **Updated**: 2026-04-04

---

## Session Summary (2026-04-04) - Full NSE Comparison Benchmark

### Benchmark Results (46 tests against Docker range)
| Metric | Result |
|--------|--------|
| Total Tests | 46 |
| PASS | 34 (73.9%) |
| FAIL | 2 |
| SKIP | 10 |
| WARN | 8 |

### Comparison with Previous Runs
| Date | PASS | FAIL | SKIP | Rate |
|------|------|------|------|------|
| Apr 3 | 26 | 8 | 12 | 56.5% |
| **Apr 4** | **34** | **2** | **10** | **73.9%** |
| Improvement | +8 PASS | -6 FAIL | -2 SKIP | +17.4% |

### FAIL Root Causes (2 - both RUSTNMAP CODE BUGS)
1. **SSL Enum Ciphers**: `format_lua_table()` in engine.rs uses Rust `table.pairs()` which ignores `__pairs` metamethods. Tables from `outlib.sorted_by_key` have no raw entries, so iteration returns empty. Runner uses Lua-side format_table and works correctly.
2. **Banner (POP3)**: `port.version.service_fp` not populated from version detection. banner.nse checks version cache first, falls through to `comm.get_banner` which times out on slow POP3.

### SKIP Classification
- **8 TARGET CONFIG**: FTP broken, VNC filtered, no CORS/cookies, MySQL has password, no default accounts
- **2 SLOW SERVICE**: IMAP/POP3 extremely slow (>10s greeting), both tools skip

### Resource Usage
| Metric | nmap | rustnmap | Ratio |
|--------|------|----------|-------|
| Peak Memory (median) | 45.7 MB | 113.3 MB | 2.5x |
| User CPU (median) | 0.40s | 0.76s | 1.9x |
| Sys CPU (median) | 0.05s | 0.18s | 3.6x |
| Speed (typical) | baseline | 2-3x slower | 0.3-0.5x |

### High-CPU Scripts
| Script | User CPU | Sys CPU | Root Cause |
|--------|----------|---------|-----------|
| HTTP Methods | 5.31s | 2.10s | format_lua_table iteration overhead |
| SMB Security Mode | 5.27s | 2.08s | SMB protocol function overhead |
| POP3 Capabilities | 4.27s | 1.81s | Repeated connection attempts on slow POP3 |

### Next Steps (Priority Order)
1. **Fix engine format_lua_table** - Replace Rust-side with Lua-side format_table (fixes ssl-enum-ciphers)
2. **Populate port.version.service_fp** - Pass version detection results to NSE port table (fixes banner on slow services)
3. **Fix output formatting** - Address WARN scripts (HTTP Methods duplicates, SSH Hostkey raw keys, MySQL capability names)

---

## Session Summary (2026-04-05) - format_output + tohex + SSL hostname fix

### Bugs Fixed

1. **stdnse.format_output skips integer-keyed array elements**: Root cause: Rust implementation only iterated string keys via `pairs()`, skipping all integer keys. This meant scripts like http-headers that pass `result.rawheader` (a string array) to `format_output(true, arr)` got empty output. Fix: Rewrote to use `sequence_values()` (ipairs equivalent) for array elements with proper indentation, matching nmap's `format_output_sub`.
   - **Files**: `stdnse.rs` (`format_output_impl`, `format_output_sub`, `lua_value_to_display_string`).

2. **stdnse.tohex rejects numeric input**: Root cause: `tohex` only accepted `mlua::String`, but nmap's version also handles `number` type (e.g., `stdnse.tohex(0x0202, {separator=".", group=1})` for SMB2 dialect names). Without this, smb-protocols showed byte values ("35.32.28") instead of dialect names ("2.1", "3.0"). Fix: Accept both `Integer`/`Number` and `String`, with proper group separator logic.
   - **Files**: `stdnse.rs` (`tohex` function registration, default `group=2` when separator present).

3. **SSL hostname empty string causes SNI error**: Root cause: Runner sets `host.name = ""` (empty string), which gets passed as SNI hostname to OpenSSL. Empty SNI is invalid. Fix: Filter empty hostname strings, fall back to IP address for SNI. Fixed in both `comm.rs` (NseSocket) and `ssl.rs` (SslSocket).
   - **Files**: `comm.rs` (`opencon_impl`, `get_ssl_certificate`), `ssl.rs` (`get_ssl_certificate` method).

4. **DUAL_MODULES list incomplete**: Reverted incorrect removal of `ftp`, `smb`, `smbauth`, `ssl` from DUAL_MODULES. All modules that have both Rust and Lua implementations must be in this list.
   - **Files**: `mod.rs` (DUAL_MODULES constant).

### Build Verification
- `cargo clippy -p rustnmap-nse --lib -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (241 tests, 0 failures)

### Script Test Results (8 key scripts - ALL PASS)
| Script | Target | Result |
|--------|--------|--------|
| ssl-cert | 172.28.0.3:443 | PASS - Subject, SAN, validity dates |
| ssl-enum-ciphers | 172.28.0.3:443 | PASS - Full cipher enumeration |
| http-title | 172.28.0.3:80 | PASS - "RustNmap HTTP Test Target" |
| http-headers | 172.28.0.3:80 | PASS - All headers listed (was EMPTY before) |
| http-methods | 172.28.0.3:80 | PASS - Risky methods listed |
| smb-protocols | 172.28.0.6:445 | PASS - "2.1, 3.0, 3.0.2, 3.1.1" (was garbled before) |
| ssh-hostkey | 172.28.0.4:22 | PASS - RSA/ECDSA/ED25519 fingerprints |
| tls-alpn | 172.28.0.3:443 | PASS - h2, http/1.1, http/1.0, http/0.9 |

---

## Session Summary (2026-04-04) - Dual-module loader + receive_buf pattern fix + runner improvements

### Bugs Fixed

1. **`host.registry` sub-table**: Scripts like ssl-cert and smb-protocols use `host.registry["ssl-cert"]` for cross-script caching. Added registry sub-table to the host table in the runner.
   - **Files**: `runner.rs` (added registry, bin_ip, interfaces tables in `create_host_table`).

2. **`host.bin_ip` binary IP representation**: The address-info script uses `host.bin_ip` (raw bytes of the IP address) for IP type classification. Added via `string.char()` in Lua.
   - **Files**: `runner.rs`.

3. **`SCRIPT_TYPE` global**: Scripts like ssh-hostkey and ssh2-enum-algos use `SCRIPT_TYPE` to dispatch between portrule/hostrule/postrule actions via an ActionsTable. Added `SCRIPT_TYPE` global to the runner.
   - **Files**: `runner.rs` (set SCRIPT_TYPE before calling action).

4. **`receive_buf` Lua pattern matching**: Changed delimiter matching from literal byte comparison to `Lua string.find()` pattern matching. Fixes scripts using patterns like `"\r?\n"` (e.g., FTP banner, SSH banner exchange).
   - **Files**: `nmap.rs` (replaced `buf.windows(pat.len()).position()` with `string.find()` via `lua.call()`).

### Build Verification
- `cargo build --release` - PASS
2. `cargo test -p rustnmap-nse --lib` - PASS (241 tests)
3. `cargo clippy -p rustnmap-nse --lib -- -D warnings` - PASS (zero warnings)

### Script Test Results (20 scripts tested)
| Script | Target | Result |
|--------|--------|--------|
| ssl-enum-ciphers | 172.28.0.3:443 | PASS - Full cipher enumeration with grades |
| ssl-date | 172.28.0.3:443 | PASS - "TLS randomness does not represent time" |
| tls-alpn | 172.28.0.3:443 | PASS - h2. http/1.1, http/1.0, http/0.9 |
| http-title | 172.28.0.3:80 | PASS - "RustNmap HTTP Test Target" |
| http-methods | 172.28.0.3:80 | PASS - Potentially risky methods listed |
| http-server-header | 172.28.0.3:80 | PASS - nginx/1.25.5 |
| ldap-rootdse | 172.28.0.13:389 | PASS |
| snmp-info | 172.28.0.15:161 | PASS |
| snmp-sysdescr | 172.28.0.15:161 | PASS |
| ssh-hostkey | 172.28.0.4:22 | PASS - RSA/ECDSA/ED25519 fingerprints |

### Remaining Failures (4 scripts)
| Script | Status | Root Cause |
|--------|--------|------------|
| ssl-cert | FAIL | SSL handshake error (OpenSSL interop) |
| auth-owners | FAIL | identd protocol not implemented |
| ssh2-enum-algos | FAIL | dual-module loader bug: `ssh2.transport` nil |
| smb-protocols | EMPTY | SMB protocol issue (needs real NBSTAT query) |

### Remaining EMPTY (5 scripts - return nil action)
| Script | Notes |
|--------|-------|
| address-info | Correctly returns nil for IPv4 (`do_ipv4()` is intentionally empty) |
| ftp-anon | Under investigation |
| ftp-syst | Under investigation |
| http-headers | Under investigation |

---

## Session Summary (2026-04-04) - Output Formatting + Port Support
### Bugs Fixed

1. **ssl-enum-ciphers empty output**: Root cause: Rust mlua `Table::pairs()` does raw iteration, ignoring `__pairs` and `__tostring` metamethods set by `outlib.sorted_by_key`. Fix: Added Lua-side `format_table` function (mirrors `nse_main.lua:format_table`) to runner.rs that respects `__pairs`, `__tostring`, and `ipairs`/pairs` metamethods. Also implemented nmap's two-return-value convention (r1=structured. r2=display text).
   - **Files**: `runner.rs` (FORMAT_TABLE_LUA constant + output handling rewrite).

2. **stdnse format_output_impl integer key duplication**: Root cause: `pairs::<mlua::String, mlua::Value>` converts integer keys to strings, causing duplicate entries. Fix: Changed to `pairs::<mlua::Value>` and skip non-string keys (matching nmap's behavior where `ipairs` handles integers separately).
   - **Files**: `stdnse.rs` (`format_output_impl` function).

3. **Runner missing port support**: The runner binary only called `action(host)` but port-rule scripts need `action(host, port)`. Added `--port`, `--protocol`, `--service` CLI arguments, port table creation. and `action(host, port)` invocation.
   Also added Tokio runtime (needed by `stdnse.sleep`), `SCRIPT_NAME` global (needed by http-title etc.).
   - **Files**: `runner.rs` (complete rewrite with port info. Tokio runtime. SCRIPT_NAME).

### Build Verification
- `cargo clippy -p rustnmap-nse -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (241 tests. 0 failures)
- `cargo fmt --check` - PASS

---

## Session Summary (2026-04-03) - Clippy Cleanup + Doc Update
### Code Quality
- Cleaned up 83 clippy errors to zero across 8 files
- Removed ~1000 lines of dead SMB protocol code (smb.rs: 1189 -> 65 lines)
- Fixed 6 test compilation errors (missing `buffer` field in NseSocket constructors)
- 241 unit tests pass. 0 failures
- `cargo clippy -p rustnmap-nse --lib -- -D warnings` CLEAN
- `cargo fmt` CLEAN

---

## Session Summary (2026-04-03) - Fix 5 FAIL Scripts
### Bugs Fixed

5. **SNMP SysDescr (UDP support)**: Added `ConnectedUdp` SocketState variant. `proto_hint` field on NseSocket, port table `protocol` extraction. UDP send/receive/receive_bytes handlers. Container: 172.28.0.15.

6. **SSL Date (receive_bytes semantics)**: Changed `receive_bytes(n)` from loop-until-exact-N to single-read-return-available. Matches nmap behavior: "If even one byte is received then it is returned."

7. **TLS ALPN**: Same receive_bytes fix as SSL Date.

8. **SMB Protocols (partial)**: Removed Rust SMB protocol functions that overwrote Lua implementations. Added `nmap.condvar()` returning a function. Added `nmap.get_port_state()`. Added `netbios.get_server_name` stub. Script still FAIL due to actual NBSTAT query needed.

9. **LDAP RootDSE + SNMP Info**: Verified fixes from prior session still work.

### Build Verification
- `cargo clippy -p rustnmap-nse --lib -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (241 tests. 0 failures)
- `cargo fmt --check` - PASS

---

## Session Summary (2026-04-01) - Phase 2
### Bugs Fixed

3. **RC-8: stdnse.debug parameter type**: Changed `debug`, `verbose`, `print_debug`, and `debug1-5` functions to accept `MultiValue` args with flexible level type. Non-numeric levels are silently skipped (Nmap behavior). Added variadic format string support via `string.format`.

4. **RC-4: dns.query/reverse nil params**: Changed `dns.query` domain and `dns.reverse` ip params from `String` to `Option<String>`. Both return nil for nil input.

### Build Verification
- `cargo clippy -p rustnmap-nse --lib -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (235 tests. 0 failures)
- `cargo fmt` - PASS

---

## Session Summary (2026-04-01) - Phase 1

### Bugs Fixed
1. **Silent Script Failures**: Changed 4 `debug!` to `warn!` in `orchestrator.rs`. Script execution and rule evaluation failures are now visible at default log level.

2. **comm.exchange/get_banner Table Arguments**: Rewrote both functions to accept `Value` for host/port parameters. Added `extract_host()` and `extract_port()` helper functions that handle both string/integer and table (with `.ip`/`.number` fields) arguments.

---

## Previous Session (2026-03-31)

### NSE Comparison Test Results Against Docker Targets
**Run 2 (06:47)**: 9 PASS/WARN, 24 FAIL. 13 SKIP out of 46 tests (19.5%)
**Run 1 (02:14)**: 8 PASS. 25 FAIL. 13 SKIP out of 46 tests (17.3%)

### What Was Done

1. Docker test range with 19 containers
2. 7 code fixes (new_try, receive_lines, comm MultiValue, etc.)
3. Two full test runs
4. Build clean with zero warnings
