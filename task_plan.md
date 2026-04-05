# Task Plan: NSE Performance Optimization

## Goal
Fix NSE scripts that are slower than nmap. Starting point: 46/46 PASS but ~20 scripts slower.
Benchmark report: `benchmarks/reports/nse_comparison_report_20260405_044043.txt`

## Rules
- Do NOT blindly change code without understanding root cause
- Verify each fix individually before moving to the next
- Track actual test results, not assumptions

## Root Cause Summary (from findings.md)

| Category | Scripts Affected | Root Cause | Fix Scope |
|----------|-----------------|------------|-----------|
| Banner timeout | SSH/SMTP/POP3 banner (0.09-0.10x) | `receive_all()` waits full socket timeout after initial data | comm.rs |
| Comm default timeout | NTP (0.24x) | `DEFAULT_TIMEOUT_MS=30s`, nmap uses ~7s | comm.rs |
| UDP scan engine | SNMP/NTP (0.06-0.24x) | UDP scan 11.4s vs nmap 0.03s | scan engine (separate) |
| Service detection | FCrDNS (0.01x) | -sV scans all 1000 ports | scan engine (separate) |
| Moderate slowness | MySQL/Redis/VNC (0.54-0.68x) | Lua VM init overhead per script | engine.rs |

---

## Phase 1: comm.rs Timeout Optimization - IN PROGRESS

### Fix 1.1: `receive_all()` linger timeout
**Problem**: After reading initial banner data, `receive_all()` waits the FULL socket timeout (5s) before returning.
Nmap's nsock uses event-driven I/O that detects "no more data" quickly (~100ms).

**Fix**: After first successful read, reduce timeout to a short "linger" window (150ms).
If no more data arrives in 150ms, return what we have.

**Impact**: Banner scripts (SSH, SMTP, POP3) should improve from 0.09-0.10x to ~0.8-1.0x

### Fix 1.2: Reduce `DEFAULT_TIMEOUT_MS` from 30s to 7s
**Problem**: NSE scripts that time out (e.g., NTP mode6 control) wait 30s vs nmap's ~7s.

**Fix**: Change `DEFAULT_TIMEOUT_MS` from 30_000 to 7_000.

**Impact**: NTP script should improve from 0.24x to ~0.6x

## Phase 2: Lua VM Reuse (engine.rs) - PENDING

**Problem**: Every portrule eval + script execution creates a brand new Lua VM + registers 30 libs.
With ~100 scripts, that's 100+ VM initializations.

**Fix**: Cache and reuse Lua VMs across evaluations. Only reload the specific script.

**Impact**: All scripts gain ~0.1-0.3s per evaluation

## Phase 3: Benchmark Verification - PENDING

Re-run benchmark to verify improvements.

---

## Previous Plan: NSE Script Compatibility Fix (COMPLETE)

### Goal (completed 2026-04-05)
Fix all NSE script failures found in Docker comparison testing.
Starting point: 20/46 scripts PASS (43.4%) on 2026-04-02.
Result: 46/46 PASS (100%)

---

## Phase 1: Root Cause Investigation - COMPLETE
Investigated all 13 FAIL scripts from 2026-04-02 test run.

## Phase 2: Fix Bugs - IN PROGRESS

### Fixed (6 scripts - now PASS)

| Script | Root Cause | Fix |
|--------|-----------|-----|
| LDAP RootDSE | `nmap.set_port_version` not implemented | Added stub in nmap.rs |
| SNMP Info | `shortport.version_port_or_service` missing | Added to shortport.rs + nmapdb module |
| SNMP SysDescr | No UDP socket support in nmap.rs | Added `ConnectedUdp` variant, proto_hint, port table protocol extraction, UDP send/receive/receive_bytes handlers |
| SSL Date | `receive_bytes` waited for exact N bytes | Changed to return partial data on first read (matches nmap behavior) |
| TLS ALPN | Same `receive_bytes` issue | Same fix as SSL Date |
| **SSL Enum Ciphers** | Runner missing port info + output formatting ignored `__pairs`/`__tostring` metamethods | Added port support (`--port`/`--protocol`/`--service`), Lua-side `format_table` (mirrors `nse_main.lua`), Tokio runtime, `SCRIPT_NAME` global, nmap two-return-value convention |

### Also Fixed (output quality)

| Script | Fix |
|--------|-----|
| SMB Protocols | `format_output_impl` integer key duplication fixed in stdnse.rs |
| RPC Info | Port support in runner (returns empty = no RPC entries on target) |
| HTTP Title | `SCRIPT_NAME` global in runner |
| Banner (various) | `comm.exchange`/`get_banner` table argument handling |
| HTTP Headers/Methods/Server-Header | Port support in runner |

### Remaining Failures (6 scripts - all need missing NSE libraries)

| Script | Root Cause | Difficulty |
|--------|-----------|-----------|
| SSL Cert | Missing `registry` NSE library | HIGH |
| SMB Protocols | Missing `registry` NSE library | HIGH |
| SSH Hostkey | Missing function reference in Lua nselib | MEDIUM |
| Auth Owners | Missing identd protocol support | MEDIUM |
| DNS TXT/Version | Script path resolution issue | LOW |
| Address Info | Host table missing interface data | LOW |

### Fixes This Session (2026-04-04)

1. **host.registry** - Added registry sub-table to host table in runner. Scripts can use `host.registry` for cross-script caching (e.g., ssl-cert, caches certificates, smb caches netbios names).

2. **host.bin_ip** - Added binary IP representation to host table. Scripts like address-info use `host.bin_ip` for IP type detection.

3. **SCRIPT_TYPE** global - Added to runner. Scripts like ssh-hostkey and ssh2-enum-algos use `SCRIPT_TYPE` to dispatch between portrule/hostrule/postrule` actions.

4. **receive_buf pattern matching** - Changed string delimiter matching from literal byte matching to Lua pattern matching via `string.find`. This fixes `"\r?\n"` pattern used by many scripts.

5. **ssh2-enum-algos** - Dual-module loader issue: Lua module functions like `ssh2.transport` are lost during merge. Need to fix the dual-module loader to properly preserve Lua module's sub-tables.

### Key Technical Findings This Session

1. **receive_buf Lua pattern matching**: The original implementation used literal byte matching (`buf.windows(pat.len()).position(|w| w == pat)`) which cannot handle Lua patterns like `"\r?\n"`. Fixed by using `string.find()` from within the Rust code via `lua.call()`.

2. **Dual-module loader bug**: When loading modules like `ssh2`, the Rust dual-module loader calls the Lua chunk and gets the table, But the some cases, the returned table loses sub-tables (like `ssh2.transport`). Manual testing shows the direct load works but but the loader doesn't. Root cause under investigation.

3. **mlua `Table::pairs()` limitation**: Rust mlua's `Table::pairs::<mlua::String, _>` does raw iteration, does NOT respect Lua `__pairs` metamethod, and converts integer keys to strings causing duplication.

4. **Runner was missing critical infrastructure**: No port support (called `action(host)` instead of `action(host, port)`), no Tokio runtime (needed by `stdnse.sleep`), no `SCRIPT_NAME` global (needed by http-title etc.).

## Phase 3: Code Quality - COMPLETE
- Cleaned up 83 clippy errors to zero
- Removed ~1000 lines of dead SMB protocol code
- 241 unit tests pass
- `cargo clippy -D warnings` clean
- `cargo fmt` clean

## Phase 4: Full Comparison Re-test - IN PROGRESS
- Runner-level testing: 14/20 scripts PASS, 6 FAIL
- All 6 remaining failures are caused by missing NSE libraries (registry. identid, DNS functions)
- Output formatting pipeline is now correct

---

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| UDP recv hangs | 1 | Set read_timeout before recv |
| UDP datagram truncated | 1 | Return full datagram. not min(recv, n) |
| Rust SMB functions overwrite Lua | 1 | Removed Rust protocol functions, kept only constants |
| NseSocket missing buffer field | 1 | Added buffer: Vec::new() to all test constructors |
| 83 clippy errors | 1 | Systematic cleanup across 8 files |
| engine tests fail without runner binary | 1 | Need `cargo build --bin rustnmap-nse-runner` first |
| mlua pairs() ignores __pairs | 1 | Use Lua-side format_table instead of Rust-side iteration |
| ssl-enum-ciphers empty output | 1 | format_table + two-return-value convention |
| runner panic: no reactor running | 1 | Added Tokio runtime in main() |
| http-title: SCRIPT_NAME nil | 1 | Set SCRIPT_NAME global before loading script |
| receive_buf literal matching | 1 | Changed to Lua string.find pattern matching |
