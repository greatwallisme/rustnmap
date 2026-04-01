# Progress: NSE Script Compatibility Testing

> **Updated**: 2026-04-01 (Phase 2 Fixes)

---

## Session Summary (2026-04-01) - Phase 2

### Bugs Fixed

3. **RC-8: stdnse.debug parameter type**: Changed `debug`, `verbose`, `print_debug`, and `debug1-5` functions to accept `MultiValue` args with flexible level type. Non-numeric levels are silently skipped (Nmap behavior). Added variadic format string support via `string.format`.

4. **RC-4: dns.query/reverse nil params**: Changed `dns.query` domain and `dns.reverse` ip params from `String` to `Option<String>`. Both return nil for nil input.

### Build Verification

- `cargo clippy -p rustnmap-nse --lib -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (235 tests, 0 failures)
- `cargo fmt` - PASS

### Regression Tests (All PASS)

| Script | Target | Result |
|--------|--------|--------|
| banner.nse | SSH 172.28.0.4:22 | PASS - shows SSH-2.0-OpenSSH_9.6 |
| smtp-commands | SMTP 172.28.0.8:25 | PASS - shows EHLO response |
| http-title | Web 172.28.0.3:80 | PASS - shows page title |
| ssl-cert | HTTPS 172.28.0.3:443 | PASS - shows certificate details |
| ssh-auth-methods | SSH 172.28.0.4:22 | PASS - shows publickey |

---

## Session Summary (2026-04-01) - Phase 1

### Bugs Fixed

1. **Silent Script Failures**: Changed 4 `debug!` to `warn!` in `orchestrator.rs`. Script execution and rule evaluation failures are now visible at default log level.

2. **comm.exchange/get_banner Table Arguments**: Rewrote both functions to accept `Value` for host/port parameters. Added `extract_host()` and `extract_port()` helper functions that handle both string/integer and table (with `.ip`/`.number` fields) arguments.

### Build Verification

- `cargo clippy -p rustnmap-nse -p rustnmap-core --lib -- -D warnings` - PASS (zero warnings)
- `cargo test -p rustnmap-nse --lib` - PASS (235 tests, 0 failures)
- `cargo fmt` - PASS

### Expected Impact

The comm fix should resolve the **banner script category** (5 scripts: banner on SSH, FTP, SMTP, POP3, Telnet). These were failing because `comm.exchange(host, port, data)` was called with table arguments, but only string/integer were accepted.

The warn-level logging makes all remaining failures visible to users for easier debugging.

---

## Previous Session (2026-03-31)

### NSE Comparison Test Results Against Docker Targets

**Run 2 (06:47)**: 9 PASS/WARN, 24 FAIL, 13 SKIP out of 46 tests (19.5%)
**Run 1 (02:14)**: 8 PASS, 25 FAIL, 13 SKIP out of 46 tests (17.3%)

### What Was Done

1. Docker test range with 19 containers
2. 7 code fixes (new_try, receive_lines, comm MultiValue, etc.)
3. Two full test runs
4. Build clean with zero warnings

### Root Causes for Remaining FAIL Tests

| Category | Scripts | Root Cause |
|----------|---------|------------|
| Banner scripts | banner (SSH, FTP, SMTP, POP3, Telnet) | `comm.exchange` returns nil data - **FIXED 2026-04-01** |
| SSL/TLS scripts | ssl-date, ssl-enum-ciphers, tls-alpn | tls.lua binary parsing incompatible |
| HTTP library scripts | http-git, http-enum, http-headers, http-date | Missing http.lua functions |
| Service-specific scripts | redis-info, smb-protocols, smtp-commands, imap-capabilities | Protocol library incompatibility |
| UDP scripts | dns-recursion, ntp-info, snmp-info, snmp-sysdescr | UDP socket/portrule issues |
| SMB/LDAP/RPC | smb-protocols, ldap-rootdse, ldap-search, rpcinfo | Complex protocol library missing |
| Network scripts | fcrdns | DNS resolution library issues |
