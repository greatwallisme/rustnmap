# Task Plan: NSE SSL Scripts Full Support

> **Created**: 2026-03-27
> **Status**: IN PROGRESS

---

## Goal

Implement full support for all 9 SSL-related NSE scripts in the NSE engine.

---

## Current State

### Already Working
- `ssl-cert.nse` -- Certificate retrieval and display (COMPLETE)
- `ssl-cert-intaddr.nse` -- Private IP disclosure (uses same sslcert API, should work)

### Requires New Implementation
All remaining scripts share a common dependency: **the `tls` Lua library must be available**.

---

## Script Categories by Implementation Complexity

### Category A: Certificate-only (minimal new work)
| Script | Status | Notes |
|--------|--------|-------|
| ssl-cert.nse | COMPLETE | Working |
| ssl-cert-intaddr.nse | LIKELY WORKS | Same sslcert API, needs ipOps.isPrivate |
| ssl-known-key.nse | NEEDS WORK | Requires nmap.fetchfile(), file I/O |

### Category B: Manual TLS (needs `tls` library)
| Script | Difficulty | Key TLS Operations |
|--------|-----------|-------------------|
| ssl-date.nse | LOW | Minimal ClientHello + ServerHello time extraction |
| ssl-poodle.nse | MEDIUM | SSLv3 ClientHello, CBC ciphers, FALLBACK_SCSV |
| ssl-heartbleed.nse | HIGH | Malformed Heartbeat record construction |
| ssl-ccs-injection.nse | HIGH | Out-of-order CCS, alert discrimination |
| ssl-enum-ciphers.nse | HIGH | Full cipher enumeration, concurrent threads |
| ssl-dh-params.nse | HIGH | DHE cipher filtering, ServerKeyExchange DH params |

---

## Implementation Phases

### Phase 1: Verify Category A Scripts - PENDING
**Goal**: Confirm ssl-cert-intaddr and ssl-known-key work or identify blockers.

Steps:
1. Test ssl-cert-intaddr.nse against a real target
2. Test ssl-known-key.nse (may need nmap.fetchfile support)
3. Fix any issues found

**Estimated files to modify**: 0-2

---

### Phase 2: Pure Lua `tls` Library - PENDING
**Goal**: Make the existing `nselib/tls.lua` loadable by NSE scripts.

The `tls.lua` is a 2073-line pure Lua library. Since we already have the Lua file loader (Phase 1 from previous session), `tls.lua` should be loadable. However, it depends on other pure Lua libraries:

**Dependencies**:
- `nselib/sslcert.lua` (1099 lines) -- already loadable
- `nselib/tls.lua` depends on: `openssl`, `stdnse`, `base64`, `bin`

The key question: does `tls.lua` use any C-based OpenSSL functions via `require "openssl"` that we haven't implemented?

Steps:
1. Verify tls.lua loads without errors
2. Test that `tls.client_hello()`, `tls.record_buffer()`, `tls.record_read()`, `tls.record_write()` work
3. Test that `tls.CIPHERS`, `tls.PROTOCOLS`, `tls.cipher_info()` tables are populated
4. Fix any missing Lua APIs

**Estimated files to modify**: 0-3

---

### Phase 3: Missing Lua Library Functions - PENDING
**Goal**: Implement any missing Lua APIs needed by SSL scripts.

Based on analysis, these may be needed:
- `match.numbytes()` -- exact byte count receive pattern
- `vulns.Report` / `vulns.STATE` -- vulnerability reporting
- `listop.filter()` -- list filtering
- `coroutine` operations for stdnse.new_thread()
- `nmap.condvar()` -- condition variable for thread sync
- `nmap.fetchfile()` -- data file path resolution
- `stdnse.new_thread()` -- concurrent script execution
- `ipOps.isPrivate()` -- RFC1918 check

Steps:
1. Run each SSL script and collect error messages
2. Implement missing APIs one by one
3. Re-test after each implementation

**Estimated files to modify**: 2-5

---

### Phase 4: Test ssl-date.nse (Simplest TLS Script) - PENDING
**Goal**: Get the simplest TLS manual script working as proof of concept.

Steps:
1. Run ssl-date.nse against www.qq.com:443
2. Debug any TLS protocol issues
3. Verify server time extraction works

---

### Phase 5: Test ssl-poodle.nse - PENDING
**Goal**: SSLv3 CBC cipher testing.

Steps:
1. Run against test target
2. Fix cipher filtering issues
3. Verify FALLBACK_SCSV detection

---

### Phase 6: Test ssl-heartbleed.nse - PENDING
**Goal**: Heartbleed vulnerability detection.

Steps:
1. Run against test target
2. Fix heartbeat record construction
3. Verify vulnerability detection logic

---

### Phase 7: Test ssl-ccs-injection.nse - PENDING
**Goal**: CCS injection vulnerability detection.

Steps:
1. Run against test target
2. Fix CCS record construction and alert parsing
3. Verify vulnerability detection

---

### Phase 8: Test ssl-enum-ciphers.nse - PENDING
**Goal**: Full cipher enumeration.

Steps:
1. Run against test target
2. Fix concurrent thread execution
3. Verify cipher list output

---

### Phase 9: Test ssl-dh-params.nse - PENDING
**Goal**: DH parameter extraction and classification.

Steps:
1. Run against test target
2. Fix ServerKeyExchange parsing
3. Verify DH group classification

---

### Phase 10: Final Verification - PENDING
**Goal**: All SSL scripts pass against real targets.

Steps:
1. Run all 9 scripts against multiple targets
2. Verify zero warnings/errors in build
3. Update documentation

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| (none yet) | | |

---

## Key Architecture Decision

**Strategy**: Leverage existing pure Lua `tls.lua` library rather than reimplementing in Rust.

The `tls.lua` library (2073 lines) contains all the TLS protocol logic. Since the Lua file loader is already working, the most efficient approach is to make `tls.lua` loadable and let the Lua scripts handle TLS protocol operations through it, rather than reimplementing the entire TLS record layer in Rust.

The Rust side only needs to provide:
1. Socket I/O (already implemented: `connect`, `send`, `receive`)
2. Missing utility libraries (`match`, `vulns`, `listop`, etc.)
3. Any missing `openssl` Lua bindings that `tls.lua` needs
