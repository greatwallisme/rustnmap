# Task Plan: FTP Bounce Scan (-b) Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Status**: In Progress
> **Created**: 2026-02-14
> **Goal**: Implement FTP Bounce Scan (-b) for indirect port scanning via FTP servers

---

## Goal

Implement FTP Bounce Scan (-b), a scanning technique that uses an FTP server as an intermediary to scan target hosts indirectly. This evades firewall rules and hides the scanner's identity.

## Background

### FTP Bounce Scan Principles

1. **FTP PORT Command**: The FTP protocol allows clients to specify a data connection target using the `PORT a,b,c,d,e,f` command (where a-f are octets of IP and port)
2. **Bounce Attack**: By specifying a target host instead of the client, the FTP server connects to the target on behalf of the scanner
3. **Port State Detection**:
   - **Open**: FTP server reports successful data connection (150/226 response)
   - **Closed**: FTP server reports connection refused (425/426 response)
   - **Filtered**: Timeout or no meaningful response

### Reference Documentation

- Design doc: `doc/modules/port-scanning.md`
- Nmap reference: `reference/nmap/scan_engine.cc`

---

## Current Phase

COMPLETE

---

## Phases

### Phase 1: Requirements & Discovery

- [x] Read design document `doc/modules/port-scanning.md` for FTP bounce requirements
- [x] Study existing scanner implementations (syn_scan.rs, connect_scan.rs)
- [x] Identify FTP command sequences needed (PORT, LIST, etc.)
- [x] Document findings in findings.md
- **Status:** complete

---

### Phase 2: Planning & Structure

- [x] Define `FtpBounceScanner` structure
- [x] Design FTP control connection handling
- [x] Design bounce attack command sequence
- [x] Determine port state mapping from FTP responses
- [x] Plan error handling strategy
- **Status:** complete

---

### Phase 3: Implementation

- [x] Create `ftp_bounce_scan.rs` module
- [x] Implement FTP control connection (TCP)
- [x] Implement PORT command construction
- [x] Implement FTP response parsing
- [x] Implement port state determination logic
- [x] Implement `PortScanner` trait for `FtpBounceScanner`
- [x] Add module export to `lib.rs`
- **Status:** complete

---

### Phase 4: Testing & Verification

- [x] Add unit tests for `FtpBounceScanner`
- [x] Add tests for FTP command generation
- [x] Add tests for response parsing
- [x] Run `cargo build` - must pass
- [x] Run `cargo clippy -- -D warnings` - zero warnings
- [x] Run `cargo test` - all tests pass (63 tests)
- **Status:** complete

---

### Phase 5: Documentation & Delivery

- [x] Update module documentation
- [x] Add examples to doc comments
- [x] Review implementation against design doc
- [x] Final verification
- **Status:** complete

---

## Implementation Complete

**Summary:**
- FTP Bounce Scan (`-b`) implemented in `crates/rustnmap-scan/src/ftp_bounce_scan.rs`
- 10 unit tests added and passing
- Zero clippy warnings
- Follows existing scanner patterns (`TcpConnectScanner`)
- Does not require root privileges

**Files Modified:**
- `crates/rustnmap-scan/src/ftp_bounce_scan.rs` (created)
- `crates/rustnmap-scan/src/lib.rs` (updated exports)

**Test Results:**
- 63 tests passing in rustnmap-scan (+10 new)
- Build: PASS
- Clippy: PASS (zero warnings)

---

## Key Questions

1. What FTP response codes indicate open vs closed ports?
2. How to handle FTP servers that don't allow PORT commands (passive mode only)?
3. Should we support authentication for protected FTP servers?
4. What's the appropriate timeout for FTP bounce operations?

---

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Follow `TcpConnectScanner` pattern | FTP bounce doesn't require root privileges, similar to connect scan |
| Use `std::net::TcpStream` | Standard TCP connection for FTP control channel |
| Implement `PortScanner` trait | Consistent with all other scanner implementations |
| Support anonymous FTP first | Most bounce servers allow anonymous; auth can be added later |

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
|       | 1       |            |

---

## Notes

- FTP Bounce Scan does NOT require root privileges (uses normal TCP connections)
- This is the only remaining scan type that doesn't need raw sockets
- Reference: Nmap's `bouncescan.cc` implementation
