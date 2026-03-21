# NSE Module Status

> **Updated**: 2026-03-21 03:30
> **Purpose**: Factual record of NSE module completion status and problems

---

## Current Test Results

Benchmark against scanme.nmap.org (45.33.32.156):

| Script | Status | Issue |
|--------|--------|-------|
| http-title | PASS | Works correctly |
| http-server-header | PASS | Works correctly |
| http-methods | PASS | Works correctly |
| ssh-hostkey | PASS | All 4 keys (DSA, RSA, ECDSA, ED25519) returned |
| ssh-auth-methods | FAIL | Only outputs banner, not auth methods |
| http-robots.txt | SKIPPED | Target has no robots.txt |
| ssl-cert | SKIPPED | Target has no port 443 |
| ssl-enum-ciphers | SKIPPED | Target has no port 443 |
| http-ssl-cert | SKIPPED | Target has no port 443 |
| http-git | SKIPPED | Target has no git repo |
| http-enum | SKIPPED | Not tested |
| smb-os-discovery | SKIPPED | Target has no port 445 |
| smb-enum-shares | SKIPPED | Target has no port 445 |

**Pass Rate**: 4/14 tested scripts work correctly (29%)
**Skipped Rate**: 9/14 tests cannot run against single target (64%)

---

## Known Problems

### 1. ssh-auth-methods - Incomplete SSH Key Exchange

**Status**: FAIL - Only outputs SSH banner

**Root Cause**:
The `libssh2_utility.rs` SSH implementation stops after KEXINIT exchange. It does NOT complete:
- DH key exchange (KEXDH_INIT/REPLY)
- NEWKEYS activation

When the script sends `SSH_MSG_SERVICE_REQUEST`, the server disconnects because key exchange is incomplete.

**Why Nmap works**:
Nmap uses the C library libssh2 which handles the full SSH handshake internally.

**Required Fix**:
Implement complete SSH key exchange in `libssh2_utility.rs`:
1. DH key exchange computation
2. KEXDH_INIT packet send
3. KEXDH_REPLY receive and parse
4. NEWKEYS send/receive
5. Service request handling

**Complexity**: High - Requires implementing Diffie-Hellman cryptographic operations

---

### 2. Test Coverage Problem

**Status**: CRITICAL - Most NSE scripts are never tested

**Problem**:
Benchmark uses single target (scanme.nmap.org) which only has ports 80 and 22 open.
- SSL/TLS scripts cannot be tested
- SMB scripts cannot be tested
- Many HTTP scripts cannot be tested

**Impact**:
- SSL/TLS implementation may have bugs, but tests won't find them
- SMB implementation may not work at all, but we don't know
- http-enum may timeout or crash, but we don't test it

**Required Fix**:
Set up test infrastructure:
1. Multiple test targets with different services
2. Local test servers for SSL/TLS, SMB, etc.
3. Mock services for comprehensive testing

**Complexity**: Medium - Requires infrastructure setup

---

## File Status

### Working (Verified)
- `engine.rs` - Script execution engine
- `stdnse.rs` - Standard NSE library functions
- `nmap.rs` - Core Nmap functions (mutex, fetchfile, registry)
- `http.rs` - HTTP library
- `ssh2.rs` - SSH-2 host key fetching (fixed binary parsing bug)
- `ssh1.rs` - SSH-1 protocol library

### Problematic
- `libssh2_utility.rs` - Incomplete SSH key exchange, causes ssh-auth-methods to fail

### Untested (Unknown Status)
- `ssl.rs` - SSL/TLS library - NEVER TESTED
- `dns.rs` - DNS library - NEVER TESTED
- `smb.rs` - SMB library - NEVER TESTED
- `comm.rs` - Communication library - MINIMALLY TESTED
- `shortport.rs` - Port matching - NOT INDEPENDENTLY TESTED

---

## Current Bugs Fixed This Session

### Binary SSH Host Key Parsing (2026-03-21)

**Problem**:
`parse_string()` was using `String::from_utf8_lossy()` on binary SSH key data, causing data corruption (435 bytes → 780 bytes).

**Fix**:
Created `parse_bytes()` function that returns raw `Vec<u8>` for binary data.

**Result**:
All 4 SSH host key types now parse correctly.

---

## Open Problems (Priority Order)

1. **ssh-auth-methods key exchange** - HIGH PRIORITY
   - Blocks SSH authentication enumeration
   - Requires cryptographic implementation

2. **Test infrastructure** - HIGH PRIORITY
   - Cannot verify SSL/TLS implementation works
   - Cannot verify SMB implementation works
   - Cannot verify many HTTP scripts work

3. **http-enum timeout** - MEDIUM PRIORITY
   - Script may timeout or hang
   - Not tested in current benchmark

---

## Next Actions

1. Fix ssh-auth-methods by implementing full SSH key exchange
2. Set up multi-target test infrastructure
3. Test SSL/TLS implementation against HTTPS target
4. Test SMB implementation against SMB target
