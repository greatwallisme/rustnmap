# NSE Module Technical Findings

> **Updated**: 2026-03-21 05:30

## Purpose
Factual record of bugs discovered and fixed during NSE module development.

---

## Recent Bugs (2026-03-21)

### Feature: SSH Key Exchange Implementation Complete

**Date**: 2026-03-21
**File**: `crates/rustnmap-nse/src/libs/libssh2_utility.rs`

**Problem**:
The SSH implementation in `libssh2_utility.rs` stopped after KEXINIT exchange. It did not complete:
- DH key exchange (KEXDH_INIT/REPLY)
- NEWKEYS activation
- Service request handling

This caused `ssh-auth-methods` script to fail, only outputting the SSH banner.

**Implementation**:
Implemented complete SSH key exchange per RFC 4253 Section 8:

1. **DH Group14 Parameters**: 2048-bit MODP prime from RFC 3526
2. **Key Pair Generation**: Random private key x, public key e = g^x mod p
3. **KEXDH_INIT**: Send client public key e to server
4. **KEXDH_REPLY**: Receive server public key f and host key
5. **Shared Secret**: Compute K = f^x mod p
6. **Exchange Hash**: H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K)
7. **NEWKEYS**: Complete key activation

**Key Functions Added**:
```rust
fn generate_dh_key_pair() -> (BigUint, BigUint)
fn build_kexdh_init(e: &BigUint) -> Vec<u8>
fn parse_kexdh_reply(data: &[u8]) -> mlua::Result<(Vec<u8>, BigUint, Vec<u8>)>
fn compute_exchange_hash(...) -> Vec<u8>
fn perform_key_exchange(...) -> mlua::Result<KeyExchangeResult>
```

**Dependencies**:
- `num-bigint` - Big integer arithmetic
- `rand` - Cryptographic random number generation
- `sha2` - SHA256 hashing

**Code Quality**:
- Zero compiler warnings (`cargo clippy -- -D warnings`)
- All 238 tests pass
- Proper documentation with backticks
- `#[expect]` attributes for justified exceptions

**Testing Required**:
Run `ssh-auth-methods` script against real SSH server to verify authentication methods are returned.

**Lines Changed**:
- Added constants: lines ~200-210
- Added helper functions: lines ~250-380
- Added key exchange functions: lines ~390-450
- Added `perform_key_exchange()`: lines ~560-650
- Updated `ConnectionState`: added key exchange fields
- Updated `connect()`: calls `perform_key_exchange()`

**Unit Tests Added (2026-03-21)**:
- `test_parse_mpint` - MPINT parsing from binary data
- `test_parse_mpint_with_high_bit_set` - MPINT with zero padding
- `test_serialize_mpint` - MPINT serialization
- `test_serialize_mpint_high_bit` - MPINT with high bit set
- `test_parse_bytes` - Binary string parsing
- `test_parse_bytes_empty` - Empty binary string
- `test_compute_shared_secret` - DH shared secret computation
- `test_build_kexdh_init` - KEXDH_INIT packet construction
- `test_parse_kexdh_reply_valid` - Valid KEXDH_REPLY parsing
- `test_parse_kexdh_reply_empty` - Empty packet error handling
- `test_parse_kexdh_reply_wrong_type` - Wrong message type error
- `test_exchange_hash_deterministic` - Hash determinism
- `test_exchange_hash_different_inputs` - Hash varies with inputs
- `test_dh_constants_defined` - DH constants validation

All 17 unit tests pass.

---

### Discovery: SSH Post-NEWKEYS Encryption Required (2026-03-21)

**Date**: 2026-03-21
**File**: `crates/rustnmap-nse/src/libs/libssh2_utility.rs`
**Test**: `ssh-auth-methods.nse` against scanme.nmap.org:22

**What Was Tested**:
Running the SSH key exchange implementation against a real SSH server to verify end-to-end functionality.

**Test Result**: FAILED

**Error Message**:
```
list auth methods failed: runtime error: Expected SERVICE_ACCEPT, got message type 1
```

**What Works**:
- ✅ Banner retrieval
- ✅ KEXINIT negotiation
- ✅ DH Group14 key exchange (2048-bit MODP)
- ✅ KEXDH_INIT/KEXDH_REPLY packet handling
- ✅ Shared secret computation
- ✅ Exchange hash calculation (SHA256)
- ✅ NEWKEYS activation (both directions)

**What's Missing**:
After NEWKEYS phase, SSH protocol (RFC 4253) requires **all packets to be encrypted**. The current implementation sends unencrypted packets, which servers reject.

**SSH Protocol Flow** (RFC 4253):
```
...key exchange steps...
NEWKEYS (client) ---------->
                  <-------- NEWKEYS (server)
[=== ENCRYPTION STARTS HERE ===]
SERVICE_REQUEST (encrypted) ------>
                  <-------- SERVICE_ACCEPT (encrypted)
USERAUTH_REQUEST (encrypted) ------>
                  <-------- USERAUTH_FAILURE (encrypted) with auth methods list
```

**Root Cause**:
When `list_auth_methods_impl()` sends SERVICE_REQUEST after NEWKEYS, the packet is unencrypted. The server correctly rejects it with `SSH_MSG_DISCONNECT` (message type 1).

**Required Implementation** (RFC 4253 Section 7.2):
1. **Key Derivation**: From shared secret K and exchange hash H, derive:
   - Client-to-server encryption key
   - Server-to-client encryption key
   - Client-to-server HMAC key
   - Server-to-client HMAC key
   - Client-to-server IV
   - Server-to-client IV

2. **Encryption**: AES-128/256-CTR or CBC mode
3. **Integrity**: HMAC-SHA1 or HMAC-SHA256

**Options**:
1. Implement full encryption (2-3 days) - Add `openssl` or `aes-gcm` + `hmac` crates
2. Link against libssh2 C library (1 day) - Use proven implementation
3. Use alternative scripts that don't require post-key-exchange communication

**Recommendation**:
Implement full encryption for RFC 4253 compliance. Use the existing `openssl` crate dependency already in the project for AES and HMAC operations.

---

## Recent Bugs (2026-03-21)

### Bug: Binary SSH Host Key Data Corrupted by UTF-8 Conversion

**Date**: 2026-03-21
**File**: `crates/rustnmap-nse/src/libs/ssh2.rs`
**Function**: `parse_string()`

**Problem**:
Binary SSH host key data was being processed by `parse_string()` which uses `String::from_utf8_lossy()`. When binary data contains invalid UTF-8 sequences, the function replaces them with the 3-byte replacement character (U+FFFD).

**Evidence**:
```
parse_string: offset=1, len_field=435, data_len=631, resulting_string_len=435
String byte length mismatch: read 435 bytes but string has 780 bytes
```

**Root Cause**:
SSH protocol defines "string" as a length-prefixed byte array that can contain binary data. The host key in KEXDH_REPLY contains binary mpint values, not UTF-8 text. Using `String::from_utf8_lossy()` corrupted this data.

**Fix**:
Created `parse_bytes()` function that returns raw `Vec<u8>`:
```rust
fn parse_bytes(data: &[u8], offset: usize) -> mlua::Result<(Vec<u8>, usize)> {
    // ... read length ...
    let value = data[new_offset..new_offset + len].to_vec();
    Ok((value, new_offset + len))
}
```

Changed `fetch_host_key_impl()` to use `parse_bytes()` for host key instead of `parse_string()`.

**Result**:
All 4 SSH host key types now parse correctly:
- DSA (1024 bits)
- RSA (2048 bits)
- ECDSA (256 bits)
- ED25519 (256 bits)

**Lines Changed**:
- Added `parse_bytes()` function: lines 531-548
- Modified `fetch_host_key_impl()`: line 802

---

## Historical Bugs (Fixed)

### Bug: SSH Fingerprint Double-Encoding

**Date**: 2026-03-20
**File**: `ssh2.rs`

**Problem**:
`calculate_md5_fingerprint()` returned a formatted string like `de:b9:9f:...`. The Lua script called `stdnse.tohex(key.fingerprint)` which expected raw bytes, causing double-encoding.

**Fix**:
Changed return type from `String` to `[u8; 16]` (raw MD5 bytes).

---

### Bug: SSH-2 Packet Padding Calculation

**Date**: 2026-03-20
**File**: `ssh2.rs`

**Problem**:
Padding calculation included the 4-byte packet length field, violating RFC 4253.

**Fix**:
Changed from `8 - ((payload.len() + 1 + 4) % 8)` to `8 - ((payload.len() + 1) % 8)`.

---

## Known Limitations

### SSH Post-NEWKEYS Encryption Not Implemented (2026-03-21)

**Status**: PARTIALLY WORKING
**What Works**: Key exchange through NEWKEYS phase (RFC 4253 compliant)
**What's Missing**: Post-NEWKEYS packet encryption

**Current Behavior**:
- Key exchange completes successfully (DH Group14, 2048-bit MODP)
- NEWKEYS activation works both directions
- **Packets after NEWKEYS must be encrypted** but are sent unencrypted
- Servers reject unencrypted post-NEWKEYS packets with disconnect

**Impact**:
- `ssh-auth-methods` script fails at SERVICE_REQUEST phase
- Any SSH communication requiring authentication will fail
- Host key fetching (`ssh2` library) still works (doesn't need encryption)

**Required Fix**:
Implement per RFC 4253 Section 7.2:
1. Derive encryption/integrity keys from shared secret K and exchange hash H
2. Add AES-CTR/CBC encryption for packet data
3. Add HMAC-SHA1/256 for packet integrity
4. Encrypt/decrypt all packets after NEWKEYS

---

## Untested Modules

The following modules have NEVER been tested against real targets:

- `ssl.rs` - SSL/TLS functionality
- `smb.rs` - SMB protocol
- `dns.rs` - DNS protocol
- Most of `http.rs` beyond basic GET requests

**Reason**: Current test target (scanme.nmap.org) only has HTTP (port 80) and SSH (port 22).

---

## Code Quality

All Rust code passes:
- `cargo clippy -- -D warnings` (zero warnings)
- `cargo test` (all 238 tests pass)
- `cargo fmt --check` (properly formatted)

`#[expect(...)]` attributes used for justified exceptions:
- `clippy::many_single_char_names` - Variable names match RFC 4253 specification
- `clippy::too_many_arguments` - Parameter count matches RFC 4253 specification
- `clippy::cast_possible_truncation` - SSH protocol uses 32-bit length prefixes

No global `#![allow(...)]` module-level attributes used.
