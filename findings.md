# NSE Module Technical Findings

> **Updated**: 2026-03-21 03:30

## Purpose
Factual record of bugs discovered and fixed during NSE module development.

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

### ssh-auth-methods Does Not Work

**Status**: FAIL
**Reason**: Incomplete SSH key exchange implementation in `libssh2_utility.rs`

**Missing Steps**:
1. DH key exchange (KEXDH_INIT/REPLY)
2. NEWKEYS activation
3. Service request handling

**Current Behavior**: Only outputs SSH banner instead of authentication methods.

**Nmap Reference**: Uses C library libssh2 which handles full handshake internally.

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
- `cargo test` (all tests pass)
- `cargo fmt --check` (properly formatted)

No `#[allow(...)]` attributes used to suppress warnings.
