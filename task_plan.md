# Task Plan: RustNmap NSE Development

> **Updated**: 2026-03-19 00:30
> **Status**: NSE Script Output Fixes Complete

---

## Current State

### What Works
| Script | Status | Notes |
|--------|--------|-------|
| http-title | PASS | Output format correct |
| http-server-header | PASS | Output format correct |
| http-methods | PASS | Output format correct |
| http-git | PASS | Works on applicable targets |

### What Doesn't Work
| Script | Status | Root Cause |
|--------|--------|------------|
| ssh-auth-methods | WARN | SSH key exchange incomplete |
| ssh-hostkey | FAIL | SSH key exchange incomplete |
| http-enum | FAIL | Needs investigation |

---

## Problems

### Problem 1: SSH Key Exchange Incomplete

**Symptom**: `list auth methods failed: Expected SERVICE_ACCEPT, got message type 1`

**Root Cause**: `libssh2_utility.rs` only implements:
1. Banner exchange
2. KEXINIT exchange

**Missing**: Complete DH/ECDH key exchange before sending SSH_MSG_SERVICE_REQUEST

**Why it matters**: SSH servers disconnect if you send SERVICE_REQUEST before completing key exchange

**Solution options**:
1. Implement full SSH2 key exchange (complex, ~500 lines)
2. Use `ssh2` crate via FFI
3. Accept SSH scripts won't work for now

### Problem 2: HTTP Enum Failure

**Symptom**: Script doesn't execute

**Root Cause**: Unknown - needs debugging

**Next step**: Add debug logging, trace script execution

---

## Fixes Applied This Session

### Fix 1: Script Return Value Handling
**File**: `engine.rs`
**Problem**: Scripts return `(table, string)` but we processed all values together
**Fix**: Use string for display, fall back to table only if no string

### Fix 2: output_table __len Metamethod
**File**: `stdnse.rs`
**Problem**: `#output` returned 0 for tables with string keys
**Fix**: Added `__len` metamethod that counts all keys

### Fix 3: Table tostring Support
**File**: `engine.rs`
**Problem**: Tables with `__tostring` metamethod weren't formatted correctly
**Fix**: Use Lua's `tostring()` for nested table values

---

## Files Modified

| File | Lines Changed | Purpose |
|------|---------------|---------|
| engine.rs | +223 | Return value handling, tostring |
| stdnse.rs | +171 | __len metamethod, debug1-5 |
| libssh2_utility.rs | ~50 | connect_pcall host table support |
| comm.rs | +98 | SSL/TLS improvements |
| mod.rs | +95 | New library registrations |

---

## Next Steps

### Priority 1: SSH Key Exchange (High Effort)
Implement full SSH2 key exchange in `libssh2_utility.rs`:
- DH group exchange
- ECDH key exchange
- New keys message handling

### Priority 2: HTTP Enum Debug (Medium Effort)
- Add trace logging
- Identify why script doesn't execute
- Check portrule matching

### Priority 3: More NSE Libraries (Lower Priority)
- snmp library
- ldap library
- mysql library

---

## Benchmark Pass Rate

| Date | Pass | Fail | Skip | Rate |
|------|------|------|------|------|
| 2026-03-18 | 3 | 4 | 8 | 20% |
| 2026-03-19 | 4 | 2 | 9 | 26.6% |

Improvement: +1 pass, -2 fail (http-methods now works)
