# Task Plan: NSE Module Fixes

> **Updated**: 2026-03-19 09:10
> **Status**: Progress Made, More Work Needed

---

## Summary of Session Progress

### Fixes Applied

| Fix | File | Description |
|-----|------|-------------|
| stdnse.mutex() | stdnse.rs | Uses block_inplace with actual mutex locking |
| stdnse.condition_variable() | stdnse.rs | Uses block_inplace with actual cvar ops |
| nmap.fetchfile() | nmap.rs | Searches for data files in multiple paths |
| http.identify_404() | http.rs | Returns standard 404 detection result |
| ssh1 library | ssh1.rs | NEW: SSH-1 protocol library with fingerprint formatting |
| SCRIPT_TYPE global | engine.rs | Sets script type (portrule/hostrule/postrule) |
| name_confidence | engine.rs | Sets port.version.name_confidence to 8 |

### Pass Rate Progress

- Previous: 26.6% (4/15 scripts)
- Current: 26.6% (4/15 scripts) - same count but more scripts execute

**Note**: ssh-hostkey now executes without Lua errors (no output yet due to SSH key fetch)

---

## Current Problems

### Problem 1: Scripts Running But No Output

| Test | Status | Issue |
|------|--------|-------|
| http-title | PASS | - |
| http-server-header | PASS | - |
| http-methods | PASS | - |
| ssh-hostkey | EXECUTES | Runs but no SSH key output (libssh2 not connected) |
| http-enum | TIMEOUT | Runs but slow (120s timeout) |

### Problem 2: SSH Implementation Issues

- `ssh-hostkey`: Needs libssh2 connection to fetch host keys
- `ssh-auth-methods`: Key exchange incomplete, shows only banner

### Problem 3: HTTP Pipeline Performance

- http-enum runs but is slow (many URLs to check)
- May need pipeline optimization

---

## Outstanding Issues

1. **SSH Key Fetching**: Need to implement actual SSH key retrieval via libssh2
2. **HTTP Pipeline Performance**: http-enum runs but is slow
3. **ssh-auth-methods Output**: Only shows banner, needs full auth method list

---

## Next Steps (Priority Order)

1. [ ] Implement libssh2 key fetching for ssh-hostkey
2. [ ] Optimize http-enum pipeline performance
3. [ ] Fix ssh-auth-methods output format
4. [ ] Run full benchmark
5. [ ] Commit changes

---

## Error Log

| Error | Script | Status |
|-------|--------|--------|
| attempt to call nil 'mutex' | http-enum | FIXED |
| attempt to call nil 'fetchfile' | http-enum | FIXED |
| attempt to call nil 'identify_404' | http-enum | FIXED |
| attempt to call nil 'ssh1' | ssh-hostkey | FIXED |
| attempt to call nil '?' (SCRIPT_TYPE) | ssh-hostkey | FIXED |
| attempt to compare nil with number | ssh-hostkey | FIXED |
| ssh1 not found | ssh-hostkey | FIXED |
| key exchange failed | ssh-auth-methods | OPEN |
| http-enum timeout | http-enum | OPEN |
