# Progress: NSE Development

> **Updated**: 2026-03-19 00:30

---

## Session 2026-03-19 00:00: Script Output Format Fixes

### Problem
http-title, http-server-header output wrong format:
```
Expected: |_http-title: Go ahead and ScanMe!
Actual:   | http-title
          |   title: Go ahead and ScanMe!
          |_  Go ahead and ScanMe!
```

### Root Causes Found

1. **Return value handling**: Scripts return `(table, string)`, we processed both
2. **Missing __len**: `#output` returned 0 for string-key tables
3. **Missing __tostring**: Nested tables with `__tostring` metamethod ignored

### Fixes Applied

| File | Change |
|------|--------|
| `engine.rs` | Use string output when available, fall back to table |
| `stdnse.rs` | Add `__len` metamethod to output_table |
| `engine.rs` | Use Lua's `tostring()` for nested table values |

### Test Results

| Test | Before | After |
|------|--------|-------|
| http-title | PASS (wrong format) | PASS (correct) |
| http-server-header | PASS (wrong format) | PASS (correct) |
| http-methods | FAIL | PASS |

### Remaining Issues

1. **SSH scripts**: Key exchange incomplete - server disconnects
2. **http-enum**: Script doesn't execute - needs debug

---

## Session 2026-03-18: Library Implementations

### Completed

| Module | Functions |
|--------|-----------|
| stringaux | strjoin, strsplit, filename_escape, ipattern |
| tableaux | tcopy, shallow_tcopy, invert, contains, keys |
| stdnse | debug1-5, output_table with __len |
| libssh2-utility | connect_pcall host table support |

### Benchmark Progress

| Date | Pass | Fail | Skip |
|------|------|------|------|
| 2026-03-18 start | 3 | 4 | 8 |
| 2026-03-19 end | 4 | 2 | 9 |

---

## Next Session Priorities

1. SSH key exchange implementation (complex)
2. http-enum debugging
3. Additional NSE library support
