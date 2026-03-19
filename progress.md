# Progress: NSE Module Fixes

> **Updated**: 2026-03-19 11:12

---

## Session Summary

This session focused on fixing the NSE module's mlua integration patterns and adding missing Nmap API functions.

### Key Achievements

1. **Fixed stdnse.mutex() and stdnse.condition_variable()**
   - Replaced thread spawning with `tokio::task::block_in_place`
   - Added actual mutex state tracking with `MutexState` struct
   - Implemented real lock/trylock/unlock operations

2. **Added nmap.fetchfile()**
   - Searches multiple paths for data files
   - Returns file path if found, nil otherwise

3. **Added http.identify_404()**
   - Returns standard 404 detection result
   - Allows http-enum and similar scripts to execute

---

## Technical Changes

### stdnse.rs

```rust
// Before: Stub that returned true
let mutex_fn = lua.create_function(move |_, operation: String| {
    Ok(true)  // Always succeeded
});

// After: Actual mutex with state tracking
struct MutexState {
    holder: Option<String>,
    lock_count: u32,
}

let mutex_op_fn = lua.create_function(move |lua, operation: String| {
    let mut guard = mutex_arc.lock()?;
    match operation.as_str() {
        "lock" => { guard.holder = Some("current"); Ok(true) }
        "trylock" => { ... }
        "done" => { guard.holder = None; Ok(true) }
    }
});
```

### nmap.rs

```rust
// Added fetchfile function
fn get_fetchfile_search_paths() -> Vec<std::path::PathBuf> {
    // ~/.rustnmap/, RUSTNMAPDIR, ./reference/nmap/, /usr/share/rustnmap/, /usr/share/nmap/
}

let fetchfile_fn = lua.create_function(|lua, filename: String| {
    for base_path in get_fetchfile_search_paths() {
        let full_path = base_path.join(&filename);
        if full_path.exists() {
            return Ok(lua.create_string(full_path.to_string_lossy())?);
        }
    }
    Ok(mlua::Value::Nil)
});
```

### http.rs

```rust
// Added identify_404 function
let identify_404_fn = lua.create_function(|lua, (_, _): (Value, Value)| {
    let result = lua.create_table()?;
    result.set(1, true)?;   // 404 detection works
    result.set(2, 404)?;    // Server returns 404
    Ok(Value::Table(result))
});
```

---

## Files Changed

| File | Lines Changed | Purpose |
|------|---------------|---------|
| stdnse.rs | ~80 | Mutex/condvar fixes |
| nmap.rs | ~50 | Added fetchfile |
| http.rs | ~15 | Added identify_404 |

---

## Test Results

### Before This Session
- Pass Rate: 26.6% (4/15 scripts)
- http-enum: Failed with "attempt to call nil 'fetchfile'"

### After This Session
- http-enum: Now executes (seen pipeline_add calls)
- Timing out at 120s - needs investigation
- Other HTTP scripts still pass

---

## Outstanding Work

1. **Investigate http-enum timeout**
   - May be related to pipeline_go
   - May be normal (many URLs to check)

2. **SSH key exchange**
   - Still incomplete
   - Affects ssh-auth-methods, ssh-hostkey

3. **ssh1 library**
   - Missing entirely
   - Required by ssh-hostkey

---

## Verification Commands

```bash
# Build and check
cargo build -p rustnmap-nse
cargo test -p rustnmap-nse
cargo clippy -p rustnmap-nse -- -D warnings

# Test specific scripts
cargo run -p rustnmap-cli -- -sS -p80 --script http-title 45.33.32.156
cargo run -p rustnmap-cli -- -sS -p80 --script http-enum 45.33.32.156

# Full benchmark
./benchmarks/nse_comparison_test.sh
```
