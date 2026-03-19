# Findings: NSE Development

> **Updated**: 2026-03-19 11:00

---

## Technical Findings

### Finding 1: Nmap Script Return Convention

**Discovery**: Nmap scripts return two values: `(table, string)`

```lua
-- http-title.nse
return output_tab, output_str
```

- First value: Table for structured output (XML/JSON)
- Second value: String for display (normal output)

**Impact**: Must use string for display, not table

**File**: `engine.rs` lines 640-688

---

### Finding 2: Lua `#` Operator Only Counts Array Keys

**Discovery**: `#table` returns length of array part, not total keys

```lua
local t = {}
t["key"] = "value"
print(#t)  -- prints 0, not 1

local t2 = { "a", "b" }
print(#t2)  -- prints 2
```

**Impact**: Scripts check `if #output > 0` to decide whether to return output. Tables with string keys returned nil.

**Fix**: Added `__len` metamethod to `output_table()` that counts all keys

**File**: `stdnse.rs` lines 346-381

---

### Finding 3: __tostring Metamethod Not Respected

**Discovery**: http-methods uses `setmetatable` with custom `__tostring`:

```lua
local spacesep = {
    __tostring = function(t)
        return table.concat(t, " ")
    end
}
setmetatable(output["Supported Methods"], spacesep)
```

**Impact**: Our manual table iteration ignored `__tostring`, outputting "1: GET, 2: HEAD..."

**Fix**: Use Lua's `tostring()` function for table values, which respects metamethods

**File**: `engine.rs` lines 206-209

---

### Finding 4: SSH Key Exchange Required Before SERVICE_REQUEST

**Discovery**: SSH servers send DISCONNECT (message type 1) if you send SSH_MSG_SERVICE_REQUEST before completing key exchange

**Current implementation**:
1. Banner exchange - DONE
2. KEXINIT exchange - DONE
3. DH key exchange - MISSING
4. NEWKEYS - MISSING
5. SERVICE_REQUEST - FAILS

**Impact**: All SSH scripts fail

**Solution**: Implement full key exchange or use libssh2

---

### Finding 5: mlua Table Clone Issue

**Discovery**: `mlua::Table` doesn't implement `Clone` directly

**Workaround**: Store reference, access through `&table`

**File**: `engine.rs` line 657

---

### Finding 6: nmap.mutex() Required for http.lua Caching

**Discovery**: http.lua uses `nmap.mutex()` for thread-safe cache access

```lua
-- http.lua line 1095
local mutex = nmap.mutex(tostring(lookup_cache)..key);
mutex "lock";
-- ... cache operations ...
mutex "done";
```

**Impact**: Scripts using http cache fail with "attempt to call nil value"

**Fix**: Implemented `nmap.mutex(object)` returning function with operations:
- `"lock"` - acquire mutex
- `"trylock"` - non-blocking acquire
- `"done"` - release mutex
- `"running"` - get holder thread

**File**: `nmap.rs` lines 155-185, 306-373

---

### Finding 7: Mutex Key Generation from Lua Values

**Problem**: How to generate consistent keys from Lua objects?

**Solution**: Use type prefix + pointer/value

```rust
fn value_to_mutex_key(value: &mlua::Value) -> Option<String> {
    match value {
        mlua::Value::String(s) => Some(format!("s:{}", s.to_str()?)),
        mlua::Value::Table(t) => Some(format!("t:{:p}", t.to_pointer())),
        mlua::Value::Function(f) => Some(format!("f:{:p}", f.to_pointer())),
        // ...
    }
}
```

**Note**: Same object = same key. Different objects with same value = different keys.

---

### Finding 8: package.preload Registration Required

**Discovery**: `require("ipOps")` fails even when library is in globals

**Cause**: Lua's `require()` checks `package.preload` first

**Fix**: Register all libraries in both globals AND package.preload

```rust
// mod.rs register_package_preload()
let library_names = [
    "nmap", "stdnse", "comm", "shortport",
    "http", "ssh2", "ssl", "dns", // ...
    "ipOps", "base64",
];
```

**File**: `mod.rs` lines 142-188

---

### Finding 9: Thread Spawning Anti-Pattern in Lua Callbacks

**Problem**: Spawning threads with new Tokio runtimes inside Lua callbacks is wasteful

**Original Code**:
```rust
let _mutex = std::thread::spawn(move || {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(get_or_create_mutex(&name_clone))
})
```

**Fix**: Use `tokio::task::block_in_place` pattern

```rust
let handle = tokio::runtime::Handle::try_current()?;
let mutex_arc = tokio::task::block_in_place(|| {
    handle.block_on(get_or_create_mutex(&name))
});
```

**File**: `stdnse.rs` lines 418-430

---

### Finding 10: nmap.fetchfile() Required for Data Files

**Discovery**: Scripts like http-enum need `nmap.fetchfile()` to locate fingerprint data files

```lua
-- http-enum.nse line 204
local filename_full = nmap.fetchfile('nselib/data/' .. fingerprint_file)
```

**Impact**: Scripts fail with "attempt to call a nil value (field 'fetchfile')"

**Fix**: Implemented `nmap.fetchfile(filename)` that searches in:
1. `~/.rustnmap/`
2. `RUSTNMAPDIR` environment variable
3. `./reference/nmap/` (development)
4. `/usr/share/rustnmap/` (installed)
5. `/usr/share/nmap/` (fallback)

**File**: `nmap.rs` lines 167-200, 383-398

---

## Code Patterns

### Pattern: Lua Function Call with tostring

```rust
let tostring_fn: mlua::Function = lua.globals().get("tostring")?;
let val_str: String = tostring_fn.call::<String>(val.clone()).unwrap_or_default();
```

### Pattern: Output Table with __len

```rust
mt.set("__len", lua.create_function(|_, this: mlua::Value| {
    if let mlua::Value::Table(t) = this {
        let count = t.pairs::<mlua::Value, mlua::Value>().count();
        Ok(i64::try_from(count).unwrap_or(0))
    } else {
        Ok(0i64)
    }
})?)?;
```

### Pattern: block_in_place for Async from Sync Lua

```rust
let handle = tokio::runtime::Handle::try_current()
    .map_err(|_| mlua::Error::RuntimeError("No tokio runtime".into()))?;
let result = tokio::task::block_in_place(|| {
    handle.block_on(async_function())
});
```

---

## Errors Encountered

| Error | Cause | Fix |
|-------|-------|-----|
| Script returned nil | `#output == 0` for string keys | Added `__len` metamethod |
| Wrong output format | Processed all return values | Use only string for display |
| "1: GET, 2: HEAD" | Ignored `__tostring` metamethod | Use Lua's `tostring()` |
| SSH DISCONNECT | Incomplete key exchange | TODO: implement full KEX |
| attempt to call nil 'mutex' | Missing nmap.mutex() | Added mutex function |
| ipOps not found | Library not registered | Added to package.preload |
| attempt to call nil 'fetchfile' | Missing nmap.fetchfile() | Added fetchfile function |

---

## Open Issues

| Issue | Status | Complexity |
|-------|--------|------------|
| SSH key exchange | BLOCKING | High |
| ssh1 library | MISSING | Medium |
| http-enum timeout | INVESTIGATING | Medium |

---

## New Findings (2026-03-19 Session 2)

### Finding 11: block_in_place vs Thread Spawning

**Problem**: Spawning threads with new Tokio runtimes in Lua callbacks is wasteful and can cause issues.

**Original Anti-Pattern**:
```rust
let _mutex = std::thread::spawn(move || {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async_function())
}).join();
```

**Correct Pattern**:
```rust
let handle = tokio::runtime::Handle::try_current()
    .map_err(|_| mlua::Error::RuntimeError("No tokio runtime".into()))?;
let result = tokio::task::block_in_place(|| {
    handle.block_on(async_function())
});
```

**Benefits**:
- No thread creation overhead
- Uses existing Tokio runtime
- Properly integrated with Tokio's blocking pool

---

### Finding 12: nmap.fetchfile Search Path Priority

**Discovery**: Nmap's fetchfile searches multiple paths in a specific order

**Implementation Priority**:
1. `~/.rustnmap/` - User's local data
2. `RUSTNMAPDIR` environment variable - Custom location
3. `./reference/nmap/` - Development path
4. `/usr/share/rustnmap/` - Installed location
5. `/usr/share/nmap/` - Nmap compatibility fallback

**File**: `nmap.rs` lines 167-200

---

### Finding 13: http.identify_404 Return Format

**Discovery**: The `identify_404` function returns a table with specific format

```lua
-- Return format: {result, status}
-- result: boolean - true if 404 detection is reliable
-- status: number - HTTP status code server returns for unknown pages
local result = http.identify_404(host, port)
if result[1] then
    -- 404 detection works, status is in result[2]
end
```

**File**: `http.rs` lines 1010-1021
