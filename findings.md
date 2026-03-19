# Findings: NSE Development

> **Updated**: 2026-03-19 00:30

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

---

## Errors Encountered

| Error | Cause | Fix |
|-------|-------|-----|
| Script returned nil | `#output == 0` for string keys | Added `__len` metamethod |
| Wrong output format | Processed all return values | Use only string for display |
| "1: GET, 2: HEAD" | Ignored `__tostring` metamethod | Use Lua's `tostring()` |
| SSH DISCONNECT | Incomplete key exchange | TODO: implement full KEX |
