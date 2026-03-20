# mlua Advanced Features Reference

> Source: https://docs.rs/mlua/latest/mlua/ (mlua 0.11.6)

## Async / Await

**Requires**: `features = ["async"]`

mlua implements async by wrapping Lua coroutines. Works with any async executor (Tokio, async-std, etc.).

```rust
// Create an async Rust function for Lua
let fetch = lua.create_async_function(|_, url: String| async move {
    let body = reqwest::get(&url).await
        .into_lua_err()?
        .text().await
        .into_lua_err()?;
    Ok(body)
})?;
lua.globals().set("fetch", fetch)?;
```

### Call a Lua async function from Rust

The function must run inside a Lua `Thread` (coroutine):

```rust
// Wrap Lua code in a coroutine and drive it as an AsyncThread
let func: Function = lua.load(r#"
    function(url)
        return fetch(url)
    end
"#).eval()?;

let result: String = func.call_async::<String>("https://example.com").await?;
```

### Async UserData methods

```rust
use mlua::UserDataRef;

impl UserData for MyType {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // `this` is UserDataRef<T> (immutable borrow)
        methods.add_async_method("fetch", |_, this, url: String| async move {
            let data = do_async_work(this.id, &url).await.into_lua_err()?;
            Ok(data)
        });
    }
}
```

### `Lua::yield_with` (0.11.3+)

Alternative to `coroutine.yield` from Rust async functions — works for all Lua versions:

```rust
let f = lua.create_async_function(|lua, ()| async move {
    lua.yield_with(42i32).await?;   // suspend and return 42 to the caller
    Ok(())
})?;
```

---

## Serde Integration

**Requires**: `features = ["serde"]`

The `LuaSerdeExt` trait is automatically implemented for `Lua`.

```rust
use mlua::LuaSerdeExt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    host: String,
    port: u16,
    debug: bool,
}

// Rust → Lua
let cfg = Config { host: "localhost".into(), port: 8080, debug: true };
let lua_val = lua.to_value(&cfg)?;
lua.globals().set("config", lua_val)?;

// Lua → Rust
let val: mlua::Value = lua.globals().get("config")?;
let cfg: Config = lua.from_value(val)?;
```

### Serialize options

```rust
use mlua::SerializeOptions;
let opts = SerializeOptions::new()
    .serialize_none_to_null(true)
    .serialize_unit_to_null(true)
    .set_array_metatable(true)
    .detect_mixed_tables(true)     // 0.11.4+
    .encode_empty_tables_as_array(false);  // 0.10.4+

let val = lua.to_value_with(&my_struct, opts)?;
```

### Deserialize options

```rust
use mlua::DeserializeOptions;
let opts = DeserializeOptions::new()
    .deny_unsupported_types(true)
    .deny_recursive_tables(true)
    .sort_keys(false);

let s: MyStruct = lua.from_value_with(val, opts)?;
```

`mlua::Value` implements `serde::Serialize`, allowing arbitrary Lua values to be serialized.

---

## `chunk!` Macro

**Requires**: `features = ["macros"]`

Captures Rust variables as Lua upvalues (not string interpolation — fully type-safe):

```rust
use mlua::chunk;

let name = "world";
let count = 3i32;

lua.load(chunk! {
    for i = 1, $count do
        print("Hello, " .. $name)
    end
}).exec()?;
```

### Known limitations (from official docs)

- Lua comments `--` should not be used in stable Rust (no line info in proc macros); use `//` instead
- `//` (floor division) operator is unusable (starts a comment)
- Escape codes `\a`, `\b`, `\f`, `\v`, `\123` (octal), `\u`, `\U` do not work  
  Accepted escapes: `\\`, `\n`, `\t`, `\r`, `\xAB`, `\0`

---

## Native Lua Modules (`lua_module`)

**Requires**: `features = ["module"]`  
**`module` and `vendored` are mutually exclusive** — do NOT combine them.

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
mlua = { version = "0.11", features = ["lua54", "module"] }
```

```rust
use mlua::prelude::*;

#[mlua::lua_module]
fn my_module(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;
    exports.set("greet", lua.create_function(|_, name: String| {
        Ok(format!("Hello, {name}!"))
    })?)?;
    Ok(exports)
}
```

The macro defines a C function `luaopen_my_module`.

### Options

```rust
// Custom module name
#[mlua::lua_module(name = "alt_name")]
fn my_module(lua: &Lua) -> LuaResult<LuaTable> { ... }

// Skip memory allocation checks (improves perf, slight risk)
#[mlua::lua_module(skip_memory_check)]
fn my_module(lua: &Lua) -> LuaResult<LuaTable> { ... }
```

From Lua:
```lua
local m = require("my_module")
print(m.greet("World"))
```

---

## Thread Safety (`send` feature)

By default `Lua` is `!Send`. With `features = ["send"]`:
- `Lua` becomes `Send + Sync`
- All Rust callbacks (`create_function`, etc.) require `+ Send`
- All `UserData` types require `+ Send`
- Internal Lua VM access uses a reentrant mutex

```toml
mlua = { version = "0.11", features = ["lua54", "vendored", "send"] }
```

```rust
use std::sync::Arc;

let lua = Arc::new(Lua::new());
let lua2 = Arc::clone(&lua);
std::thread::spawn(move || {
    lua2.load("print('from thread')").exec().unwrap();
}).join().unwrap();
```

> **Note**: `send` feature is disabled in `module` mode (the host controls the Lua state).

---

## Safety Model

From the official mlua documentation and README:

- **Goal**: Safe use without writing `unsafe`. If you can cause UB without `unsafe`, that is a bug.
- Every Lua C API call that may `longjmp` is wrapped in `lua_pcall`.
- Rust panics inside Lua callbacks are caught and converted to Lua errors. They are re-raised if propagated back to Rust.
- The library contains significant `unsafe` internally; absolute safety is not guaranteed.
- A panic with the text `"mlua internal error"` indicates a bug in mlua itself.
- `Lua` instances remain valid after a user-generated panic (important for `Drop` impls).

### Common pitfalls

| Pitfall | Fix |
|---------|-----|
| No Lua version feature selected | Add exactly one: `lua54`, `luajit`, etc. |
| `module` + `vendored` together | They are mutually exclusive — remove one |
| `Lua: !Send` compile error | Add `send` feature, or keep `Lua` on one thread |
| Non-`'static` closure in `create_function` | Use `lua.scope(...)` |
| Returning ref into UserData field | Return a clone, or use `Arc<Mutex<T>>` |
| Wrong memory method name | Use `lua.used_memory()` not `memory_used()` |
| `send` feature in module mode | Not supported — module host controls the state |
