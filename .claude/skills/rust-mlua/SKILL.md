---
name: rust-mlua
description: >
  Expert guidance for embedding Lua in Rust using the mlua crate (https://github.com/mlua-rs/mlua).
  Use this skill whenever the user is working with mlua, embedding Lua scripting in Rust, writing
  Lua bindings, creating UserData types, calling Lua from Rust or Rust functions from Lua, using
  mlua async/await, serde integration, native Lua modules in Rust, or any mlua API question.
  Trigger on: "mlua", "embed lua in rust", "lua bindings rust", "UserData", "lua_module",
  "create_function", "LuaResult", "Lua::new", "chunk! macro", "mlua coroutine", "mlua async".
  Always use this skill before writing any mlua code — even simple examples.
---

# Rust × mlua Development Guide

> **Sources**: https://github.com/mlua-rs/mlua | https://docs.rs/mlua  
> **Current stable**: 0.11.6 — Requires **Rust 1.85.0+**

---

## Quick Start

```toml
# Cargo.toml — must pick exactly ONE Lua version feature
[dependencies]
mlua = { version = "0.11", features = ["lua54", "vendored"] }
```

```rust
use mlua::prelude::*;

fn main() -> LuaResult<()> {
    let lua = Lua::new();
    let greet = lua.create_function(|_, name: String| {
        Ok(format!("Hello, {name}!"))
    })?;
    lua.globals().set("greet", greet)?;
    lua.load(r#"print(greet("Lua"))"#).exec()?;
    Ok(())
}
```

---

## Core Patterns

### 1. Create the VM

```rust
let lua = Lua::new();                                                   // safe stdlib only
let lua = Lua::new_with(StdLib::ALL_SAFE, LuaOptions::default())?;     // selective stdlib
let lua = unsafe { Lua::unsafe_new() };                                 // all stdlib (IO/OS/debug)
```

`LuaOptions` fields (both `bool`/`usize`): `catch_rust_panics`, `thread_pool_size`.

### 2. Load and Run Lua Code

```rust
lua.load("print('hi')").exec()?;                  // execute, no return
let n: i32 = lua.load("1 + 2").eval()?;           // evaluate expression
lua.load("code").set_name("my_script").exec()?;   // name chunk for error messages
```

### 3. Globals and Tables

```rust
lua.globals().set("x", 42i32)?;
let x: i32 = lua.globals().get("x")?;

let t = lua.create_table()?;
t.set("key", "val")?;
for pair in t.pairs::<String, i32>() { let (k, v) = pair?; }
for val in t.sequence_values::<String>() { let v = val?; }
```

### 4. Rust Functions for Lua

```rust
// Signature: |&Lua, Args| -> LuaResult<Return>
let add = lua.create_function(|_, (a, b): (i32, i32)| Ok(a + b))?;
lua.globals().set("add", add)?;

// Variadic args
let sum = lua.create_function(|_, args: Variadic<f64>| Ok(args.iter().sum::<f64>()))?;

// Call a Lua function from Rust
let f: Function = lua.globals().get("add")?;
let r: i32 = f.call((1, 2))?;
```

### 5. UserData — Expose Rust Types to Lua

```rust
use mlua::{UserData, UserDataFields, UserDataMethods, MetaMethod};

struct Point { x: f64, y: f64 }

impl UserData for Point {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("x", |_, this| Ok(this.x));
        fields.add_field_method_set("x", |_, this, v: f64| { this.x = v; Ok(()) });
    }
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok((this.x*this.x + this.y*this.y).sqrt()));
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| {
            Ok(format!("Point({}, {})", this.x, this.y))
        });
    }
}

lua.globals().set("p", Point { x: 3.0, y: 4.0 })?;
```

### 6. Error Handling

```rust
// In callbacks: return Err(mlua::Error::runtime("msg"))
// Convert std::error::Error:
use mlua::ExternalResult;
std::fs::read("file.txt").into_lua_err()?;

// Add context (ErrorContext trait):
use mlua::ErrorContext;
some_result.context("while loading config")?;
```

---

## Feature Flags Reference

**Pick exactly ONE Lua version** (mutually exclusive):

| Feature     | Version |
|-------------|---------|
| `lua55`     | Lua 5.5 *(added in 0.11.6)* |
| `lua54`     | Lua 5.4 *(recommended)* |
| `lua53`     | Lua 5.3 |
| `lua52`     | Lua 5.2 |
| `lua51`     | Lua 5.1 |
| `luajit`    | LuaJIT (5.1 compat) |
| `luajit52`  | LuaJIT (5.2 compat) |
| `luau`      | Luau (Roblox) |

**Optional features:**

| Feature             | Description |
|---------------------|-------------|
| `vendored`          | Compile & statically link Lua. **Mutually exclusive with `module`** |
| `async`             | `async/await` via Lua coroutines |
| `send`              | Make `Lua: Send + Sync`; requires `Send` on callbacks and `UserData` |
| `serde`             | Lua ↔ Rust serde serialization (`LuaSerdeExt`) |
| `macros`            | `chunk!` macro + `#[derive(FromLua)]` |
| `module`            | `#[lua_module]` for native `.so`/`.dll`. **Mutually exclusive with `vendored`** |
| `userdata-wrappers` | Auto-impl `UserData` for `Arc<Mutex<T>>`, `Rc<RefCell<T>>`, etc. |
| `anyhow`            | `anyhow::Error` ↔ `mlua::Error` conversions |

---

## Reference Files

For deeper guidance, read the relevant file before writing code:

| File | When to read |
|------|-------------|
| `references/api_types.md` | Full `Lua`, `Table`, `Function`, `Thread`, `AnyUserData` method lists; `Value` enum; `Error` enum |
| `references/userdata.md`  | Complete `UserData` fields/methods/metamethods API with examples |
| `references/advanced.md`  | `async`, `serde`, `chunk!`, `lua_module`, `Scope`, `send` feature |
