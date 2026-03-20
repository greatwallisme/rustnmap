# mlua API Types Reference

> Source: https://docs.rs/mlua/latest/mlua/ (mlua 0.11.6)

## `Lua` — Key Methods

```rust
// Constructors
Lua::new()                                          // safe stdlib only
Lua::new_with(StdLib, LuaOptions) -> Result<Lua>    // selective safe stdlib
unsafe { Lua::unsafe_new() }                        // all stdlib (IO/OS/debug)
unsafe { Lua::unsafe_new_with(StdLib, LuaOptions) }

// Code loading
lua.load(chunk) -> Chunk   // chunk: &str / String / &[u8] / Vec<u8> / chunk! output

// Globals
lua.globals() -> Table
lua.set_globals(table: Table) -> Result<()>   // replace global env (0.11.0+)

// Value / table creation
lua.create_table() -> Result<Table>
lua.create_table_from(iter) -> Result<Table>          // IntoIterator<(K, V)>
lua.create_table_with_capacity(narr, nrec) -> Result<Table>
lua.create_sequence_from(iter) -> Result<Table>       // array-style
lua.create_string(s) -> Result<mlua::String>
lua.create_function(f) -> Result<Function>
lua.create_function_mut(f) -> Result<Function>
lua.create_async_function(f) -> Result<Function>      // async feature
lua.create_thread(f: Function) -> Result<Thread>
lua.create_userdata(T: UserData) -> Result<AnyUserData>
lua.create_any_userdata(T) -> Result<AnyUserData>     // no UserData trait required
lua.create_proxy::<T: UserData>() -> Result<AnyUserData> // static methods/fields, no instance

// Registry
lua.create_registry_value(v) -> Result<RegistryKey>
lua.registry_value::<V>(key) -> Result<V>
lua.replace_registry_value(key: &mut RegistryKey, v) -> Result<()>
lua.remove_registry_value(key) -> Result<()>
lua.owns_registry_value(key) -> bool

// App data (Rust-only storage on the Lua state)
lua.set_app_data::<T>(data) -> Option<T>
lua.app_data_ref::<T>() -> Option<AppDataRef<T>>
lua.app_data_mut::<T>() -> Option<AppDataRefMut<T>>
lua.try_app_data_ref::<T>() -> Result<AppDataRef<T>>   // 0.10.1+
lua.try_app_data_mut::<T>() -> Result<AppDataRefMut<T>>
lua.remove_app_data::<T>() -> Option<T>

// GC
lua.gc_collect() -> Result<()>
lua.gc_stop() -> Result<()>
lua.gc_restart() -> Result<()>
lua.gc_is_running() -> bool
lua.gc_step(kbytes: usize) -> Result<bool>   // lua55/lua54/lua53/lua52/luau
lua.gc_inc(pause, step_multiplier, step_size) -> Result<GCMode>   // lua55/lua54
lua.gc_gen(minor_multiplier, major_multiplier) -> Result<GCMode>  // lua55/lua54

// Memory
lua.used_memory() -> usize                   //  method is `used_memory`, NOT `memory_used`
lua.set_memory_limit(bytes: usize) -> Result<usize>  // not available in module mode

// Scope
lua.scope(|scope: &Scope| -> Result<T>) -> Result<T>

// Module system
lua.register_module(name, f) -> Result<()>
lua.preload_module(name, f) -> Result<()>
lua.unload_module(name) -> Result<()>

// Misc
lua.current_thread() -> Thread
lua.weak() -> WeakLua              // weak reference (0.10.4+)
lua.traceback(msg, level) -> String  // stack trace (0.11.5+)
lua.inspect_stack(level, |debug: &Debug|)  // callback-based (0.11.0+)
lua.pack(v) -> Result<Value>
lua.unpack::<V>(value) -> Result<V>
```

### `LuaOptions` (non-exhaustive)

```rust
LuaOptions {
    catch_rust_panics: bool,  // default: true — catch Rust panics in pcall/xpcall
    thread_pool_size: usize,  // coroutine thread pool size
}
LuaOptions::default()
```

### `StdLib` flags

```rust
StdLib::BASE       // basic functions (print, assert, error, …)
StdLib::TABLE      // table library
StdLib::STRING     // string library
StdLib::MATH       // math library
StdLib::IO         // file I/O  [unsafe — do not use with Lua::new]
StdLib::OS         // OS functions [unsafe]
StdLib::PACKAGE    // module system
StdLib::DEBUG      // debug library [unsafe]
StdLib::COROUTINE  // coroutine library
StdLib::ALL_SAFE   // all except IO, OS, DEBUG
StdLib::ALL        // everything (requires unsafe_new / unsafe_new_with)
```

---

## `Chunk` — Code Execution Builder

```rust
lua.load("code")
    .set_name("name")             // label in error messages / stack traces
    .set_mode(ChunkMode::Text)    // ChunkMode::Text | ChunkMode::Binary
    .set_environment(table: Table)// replace _ENV for this chunk
    // Terminal operations:
    .exec() -> Result<()>
    .eval::<T>() -> Result<T>
    .call::<T>(args) -> Result<T>
    .into_function() -> Result<Function>
```

---

## `Table`

```rust
t.set(key, val) -> Result<()>
t.get::<V>(key) -> Result<V>
t.raw_set(key, val) -> Result<()>     // bypass __newindex
t.raw_get::<V>(key) -> Result<V>      // bypass __index
t.raw_len() -> usize                  // sequence length, no __len
t.contains_key(key) -> Result<bool>
t.is_empty() -> Result<bool>          // checks both array and hash parts
t.pairs::<K, V>() -> TablePairs<K, V>
t.sequence_values::<V>() -> TableSequence<V>   // ipairs-style, no metamethods
t.for_each(|k: K, v: V| -> Result<()>) -> Result<()>  // fast traversal
t.push(val) -> Result<()>             // append to array part
t.pop::<V>() -> Result<V>
t.clear() -> Result<()>
t.to_pointer() -> *const c_void
t.metatable() -> Result<Option<Table>>
t.set_metatable(Option<Table>) -> Result<()>
```

---

## `Function`

```rust
f.call::<R>(args) -> Result<R>
f.call_async::<R>(args) -> impl Future<Output = Result<R>>  // async feature
f.bind(args) -> Result<Function>      // partial application
f.info() -> FunctionInfo              // name, source, what, current_line, …
f.to_pointer() -> *const c_void
```

Class methods:
```rust
Function::wrap(f)           // create from LuaNativeFn without &Lua
Function::wrap_mut(f)       // LuaNativeFnMut
Function::wrap_async(f)     // LuaNativeAsyncFn (async feature)
```

---

## `Thread` (coroutine)

```rust
t.status() -> ThreadStatus  // Resumable | Running | Normal | Finished | Error
t.resume::<R>(args) -> Result<R>
t.reset(f: Function) -> Result<()>   // reuse thread (all Lua versions; limited 5.1–5.3)
t.into_async::<R>(args) -> AsyncThread<R>   // async feature
t.set_hook(triggers, fn) -> Result<()>      // per-thread hook (non-luau)
t.to_pointer() -> *const c_void
```

---

## `AnyUserData`

```rust
ud.borrow::<T>() -> Result<UserDataRef<T>>
ud.borrow_mut::<T>() -> Result<UserDataRefMut<T>>
ud.take::<T>() -> Result<T>               // move out and destroy
ud.destroy() -> Result<()>                // explicitly destroy (0.10.1+)
ud.is_proxy() -> bool                     // (0.11.6+)
ud.type_name() -> Result<Option<StdString>>
ud.type_id() -> Result<Option<TypeId>>    // (0.10.4+)
ud.metatable() -> Result<UserDataMetatable>
ud.set_nth_user_value(n, val) -> Result<()>
ud.nth_user_value::<V>(n) -> Result<V>
ud.to_pointer() -> *const c_void
```

---

## `Value` enum

```rust
Value::Nil
Value::Boolean(bool)
Value::Integer(i64)           // mlua::Integer = i64
Value::Number(f64)            // mlua::Number  = f64
Value::String(mlua::String)
Value::Table(Table)
Value::Function(Function)
Value::Thread(Thread)
Value::UserData(AnyUserData)
Value::LightUserData(LightUserData)
Value::Error(Error)
Value::Other(lua_State)       // unknown types e.g. LuaJIT cdata
```

`Value` implements `Default` → `Value::Nil`.  
Helpers: `as_boolean()`, `as_integer()`, `as_number()`, `as_string()`, `as_table()`,
`as_function()`, `as_userdata()`, `is_nil()`, `is_error()`, `type_name()`.

---

## `Error` enum (non-exhaustive)

```rust
Error::SyntaxError { message: String, incomplete_input: bool }
Error::RuntimeError(String)
Error::MemoryError(String)
Error::SafetyError(String)
Error::GarbageCollectorError(String)
Error::CallbackError { traceback: String, cause: Arc<Error> }
Error::ExternalError(Arc<dyn StdError + Send + Sync>)
Error::WithContext { context: String, cause: Arc<Error> }
Error::FromLuaConversionError { from, to, message }
Error::ToLuaConversionError { from, to, message }
Error::BadArgument { to, pos, name, cause }
Error::RecursiveMutCallback
Error::CallbackDestructed
Error::StackError
Error::CoroutineUnresumable
Error::UserDataTypeMismatch
Error::UserDataDestructed
Error::UserDataBorrowError
Error::UserDataBorrowMutError
Error::SerializeError(String)    // serde feature
Error::DeserializeError(String)  // serde feature
```

Constructors: `Error::runtime(msg)` · `Error::external(e)` · `Error::bad_argument(pos, name, cause)`

`Error::chain()` — iterator over nested error chain.
`Error::downcast_ref::<E>()` — downcast `ExternalError`.

---

## Key Conversion Traits

| Trait | Purpose |
|-------|---------|
| `IntoLua` | `self` → `Value` |
| `FromLua` | `Value` → `Self` |
| `IntoLuaMulti` | `self` → any number of Lua values |
| `FromLuaMulti` | any number of Lua values → `Self` |
| `ExternalError` | `.into_lua_err()` on `dyn StdError` |
| `ExternalResult` | `.into_lua_err()?` on `Result<_, E: StdError>` |
| `ErrorContext` | `.context("msg")` / `.with_context(|| msg)` |
| `ObjectLike` | unified `get`/`set`/`call`/`get_path` for `Table` and `AnyUserData` |
| `AsChunk` | implemented for `&str`, `String`, `&[u8]`, `Vec<u8>`, `Path`, `chunk!` output |
| `MaybeSend` | adds `Send` bound only when `send` feature is enabled |

`#[derive(FromLua)]` — requires `macros` feature; generates impl that borrows+clones from `UserData`.
