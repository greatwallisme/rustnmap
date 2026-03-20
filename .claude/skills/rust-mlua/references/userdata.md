# mlua UserData Reference

> Source: https://docs.rs/mlua/latest/mlua/trait.UserData.html (mlua 0.11.6)

## The `UserData` Trait

```rust
pub trait UserData: Sized {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {}
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {}
}
```

Implementing this trait on a Rust type allows pushing it into Lua as a userdata value.
`IntoLua` is automatically provided. For `FromLua`, use `#[derive(FromLua)]` (with `macros` feature)
or implement manually.

---

## `UserDataFields<T>` — Field Registration

```rust
// Getter: obj.field
fields.add_field_method_get("name", |lua: &Lua, this: &T| -> Result<R> { ... });

// Setter: obj.field = val
fields.add_field_method_set("name", |lua: &Lua, this: &mut T, val: A| -> Result<()> { ... });

// Static constant field (no self)
fields.add_field("PI", std::f64::consts::PI);

// Metatable-level field (e.g. __type for typeof())
fields.add_meta_field("__type", "MyType");
```

---

## `UserDataMethods<T>` — Method Registration

```rust
// Immutable self: obj:method(args)
methods.add_method("name", |lua: &Lua, this: &T, args: A| -> Result<R> { ... });

// Mutable self: obj:method(args) — modifies T
methods.add_method_mut("name", |lua: &Lua, this: &mut T, args: A| -> Result<R> { ... });

// Static function (no self): obj.func(args) or MyType.func(args)
methods.add_function("name", |lua: &Lua, args: A| -> Result<R> { ... });
methods.add_function_mut("name", |lua: &Lua, args: A| -> Result<R> { ... });

// Metamethods (with &T self)
methods.add_meta_method(MetaMethod::X, |lua: &Lua, this: &T, args: A| -> Result<R> { ... });
methods.add_meta_method_mut(MetaMethod::X, |lua: &Lua, this: &mut T, args: A| -> Result<R> { ... });

// Metamethods (generic args — for binary ops where LHS might not be T)
methods.add_meta_function(MetaMethod::X, |lua: &Lua, args: A| -> Result<R> { ... });
methods.add_meta_function_mut(MetaMethod::X, |lua: &Lua, args: A| -> Result<R> { ... });

// Async methods (async feature)
methods.add_async_method("name", |lua: Lua, this: UserDataRef<T>, args: A| async move { ... });
methods.add_async_method_mut("name", |lua: Lua, this: UserDataRefMut<T>, args: A| async move { ... });
methods.add_async_function("name", |lua: Lua, args: A| async move { ... });
```

---

## `MetaMethod` Variants

Source: https://docs.rs/mlua/latest/mlua/enum.MetaMethod.html

### Arithmetic
`Add` (`+`), `Sub` (`-`), `Mul` (`*`), `Div` (`/`), `Mod` (`%`), `Pow` (`^`),
`Unm` (unary `-`), `IDiv` (`//` floor div, Lua 5.3+)

### Bitwise (Lua 5.3+)
`BAnd` (`&`), `BOr` (`|`), `BXor` (`~`), `BNot` (unary `~`), `Shl` (`<<`), `Shr` (`>>`)

### String / Length
`Concat` (`..`), `Len` (`#`)

### Comparison
`Eq` (`==`), `Lt` (`<`), `Le` (`<=`)

### Table-like
`Index` (`obj[key]` — fallback when key not found),
`NewIndex` (`obj[key] = val` — fallback),
`Call` (`obj(...)` — makes userdata callable)

### Lifecycle / Display
`ToString` (`tostring(obj)`),
`Pairs` (`pairs(obj)` — custom iteration),
`Close` (to-be-closed variables, Lua 5.4+)

### Custom string metamethods
```rust
methods.add_meta_method(MetaMethod::Custom("__type".to_string()), |_, this, ()| Ok("MyType"));
```

> **Note on binary metamethods**: For `Add`, `Sub`, `Eq`, etc., either operand may trigger the
> metamethod. The first argument is not guaranteed to be `T`. Use `add_meta_function` with
> `AnyUserData` args for correct binary metamethods.

---

## Full Example

```rust
use mlua::{Lua, MetaMethod, Result, UserData, UserDataFields, UserDataMethods};

struct Counter {
    value: i32,
    name: String,
}

impl UserData for Counter {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("value", |_, this| Ok(this.value));
        fields.add_field_method_set("value", |_, this, v: i32| {
            this.value = v;
            Ok(())
        });
        fields.add_field_method_get("name", |_, this| Ok(this.name.clone()));
        // Static constant field
        fields.add_field("MAX", i32::MAX);
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Instance methods
        methods.add_method_mut("increment", |_, this, n: i32| {
            this.value += n;
            Ok(this.value)
        });
        methods.add_method("reset_to", |_, this, n: i32| {
            // can't mutate — just shows immutable read
            Ok(this.value - n)
        });

        // Static constructor (call as Counter.new("name"))
        methods.add_function("new", |_, name: String| {
            Ok(Counter { value: 0, name })
        });

        // Metamethods
        methods.add_meta_method(MetaMethod::Add, |_, this, n: i32| {
            Ok(this.value + n)
        });
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| {
            Ok(format!("Counter[{}]={}", this.name, this.value))
        });
        methods.add_meta_method(MetaMethod::Len, |_, this, ()| {
            Ok(this.value as usize)
        });
    }
}

fn main() -> mlua::Result<()> {
    let lua = Lua::new();
    // Register static proxy so Lua can call Counter.new(...)
    lua.globals().set("Counter", lua.create_proxy::<Counter>()?)?;
    lua.load(r#"
        local c = Counter.new("hits")
        c:increment(10)
        print(tostring(c))   -- Counter[hits]=10
        print(c.value)       -- 10
        print(#c)            -- 10
    "#).exec()
}
```

---

## `userdata-wrappers` Feature

With `features = ["userdata-wrappers"]`, mlua auto-implements `UserData` for:
- `Rc<T>` where `T: UserData`
- `Arc<T>` where `T: UserData`
- `Rc<RefCell<T>>` where `T: UserData`
- `Arc<Mutex<T>>` where `T: UserData`

This allows sharing Rust state without manual delegation.

---

## `Scope` — Non-`'static` UserData

`lua.scope(|scope| { ... })` allows registering userdata that borrows from the local stack:

```rust
let mut local_val = 0i32;
lua.scope(|scope| {
    let ud = scope.create_userdata_ref_mut(&mut local_val)?;
    lua.globals().set("val", ud)?;
    lua.load("val = val + 1").exec()  // error: userdata is read-only via ref
})?;
// local_val is accessible again; any Lua references to it are now invalidated
```

`Scope` methods:
- `scope.create_userdata(T: UserData)` — owned, non-`'static`
- `scope.create_any_userdata(T)` — any type, non-`'static`
- `scope.create_function(f)` — non-`'static` closure
- `scope.create_function_mut(f)`
- `scope.add_destructor(f)` — custom cleanup on scope exit (0.10.1+)

> **Important**: All Lua values (functions/userdata) created inside a `scope` are invalidated
> when the scope closure returns. Calling them from Lua after that produces an error.

---

## `register_userdata_type` — Without Implementing `UserData`

```rust
lua.register_userdata_type::<MyType>(|reg| {
    reg.add_method("greet", |_, this, ()| Ok(format!("Hi from {:?}", this)));
})?;
let ud = lua.create_any_userdata(MyType { ... })?;
```

This registers methods for a type without needing to implement the `UserData` trait directly.
