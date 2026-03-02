# Rust Idioms

Source: rust-unofficial/patterns Idioms chapter, deeply organized

## Table of Contents
1. [Prefer Borrowed Types Over Owned Types](#prefer-borrowed-types-over-owned-types)
2. [Constructor Conventions](#constructor-conventions)
3. [Correct Usage of the Default Trait](#correct-usage-of-the-default-trait)
4. [Collections as Smart Pointers (Deref Idiom)](#collections-as-smart-pointers)
5. [Destructors as Finalization Logic (RAII)](#destructors-as-finalization-logic)
6. [mem::take / mem::replace In-Place Transformation](#memtake--memreplace-in-place-transformation)
7. [Dynamic Dispatch on the Stack](#dynamic-dispatch-on-the-stack)
8. [Iterator Usage with Option](#iterator-usage-with-option)
9. [Precise Control of Closure Variable Capture](#precise-control-of-closure-variable-capture)
10. [Temporary Mutability](#temporary-mutability)
11. [Returning Consumed Parameters on Error](#returning-consumed-parameters-on-error)
12. [#[non_exhaustive] and Extensibility](#non_exhaustive-and-extensibility)
13. [Documentation Example Initialization Tricks](#documentation-example-initialization-tricks)
14. [FFI Idioms](#ffi-idioms)

---

## Prefer Borrowed Types Over Owned Types

**Core Principle**: Always use the target type of deref coercion for function parameters, not the reference to the owned type.

| Owned Type | Don't Use | Use Instead |
|---|---|---|
| `String` | `&String` | `&str` |
| `Vec<T>` | `&Vec<T>` | `&[T]` |
| `Box<T>` | `&Box<T>` | `&T` |
| `PathBuf` | `&PathBuf` | `&Path` |

**Why?** `&String` has two levels of indirection (reference -> String -> heap data), while `&str` has only one. More importantly, `&str` accepts string literals, references to `String`, and string slices - more flexible.

```rust
// WRONG: Only accepts &String, not "hello" literals or string slices
fn greet(name: &String) -> String { format!("Hello, {name}!") }

// CORRECT: Accepts all string types (via deref coercion)
fn greet(name: &str) -> String { format!("Hello, {name}!") }

fn main() {
    let owned = String::from("Alice");
    greet(&owned);         // &String -> &str automatic conversion
    greet("Bob");          // &'static str passed directly
    greet(&owned[0..3]);   // String slice
}
```

**Practical implication**: When using `split()` on a string, it produces `&str`, not `&String`. If the parameter type is `&String`, it will fail to compile.

---

## Constructor Conventions

Rust has no constructor keyword. The community convention is to use an associated function `new()` as the primary constructor:

```rust
pub struct Connection {
    host: String,
    port: u16,
}

impl Connection {
    // Primary constructor: pub fn new(...)
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }

    // Named constructor: expresses specific semantics, clearer than single new
    pub fn localhost(port: u16) -> Self {
        Self::new("127.0.0.1", port)
    }

    pub fn from_env() -> Result<Self, EnvError> {
        // Read configuration from environment variables
    }
}
```

**Rules**:
- Implement both `Default` and `new()` (when zero-argument construction makes sense)
- When `Default::default()` and `new()` do the same thing, implement both - users expect both to exist
- `Default` allows types to participate in standard library APIs like `Option::unwrap_or_default()`, `HashMap::entry().or_default()`

```rust
#[derive(Default)]
struct Config {
    timeout: Duration,    // defaults to Duration::ZERO
    retries: u32,         // defaults to 0
    verbose: bool,        // defaults to false
    endpoint: Option<String>,  // defaults to None
}

// Partial initialization idiom
let config = Config { verbose: true, ..Config::default() };
```

---

## Correct Usage of the Default Trait

`Default` is a key participant in generic code. Types implementing it can appear in more contexts:

```rust
// Standard library extensively relies on Default
vec.entry(key).or_default();           // Requires V: Default
Option::<Vec<i32>>::None.unwrap_or_default();  // Requires T: Default
mem::take(&mut value);                 // Requires T: Default

// Same when defining custom generics
fn reset<T: Default>(val: &mut T) {
    *val = T::default();
}
```

**When to manually implement vs derive**:
- All fields implement `Default` -> use `#[derive(Default)]`
- Default values aren't "zero value" semantics (e.g., default timeout should be 30s, not 0s) -> manual implementation
- Contains types that don't implement `Default` -> manual implementation

---

## Collections as Smart Pointers

Implementing `Deref` allows owned types to automatically provide all methods of borrowed types:

```rust
use std::ops::Deref;

struct Matrix {
    data: Vec<f64>,
    rows: usize,
    cols: usize,
}

impl Deref for Matrix {
    type Target = [f64];
    fn deref(&self) -> &[f64] { &self.data }
}

// Now Matrix automatically has all &[f64] methods:
let m = Matrix::new(3, 3);
m.len();         // from &[f64]
m.iter();        // from &[f64]
m.contains(&0.0); // from &[f64]
```

**Correspondence with standard library**: `Vec<T>: Deref<Target=[T]>`, `String: Deref<Target=str>`, `Box<T>: Deref<Target=T>`, `Rc<T>: Deref<Target=T>`

**Note**: `DerefMut` can also be implemented, but use caution - overusing `Deref` to simulate inheritance is an anti-pattern (see anti-patterns.md).

---

## Destructors as Finalization Logic

Rust has no `finally` block. Use the `Drop` trait to guarantee cleanup code executes on any exit path (normal, `?`, panic):

```rust
struct DatabaseTransaction<'a> {
    conn: &'a mut Connection,
    committed: bool,
}

impl<'a> DatabaseTransaction<'a> {
    fn new(conn: &'a mut Connection) -> Self {
        conn.begin();
        DatabaseTransaction { conn, committed: false }
    }

    fn commit(mut self) {
        self.conn.execute("COMMIT");
        self.committed = true;
    }
}

impl<'a> Drop for DatabaseTransaction<'a> {
    fn drop(&mut self) {
        if !self.committed {
            // Automatic rollback: regardless of how function exits
            self.conn.execute("ROLLBACK");
        }
    }
}

fn transfer_funds(conn: &mut Connection) -> Result<(), Error> {
    let tx = DatabaseTransaction::new(conn);
    debit_account(conn, 100)?;   // If this fails, Drop automatically ROLLBACKs
    credit_account(conn, 100)?;  // Same here
    tx.commit();                 // Only commits on explicit commit
    Ok(())
}
```

**Key details**:
- Variables must be bound to a named variable (`let _guard = Guard`), otherwise immediate drop
- Don't use `let _ = Guard` (underscore doesn't bind, immediate drop)
- Drop runs **even on panic** (panic unwinds the stack)
- Panic in Drop will abort the process - don't panic in Drop

---

## mem::take / mem::replace In-Place Transformation

Solves the borrow checker dilemma when transforming enum variants in place, avoiding unnecessary `clone()`:

```rust
use std::mem;

enum AppState {
    Loading { url: String },
    Ready { data: Vec<u8>, url: String },
    Error { message: String },
}

fn finish_loading(state: &mut AppState, data: Vec<u8>) {
    // Problem: can't move url out of &mut AppState
    // Solution: use mem::take to extract, leaving Default value (empty string doesn't allocate)
    if let AppState::Loading { url } = state {
        let url = mem::take(url);  // Extract url, leaving String::new() in place
        *state = AppState::Ready { data, url };
    }
}
```

**`mem::take` vs `mem::replace`**:
- `mem::take(val)` - equivalent to `mem::replace(val, Default::default())`, clearer semantics
- `mem::replace(val, replacement)` - use when replacement value isn't Default
- `Option::take()` - Option-specialized version, more concise: `let val = opt.take()`

**Multi-variant transformation example**:
```rust
fn rotate_state(state: &mut State) {
    *state = match mem::take(state) {
        State::A { data } => State::B { processed: transform(data) },
        State::B { processed } => State::C { final_result: finalize(processed) },
        State::C { .. } => State::A { data: vec![] },
    };
}
```

---

## Dynamic Dispatch on the Stack

Rust 1.79+ supports heap-allocation-free dynamic dispatch for scenarios where the lifetime is within a function:

```rust
use std::io::{self, Read, Write};

fn process(input_path: Option<&str>, output_path: Option<&str>) -> io::Result<()> {
    // No heap allocation for dynamic dispatch (Rust 1.79+)
    let mut input_storage;
    let mut stdin_storage;
    let readable: &mut dyn Read = match input_path {
        Some(path) => { input_storage = std::fs::File::open(path)?; &mut input_storage }
        None => { stdin_storage = io::stdin(); &mut stdin_storage }
    };

    let mut buf = Vec::new();
    readable.read_to_end(&mut buf)?;
    // ...
    Ok(())
}
```

**When to use stack dispatch vs Box<dyn Trait>**:
- Value lifetime within current scope -> stack dispatch (zero allocation)
- Need to store in struct or return -> `Box<dyn Trait>` (heap allocation, but reasonable when necessary)
- Code before 1.79 -> requires two `let` bindings + delayed initialization

---

## Iterator Usage with Option

`Option<T>` implements `IntoIterator`, seamlessly composing with iterator chains:

```rust
let maybe_extra = Some("bonus_item");
let mut items = vec!["a", "b", "c"];

// extend: append 0 or 1 elements
items.extend(maybe_extra);

// chain: optionally add elements in iterator chain
for item in items.iter().chain(maybe_extra.iter()) {
    println!("{item}");
}

// filter_map: handle mappings that return Option
let results: Vec<i32> = strings.iter()
    .filter_map(|s| s.parse().ok())
    .collect();

// flatten: flatten nested Option/iterators
let nested: Vec<Option<i32>> = vec![Some(1), None, Some(3)];
let flat: Vec<i32> = nested.into_iter().flatten().collect();
```

---

## Precise Control of Closure Variable Capture

Use separate scopes to precisely control each variable's capture method (move, clone, or borrow):

```rust
use std::sync::Arc;

let shared_config = Arc::new(Config::load());
let owned_data = vec![1, 2, 3];
let borrowed_id = 42u64;

// GOOD: Precise control - each variable handled independently
let callback = {
    let config = Arc::clone(&shared_config);  // Only clone Arc pointer (cheap)
    let data = owned_data;                    // Move entire Vec
    // borrowed_id is Copy, under move semantics it's also copied
    move || {
        println!("id={borrowed_id}, data len={}", data.len());
        process(&config, &data);
    }
};

// BAD: Coarse approach - move captures everything, pollutes outer scope
let callback = move || { /* shared_config entirely moved away */ };
// shared_config is no longer usable here
```

**Pattern**: Each variable name inside `move || { ... }` corresponds to an outer-scope variable with the same name. Using inner scope + rebinding allows "preprocessing" each capture before entering the `move` closure.

---

## Temporary Mutability

Make data immutable immediately after construction, using the type system to prevent accidental modification:

```rust
// Method 1: Nested block (recommended, clear semantics)
let config = {
    let mut c = Config::default();
    c.timeout = Duration::from_secs(30);
    c.max_retries = 3;
    if env::var("DEBUG").is_ok() { c.verbose = true; }
    c  // Returns, after which config is immutable
};
// config.timeout = Duration::ZERO;  // <- Compile error: immutable

// Method 2: Variable rebinding (suitable for inline use)
let mut data = fetch_data();
data.sort_unstable();
data.dedup();
let data = data;  // Rebind as immutable
```

---

## Returning Consumed Parameters on Error

When a function consumes a parameter via move, return it to the caller on error, avoiding forced clone:

```rust
pub struct SendError {
    pub message: String,  // Return the consumed value
    pub kind: ErrorKind,
}

pub fn send(message: String) -> Result<MessageId, SendError> {
    match do_send(&message) {
        Ok(id) => Ok(id),
        Err(kind) => Err(SendError { message, kind }),  // Return message
    }
}

fn main() {
    let msg = String::from("important message");
    let msg = match send(msg) {
        Ok(id) => { println!("sent: {id}"); return; }
        Err(e) => {
            log_error(&e.kind);
            e.message  // Retrieve, can retry
        }
    };
    // Can retry with msg, no cloning needed
}
```

**Standard library example**: `String::from_utf8(bytes)` on failure, `FromUtf8Error::into_bytes()` returns the original bytes.

---

## #[non_exhaustive] and Extensibility

Allows adding fields or variants to public structs/enums without breaking semver:

```rust
// Library code
#[non_exhaustive]
pub struct Config {
    pub timeout: Duration,
    pub max_retries: u32,
    // May add more fields in future without breaking existing code
}

#[non_exhaustive]
pub enum Error {
    NotFound,
    PermissionDenied,
    // May add more variants in future
}

// User code (across crates)
let Config { timeout, max_retries, .. } = config;  // Must add ..
match error {
    Error::NotFound => { /* ... */ }
    Error::PermissionDenied => { /* ... */ }
    _ => { /* Must handle unknown variants */ }
}
```

**When to use, when not to**:
- ✅ Modeling external resources (HTTP status codes, OS error codes) - may extend anytime
- ✅ Early API design phase, uncertain about complete field set
- ❌ Internal enums in mature APIs - forcing users to handle `_` branches reduces usability
- ❌ As substitute for semver versioning - semantic changes should bump major version

**Within crate**: `#[non_exhaustive]` only takes effect across crate boundaries. Within same crate, can match freely. Can use private field `_priv: ()` as alternative.

---

## Documentation Example Initialization Tricks

Wrap complex types' doc tests with helper functions to avoid repetitive boilerplate:

```rust
impl Client {
    /// Send GET request
    ///
    /// # Example
    /// ```
    /// # fn example(client: Client) {  // Lines starting with # are hidden in docs but compiled
    /// let response = client.get("https://example.com").send();
    /// assert!(response.is_ok());
    /// # }
    /// ```
    pub fn get(&self, url: &str) -> RequestBuilder { ... }
}
```

**`# ` prefix**: Hidden in documentation, but compiled and run during `cargo test`. Used to set up test preconditions.

**`no_run` annotation**: Code compiles but doesn't run (suitable for examples needing real network/filesystem):
```rust
/// ```no_run
/// let conn = Database::connect("postgres://...")?;
/// ```
```

---

## FFI Idioms

### Error Handling
Three levels for passing errors across FFI boundaries:

```rust
// 1. Flat enum -> integer code (simplest)
#[repr(C)]
pub enum DbError { IsReadOnly = 1, IOError = 2, Corrupted = 3 }

// 2. Structured error -> integer code + string description (separates concerns)
impl From<DatabaseError> for libc::c_int { ... }
pub extern "C" fn db_error_description(e: *const DatabaseError) -> *const c_char { ... }

// 3. Custom #[repr(C)] type (for complex structured errors)
#[repr(C)]
pub struct ParseError { pub line: u32, pub col: u16, pub expected: c_char }
```

### Receiving C Strings (Minimizing unsafe)
```rust
#[no_mangle]
pub unsafe extern "C" fn process_message(msg: *const libc::c_char) {
    // Convert immediately, all subsequent code is safe
    let msg = unsafe { CStr::from_ptr(msg) }
        .to_str()
        .unwrap_or_default();
    // No unsafe needed after this
    do_process(msg);
}
```

**Principles**:
1. `unsafe` blocks should be as small as possible - only contain the line that must be unsafe
2. Use `CStr`/`CString` instead of manual pointer arithmetic
3. Borrow rather than copy C strings (zero cost, avoids memory allocation)
4. `CString` lifetime must cover entire FFI call (common mistake: temporary CString)

```rust
// WRONG: Dangling pointer! CString drops immediately after ;
seterr(CString::new(msg)?.as_ptr());

// CORRECT: CString bound to variable, extended lifetime
let c_msg = CString::new(msg)?;
seterr(c_msg.as_ptr());
// c_msg drops here
```
