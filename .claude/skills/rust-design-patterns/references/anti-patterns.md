# Rust Anti-Patterns

Source: rust-unofficial/patterns Anti-Patterns chapter, deeply organized

## Table of Contents
1. [Clone to Appease the Borrow Checker](#clone-to-appease-the-borrow-checker)
2. [Deref Polymorphism](#deref-polymorphism)
3. [`#![deny(warnings)]` in Libraries](#deny-warnings-in-libraries)
4. [Overusing String Types](#overusing-string-types)
5. [Unnecessary `Box<T>`](#unnecessary-boxt)
6. [Using `panic!` Instead of `Result`](#using-panic-instead-of-result)

---

## Clone to Appease the Borrow Checker

**Pattern Recognition**: Code contains `.clone()` calls not because an independent copy is genuinely needed, but because the borrow checker reported an error, and clone was used to silence the compiler.

### Typical Scenarios

```rust
// WRONG: Clone just to "bypass" borrow rules
fn process(data: &mut Vec<String>) {
    let names = data.clone();  // No reason to clone!
    for name in &names {
        if name.starts_with('A') {
            data.push(format!("{name}_processed"));  // This is the real intent
        }
    }
}

// WRONG: Useless clone in enum variant transformation
fn transform_state(state: &mut State) {
    if let State::Loading { url } = state {
        let url = url.clone();  // <- Only to resolve borrow conflict
        *state = State::Ready { url };
    }
}
```

### Root Causes and Correct Solutions

**Scenario A: Simultaneous Immutable Iteration + Mutable Modification**
```rust
// Problem: data is borrowed by for loop while also being mutated by push
// Correct: Collect needed changes, apply all at once at the end
fn process(data: &mut Vec<String>) {
    let additions: Vec<String> = data.iter()
        .filter(|name| name.starts_with('A'))
        .map(|name| format!("{name}_processed"))
        .collect();
    data.extend(additions);
}
```

**Scenario B: Enum Variant Transformation**
```rust
// Correct: Use mem::take (zero allocation)
use std::mem;
fn transform_state(state: &mut State) {
    if let State::Loading { url } = state {
        let url = mem::take(url);  // Extract url, leaving empty string
        *state = State::Ready { url };
    }
}
```

**Scenario C: Struct Field Borrow Conflicts**
```rust
// Problem: Simultaneously borrowing self.name and &mut self.jobs
// Correct: Split struct (see structural.md Struct Decomposition)
```

**Scenario D: Genuinely Need Independent Ownership (Legitimate Clone)**
```rust
// OK: Spawning new thread requires independent ownership
let data_for_thread = data.clone();
thread::spawn(move || process(data_for_thread));

// OK: Rc/Arc shared ownership
let shared = Arc::new(config);
let shared_clone = Arc::clone(&shared);  // Cheap: only increments reference count
```

**Diagnostic Question**: When encountering `clone()`, ask yourself: "If I couldn't clone, what would I want this code to do?" If the answer is "I just want it to compile", that's an anti-pattern.

---

## Deref Polymorphism

**Pattern Recognition**: Implementing `Deref<Target=Base>` to simulate OOP inheritance, making `Derived` "pretend to be" `Base`.

```rust
// WRONG: Using Deref to simulate inheritance
struct Animal { name: String }
impl Animal {
    fn name(&self) -> &str { &self.name }
    fn breathe(&self) { println!("{} breathes", self.name); }
}

struct Dog { animal: Animal, breed: String }
impl Deref for Dog {
    type Target = Animal;
    fn deref(&self) -> &Animal { &self.animal }
}

// Looks like inheritance:
let dog = Dog { animal: Animal { name: "Rex".into() }, breed: "Labrador".into() };
dog.breathe();   // Calls Animal::breathe via Deref, "appears" inherited
dog.name();      // Same
```

### Why This Is an Anti-Pattern

1. **Confused Semantics**: `Deref` semantics are "I am some kind of pointer/container", not "I inherit from some class". `Vec<T>: Deref<Target=[T]>` is correct; `Dog: Deref<Target=Animal>` is wrong.

2. **Trait Bounds Fail**: Deref coercion doesn't count toward trait bound checking.
   ```rust
   fn pet(animal: &Animal) { /* ... */ }
   fn pet_generic<T: AnimalTrait>(t: &T) { /* ... */ }

   pet(&dog);          // OK (Deref coercion)
   pet_generic(&dog);  // COMPILE ERROR! Dog doesn't implement AnimalTrait
                       // Even though *dog: Animal implements AnimalTrait
   ```

3. **Mutability Issues**: `DerefMut` exposes internal structure, breaking encapsulation.

### Correct Alternatives

**Approach A: Composition + Delegation (Explicit Forwarding)**
```rust
struct Dog { animal: Animal, breed: String }
impl Dog {
    // Explicitly delegate methods you need
    pub fn name(&self) -> &str { self.animal.name() }
    pub fn breathe(&self) { self.animal.breathe() }
    // Also add Dog-specific behavior
    pub fn fetch(&self) { println!("{} fetches!", self.animal.name()); }
}
```

**Approach B: Shared Trait (Rust's Recommended Polymorphism)**
```rust
pub trait Animal {
    fn name(&self) -> &str;
    fn breathe(&self) { println!("{} breathes", self.name()); }  // default impl
}

struct Dog { name: String, breed: String }
struct Cat { name: String, indoor: bool }

impl Animal for Dog { fn name(&self) -> &str { &self.name } }
impl Animal for Cat { fn name(&self) -> &str { &self.name } }

fn pet<A: Animal>(animal: &A) { animal.breathe(); }
```

**When `Deref` Is Appropriate**: Only for smart pointer semantics - when your type **IS** some kind of pointer/container. `Box<T>`, `Rc<T>`, `Vec<T>`, `String`'s `Deref` implementations are all appropriate.

---

## `#![deny(warnings)]` in Libraries

**Pattern Recognition**: Writing `#![deny(warnings)]` at the top of `lib.rs`.

```rust
// WRONG: Using in a library
#![deny(warnings)]  // Will cause users' CI to fail when upgrading Rust compiler versions!
```

### Harm

New Rust versions may introduce new lints. If your library has `deny(warnings)`, users' CI may suddenly fail when they upgrade their compiler - even if they haven't changed any code. This is a time bomb you cannot control that breaks users' CI.

### Correct Alternatives

```rust
// OK in libraries: Allow warnings to exist (let users decide whether to treat as errors)
// If you want to prompt users, you can use:
#![warn(missing_docs)]  // Just a warning, not an error

// OK in binaries/applications (you control the compilation environment):
#![deny(warnings)]  // Don't use in lib.rs, can consider in main.rs

// OK in CI (via environment variable):
// RUSTFLAGS="-D warnings" cargo build
// This only affects your CI, not library users
```

**Specify Exact Warnings to Deny** (safer than global deny):
```rust
#![deny(unused_must_use)]    // Specific warning
#![deny(clippy::all)]        // Deny all clippy warnings (requires nightly or configuration)
```

---

## Overusing String Types

**Pattern Recognition**: Using `String` or `&str` to pass values that should be structured types (like status, error types, configuration keys).

```rust
// WRONG: String-typed "enum"
fn set_log_level(level: &str) {  // "debug", "info", "warn", "error"
    match level {
        "debug" => { /* ... */ }
        "info" => { /* ... */ }
        _ => panic!("unknown level: {level}"),  // Only discover errors at runtime!
    }
}
fn connect(protocol: String) {  // "tcp", "udp"
    if protocol != "tcp" && protocol != "udp" {
        panic!("unsupported protocol");
    }
}
```

### Correct Alternatives

```rust
// OK: Use enum instead of string "enum"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel { Debug, Info, Warn, Error }

fn set_log_level(level: LogLevel) {  // Compile-time type checking, no need for default match branch
    match level {
        LogLevel::Debug => { /* ... */ }
        LogLevel::Info => { /* ... */ }
        LogLevel::Warn => { /* ... */ }
        LogLevel::Error => { /* ... */ }
    }
}

// OK: Use Newtype instead of bare string (adds type safety)
pub struct HostName(String);
pub struct TableName(String);

fn connect(host: HostName, table: TableName) { /* Can't mix them up */ }
```

---

## Unnecessary `Box<T>`

**Pattern Recognition**: Using `Box<T>` in scenarios where it's not needed.

```rust
// WRONG: Types with known compile-time size don't need Box
fn process(data: Box<Vec<i32>>) { /* ... */ }  // Vec is already heap-allocated
let x: Box<i32> = Box::new(42);               // i32 is fine on the stack
let s: Box<String> = Box::new("hello".into()); // String itself is a heap pointer

// WRONG: Box inside Option (unless type is particularly large)
fn find_config() -> Option<Box<Config>> { /* ... */ }  // Usually unnecessary
```

### Legitimate Uses of `Box<T>`

```rust
// OK: Trait objects (must use Box or &dyn)
fn create_logger(verbose: bool) -> Box<dyn Logger> {
    if verbose { Box::new(VerboseLogger) } else { Box::new(SilentLogger) }
}

// OK: Recursive data structures (direct recursion would be infinite size)
enum Tree<T> {
    Leaf(T),
    Node { value: T, left: Box<Tree<T>>, right: Box<Tree<T>> },  // Must Box
}

// OK: Large structs need heap allocation (avoid stack overflow)
struct HugeStruct { data: [u8; 1_000_000] }
let huge = Box::new(HugeStruct { data: [0; 1_000_000] });

// OK: Ownership transfer to FFI or scenarios where size doesn't matter
```

---

## Using `panic!` Instead of `Result`

**Pattern Recognition**: Using `panic!`, `.unwrap()`, or `.expect()` instead of returning `Result` in situations that could reasonably fail.

```rust
// WRONG: Panicking in library code (deprives callers of error handling control)
pub fn parse_config(path: &str) -> Config {
    let content = std::fs::read_to_string(path).unwrap();  // Panics if file doesn't exist
    toml::from_str(&content).expect("Invalid config")       // Panics if format is wrong
}

// WRONG: Panicking in potentially failing conversion
pub fn to_positive(n: i32) -> u32 {
    assert!(n >= 0, "must be positive");  // Caller can't handle gracefully
    n as u32
}
```

### Correct Distinctions

| Scenario | Appropriate Handling |
|----------|---------------------|
| Truly impossible errors (logic bugs) | `unwrap()`/`expect()` + clear error message |
| Operations that might fail (I/O, parsing, etc.) | Return `Result<T, E>` |
| In tests | `unwrap()` is acceptable |
| Library public APIs | Almost always `Result` |
| Application `main` function | `Result<(), Box<dyn Error>>` or `anyhow::Result` |

```rust
// OK: Library API returns Result
pub fn parse_config(path: &str) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::Io { path: path.into(), source: e })?;
    toml::from_str(&content)
        .map_err(|e| ConfigError::Parse { source: e })
}

// OK: Legitimate panic: violated documented precondition (logic bug)
/// # Panics
/// Panics if `index >= self.len()`.
pub fn get_unchecked(&self, index: usize) -> &T {
    assert!(index < self.len(), "index out of bounds: {index} >= {}", self.len());
    unsafe { self.data.get_unchecked(index) }
}

// OK: Use ? to propagate errors (not unwrap)
fn load_and_process() -> Result<Output, AppError> {
    let config = parse_config("config.toml")?;
    let data = fetch_data(&config.url)?;
    Ok(process(data))
}
```

**`expect()` Usage Principle**: When you're certain this unwrap cannot fail (but if it does, the error message should be meaningful):
```rust
// OK: Legitimate expect: writing to stderr shouldn't fail
writeln!(stderr, "Error: {e}").expect("failed to write to stderr");

// OK: Legitimate expect: regex literals are never invalid
let re = Regex::new(r"^\d+$").expect("hardcoded regex is always valid");
```
