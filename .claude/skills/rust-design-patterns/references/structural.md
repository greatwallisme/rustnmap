# Structural Design Patterns

Source: fadeevab/design-patterns-rust + rust-unofficial/patterns comprehensive compilation

## Table of Contents
1. [Adapter](#adapter)
2. [Decorator](#decorator)
3. [Facade](#facade)
4. [Proxy](#proxy)
5. [Composite](#composite)
6. [Bridge](#bridge)
7. [Flyweight](#flyweight)
8. [Rust-specific: Newtype Pattern](#newtype-pattern)
9. [Rust-specific: RAII Guard](#raii-guard)
10. [Rust-specific: Struct Decomposition](#struct-decomposition)
11. [Rust-specific: Fold Pattern](#fold-pattern)

---

## Adapter

**Intent**: Convert incompatible interfaces into target interfaces.

**Rust Specificity**: The orphan rule (cannot implement foreign traits for foreign types) makes Adapter especially common in Rust. Newtype is the standard tool for implementing Adapter.

### Newtype Adapter (Bypassing Orphan Rule)

```rust
// Scenario: Want third-party Vec<String> to implement our Logger trait
use third_party::Logger as ThirdPartyLogger;

// Our trait
pub trait Logger {
    fn log(&self, level: Level, msg: &str);
    fn flush(&self);
}

// Adapter: Wrap external type
pub struct LoggerAdapter(ThirdPartyLogger);

impl LoggerAdapter {
    pub fn new(inner: ThirdPartyLogger) -> Self { Self(inner) }
    pub fn into_inner(self) -> ThirdPartyLogger { self.0 }
}

impl Logger for LoggerAdapter {
    fn log(&self, level: Level, msg: &str) {
        // Adapt interface differences
        self.0.write_log(level.to_str(), msg);
    }
    fn flush(&self) { self.0.force_flush(); }
}
```

### Function Adapter (Adapting Different Function Signatures)

```rust
// External library requires fn(i32) -> i32
// Our code uses fn(f64) -> f64
fn adapt_fn<F>(f: F) -> impl Fn(i32) -> i32
where F: Fn(f64) -> f64
{
    move |x| f(x as f64) as i32
}
```

### Bidirectional Adapter: `From`/`Into` Trait

```rust
// Standard library's From/Into is language-level support for adapter pattern
impl From<OldConfig> for NewConfig {
    fn from(old: OldConfig) -> Self {
        NewConfig {
            host: old.server_address,
            port: old.port_number,
            // Handle interface differences
            timeout: Duration::from_millis(old.timeout_ms),
        }
    }
}

let new_config = NewConfig::from(old_config);
// or
let new_config: NewConfig = old_config.into();
```

---

## Decorator

**Intent**: Dynamically add responsibilities to objects, more flexible than inheritance.

```rust
pub trait TextProcessor {
    fn process(&self, text: &str) -> String;
}

// Base implementation
pub struct PlainText;
impl TextProcessor for PlainText {
    fn process(&self, text: &str) -> String { text.to_string() }
}

// Decorator: Wrap Box<dyn TextProcessor> and add behavior
pub struct TrimDecorator { inner: Box<dyn TextProcessor> }
impl TextProcessor for TrimDecorator {
    fn process(&self, text: &str) -> String {
        self.inner.process(text.trim())
    }
}

pub struct UpperCaseDecorator { inner: Box<dyn TextProcessor> }
impl TextProcessor for UpperCaseDecorator {
    fn process(&self, text: &str) -> String {
        self.inner.process(text).to_uppercase()
    }
}

pub struct CensorDecorator {
    inner: Box<dyn TextProcessor>,
    banned_words: Vec<String>,
}
impl TextProcessor for CensorDecorator {
    fn process(&self, text: &str) -> String {
        let processed = self.inner.process(text);
        self.banned_words.iter().fold(processed, |acc, word| {
            acc.replace(word.as_str(), &"*".repeat(word.len()))
        })
    }
}

// Build decorator stack
fn build_processor() -> Box<dyn TextProcessor> {
    Box::new(CensorDecorator {
        inner: Box::new(UpperCaseDecorator {
            inner: Box::new(TrimDecorator {
                inner: Box::new(PlainText),
            }),
        }),
        banned_words: vec!["spam".to_string()],
    })
}
```

**Note**: Rust has no inheritance, each layer needs full trait implementation - more verbose than some OOP languages, but also more explicit. Consider `derive_more` crate to reduce boilerplate.

---

## Facade

**Intent**: Provide a unified high-level interface for a set of interfaces in a subsystem.

**Rust Implementation**: Module system + `pub use` is a natural Facade.

```rust
// Internal complex subsystem
mod http_client { pub struct Client { /* ... */ } }
mod serializer { pub fn to_json<T: Serialize>(v: &T) -> Result<String, Error> { /* ... */ } }
mod auth { pub struct TokenStore { /* ... */ } pub fn validate(token: &str) -> bool { /* ... */ } }
mod retry { pub struct RetryPolicy { /* ... */ } }

// Facade: Unified public interface
pub struct ApiClient {
    http: http_client::Client,
    tokens: auth::TokenStore,
    retry: retry::RetryPolicy,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self, InitError> { /* ... */ }

    // High-level interface - hides subsystem complexity
    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let token = self.tokens.get_valid_token()?;
        self.retry.execute(|| {
            let response = self.http.get(&format!("{}/{}", self.base_url, path))
                .header("Authorization", &format!("Bearer {token}"))
                .send()?;
            let body = response.text()?;
            let result = serializer::from_json(&body)?;
            Ok(result)
        })
    }

    pub fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R, ApiError> {
        /* ... */
    }
}

// Module-level Facade: re-export selected public APIs
pub use self::api_client::ApiClient;
pub use self::types::{User, Post, Comment};
pub use self::errors::ApiError;
// Internal modules not visible externally
```

---

## Proxy

**Intent**: Provide a proxy for an object to control access to it (lazy loading, access control, logging, caching).

### Caching Proxy

```rust
pub trait DataSource {
    fn fetch(&self, key: &str) -> Option<String>;
    fn store(&mut self, key: String, value: String);
}

pub struct CachingProxy {
    real_source: Box<dyn DataSource>,
    cache: HashMap<String, String>,
    hits: u64,
    misses: u64,
}

impl DataSource for CachingProxy {
    fn fetch(&self, key: &str) -> Option<String> {
        if let Some(cached) = self.cache.get(key) {
            // Note: self is immutable reference, can't update hits
            // Need RefCell or extract stats to Cell
            return Some(cached.clone());
        }
        self.real_source.fetch(key)
    }

    fn store(&mut self, key: String, value: String) {
        self.cache.insert(key.clone(), value.clone());
        self.real_source.store(key, value);
    }
}
```

### Lazy Loading Proxy

```rust
pub struct LazyProxy<T, F: Fn() -> T> {
    value: Option<T>,
    factory: F,
}

impl<T, F: Fn() -> T> LazyProxy<T, F> {
    pub fn new(factory: F) -> Self { Self { value: None, factory } }

    pub fn get(&mut self) -> &T {
        self.value.get_or_insert_with(|| (self.factory)())
    }
}

// Usage
let mut expensive = LazyProxy::new(|| {
    println!("Loading expensive resource...");
    ExpensiveResource::load()
});
// Not actually loaded until first .get() call
let resource = expensive.get();
```

---

## Composite

**Intent**: Compose objects into tree structures to represent part-whole hierarchies. Clients treat individual objects and compositions uniformly.

**Rust Implementation**: Recursive enums are the most natural Composite implementation.

```rust
#[derive(Debug)]
pub enum FileSystemNode {
    File {
        name: String,
        size_bytes: u64,
    },
    Directory {
        name: String,
        children: Vec<FileSystemNode>,
    },
    Symlink {
        name: String,
        target: String,
    },
}

impl FileSystemNode {
    pub fn name(&self) -> &str {
        match self {
            Self::File { name, .. } | Self::Directory { name, .. } | Self::Symlink { name, .. } => name,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::File { size_bytes, .. } => *size_bytes,
            Self::Directory { children, .. } => children.iter().map(|c| c.size()).sum(),
            Self::Symlink { .. } => 0,
        }
    }

    pub fn find(&self, name: &str) -> Option<&FileSystemNode> {
        match self {
            Self::File { name: n, .. } if n == name => Some(self),
            Self::Directory { name: n, children, .. } => {
                if n == name { return Some(self); }
                children.iter().find_map(|c| c.find(name))
            }
            _ => None,
        }
    }
}
```

---

## Bridge

**Intent**: Separate abstraction from implementation so both can vary independently.

```rust
// Implementation layer trait
pub trait Renderer {
    fn render_circle(&self, x: f64, y: f64, radius: f64);
    fn render_rectangle(&self, x: f64, y: f64, w: f64, h: f64);
}

// Abstraction layer
pub trait Shape {
    fn draw(&self);
    fn resize(&mut self, factor: f64);
}

// Concrete abstraction - holds implementation layer reference (this is the Bridge)
pub struct Circle {
    x: f64, y: f64, radius: f64,
    renderer: Box<dyn Renderer>,  // Bridge to implementation layer
}

impl Shape for Circle {
    fn draw(&self) {
        self.renderer.render_circle(self.x, self.y, self.radius);
    }
    fn resize(&mut self, factor: f64) { self.radius *= factor; }
}

// Concrete implementation A
pub struct SvgRenderer;
impl Renderer for SvgRenderer {
    fn render_circle(&self, x: f64, y: f64, r: f64) {
        println!(r#"<circle cx="{x}" cy="{y}" r="{r}"/>"#);
    }
    fn render_rectangle(&self, x: f64, y: f64, w: f64, h: f64) {
        println!(r#"<rect x="{x}" y="{y}" width="{w}" height="{h}"/>"#);
    }
}

// Concrete implementation B (independently evolved)
pub struct CanvasRenderer { ctx: CanvasContext }
impl Renderer for CanvasRenderer { /* ... */ }

// Generic version (compile-time bridging, zero virtual function calls)
pub struct GenericCircle<R: Renderer> {
    radius: f64,
    renderer: R,
}
```

---

## Flyweight

**Intent**: Use sharing to support large numbers of fine-grained objects efficiently.

**Rust Implementation**: `Arc<T>` is language-level Flyweight - reference-counted shared immutable data.

```rust
// Shared intrinsic state (doesn't vary per instance)
#[derive(Debug)]
pub struct TreeType {
    pub name: String,
    pub color: [u8; 3],
    pub texture: Vec<u8>,  // Potentially large texture data
}

// Unique extrinsic state (different per instance)
pub struct Tree {
    pub x: f32,
    pub y: f32,
    pub scale: f32,
    pub tree_type: Arc<TreeType>,  // Arc = shared ownership, no need to copy large data
}

// Flyweight factory: manages shared object pool
pub struct TreeFactory {
    types: HashMap<String, Arc<TreeType>>,
}

impl TreeFactory {
    pub fn get_tree_type(&mut self, name: &str, color: [u8; 3]) -> Arc<TreeType> {
        let key = format!("{name}:{color:?}");
        self.types
            .entry(key)
            .or_insert_with(|| {
                println!("Creating new TreeType: {name}");
                Arc::new(TreeType {
                    name: name.to_string(),
                    color,
                    texture: load_texture(name),  // Only load once
                })
            })
            .clone()  // clone Arc only increments reference count (cheap)
    }

    pub fn plant_tree(&mut self, x: f32, y: f32, name: &str, color: [u8; 3]) -> Tree {
        Tree { x, y, scale: 1.0, tree_type: self.get_tree_type(name, color) }
    }
}

// Plant a million trees, but only a few TreeType instances
let mut factory = TreeFactory::default();
let forest: Vec<Tree> = (0..1_000_000)
    .map(|i| factory.plant_tree(i as f32 * 0.1, (i % 100) as f32, "oak", [34, 100, 34]))
    .collect();
// Arc reference count = 1,000,000, but only 1 TreeType instance
```

---

## Newtype Pattern

**Rust-specific.** Use zero-cost tuple structs to wrap types, providing: type safety, API restrictions, orphan rule bypass, custom trait implementations.

```rust
// 1. Type safety: Prevent confusion between values of same underlying type
pub struct Meters(f64);
pub struct Kilograms(f64);
// Compiler prevents: let m: Meters = Kilograms(70.0);

// 2. Orphan rule bypass: Implement foreign trait for foreign type
use serde::{Serialize, Deserialize};
pub struct UserId(uuid::Uuid);  // Can't directly impl Display for uuid::Uuid
impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "user:{}", self.0) }
}

// 3. API restriction: Only expose methods you want to expose
pub struct NonEmptyVec<T>(Vec<T>);
impl<T> NonEmptyVec<T> {
    pub fn new(first: T) -> Self { Self(vec![first]) }
    pub fn push(&mut self, item: T) { self.0.push(item) }
    pub fn len(&self) -> NonZeroUsize { unsafe { NonZeroUsize::new_unchecked(self.0.len()) } }
    // pop() not exposed - could result in empty Vec
}

// 4. Custom display (security-sensitive data)
pub struct Password(String);
impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "Password([REDACTED])") }
}
impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "***") }
}
```

**Accessing inner value**:
```rust
// Method 1: Direct access (pub tuple field)
pub struct Meters(pub f64);
let m = Meters(5.0);
println!("{}", m.0);

// Method 2: Provide unwrap method
impl Meters {
    pub fn value(&self) -> f64 { self.0 }
    pub fn into_inner(self) -> f64 { self.0 }
}

// Method 3: Implement Deref (let users transparently access inner methods, use cautiously)
impl Deref for NonEmptyVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] { &self.0 }
}
```

---

## RAII Guard

**Rust-specific.** Use `Drop` trait to implement cleanup logic that automatically executes at scope end, corresponding to RAII (Resource Acquisition Is Initialization).

```rust
// Example: Mutex guard (equivalent to simplified standard library MutexGuard)
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T { unsafe { &*self.lock.data.get() } }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.data.get() } }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
// Lock is released no matter how scope exits

// Example: Performance timing Guard
pub struct Timer { label: String, start: Instant }
impl Timer {
    pub fn start(label: impl Into<String>) -> Self {
        Self { label: label.into(), start: Instant::now() }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        println!("{}: {:?}", self.label, self.start.elapsed());
    }
}

fn expensive_operation() {
    let _timer = Timer::start("expensive_operation");  // Automatic timing
    // ... prints elapsed time no matter how it exits
}
```

---

## Struct Decomposition

**Rust-specific.** Solve the borrow checker's inability to simultaneously mutably borrow multiple fields of the same struct by splitting struct fields into sub-structs.

```rust
// WRONG: Won't compile - can't simultaneously mutably borrow name and jobs
struct Employee { name: String, skills: Vec<String>, jobs: Vec<Job> }
fn add_job(emp: &mut Employee, job: Job) {
    emp.jobs.push(job);
    log(&emp.name, &emp.jobs);  // After borrowing jobs, name is still locked by mut borrow
}

// CORRECT: Split into meaningful sub-structs
struct EmployeeProfile { name: String, skills: Vec<String> }
struct EmployeeWork { jobs: Vec<Job>, current_role: Option<String> }

struct Employee { profile: EmployeeProfile, work: EmployeeWork }

fn add_job(emp: &mut Employee, job: Job) {
    emp.work.jobs.push(job);
    log(&emp.profile.name, &emp.work.jobs);  // Borrowing different fields, valid
}

// More direct approach: Provide method returning multiple mutable references
impl Employee {
    fn borrow_both(&mut self) -> (&mut EmployeeProfile, &mut EmployeeWork) {
        (&mut self.profile, &mut self.work)
    }
}
```

---

## Fold Pattern

**Rust-specific.** Transform a data structure into another instance of the same type (e.g., AST transformation), where each node type has a corresponding fold method. Default implementations recursively process, only overriding nodes needing transformation.

```rust
// Data structure being folded
#[derive(Clone)]
pub enum Ast {
    Number(f64),
    Var(String),
    BinOp { op: String, lhs: Box<Ast>, rhs: Box<Ast> },
    FuncCall { name: String, args: Vec<Ast> },
}

// Folder trait: one method per node type, defaults to recursion
pub trait AstFolder {
    fn fold_number(&mut self, n: f64) -> Ast { Ast::Number(n) }
    fn fold_var(&mut self, name: String) -> Ast { Ast::Var(name) }

    fn fold_binop(&mut self, op: String, lhs: Ast, rhs: Ast) -> Ast {
        Ast::BinOp {
            op,
            lhs: Box::new(self.fold(lhs)),
            rhs: Box::new(self.fold(rhs)),
        }
    }

    fn fold_func_call(&mut self, name: String, args: Vec<Ast>) -> Ast {
        Ast::FuncCall { name, args: args.into_iter().map(|a| self.fold(a)).collect() }
    }

    fn fold(&mut self, ast: Ast) -> Ast {
        match ast {
            Ast::Number(n) => self.fold_number(n),
            Ast::Var(s) => self.fold_var(s),
            Ast::BinOp { op, lhs, rhs } => self.fold_binop(op, *lhs, *rhs),
            Ast::FuncCall { name, args } => self.fold_func_call(name, args),
        }
    }
}

// Concrete Folder: Constant folding optimization
struct ConstantFolder;
impl AstFolder for ConstantFolder {
    fn fold_binop(&mut self, op: String, lhs: Ast, rhs: Ast) -> Ast {
        let lhs = self.fold(lhs);
        let rhs = self.fold(rhs);
        // Try folding two numbers
        if let (Ast::Number(l), Ast::Number(r)) = (&lhs, &rhs) {
            match op.as_str() {
                "+" => return Ast::Number(l + r),
                "*" => return Ast::Number(l * r),
                _ => {}
            }
        }
        Ast::BinOp { op, lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }
}
```
