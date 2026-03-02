# Creational Design Patterns

Source: fadeevab/design-patterns-rust + rust-unofficial/patterns

## Table of Contents
1. [Builder](#builder)
2. [Factory Method](#factory-method)
3. [Abstract Factory](#abstract-factory)
4. [Prototype](#prototype)
5. [Singleton](#singleton)
6. [Static Creation Method](#static-creation-method)

---

## Builder

**Intent**: Separate complex object construction from its representation, allowing the same construction process to create different representations.

**Use Cases**: Objects with many optional parameters, or when construction steps have order dependencies. `std::process::Command` in the standard library is a Builder.

### Consuming Builder (Method Chaining, Recommended)

```rust
pub struct ServerConfig {
    host: String,
    port: u16,
    max_connections: usize,
    timeout: Duration,
    tls: Option<TlsConfig>,
}

pub struct ServerConfigBuilder {
    host: String,
    port: u16,
    max_connections: usize,
    timeout: Duration,
    tls: Option<TlsConfig>,
}

impl ServerConfigBuilder {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            max_connections: 100,    // Reasonable defaults
            timeout: Duration::from_secs(30),
            tls: None,
        }
    }

    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    pub fn build(self) -> Result<ServerConfig, ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidPort);
        }
        Ok(ServerConfig {
            host: self.host,
            port: self.port,
            max_connections: self.max_connections,
            timeout: self.timeout,
            tls: self.tls,
        })
    }
}

// Usage:
let config = ServerConfigBuilder::new("0.0.0.0", 8080)
    .max_connections(1000)
    .timeout(Duration::from_secs(60))
    .tls(TlsConfig::from_files("cert.pem", "key.pem")?)
    .build()?;
```

### Reference Builder (`&mut self`, for Pre-created Builder Variables)

```rust
impl ServerConfigBuilder {
    pub fn max_connections(&mut self, n: usize) -> &mut Self {
        self.max_connections = n;
        self
    }
    // ...
    pub fn build(&self) -> Result<ServerConfig, ConfigError> {
        // Doesn't consume self, can build multiple times
    }
}

// Usage:
let mut builder = ServerConfigBuilder::new("localhost", 3000);
builder.max_connections(50).timeout(Duration::from_secs(10));
let dev_config = builder.build()?;
let test_config = builder.max_connections(5).build()?;  // Reusable
```

### Type-State Builder (Compile-time Guaranteed Required Fields)

Use generic parameters to encode builder state - `build()` cannot be called without setting required fields:

```rust
struct Missing;
struct Provided;

struct QueryBuilder<HostState, TableState> {
    host: Option<String>,
    table: Option<String>,
    conditions: Vec<String>,
    _phantom: PhantomData<(HostState, TableState)>,
}

impl QueryBuilder<Missing, Missing> {
    pub fn new() -> Self {
        QueryBuilder { host: None, table: None, conditions: vec![], _phantom: PhantomData }
    }
}

impl<T> QueryBuilder<Missing, T> {
    pub fn host(mut self, host: impl Into<String>) -> QueryBuilder<Provided, T> {
        self.host = Some(host.into());
        QueryBuilder { host: self.host, table: self.table, conditions: self.conditions, _phantom: PhantomData }
    }
}

impl<H> QueryBuilder<H, Missing> {
    pub fn table(mut self, table: impl Into<String>) -> QueryBuilder<H, Provided> {
        self.table = Some(table.into());
        QueryBuilder { host: self.host, table: self.table, conditions: self.conditions, _phantom: PhantomData }
    }
}

// build() only available for <Provided, Provided>
impl QueryBuilder<Provided, Provided> {
    pub fn build(self) -> Query {
        Query { host: self.host.unwrap(), table: self.table.unwrap(), conditions: self.conditions }
    }
}
```

**Selection criteria**:
- All parameters optional/have defaults -> Consuming Builder
- Need multiple builds from same base config -> Reference Builder
- Required fields need compile-time guarantee -> Type-State Builder (more complex, but safer)

---

## Factory Method

**Intent**: Define an interface for creating objects, letting subclasses decide which class to instantiate.

**Rust Implementation**: Define creation method in trait, implementers decide concrete type.

```rust
pub trait Button {
    fn render(&self);
    fn on_click(&self);
}

pub trait Dialog {
    type ButtonType: Button;

    // Factory method
    fn create_button(&self) -> Self::ButtonType;

    // Template method using factory method
    fn render_dialog(&self) {
        let button = self.create_button();
        self.render_title();
        button.render();
    }

    fn render_title(&self);
}

// Concrete factory A
struct WebButton { label: String }
impl Button for WebButton {
    fn render(&self) { println!("<button>{}</button>", self.label); }
    fn on_click(&self) { /* ... */ }
}

struct WebDialog;
impl Dialog for WebDialog {
    type ButtonType = WebButton;
    fn create_button(&self) -> WebButton { WebButton { label: "OK".into() } }
    fn render_title(&self) { println!("<h1>Web Dialog</h1>"); }
}

// When runtime polymorphism is needed (different platforms):
trait DynDialog {
    fn create_button(&self) -> Box<dyn Button>;
}
```

---

## Abstract Factory

**Intent**: Provide an interface for creating families of related or dependent objects without specifying concrete classes.

**Rust Implementation**: Factory trait returns multiple related trait objects.

```rust
// Product traits
pub trait Button: fmt::Display { fn click(&self); }
pub trait Checkbox: fmt::Display { fn check(&mut self); fn is_checked(&self) -> bool; }
pub trait TextField: fmt::Display { fn input(&mut self, text: &str); fn value(&self) -> &str; }

// Abstract factory trait
pub trait GuiFactory {
    fn create_button(&self, label: &str) -> Box<dyn Button>;
    fn create_checkbox(&self, initial: bool) -> Box<dyn Checkbox>;
    fn create_text_field(&self, placeholder: &str) -> Box<dyn TextField>;
}

// Concrete factory: Material Design
pub struct MaterialFactory { theme: Theme }
impl GuiFactory for MaterialFactory {
    fn create_button(&self, label: &str) -> Box<dyn Button> {
        Box::new(MaterialButton::new(label, &self.theme))
    }
    fn create_checkbox(&self, initial: bool) -> Box<dyn Checkbox> {
        Box::new(MaterialCheckbox::new(initial, &self.theme))
    }
    fn create_text_field(&self, placeholder: &str) -> Box<dyn TextField> {
        Box::new(MaterialTextField::new(placeholder, &self.theme))
    }
}

// Concrete factory: Flat UI
pub struct FlatFactory;
impl GuiFactory for FlatFactory { /* ... */ }

// Select factory based on configuration
fn create_factory(theme: AppTheme) -> Box<dyn GuiFactory> {
    match theme {
        AppTheme::Material(t) => Box::new(MaterialFactory { theme: t }),
        AppTheme::Flat => Box::new(FlatFactory),
    }
}

// Business code doesn't depend on concrete factory
fn build_login_form(factory: &dyn GuiFactory) {
    let username = factory.create_text_field("Username");
    let password = factory.create_text_field("Password");
    let login_btn = factory.create_button("Login");
    let remember_me = factory.create_checkbox(false);
    // ...
}
```

**Generic version (compile-time determined factory, zero vtable overhead)**:
```rust
fn build_login_form<F: GuiFactory>(factory: &F) { /* same as above */ }
```

---

## Prototype

**Intent**: Specify the kind of objects to create using a prototypical instance, and create new objects by copying this prototype.

**Rust-specific note**: `#[derive(Clone)]` IS the Prototype pattern. This is the simplest GoF pattern in Rust.

```rust
#[derive(Debug, Clone)]
pub struct EnemyConfig {
    health: u32,
    damage: u32,
    speed: f32,
    abilities: Vec<Ability>,
    drop_table: DropTable,
}

#[derive(Debug, Clone)]
pub struct EnemyFactory {
    prototypes: HashMap<String, EnemyConfig>,
}

impl EnemyFactory {
    pub fn register(&mut self, name: impl Into<String>, prototype: EnemyConfig) {
        self.prototypes.insert(name.into(), prototype);
    }

    pub fn spawn(&self, name: &str) -> Option<EnemyConfig> {
        self.prototypes.get(name).cloned()
    }

    pub fn spawn_modified(&self, name: &str, modifier: impl Fn(&mut EnemyConfig)) -> Option<EnemyConfig> {
        let mut config = self.prototypes.get(name)?.clone();
        modifier(&mut config);
        Some(config)
    }
}

// Register prototypes
let mut factory = EnemyFactory::default();
factory.register("goblin", EnemyConfig { health: 50, damage: 10, speed: 1.5, /* ... */ });
factory.register("orc", EnemyConfig { health: 200, damage: 40, speed: 0.8, /* ... */ });

// Clone + modify
let elite_goblin = factory.spawn_modified("goblin", |e| {
    e.health *= 3;
    e.damage *= 2;
    e.abilities.push(Ability::Rage);
}).unwrap();
```

**Deep clone considerations**:
- `#[derive(Clone)]` calls `.clone()` on all fields, typically a deep clone
- If containing `Arc<T>`, clone only increments reference count (shares underlying data) - this may or may not be what you want
- If truly independent deep clone needed, manually implement `Clone` or consider `deep-clone` crate

---

## Singleton

**Intent**: Ensure a class has only one instance and provide a global access point.

### Modern Rust: `OnceLock` (Rust 1.70+, Recommended)

```rust
use std::sync::OnceLock;

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

pub fn get_config() -> &'static AppConfig {
    CONFIG.get_or_init(|| {
        AppConfig::load_from_env().expect("Failed to load config")
    })
}
```

### Mutable Singleton: `OnceLock<Mutex<T>>`

```rust
use std::sync::{OnceLock, Mutex};

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

fn get_logger() -> &'static Mutex<Logger> {
    LOGGER.get_or_init(|| Mutex::new(Logger::new()))
}

pub fn log(message: &str) {
    get_logger().lock().unwrap().write(message);
}
```

### Dependency Injection Friendly Singleton (Recommended for Testing)

Global singletons are hard to replace in tests. More flexible approach:

```rust
// Instead of global variables, pass "singleton" via dependency injection
pub struct App {
    config: Arc<AppConfig>,   // Arc allows multiple sharing, thread-safe
    logger: Arc<Mutex<Logger>>,
}

impl App {
    pub fn new() -> Self {
        Self {
            config: Arc::new(AppConfig::load()),
            logger: Arc::new(Mutex::new(Logger::new())),
        }
    }
}
// In tests, can pass mock config and logger
```

**When to use true global singleton**:
- OK: Logging systems, configuration, metrics collection - truly global infrastructure
- NO: Business logic dependencies - makes code hard to test
- NO: State that may need reset between tests

---

## Static Creation Method

**Intent**: Provide multiple creation paths through named associated functions, each name expressing specific semantics.

```rust
pub struct Color { r: u8, g: u8, b: u8, a: u8 }

impl Color {
    // Primary constructor
    pub fn new(r: u8, g: u8, b: u8) -> Self { Self { r, g, b, a: 255 } }
    pub fn with_alpha(r: u8, g: u8, b: u8, a: u8) -> Self { Self { r, g, b, a } }

    // Named semantic constructors
    pub fn black() -> Self { Self::new(0, 0, 0) }
    pub fn white() -> Self { Self::new(255, 255, 255) }
    pub fn transparent() -> Self { Self::with_alpha(0, 0, 0, 0) }

    // Parsing constructor (may fail)
    pub fn from_hex(hex: &str) -> Result<Self, ParseColorError> {
        let hex = hex.trim_start_matches('#');
        if hex.len() != 6 {
            return Err(ParseColorError::InvalidLength);
        }
        let r = u8::from_str_radix(&hex[0..2], 16)?;
        let g = u8::from_str_radix(&hex[2..4], 16)?;
        let b = u8::from_str_radix(&hex[4..6], 16)?;
        Ok(Self::new(r, g, b))
    }

    // Conversion constructor (From trait)
    pub fn from_grayscale(value: u8) -> Self { Self::new(value, value, value) }
}

// Standard library convention: From/Into traits for type conversion
impl From<u32> for Color {
    fn from(packed: u32) -> Self {
        Self {
            r: ((packed >> 16) & 0xFF) as u8,
            g: ((packed >> 8) & 0xFF) as u8,
            b: (packed & 0xFF) as u8,
            a: ((packed >> 24) & 0xFF) as u8,
        }
    }
}

// Usage
let red = Color::from_hex("#FF0000")?;
let bg = Color::black();
let c: Color = 0xFF0080FFu32.into();
```

**Naming conventions**:
- `Type::new(...)` — Primary constructor
- `Type::from_xxx(...)` — Convert from another type (if `From<X>` is implemented, use `x.into()`)
- `Type::with_xxx(...)` — Variant with additional options
- `Type::name()` — Named instance with special semantics (`Color::black()`, `Duration::ZERO`)
