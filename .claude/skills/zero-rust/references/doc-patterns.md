# Documentation Patterns

Templates for properly documenting Rust code to pass rustdoc checks.

---

## Functions

### Basic Function

```rust
/// Brief description in imperative mood ("Calculate" not "Calculates").
///
/// Additional details if needed. Explain algorithm, edge cases, or usage notes.
///
/// # Arguments
///
/// * `param_a` - Description of parameter a
/// * `param_b` - Description of parameter b
///
/// # Returns
///
/// Description of return value.
///
/// # Examples
///
/// ```rust
/// use crate::module::function_name;
/// let result = function_name(1, "hello");
/// assert_eq!(result, 42);
/// ```
pub fn function_name(param_a: i32, param_b: &str) -> i32 {
    // ...
}
```

### Function with Errors

```rust
/// Reads configuration from the specified path.
///
/// Parses TOML format and validates required fields.
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Returns
///
/// Returns `Ok(Config)` on success.
///
/// # Errors
///
/// Returns `io::Error` if:
/// - The file does not exist
/// - Read permissions are insufficient
///
/// Returns `ConfigError` if:
/// - The TOML syntax is invalid
/// - Required fields are missing
///
/// # Examples
///
/// ```rust
/// use my_crate::read_config;
/// let config = read_config("config.toml")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn read_config(path: &Path) -> Result<Config, ConfigError> {
    // ...
}
```

### Function that Panics

```rust
/// Returns the first element of a slice.
///
/// # Arguments
///
/// * `slice` - The input slice
///
/// # Returns
///
/// The first element of the slice.
///
/// # Panics
///
/// Panics if `slice` is empty.
///
/// # Examples
///
/// ```rust
/// let first = get_first(&[1, 2, 3]);
/// assert_eq!(first, 1);
/// ```
pub fn get_first<T>(slice: &[T]) -> &T {
    assert!(!slice.is_empty(), "slice must not be empty");
    &slice[0]
}

/// Alternative: Return Option instead of panicking
///
/// Returns the first element of a slice, if any.
pub fn try_first<T>(slice: &[T]) -> Option<&T> {
    slice.first()
}
```

### Unsafe Function

```rust
/// Reads a value from a raw pointer.
///
/// # Arguments
///
/// * `ptr` - Pointer to the value. Must be valid and properly aligned.
///
/// # Returns
///
/// The value pointed to by `ptr`.
///
/// # Safety
///
/// - `ptr` must be non-null and properly aligned
/// - `ptr` must point to initialized memory
/// - The memory must remain valid for the duration of the call
///
/// # Examples
///
/// ```rust
/// let x = 42;
/// let ptr = &x as *const i32;
/// unsafe {
///     assert_eq!(read_value(ptr), 42);
/// }
/// ```
///
/// # Safety
///
/// This function is unsafe because improper use may lead to undefined behavior.
pub unsafe fn read_value<T>(ptr: *const T) -> T {
    ptr.read()
}
```

---

## Structs

### Plain Struct

```rust
/// Configuration options for the HTTP client.
///
/// Controls connection pooling, timeouts, and retry behavior.
///
/// # Examples
///
/// ```rust
/// use my_crate::ClientConfig;
///
/// let config = ClientConfig {
///     timeout_secs: 30,
///     max_retries: 3,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// Connection timeout in seconds. 0 means no timeout.
    pub timeout_secs: u64,

    /// Maximum number of retry attempts for failed requests.
    pub max_retries: u32,

    /// Whether to enable connection pooling.
    pub use_pooling: bool,
}
```

### Struct with Private Fields

```rust
/// A builder for constructing HTTP requests.
///
/// Use `RequestBuilder::new()` to create a new builder,
/// then chain method calls to configure the request.
///
/// # Examples
///
/// ```rust
/// use my_crate::RequestBuilder;
///
/// let request = RequestBuilder::new()
///     .url("https://example.com")
///     .method("POST")
///     .body("data")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct RequestBuilder {
    url: String,
    method: String,
    body: Option<String>,
}

impl RequestBuilder {
    /// Creates a new request builder with default settings.
    pub fn new() -> Self {
        Self {
            url: String::new(),
            method: "GET".to_string(),
            body: None,
        }
    }

    /// Sets the request URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The target URL
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    // ... more builder methods
}
```

### Generic Struct

```rust
/// A wrapper around a value that tracks access patterns.
///
/// # Type Parameters
///
/// * `T` - The type of the wrapped value
///
/// # Examples
///
/// ```rust
/// use my_crate::Tracked;
///
/// let tracked = Tracked::new(42);
/// let value = tracked.get();
/// assert_eq!(tracked.access_count(), 1);
/// ```
pub struct Tracked<T> {
    value: T,
    access_count: std::cell::Cell<usize>,
}

impl<T> Tracked<T> {
    /// Creates a new tracked value.
    pub fn new(value: T) -> Self {
        Self {
            value,
            access_count: std::cell::Cell::new(0),
        }
    }

    /// Returns a reference to the value, incrementing access count.
    pub fn get(&self) -> &T {
        self.access_count.set(self.access_count.get() + 1);
        &self.value
    }
}
```

---

## Enums

### Simple Enum

```rust
/// HTTP status code categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCategory {
    /// 1xx informational response
    Informational,

    /// 2xx successful response
    Success,

    /// 3xx redirection
    Redirection,

    /// 4xx client error
    ClientError,

    /// 5xx server error
    ServerError,
}
```

### Enum with Data

```rust
/// Result of a parsing operation.
///
/// # Examples
///
/// ```rust
/// use my_crate::ParseResult;
///
/// match parse("42") {
///     ParseResult::Success { value, consumed } => {
///         println!("Parsed: {} (consumed {} chars)", value, consumed);
///     }
///     ParseResult::Error { message, position } => {
///         eprintln!("Error at {}: {}", position, message);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum ParseResult<T> {
    /// Parsing succeeded.
    Success {
        /// The parsed value.
        value: T,

        /// Number of characters consumed.
        consumed: usize,
    },

    /// Parsing failed.
    Error {
        /// Error message describing what went wrong.
        message: String,

        /// Position in the input where the error occurred.
        position: usize,
    },
}
```

### Error Enum

```rust
/// Errors that can occur when processing a request.
#[derive(Debug, Clone)]
pub enum RequestError {
    /// The URL format was invalid.
    InvalidUrl {
        /// The URL that failed parsing.
        url: String,
    },

    /// Connection to the server failed.
    ConnectionFailed {
        /// The host that could not be reached.
        host: String,
    },

    /// The request timed out.
    Timeout {
        /// Duration waited before timing out.
        duration_secs: u64,
    },
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl { url } => write!(f, "invalid URL: {}", url),
            Self::ConnectionFailed { host } => write!(f, "connection failed to: {}", host),
            Self::Timeout { duration_secs } => write!(f, "timeout after {}s", duration_secs),
        }
    }
}

impl std::error::Error for RequestError {}
```

---

## Traits

### Basic Trait

```rust
/// A type that can be serialized to JSON.
///
/// Implement this trait for types that need custom JSON serialization.
///
/// # Examples
///
/// ```rust
/// use my_crate::JsonSerializable;
///
/// struct Point { x: i32, y: i32 }
///
/// impl JsonSerializable for Point {
///     fn to_json(&self) -> String {
///         format!("{{\"x\":{},\"y\":{}}}", self.x, self.y)
///     }
/// }
///
/// let point = Point { x: 1, y: 2 };
/// assert_eq!(point.to_json(), r#"{"x":1,"y":2}"#);
/// ```
pub trait JsonSerializable {
    /// Serializes the value to a JSON string.
    fn to_json(&self) -> String;
}
```

### Trait with Associated Types

```rust
/// A data source that provides streaming access to records.
///
/// # Type Parameters
///
/// Implementors define the `Item` type representing individual records.
///
/// # Examples
///
/// ```rust
/// use my_crate::DataSource;
///
/// struct CsvSource { /* ... */ }
///
/// impl DataSource for CsvSource {
///     type Item = Vec<String>;
///
///     fn next(&mut self) -> Option<Self::Item> {
///         // Parse next CSV row
///         # None
///     }
/// }
/// ```
pub trait DataSource {
    /// The type of records produced by this source.
    type Item;

    /// Returns the next record, or `None` if exhausted.
    fn next(&mut self) -> Option<Self::Item>;

    /// Resets the source to the beginning.
    fn reset(&mut self);
}
```

### Trait with Required Methods

```rust
/// A cache backend that stores key-value pairs.
///
/// # Required Methods
///
/// Implementors must provide `get` and `set`.
///
/// # Provided Methods
///
/// `get_or_insert` is provided based on the required methods.
///
/// # Examples
///
/// ```rust
/// use my_crate::Cache;
///
/// struct MemoryCache;
///
/// impl Cache for MemoryCache {
///     type Key = String;
///     type Value = Vec<u8>;
///
///     fn get(&self, key: &Self::Key) -> Option<Self::Value> {
///         // Implementation
///         # None
///     }
///
///     fn set(&mut self, key: Self::Key, value: Self::Value) {
///         // Implementation
///     }
/// }
/// ```
pub trait Cache {
    /// The key type for cache entries.
    type Key;

    /// The value type for cache entries.
    type Value;

    /// Retrieves a value from the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// `Some(value)` if found, `None` otherwise.
    fn get(&self, key: &Self::Key) -> Option<Self::Value>;

    /// Stores a value in the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store under
    /// * `value` - The value to store
    fn set(&mut self, key: Self::Key, value: Self::Value);

    /// Gets a value or inserts a default.
    ///
    /// Provided method - implementors should not override unless
    /// an optimized version is available.
    fn get_or_insert<F>(&mut self, key: Self::Key, default: F) -> Self::Value
    where
        F: FnOnce() -> Self::Value,
    {
        match self.get(&key) {
            Some(value) => value,
            None => {
                let value = default();
                self.set(key, value.clone());
                value
            }
        }
    }
}
```

---

## Modules

### Module-Level Documentation

```rust
//! HTTP client implementation.
//!
//! This module provides an HTTP client with support for:
//! - Connection pooling
//! - Request/response handling
//! - Automatic retries
//!
//! # Example
//!
//! ```rust
//! use my_crate::http::Client;
//!
//! let client = Client::new();
//! let response = client.get("https://example.com").send()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod client;
pub mod request;
pub mod response;
```

---

## Constants and Statics

```rust
/// Default timeout for network operations in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum number of retry attempts for failed requests.
pub const MAX_RETRIES: u32 = 3;

/// Global configuration for the library.
///
/// This is initialized lazily on first access.
pub static CONFIG: std::sync::LazyLock<Config> = std::sync::LazyLock::new(Config::default);
```

---

## Type Aliases

```rust
/// Result type used throughout the crate.
///
/// Uses `crate::Error` as the error type.
pub type Result<T> = std::result::Result<T, crate::Error>;

/// A map of string keys to string values.
pub type StringMap = std::collections::HashMap<String, String>;
```

---

## Macros

```rust
/// Creates a new HTTP request builder.
///
/// # Arguments
///
/// * `method` - The HTTP method (GET, POST, etc.)
/// * `url` - The target URL
///
/// # Examples
///
/// ```rust
/// let request = request!(GET, "https://example.com");
/// ```
#[macro_export]
macro_rules! request {
    ($method:expr, $url:expr) => {
        $crate::RequestBuilder::new()
            .method($method)
            .url($url)
    };
}
```

---

## Re-exports

```rust
/// Public API re-exports.
///
/// These are the types most commonly needed when using this crate.

pub use self::client::Client;
pub use self::request::Request;
pub use self::response::Response;
pub use self::error::{Error, Result};
```

---

## Doc Test Tips

### Hiding Setup Code

```rust
/// Example with hidden setup:
///
/// ```rust
/// # use my_crate::setup_context;
/// # let ctx = setup_context();
/// let result = ctx.do_something();
/// assert!(result.is_ok());
/// ```
```

### Ignoring Tests (Compile Only)

```rust
/// This example requires network access:
///
/// ```rust,no_run
/// let response = reqwest::get("https://example.com").await?;
/// # Ok::<(), reqwest::Error>(())
/// ```
```

### Should Panic Example

```rust
/// This function panics on invalid input:
///
/// ```rust,should_panic
/// my_crate::parse_number("not a number"); // Panics!
/// ```
pub fn parse_number(s: &str) -> i32 {
    s.parse().unwrap()
}
```

### Using ? in Doc Tests

```rust
/// Example with fallible operation:
///
/// ```rust
/// use my_crate::read_file;
///
/// let content = read_file("path/to/file")?;
/// println!("{}", content);
/// # Ok::<(), std::io::Error>(())
/// ```
```

---

## Common Missing Docs Fixes

When encountering `missing_docs` warnings:

1. **Module is missing docs**: Add `//!` comment at top of file
2. **Public item is missing docs**: Add `///` comment before the item
3. **Field is missing docs**: Add `///` comment before the field
4. **Variant is missing docs**: Add `///` comment before the variant

For private items, you can either:
- Add documentation (best practice)
- Use `#![allow(missing_docs)]` at crate root for internal modules
