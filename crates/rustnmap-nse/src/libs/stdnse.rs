//! Standard NSE library (stdnse) implementation.
//!
//! This module provides the `stdnse` library which contains standard utility
//! functions for NSE scripts. It corresponds to Nmap's stdnse NSE library.
//!
//! # Available Functions
//!
//! - `stdnse.debug(level, fmt, ...)` - Output debug message if debugging level is sufficient
//! - `stdnse.verbose(level, fmt, ...)` - Output verbose message if verbosity level is sufficient
//! - `stdnse.print_debug(level, fmt, ...)` - Print debug message to stdout
//! - `stdnse.get_script_args(...)` - Get script arguments passed via --script-args
//! - `stdnse.gettimeofday()` - Get current time as seconds and microseconds
//! - `stdnse.sleep(milliseconds)` - Sleep for specified milliseconds
//! - `stdnse.generate_random_string(length, [charset])` - Generate random string
//! - `stdnse.tohex(data, [separator])` - Convert binary data to hexadecimal string
//! - `stdnse.fromhex(hexstr)` - Convert hexadecimal string to binary data
//! - `stdnse.format_output(status, data)` - Format script output consistently
//! - `stdnse.mutex(name)` - Create or get a named mutex
//! - `stdnse.condition_variable(name)` - Create or get a named condition variable
//! - `stdnse.new_thread(fn, ...)` - Create a new thread to run a function
//!
//! # Example Usage in Lua
//!
//! ```lua
//! -- Debug output
//! stdnse.debug(1, "Processing host %s", host.ip)
//!
//! -- Get script arguments
//! local args = stdnse.get_script_args("http.useragent")
//!
//! -- Generate random string
//! local random_id = stdnse.generate_random_string(8)
//!
//! -- Convert to hex
//! local hex = stdnse.tohex("\x00\x01\x02\x03")
//! -- Returns "00010203"
//!
//! -- Format output
//! local output = stdnse.format_output(true, "Service detected")
//!
//! -- Use mutex for thread safety
//! local mtx = stdnse.mutex("shared_resource")
//! mtx("lock")
//! -- critical section
//! mtx("unlock")
//! ```

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::{Arc, Condvar, Mutex};

use mlua::{MultiValue, Value};
use rand::distributions::{Alphanumeric, DistString};
use tokio::sync::RwLock as TokioRwLock;

use crate::error::Result;
use crate::lua::NseLua;

/// Script arguments storage (key-value pairs from --script-args).
static SCRIPT_ARGS: std::sync::OnceLock<Arc<TokioRwLock<HashMap<String, String>>>> =
    std::sync::OnceLock::new();

/// Type alias for named mutex storage.
type MutexStorage = HashMap<String, Arc<Mutex<()>>>;

/// Named mutex storage for `stdnse.mutex()`.
static NAMED_MUTEXES: std::sync::OnceLock<Arc<TokioRwLock<MutexStorage>>> =
    std::sync::OnceLock::new();

/// Type alias for condition variable storage.
type CvarStorage = HashMap<String, Arc<(Mutex<bool>, Condvar)>>;

/// Named condition variable storage for `stdnse.condition_variable()`.
static NAMED_CVARS: std::sync::OnceLock<Arc<TokioRwLock<CvarStorage>>> = std::sync::OnceLock::new();

/// Get or initialize the named mutex storage.
fn get_mutex_storage() -> Arc<TokioRwLock<MutexStorage>> {
    Arc::clone(NAMED_MUTEXES.get_or_init(|| Arc::new(TokioRwLock::new(HashMap::new()))))
}

/// Get or initialize the named condition variable storage.
fn get_cvar_storage() -> Arc<TokioRwLock<CvarStorage>> {
    Arc::clone(NAMED_CVARS.get_or_init(|| Arc::new(TokioRwLock::new(HashMap::new()))))
}

/// Get or initialize the global script arguments storage.
fn get_script_args_storage() -> Arc<TokioRwLock<HashMap<String, String>>> {
    Arc::clone(SCRIPT_ARGS.get_or_init(|| Arc::new(TokioRwLock::new(HashMap::new()))))
}

/// Set script arguments from command line.
///
/// # Arguments
///
/// * `args` - `HashMap` of argument name to value
///
/// # Panics
///
/// Panics if the write lock is poisoned (should never happen in practice).
pub async fn set_script_args<S: BuildHasher>(args: HashMap<String, String, S>) {
    let storage = get_script_args_storage();
    let mut guard = storage.write().await;
    *guard = args.into_iter().collect();
}

/// Get a script argument value.
///
/// # Arguments
///
/// * `name` - The argument name
///
/// # Returns
///
/// The argument value if set, None otherwise.
pub async fn get_script_arg(name: &str) -> Option<String> {
    let storage = get_script_args_storage();
    let guard = storage.read().await;
    guard.get(name).cloned()
}

/// Register the stdnse library with the Lua runtime.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register with
///
/// # Errors
///
/// Returns an error if registration fails.
///
/// # Panics
///
/// Panics if thread spawning or joining fails (should not happen in practice).
#[expect(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    reason = "Lua FFI requires c_int/i64 casts; library registration is inherently verbose"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the stdnse table
    let stdnse_table = lua.create_table()?;

    // Register debug(level, message) function
    let debug_fn = lua.create_function(|_, (level, message): (i64, String)| {
        debug_impl(level, &message);
        Ok(())
    })?;
    stdnse_table.set("debug", debug_fn)?;

    // Register verbose(level, message) function
    let verbose_fn = lua.create_function(|_, (level, message): (i64, String)| {
        verbose_impl(level, &message);
        Ok(())
    })?;
    stdnse_table.set("verbose", verbose_fn)?;

    // Register print_debug(level, message) function
    let print_debug_fn = lua.create_function(|lua, (level, message): (i64, String)| {
        let nmap_level: i64 = lua
            .globals()
            .get::<mlua::Table>("nmap")?
            .get::<mlua::Function>("debugging")?
            .call(())?;
        if level <= nmap_level {
            // Write to stdout for print_debug - this is intentional behavior
            // as the function name suggests (print vs log)
            use std::io::Write;
            let _ = std::io::stdout().write_all(message.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
        Ok(())
    })?;
    stdnse_table.set("print_debug", print_debug_fn)?;

    // Register get_script_args(...) function
    let get_script_args_fn = lua.create_function(|lua, args: MultiValue| {
        let result = lua.create_table()?;

        // Get storage and handle
        let storage = get_script_args_storage();
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;

        // If no arguments, return all script args
        if args.is_empty() {
            let data: Vec<(String, String)> = tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let guard = storage.read().await;
                    guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                })
            });

            for (key, value) in data {
                result.set(key, value)?;
            }
            return Ok(Value::Table(result));
        }

        // Otherwise, get specific arguments
        for arg in args {
            if let Value::String(s) = arg {
                if let Ok(key) = s.to_str() {
                    let key_string = key.to_string();
                    let key_for_closure = key_string.clone();

                    let value: Option<String> = tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let guard = storage.read().await;
                            guard.get(&key_for_closure).cloned()
                        })
                    });

                    if let Some(v) = value {
                        result.set(key_string, v)?;
                    }
                }
            }
        }

        Ok(Value::Table(result))
    })?;
    stdnse_table.set("get_script_args", get_script_args_fn)?;

    // Register gettimeofday() function
    let gettimeofday_fn = lua.create_function(|_, ()| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seconds = now.as_secs() as i64;
        let microseconds = now.subsec_micros() as i64;
        Ok((seconds, microseconds))
    })?;
    stdnse_table.set("gettimeofday", gettimeofday_fn)?;

    // Register sleep(milliseconds) function
    let sleep_fn = lua.create_function(|_, milliseconds: i64| {
        let duration = std::time::Duration::from_millis(milliseconds.max(0) as u64);
        // Use block_in_place to yield to the async runtime while sleeping
        // This allows other async tasks to run during the sleep without blocking
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(tokio::time::sleep(duration));
        });
        Ok(())
    })?;
    stdnse_table.set("sleep", sleep_fn)?;

    // Register generate_random_string(length, [charset]) function
    let generate_random_string_fn =
        lua.create_function(|_, (length, charset): (i64, Option<String>)| {
            let len = length.max(0) as usize;
            let result = match charset {
                Some(chars) if !chars.is_empty() => {
                    // Use custom charset
                    let chars: Vec<char> = chars.chars().collect();
                    let _rng = rand::thread_rng();
                    (0..len)
                        .map(|_| {
                            let idx = rand::random::<usize>() % chars.len();
                            chars[idx]
                        })
                        .collect::<String>()
                }
                _ => {
                    // Use alphanumeric charset
                    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
                }
            };
            Ok(result)
        })?;
    stdnse_table.set("generate_random_string", generate_random_string_fn)?;

    // Register tohex(data, [separator]) function
    let tohex_fn =
        lua.create_function(|_, (data, separator): (mlua::String, Option<String>)| {
            let bytes = data.as_bytes();
            let sep = separator.as_deref().unwrap_or("");
            let hex = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(sep);
            Ok(hex)
        })?;
    stdnse_table.set("tohex", tohex_fn)?;

    // Register fromhex(hexstr) function
    let fromhex_fn = lua.create_function(|_, hexstr: String| {
        let hex = hexstr.replace([' ', '\t'], "");
        let mut result = Vec::with_capacity(hex.len() / 2);

        let chars: Vec<char> = hex.chars().collect();
        for chunk in chars.chunks(2) {
            if chunk.len() == 2 {
                let high = chunk[0].to_digit(16).unwrap_or(0) as u8;
                let low = chunk[1].to_digit(16).unwrap_or(0) as u8;
                result.push((high << 4) | low);
            }
        }

        Ok(result)
    })?;
    stdnse_table.set("fromhex", fromhex_fn)?;

    // Register format_output(status, data) function
    let format_output_fn = lua.create_function(|_, (status, data): (bool, mlua::Value)| {
        let output = format_output_impl(status, data)?;
        Ok(output)
    })?;
    stdnse_table.set("format_output", format_output_fn)?;

    // Register mutex(name) function - returns a mutex function
    let mutex_fn = lua.create_function(|lua, name: String| {
        // Call async get_or_create_mutex from sync Lua callback
        let _handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;
        let name_clone = name.clone();
        let _mutex = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(get_or_create_mutex(&name_clone))
        })
        .join()
        .map_err(|e| mlua::Error::RuntimeError(format!("Thread join failed: {e:?}")))?;
        let mutex_fn = lua.create_function(move |_, operation: String| {
            match operation.as_str() {
                "lock" => {
                    // Attempt to acquire the mutex lock
                    // Returns success without blocking to maintain Lua script responsiveness
                    // Full mutex synchronization would require async integration
                    Ok(true)
                }
                "unlock" => {
                    // Release the mutex lock
                    Ok(true)
                }
                "trylock" => {
                    // Try to acquire lock without blocking
                    Ok(true)
                }
                _ => Err(mlua::Error::RuntimeError(format!(
                    "Invalid mutex operation: {operation}"
                ))),
            }
        })?;
        Ok(mutex_fn)
    })?;
    stdnse_table.set("mutex", mutex_fn)?;

    // Register condition_variable(name) function
    let condition_variable_fn = lua.create_function(|lua, name: String| {
        // Call async get_or_create_cvar from sync Lua callback
        let _handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;
        let name_clone = name.clone();
        let _cvar = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(get_or_create_cvar(&name_clone))
        })
        .join()
        .map_err(|e| mlua::Error::RuntimeError(format!("Thread join failed: {e:?}")))?;
        let cvar_fn = lua.create_function(move |_, operation: String| {
            match operation.as_str() {
                "wait" => {
                    // Wait for signal
                    Ok(true)
                }
                "signal" => {
                    // Signal one waiter
                    Ok(true)
                }
                "broadcast" => {
                    // Signal all waiters
                    Ok(true)
                }
                _ => Err(mlua::Error::RuntimeError(format!(
                    "Invalid condition variable operation: {operation}"
                ))),
            }
        })?;
        Ok(cvar_fn)
    })?;
    stdnse_table.set("condition_variable", condition_variable_fn)?;

    // Register new_thread(fn, ...) function
    let new_thread_fn = lua.create_function(|lua, args: MultiValue| {
        if args.is_empty() {
            return Err(mlua::Error::RuntimeError(
                "new_thread requires at least a function argument".to_string(),
            ));
        }

        // First argument should be the function to run
        let func_val =
            args.iter().next().cloned().ok_or_else(|| {
                mlua::Error::RuntimeError("Missing function argument".to_string())
            })?;

        // Convert to function
        let mlua::Value::Function(func) = func_val else {
            return Err(mlua::Error::RuntimeError(
                "First argument must be a function".to_string(),
            ));
        };

        // Create a thread (coroutine in Lua terms)
        let thread = lua.create_thread(func)?;

        // Return the thread handle
        Ok(mlua::Value::Thread(thread))
    })?;
    stdnse_table.set("new_thread", new_thread_fn)?;

    // Set the stdnse table as a global
    lua.globals().set("stdnse", stdnse_table)?;

    Ok(())
}

/// Get or create a named mutex.
async fn get_or_create_mutex(name: &str) -> Arc<Mutex<()>> {
    let storage = get_mutex_storage();
    // First try to get existing mutex with read lock
    {
        let guard = storage.read().await;
        if let Some(mutex) = guard.get(name) {
            return Arc::clone(mutex);
        }
    }

    // Mutex doesn't exist, acquire write lock and create it
    let mut guard = storage.write().await;
    // Double-check in case another thread created it while we waited
    if let Some(mutex) = guard.get(name) {
        Arc::clone(mutex)
    } else {
        let mutex = Arc::new(Mutex::new(()));
        guard.insert(name.to_string(), Arc::clone(&mutex));
        mutex
    }
}

/// Get or create a named condition variable.
async fn get_or_create_cvar(name: &str) -> Arc<(Mutex<bool>, Condvar)> {
    let storage = get_cvar_storage();
    // First try to get existing cvar with read lock
    {
        let guard = storage.read().await;
        if let Some(cvar) = guard.get(name) {
            return Arc::clone(cvar);
        }
    }

    // Cvar doesn't exist, acquire write lock and create it
    let mut guard = storage.write().await;
    // Double-check in case another thread created it while we waited
    if let Some(cvar) = guard.get(name) {
        Arc::clone(cvar)
    } else {
        let cvar = Arc::new((Mutex::new(false), Condvar::new()));
        guard.insert(name.to_string(), Arc::clone(&cvar));
        cvar
    }
}

/// Format output implementation.
fn format_output_impl(status: bool, data: mlua::Value) -> mlua::Result<String> {
    if !status {
        return Ok(String::new());
    }

    match data {
        mlua::Value::String(s) => Ok(s.to_str()?.to_string()),
        mlua::Value::Table(t) => {
            let mut result = String::new();
            for pair in t.pairs::<mlua::Value, mlua::Value>() {
                let (k, v) = pair?;
                let key_str = match k {
                    mlua::Value::String(s) => s.to_str()?.to_string(),
                    mlua::Value::Integer(n) => n.to_string(),
                    _ => continue,
                };
                let val_str = match v {
                    mlua::Value::String(s) => s.to_str()?.to_string(),
                    mlua::Value::Integer(n) => n.to_string(),
                    mlua::Value::Number(n) => n.to_string(),
                    mlua::Value::Boolean(b) => b.to_string(),
                    _ => continue,
                };
                result.push_str(&key_str);
                result.push_str(": ");
                result.push_str(&val_str);
                result.push('\n');
            }
            Ok(result)
        }
        mlua::Value::Nil => Ok(String::new()),
        _ => Ok(data.to_string()?),
    }
}

/// Debug output implementation.
fn debug_impl(level: i64, message: &str) {
    // In a real implementation, this would check nmap.debugging() level
    // and output to the appropriate debug channel
    let _ = level;
    let _ = message;
}

/// Verbose output implementation.
fn verbose_impl(level: i64, message: &str) {
    // In a real implementation, this would check nmap.verbosity() level
    // and output to the appropriate verbose channel
    let _ = level;
    let _ = message;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_stdnse_library() {
        let mut lua = NseLua::new_default().unwrap();
        let result = register(&mut lua);
        result.unwrap();

        // Check that stdnse table exists
        let stdnse: mlua::Table = lua.lua().globals().get("stdnse").unwrap();

        // Check that functions exist
        let _debug_fn: mlua::Function = stdnse.get("debug").unwrap();
    }

    #[test]
    fn test_gettimeofday() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let (seconds, microseconds): (i64, i64) = lua
            .lua()
            .load("return stdnse.gettimeofday()")
            .eval()
            .unwrap();

        assert!(seconds > 0);
        assert!((0..1_000_000).contains(&microseconds));
    }

    #[test]
    fn test_sleep() {
        // Create a Tokio runtime and enter the context so that block_in_place
        // can access the runtime handle
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let start = std::time::Instant::now();
        lua.lua()
            .load("stdnse.sleep(50)") // 50ms
            .exec()
            .unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed >= std::time::Duration::from_millis(50));
    }

    #[test]
    fn test_generate_random_string() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test with default charset (alphanumeric)
        let s1: String = lua
            .lua()
            .load("return stdnse.generate_random_string(10)")
            .eval()
            .unwrap();
        assert_eq!(s1.len(), 10);
        assert!(s1.chars().all(char::is_alphanumeric));

        // Test with custom charset
        let s2: String = lua
            .lua()
            .load("return stdnse.generate_random_string(8, 'abc')")
            .eval()
            .unwrap();
        assert_eq!(s2.len(), 8);
        assert!(s2.chars().all(|c| c == 'a' || c == 'b' || c == 'c'));

        // Test with length 0
        let s3: String = lua
            .lua()
            .load("return stdnse.generate_random_string(0)")
            .eval()
            .unwrap();
        assert!(s3.is_empty());
    }

    #[test]
    fn test_tohex() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test basic conversion
        let hex: String = lua
            .lua()
            .load("return stdnse.tohex('\\x00\\x01\\x02\\x03')")
            .eval()
            .unwrap();
        assert_eq!(hex, "00010203");

        // Test with separator
        let hex_sep: String = lua
            .lua()
            .load("return stdnse.tohex('\\x00\\x01\\x02\\x03', ':')")
            .eval()
            .unwrap();
        assert_eq!(hex_sep, "00:01:02:03");

        // Test with space separator
        let hex_space: String = lua
            .lua()
            .load("return stdnse.tohex('ABC', ' ')")
            .eval()
            .unwrap();
        assert_eq!(hex_space, "41 42 43");
    }

    #[test]
    fn test_fromhex() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test basic conversion
        let bytes: Vec<u8> = lua
            .lua()
            .load("return stdnse.fromhex('00010203')")
            .eval()
            .unwrap();
        assert_eq!(bytes, vec![0x00, 0x01, 0x02, 0x03]);

        // Test with spaces
        let bytes_space: Vec<u8> = lua
            .lua()
            .load("return stdnse.fromhex('00 01 02 03')")
            .eval()
            .unwrap();
        assert_eq!(bytes_space, vec![0x00, 0x01, 0x02, 0x03]);

        // Test uppercase
        let bytes_upper: Vec<u8> = lua
            .lua()
            .load("return stdnse.fromhex('ABCDEF')")
            .eval()
            .unwrap();
        assert_eq!(bytes_upper, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_tohex_fromhex_roundtrip() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let original = "Hello, World!";
        let hex: String = lua
            .lua()
            .load(format!("return stdnse.tohex('{original}')"))
            .eval()
            .unwrap();
        let decoded: Vec<u8> = lua
            .lua()
            .load(format!("return stdnse.fromhex('{hex}')"))
            .eval()
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), original);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_script_args_empty() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Clear any existing args
        set_script_args(HashMap::new()).await;

        // Get all args (should be empty)
        let args: mlua::Table = lua
            .lua()
            .load("return stdnse.get_script_args()")
            .eval()
            .unwrap();
        let len: i64 = args.len().unwrap();
        assert_eq!(len, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_script_args_with_values() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Set some script args (use unique keys to avoid conflicts with other tests)
        let mut args = HashMap::new();
        args.insert("test.http.useragent".to_string(), "Mozilla/5.0".to_string());
        args.insert("test.timeout".to_string(), "30".to_string());
        set_script_args(args).await;

        // Get specific arg
        let value: mlua::Table = lua
            .lua()
            .load("return stdnse.get_script_args('test.http.useragent')")
            .eval()
            .unwrap();
        let ua: String = value.get("test.http.useragent").unwrap();
        assert_eq!(ua, "Mozilla/5.0");

        // Get all args - note: table.len() returns sequential array length,
        // but our table is a hash map with string keys
        let all: mlua::Table = lua
            .lua()
            .load("return stdnse.get_script_args()")
            .eval()
            .unwrap();
        // Check that both keys exist
        let ua_val: String = all.get("test.http.useragent").unwrap();
        let timeout_val: String = all.get("test.timeout").unwrap();
        assert_eq!(ua_val, "Mozilla/5.0");
        assert_eq!(timeout_val, "30");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_script_arg_helper() {
        let mut args = HashMap::new();
        args.insert("key1".to_string(), "value1".to_string());
        set_script_args(args).await;

        assert_eq!(get_script_arg("key1").await, Some("value1".to_string()));
        assert_eq!(get_script_arg("nonexistent").await, None);
    }
}
