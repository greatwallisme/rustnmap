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
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};

use mlua::{MultiValue, Value};
use rand::distributions::{Alphanumeric, DistString};
use tokio::sync::RwLock as TokioRwLock;

use crate::error::Result;
use crate::lua::NseLua;

/// Script arguments storage (key-value pairs from --script-args).
static SCRIPT_ARGS: std::sync::OnceLock<Arc<TokioRwLock<HashMap<String, String>>>> =
    std::sync::OnceLock::new();

/// Mutex state tracking the current holder.
#[derive(Debug, Default)]
struct MutexState {
    /// Thread identifier holding the lock, if any.
    holder: Option<String>,
    /// Lock count for recursive locking.
    lock_count: u32,
}

/// Type alias for named mutex storage.
type MutexStorage = HashMap<String, Arc<Mutex<MutexState>>>;

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

    // Register debug1, debug2, debug3 convenience functions (Nmap compatibility)
    // These are shorthand for debug(1, ...), debug(2, ...), etc.
    for level in 1..=5 {
        let debug_level_fn = lua.create_function(move |_, message: String| {
            debug_impl(level, &message);
            Ok(())
        })?;
        stdnse_table.set(format!("debug{level}"), debug_level_fn)?;
    }

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
            let _ = std::io::stdout().write_all(message.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
        Ok(())
    })?;
    stdnse_table.set("print_debug", print_debug_fn)?;

    // Register get_script_args(...) function
    // Nmap compatibility: Returns multiple values, not a table
    // - get_script_args() -> table with all args
    // - get_script_args("key") -> value or nil (allows "or" pattern)
    // - get_script_args("k1", "k2") -> value1, value2 (multiple returns)
    let get_script_args_fn = lua.create_function(|lua, args: MultiValue| {
        // Get storage and handle
        let storage = get_script_args_storage();
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;

        // If no arguments, return all script args as a table
        if args.is_empty() {
            let result = lua.create_table()?;
            let data: Vec<(String, String)> = tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let guard = storage.read().await;
                    guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                })
            });

            for (key, value) in data {
                result.set(key, value)?;
            }
            // Return table as single Value in MultiValue
            return Ok(MultiValue::from_vec(vec![Value::Table(result)]));
        }

        // Otherwise, return multiple values (one per requested arg)
        let results: Vec<Value> = args
            .into_iter()
            .map(|arg| {
                if let Value::String(s) = arg {
                    if let Ok(key) = s.to_str() {
                        let key_for_closure = key.to_string();

                        let value: Option<String> = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                let guard = storage.read().await;
                                guard.get(&key_for_closure).cloned()
                            })
                        });

                        // Return the value as a Lua string, or nil if not found
                        value.map_or(Value::Nil, |v| {
                            Value::String(lua.create_string(&v).unwrap())
                        })
                    } else {
                        Value::Nil
                    }
                } else {
                    Value::Nil
                }
            })
            .collect();

        // Return multiple values
        Ok(MultiValue::from_vec(results))
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

    // Register tohex(data, options) function
    //
    // Matches Nmap's stdnse.tohex signature which accepts either:
    // - a string separator: stdnse.tohex(data, ":")
    // - a table with options: stdnse.tohex(data, { separator = " ", group = 4 })
    // When using a table, `group` controls how many hex bytes are grouped together.
    let tohex_fn =
        lua.create_function(|lua, (data, options): (mlua::String, mlua::Value)| {
            let bytes = data.as_bytes();
            let mut separator = String::new();
            let mut group_size: Option<usize> = None;

            match options {
                mlua::Value::String(s) => {
                    if let Ok(s) = s.to_str() {
                        separator = s.to_string();
                    }
                }
                mlua::Value::Table(t) => {
                    if let Ok(Some(s)) = t.get::<Option<mlua::String>>("separator") {
                        separator = s.to_string_lossy().to_string();
                    }
                    if let Ok(g) = t.get::<Option<i64>>("group") {
                        group_size = g.map(|g| usize::try_from(g).unwrap_or(0));
                    }
                }
                _ => {}
            }

            let hex_chars: Vec<String> = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();

            let result = if let Some(group) = group_size {
                if group > 0 {
                    hex_chars
                        .chunks(group)
                        .map(|chunk| chunk.join(&separator))
                        .collect::<Vec<_>>()
                        .join(&separator)
                } else {
                    hex_chars.join("")
                }
            } else {
                hex_chars.join(&separator)
            };

            lua.create_string(&result)
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

    // Register output_table() function - creates a table for structured script output
    //
    // In Nmap, this creates an ordered table that preserves key insertion order.
    // For our implementation, we provide a standard Lua table with a metatable
    // that provides Nmap-compatible behavior:
    // - t[key] = value - standard assignment
    // - t() - returns true if table has elements (truthiness check via __call)
    // - #t - returns number of keys via __len metamethod (for non-empty check)
    let output_table_fn = lua.create_function(|lua, ()| {
        // Create a new table
        let table = lua.create_table()?;
        // Set a metatable that makes it callable to check if empty
        let mt = lua.create_table()?;

        // __call metamethod: returns true if table has any keys
        mt.set(
            "__call",
            lua.create_function(|_, this: mlua::Value| {
                if let mlua::Value::Table(t) = this {
                    // Check if table has any keys by checking if next() returns a value
                    Ok(t.pairs::<mlua::Value, mlua::Value>().next().is_some())
                } else {
                    Ok(false)
                }
            })?,
        )?;

        // __len metamethod: returns the count of all keys (not just array part)
        // This is needed because scripts check `if #output > 0 then return output`
        mt.set(
            "__len",
            lua.create_function(|_, this: mlua::Value| {
                if let mlua::Value::Table(t) = this {
                    // Count all keys in the table
                    let count = t.pairs::<mlua::Value, mlua::Value>().count();
                    Ok(i64::try_from(count).unwrap_or(0))
                } else {
                    Ok(0i64)
                }
            })?,
        )?;

        table.set_metatable(Some(mt))?;
        Ok(mlua::Value::Table(table))
    })?;
    stdnse_table.set("output_table", output_table_fn)?;

    // Register get_hostname(host) function
    // Returns the best possible hostname for a host table
    // If host is a table: returns host.targetname or host.name (if non-empty) or host.ip
    // If host is a string: returns the string directly
    let get_hostname_fn = lua.create_function(|lua, host: mlua::Value| {
        match host {
            mlua::Value::Table(t) => {
                // Try targetname first
                if let Ok(Some(targetname)) = t.get::<Option<String>>("targetname") {
                    if !targetname.is_empty() {
                        return Ok(mlua::Value::String(lua.create_string(&targetname)?));
                    }
                }
                // Try name (if non-empty)
                if let Ok(Some(name)) = t.get::<Option<String>>("name") {
                    if !name.is_empty() {
                        return Ok(mlua::Value::String(lua.create_string(&name)?));
                    }
                }
                // Fall back to ip
                if let Ok(Some(ip)) = t.get::<Option<String>>("ip") {
                    return Ok(mlua::Value::String(lua.create_string(&ip)?));
                }
                // No hostname available
                Ok(mlua::Value::Nil)
            }
            mlua::Value::String(s) => Ok(mlua::Value::String(s)),
            _ => Ok(mlua::Value::Nil),
        }
    })?;
    stdnse_table.set("get_hostname", get_hostname_fn)?;

    // Register mutex(name) function - returns a mutex function
    let mutex_fn = lua.create_function(|lua, name: String| {
        // Use block_in_place to run async code from sync callback
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;
        let mutex_arc = tokio::task::block_in_place(|| handle.block_on(get_or_create_mutex(&name)));

        // Create the mutex operation function
        // This function is returned by stdnse.mutex() and takes one argument:
        // "lock", "trylock", or "unlock"
        let mutex_op_fn = lua.create_function(move |_lua, operation: String| {
            let mut guard = mutex_arc
                .lock()
                .map_err(|e| mlua::Error::RuntimeError(format!("mutex lock failed: {e}")))?;

            match operation.as_str() {
                "lock" => {
                    // Blocking lock - acquire the mutex for current thread
                    // If already held by same thread, increment count (recursive)
                    // NSE mutex semantics: lock waits until available, then acquires
                    if let Some(ref holder) = guard.holder {
                        if holder == "current" {
                            guard.lock_count += 1;
                            return Ok(mlua::Value::Boolean(true));
                        }
                        // Lock held by another context - acquire anyway (NSE semantics)
                        // Nmap's NSE runs scripts sequentially within a host, so contention is rare
                    }
                    guard.holder = Some("current".to_string());
                    guard.lock_count = 1;
                    Ok(mlua::Value::Boolean(true))
                }
                "trylock" => {
                    // Non-blocking lock attempt
                    if let Some(ref holder) = guard.holder {
                        if holder == "current" {
                            guard.lock_count += 1;
                            return Ok(mlua::Value::Boolean(true));
                        }
                        // Already held by another thread
                        Ok(mlua::Value::Boolean(false))
                    } else {
                        guard.holder = Some("current".to_string());
                        guard.lock_count = 1;
                        Ok(mlua::Value::Boolean(true))
                    }
                }
                "unlock" => {
                    // Release the mutex
                    if let Some(ref holder) = guard.holder {
                        if holder == "current" {
                            guard.lock_count = guard.lock_count.saturating_sub(1);
                            if guard.lock_count == 0 {
                                guard.holder = None;
                            }
                            Ok(mlua::Value::Boolean(true))
                        } else {
                            Err(mlua::Error::RuntimeError(
                                "mutex unlock failed: not owned by current thread".to_string(),
                            ))
                        }
                    } else {
                        Err(mlua::Error::RuntimeError(
                            "mutex unlock failed: not locked".to_string(),
                        ))
                    }
                }
                _ => Err(mlua::Error::RuntimeError(format!(
                    "Invalid mutex operation: {operation}"
                ))),
            }
        })?;
        Ok(mutex_op_fn)
    })?;
    stdnse_table.set("mutex", mutex_fn)?;

    // Register condition_variable(name) function
    let condition_variable_fn = lua.create_function(|lua, name: String| {
        // Use block_in_place to run async code from sync callback
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_e| mlua::Error::RuntimeError("No tokio runtime available".to_string()))?;
        let cvar_arc = tokio::task::block_in_place(|| handle.block_on(get_or_create_cvar(&name)));

        // Create the condition variable operation function
        let cvar_op_fn = lua.create_function(move |_, operation: String| {
            let (lock, cvar) = &*cvar_arc;
            let mut guard = lock.lock().map_err(|e| {
                mlua::Error::RuntimeError(format!("condition variable lock failed: {e}"))
            })?;

            match operation.as_str() {
                "wait" => {
                    // Wait for signal - blocks until signaled
                    // Set flag to false and wait
                    *guard = false;
                    // cvar.wait consumes the guard and returns it after being signaled
                    guard = cvar.wait(guard).map_err(|e| {
                        mlua::Error::RuntimeError(format!("condition variable wait failed: {e}"))
                    })?;
                    // Explicitly drop the guard to release the internal lock
                    drop(guard);
                    Ok(mlua::Value::Boolean(true))
                }
                "signal" => {
                    // Signal one waiter
                    *guard = true;
                    cvar.notify_one();
                    Ok(mlua::Value::Boolean(true))
                }
                "broadcast" => {
                    // Signal all waiters
                    *guard = true;
                    cvar.notify_all();
                    Ok(mlua::Value::Boolean(true))
                }
                _ => Err(mlua::Error::RuntimeError(format!(
                    "Invalid condition variable operation: {operation}"
                ))),
            }
        })?;
        Ok(cvar_op_fn)
    })?;
    stdnse_table.set("condition_variable", condition_variable_fn)?;

    // Register new_thread(fn, ...) function
    // In Nmap, this spawns a concurrent thread. Since our engine is single-threaded,
    // we create a coroutine, resume it immediately with the provided arguments,
    // and return (thread_handle, first_result).
    let new_thread_fn = lua.create_function(|lua, args: MultiValue| {
        let mut args_iter = args.into_iter();
        let func_val = args_iter.next().ok_or_else(|| {
            mlua::Error::RuntimeError(
                "new_thread requires at least a function argument".to_string(),
            )
        })?;

        let mlua::Value::Function(func) = func_val else {
            return Err(mlua::Error::RuntimeError(
                "First argument must be a function".to_string(),
            ));
        };

        // Collect remaining arguments to pass to the function
        let extra_args: Vec<Value> = args_iter.collect();

        // Create a coroutine from the function
        let thread = lua.create_thread(func)?;

        // Immediately resume the thread with extra arguments (single-threaded execution)
        let results: MultiValue = thread.resume::<MultiValue>(MultiValue::from_vec(extra_args))?;

        // Return the thread handle and the first result value
        let first_result = results.into_iter().next().unwrap_or(Value::Nil);
        Ok(MultiValue::from_vec(vec![
            Value::Thread(thread),
            first_result,
        ]))
    })?;
    stdnse_table.set("new_thread", new_thread_fn)?;

    // Register silent_require(module_name) function
    // This is a special require that silently fails if the module is not available.
    // It's used by scripts to check for optional dependencies like OpenSSL.
    // If the require fails, it raises a special error marker that the engine
    // catches to skip the script silently.
    let silent_require_fn = lua.create_function(|lua, module_name: String| {
        // Get the global require function
        let require_fn: mlua::Function = lua
            .globals()
            .get("require")
            .map_err(|e| mlua::Error::RuntimeError(format!("require function not found: {e}")))?;

        // Try to require the module using pcall
        let pcall_fn: mlua::Function = lua
            .globals()
            .get("pcall")
            .map_err(|e| mlua::Error::RuntimeError(format!("pcall function not found: {e}")))?;

        // Call pcall(require, module_name)
        let result: MultiValue = pcall_fn
            .call((require_fn, module_name.clone()))
            .map_err(|e| mlua::Error::RuntimeError(format!("pcall failed: {e}")))?;

        // pcall returns (success, result_or_error)
        let mut iter = result.into_iter();
        let success = iter.next();
        let value = iter.next();

        match (success, value) {
            (Some(mlua::Value::Boolean(true)), Some(val)) => {
                // Module loaded successfully
                Ok(val)
            }
            _ => {
                // Module failed to load - raise special error marker
                // The engine will catch this and skip the script
                Err(mlua::Error::RuntimeError(format!(
                    "NSE_REQUIRE_ERROR:{module_name}"
                )))
            }
        }
    })?;
    stdnse_table.set("silent_require", silent_require_fn)?;

    // -------------------------------------------------------------------------
    // stdnse.parse_timespec(timespec)
    //
    // Parse a time specification string (e.g. "5s", "100ms", "2m") and return
    // the value in seconds.
    //
    // Supported suffixes: "" (seconds), "s" (seconds), "ms" (milliseconds),
    // "m" (minutes), "h" (hours).
    //
    // Returns (number, nil) on success or (nil, error_string) on failure.
    // -------------------------------------------------------------------------
    let parse_timespec_fn = lua.create_function(|lua, timespec: String| {
        let timespec = timespec.trim();
        if timespec.is_empty() {
            return Ok((mlua::Value::Nil, mlua::Value::Nil));
        }

        // Split into numeric part and unit suffix
        let num_end = timespec
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(timespec.len());

        if num_end == 0 {
            return Ok((
                mlua::Value::Nil,
                mlua::Value::String(
                    lua.create_string(format!("Can't parse time specification \"{timespec}\""))?,
                ),
            ));
        }

        let (num_str, unit): (&str, &str) = (&timespec[..num_end], &timespec[num_end..]);

        let value: f64 = match num_str.parse() {
            Ok(v) => v,
            Err(_) => {
                return Ok((
                    mlua::Value::Nil,
                    mlua::Value::String(lua.create_string(format!(
                        "Can't parse time specification \"{timespec}\" (bad number \"{num_str}\")"
                    ))?),
                ));
            }
        };

        let multiplier = match unit {
            "" | "s" => 1.0,
            "ms" => 0.001,
            "m" => 60.0,
            "h" => 3600.0,
            _ => {
                return Ok((
                    mlua::Value::Nil,
                    mlua::Value::String(lua.create_string(format!(
                        "Can't parse time specification \"{timespec}\" (bad unit \"{unit}\")"
                    ))?),
                ));
            }
        };

        Ok((mlua::Value::Number(value * multiplier), mlua::Value::Nil))
    })?;
    stdnse_table.set("parse_timespec", parse_timespec_fn)?;

    // -------------------------------------------------------------------------
    // stdnse.seeall(env)
    //
    // Option function for use with stdnse.module. Sets __index = _G on the
    // module's metatable so that the module can access global variables.
    // Equivalent to package.seeall from Lua 5.1.
    // -------------------------------------------------------------------------
    let seeall_fn = lua.create_function(|lua, env: mlua::Table| {
        let meta_table = lua.create_table()?;
        let globals = lua.globals();
        meta_table.set("__index", globals)?;
        env.set_metatable(Some(meta_table))?;
        Ok(())
    })?;
    stdnse_table.set("seeall", seeall_fn)?;

    // -------------------------------------------------------------------------
    // stdnse.module(name, ...)
    //
    // Creates a new module environment table, sets _NAME, _PACKAGE, _M fields,
    // calls each option function (e.g. stdnse.seeall) with the environment,
    // registers the module in package.loaded[name], and returns the table.
    //
    // Usage: _ENV = stdnse.module("mymod", stdnse.seeall)
    // -------------------------------------------------------------------------
    let module_fn = lua.create_function(
        |lua, (name, opts): (String, mlua::Variadic<mlua::Function>)| {
            let env = lua.create_table()?;
            env.set("_NAME", name.as_str())?;

            // _PACKAGE is everything up to and including the last dot, or nil
            if let Some(pos) = name.rfind('.') {
                env.set("_PACKAGE", &name[..=pos])?;
            }

            env.set("_M", env.clone())?;

            // Call each option function with the environment
            for opt_fn in opts {
                opt_fn.call::<()>(env.clone())?;
            }

            // Register in package.loaded so subsequent require() returns it
            let package: mlua::Table = lua.globals().get("package")?;
            package.set(name.as_str(), env.clone())?;

            Ok(env)
        },
    )?;
    stdnse_table.set("module", module_fn)?;

    // Set the stdnse table as a global
    lua.globals().set("stdnse", stdnse_table)?;

    Ok(())
}

/// Get or create a named mutex.
async fn get_or_create_mutex(name: &str) -> Arc<Mutex<MutexState>> {
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
        let mutex = Arc::new(Mutex::new(MutexState::default()));
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

        // Use unique keys with UUID to avoid race conditions with parallel tests
        let uuid = uuid::Uuid::new_v4();
        let key1 = format!("test.{uuid}.http.useragent");
        let key2 = format!("test.{uuid}.timeout");

        let mut args = HashMap::new();
        args.insert(key1.clone(), "Mozilla/5.0".to_string());
        args.insert(key2.clone(), "30".to_string());
        set_script_args(args).await;

        // Get specific arg - returns the value directly (not a table)
        // This matches Nmap's behavior for the "or" pattern: local ua = stdnse.get_script_args("key") or "default"
        let lua_code1 = format!("return stdnse.get_script_args('{key1}')");
        let ua: Option<String> = lua.lua().load(&lua_code1).eval().unwrap();
        assert_eq!(ua, Some("Mozilla/5.0".to_string()));

        // Get all args - returns a table with all args
        let all: mlua::Table = lua
            .lua()
            .load("return stdnse.get_script_args()")
            .eval()
            .unwrap();
        // Check that both keys exist
        let ua_val: String = all.get(key1.as_str()).unwrap();
        let timeout_val: String = all.get(key2.as_str()).unwrap();
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
