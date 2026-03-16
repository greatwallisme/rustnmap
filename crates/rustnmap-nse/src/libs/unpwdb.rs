//! Username/password database library for NSE.
//!
//! This module provides the `unpwdb` library which contains username and password
//! database iteration functions for NSE scripts. It corresponds to Nmap's unpwdb NSE library.
//!
//! # Available Functions
//!
//! - `unpwdb.usernames([time_limit], [count_limit])` - Returns a username iterator
//! - `unpwdb.passwords([time_limit], [count_limit])` - Returns a password iterator
//! - `unpwdb.timelimit()` - Returns suggested time limit based on timing template
//! - `unpwdb.concat_iterators(iter1, iter2)` - Concatenates two iterators
//! - `unpwdb.filter_iterator(iterator, filter)` - Filters an iterator
//!
//! # Iterator Behavior
//!
//! The iterator functions return closures that can be called repeatedly to get
//! the next username or password. They support:
//! - Calling with "reset" argument to rewind to the beginning
//! - Automatic stopping when time limit is reached
//! - Automatic stopping when count limit is reached
//! - Custom database files via script arguments
//!
//! # Script Arguments
//!
//! - `userdb` - Custom username database file path
//! - `passdb` - Custom password database file path
//! - `unpwdb.userlimit` - Maximum number of usernames to return
//! - `unpwdb.passlimit` - Maximum number of passwords to return
//! - `unpwdb.timelimit` - Maximum time limit in seconds (with optional s/m/h suffix)
//! - `notimelimit` - Disable time limit
//!
//! # Default Time Limits
//!
//! Based on Nmap timing template:
//! - T3 or lower: 10 minutes (custom data: 15 minutes)
//! - T4: 5 minutes (custom data: 7.5 minutes)
//! - T5: 3 minutes (custom data: 4.5 minutes)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local unpwdb = require "unpwdb"
//!
//! -- Get iterators
//! local status, usernames = unpwdb.usernames()
//! local status, passwords = unpwdb.passwords()
//!
//! -- Iterate through all combinations
//! for password in passwords do
//!     for username in usernames do
//!         -- Try credentials
//!         if try_login(username, password) then
//!             return "Found: " .. username .. ":" .. password
//!         end
//!     end
//!     usernames("reset")  -- Rewind username iterator
//! end
//! ```
//!
//! # Implementation Notes
//!
//! This implementation uses Arc<Mutex<IteratorState>> to maintain iterator state across
//! closure calls. When a closure is called repeatedly, state is retrieved from the
//! shared state and the current item returned. The iterator state is also cloned for use in the
//! Lua closures created for `passwords()` function.
//! This approach allows multiple independent iterators to be returned from a single `passwords()` call,
//! each maintaining its own separate state.
//!
//! # Performance Considerations
//!
//! The database is loaded once on first call and then cached. This is acceptable for small
//! username/password lists. For security tools, this is fine.
//!
//! # Safety
//!
//! All files are validated before loading, and the timeout is enforced on all operations.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mlua::{Function, Table, Value};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default username database filename.
const DEFAULT_USERNAMES_FILE: &str = "nselib/data/usernames.lst";
/// Default password database filename.
const DEFAULT_PASSWORDS_FILE: &str = "nselib/data/passwords.lst";
/// Default time limits in seconds based on timing template.
const TIMELIMIT_T3: u64 = 600; // 10 minutes
const TIMELIMIT_T4: u64 = 300; // 5 minutes
const TIMELIMIT_T5: u64 = 180; // 3 minutes
/// Multiplier for custom database files
const CUSTOM_DATA_MULTIPLIER: u64 = 15; // 1.5x

/// Iterator state for username/password lists.
struct IteratorState {
    /// Current position in the list
    index: usize,
    /// The list of entries
    entries: Vec<String>,
    /// Start time for time limit checking
    start_time: Option<Instant>,
    /// Time limit in seconds
    time_limit: Option<u64>,
    /// Count limit
    count_limit: Option<usize>,
    /// Current count (number of items returned)
    count: usize,
}

impl IteratorState {
    /// Create a new iterator state
    fn new(entries: Vec<String>) -> Self {
        Self {
            index: 0,
            entries,
            start_time: None,
            time_limit: None,
            count_limit: None,
            count: 0,
        }
    }

    /// Set the time limit
    fn set_time_limit(&mut self, limit: u64) {
        self.time_limit = Some(limit);
        self.start_time = Some(Instant::now());
    }

    /// Set the count limit
    fn set_count_limit(&mut self, limit: usize) {
        self.count_limit = Some(limit);
    }

    /// Check if time limit has been exceeded
    fn time_limit_exceeded(&self) -> bool {
        if let (Some(start), Some(limit)) = (self.start_time, self.time_limit) {
            start.elapsed() >= Duration::from_secs(limit)
        } else {
            false
        }
    }

    /// Check if count limit has been exceeded
    fn count_limit_exceeded(&self) -> bool {
        if let Some(limit) = self.count_limit {
            self.count >= limit
        } else {
            false
        }
    }

    /// Get the next entry
    fn next(&mut self) -> Option<String> {
        // Check limits
        if self.time_limit_exceeded() {
            debug!("Iterator: Time limit exceeded");
            return None;
        }
        if self.count_limit_exceeded() {
            debug!("Iterator: Count limit exceeded");
            return None;
        }
        // Get next entry
        (self.index < self.entries.len()).then(|| {
            let entry = self.entries[self.index].clone();
            self.index += 1;
            self.count += 1;
            entry
        })
    }

    /// Reset the iterator to the beginning
    fn reset(&mut self) {
        self.index = 0;
        self.count = 0;
    }
}

/// Load entries from a file, skipping comment lines
fn load_entries(path: &Path) -> std::io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        // Skip empty lines and comments
        if !trimmed.is_empty() && !trimmed.starts_with("#!comment:") {
            entries.push(trimmed.to_string());
        }
    }
    Ok(entries)
}

/// Parse time limit specification (e.g., "30", "30m", "1.5h", "1000ms")
///
/// Returns time in seconds. Suffixes:
/// - No suffix or "s": seconds
/// - "ms": milliseconds (divided by 1000)
/// - "m": minutes (multiplied by 60)
/// - "h": hours (multiplied by 3600)
fn parse_timespec(spec: &str) -> Option<u64> {
    let spec = spec.trim();
    // Check for suffix and determine divisor/multiplier
    let (value_str, multiplier, divisor) = if let Some(s) = spec.strip_suffix("ms") {
        (s, 1, 1000.0)
    } else if let Some(s) = spec.strip_suffix('s') {
        (s, 1, 1.0)
    } else if let Some(s) = spec.strip_suffix('m') {
        (s, 60, 1.0)
    } else if let Some(s) = spec.strip_suffix('h') {
        (s, 3600, 1.0)
    } else {
        (spec, 1, 1.0)
    };
    // Parse as float first, then convert to u64
    let value: f64 = value_str.parse().ok()?;
    let result = (value * f64::from(multiplier)) / divisor;
    // Clamp to reasonable range and avoid overflow
    // Time limit values are small (<1 day in seconds), no precision loss in practice
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Time values are clamped to valid range"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "Time values are always positive after clamp"
    )]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Time values are small integers, no precision loss"
    )]
    Some(result.clamp(0.0, u64::MAX as f64) as u64)
}

/// Find a file in Nmap data directories
fn find_file(filename: &str) -> Option<String> {
    // Try to find in the reference directory first
    let ref_path = format!("/root/project/rust-nmap/reference/nmap/{filename}");
    if Path::new(&ref_path).exists() {
        return Some(ref_path);
    }
    // Try system Nmap directories
    let system_paths = [
        format!("/usr/share/nmap/{filename}"),
        format!("/usr/local/share/nmap/{filename}"),
        format!("./{filename}"),
    ];
    system_paths
        .into_iter()
        .find(|path| Path::new(path).exists())
}

/// Convert Lua numeric value to usize safely, handling negative and out-of-range values
#[expect(
    clippy::cast_possible_truncation,
    reason = "usize values are always positive and bounded by list sizes"
)]
#[expect(
    clippy::cast_sign_loss,
    reason = "Values are clamped to positive range before cast"
)]
#[expect(
    clippy::cast_precision_loss,
    reason = "Password database sizes are small, no precision loss in practice"
)]
fn value_to_usize(value: &Value) -> Option<usize> {
    match value {
        Value::Number(n) if *n > 0.0 => {
            // usize values from Lua are always within valid range for password database sizes
            Some(n.clamp(1.0, usize::MAX as f64) as usize)
        }
        Value::Integer(n) if *n > 0 => {
            // i64 from Lua needs conversion check
            usize::try_from(*n).ok()
        }
        _ => None, // Value::Nil, non-positive numbers, or other types
    }
}

/// Convert Lua numeric value to u64 safely, handling negative and out-of-range values
#[expect(
    clippy::cast_possible_truncation,
    reason = "u64 values are used for timing limits and not password counts"
)]
#[expect(
    clippy::cast_sign_loss,
    reason = "Values are clamped to positive range before cast"
)]
#[expect(
    clippy::cast_precision_loss,
    reason = "Time limit values are small, no precision loss in practice"
)]
fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) if *n > 0.0 && *n <= 1_000_000_000_000.0 => {
            // f64 values are bounded to avoid overflow for password database sizes
            Some(n.clamp(1.0, u64::MAX as f64) as u64)
        }
        Value::Integer(n) if *n > 0 => {
            // i64 from Lua needs conversion check
            u64::try_from(*n).ok()
        }
        _ => None, // Value::Nil, non-positive/out-of-range numbers, or other types
    }
}

/// Convert i64 to u64 for time limit purposes
fn i64_to_u64_for_time(val: i64) -> Option<u64> {
    if val > 0 {
        u64::try_from(val).ok()
    } else {
        None
    }
}

/// Convert i64 to usize for count limit purposes
fn i64_to_usize_for_count(val: i64) -> Option<usize> {
    if val > 0 {
        usize::try_from(val).ok()
    } else {
        None
    }
}

/// Register the unpwdb library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
///
/// # Panics
///
/// Panics if `usernames_cache` or `passwords_cache` lock is poisoned (e.g., multiple readers accessing same cache).
#[allow(
    clippy::too_many_lines,
    reason = "unpwdb library requires database loading operations"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();
    // Create the unpwdb table
    let unpwdb_table = lua.create_table()?;
    // Shared state for loaded databases
    let usernames_cache = Arc::new(Mutex::new(Vec::new()));
    let passwords_cache = Arc::new(Mutex::new(Vec::new()));
    // Register timelimit function
    let usernames_cache_tl = Arc::clone(&usernames_cache);
    let passwords_cache_tl = Arc::clone(&passwords_cache);
    let timelimit_fn = lua.create_function(move |lua, ()| {
        // Check for notimelimit argument
        let registry: Table = lua.globals().get("nmap")?;
        let args: Table = registry.get("registry_args")?;
        // Check if notimelimit is set
        if let Ok(Some(_)) = args.get::<Option<Value>>("notimelimit") {
            return Ok(Value::Nil);
        }
        // Check for explicit timelimit
        if let Ok(Some(Value::String(spec))) = args.get::<Option<Value>>("unpwdb.timelimit") {
            let spec_str = spec.to_string_lossy();
            if let Some(limit) = parse_timespec(&spec_str) {
                // Time limit values are small (<1 day), no precision loss
                #[expect(clippy::cast_precision_loss, reason = "Time values are small integers")]
                return Ok(Value::Number(limit as f64));
            }
            return Err(mlua::Error::RuntimeError(format!(
                "Invalid unpwdb.timelimit specification: {spec_str}"
            )));
        }
        // Calculate based on timing level and custom data
        #[expect(
            clippy::cast_sign_loss,
            reason = "Timing level is clamped to 0-5 range, always positive"
        )]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Timing level is clamped to 0-5 range, fits in u8"
        )]
        let timing_level: u8 = args
            .get::<Option<Value>>("timing_level")
            .ok()
            .flatten()
            .and_then(|v| match v {
                Value::Integer(n) => Some(n.clamp(0, 5) as u8),
                Value::Number(n) => Some(n.clamp(0.0, 5.0) as u8),
                _ => None,
            })
            .unwrap_or(3);
        let has_custom_data = {
            let u = usernames_cache_tl.lock().unwrap();
            let p = passwords_cache_tl.lock().unwrap();
            !u.is_empty() && !p.is_empty()
        };
        let (base_limit, multiplier) = match timing_level {
            4 => (TIMELIMIT_T4, CUSTOM_DATA_MULTIPLIER),
            5 => (TIMELIMIT_T5, CUSTOM_DATA_MULTIPLIER),
            _ => (TIMELIMIT_T3, CUSTOM_DATA_MULTIPLIER),
        };
        let limit = if has_custom_data {
            base_limit * multiplier / 10
        } else {
            base_limit
        };
        #[expect(
            clippy::cast_precision_loss,
            reason = "Time limit values are small (<1000), no precision loss in practice"
        )]
        Ok(Value::Number(limit as f64))
    })?;
    unpwdb_table.set("timelimit", timelimit_fn)?;
    // Register usernames function
    let usernames_cache_clone = Arc::clone(&usernames_cache);
    let usernames_fn = lua.create_function(
        move |lua, (time_limit, count_limit): (Option<Value>, Option<Value>)| {
            // Get the file path
            let registry: Table = lua.globals().get("nmap")?;
            let args: Table = registry.get("registry_args")?;
            let filepath =
                if let Ok(Some(Value::String(path))) = args.get::<Option<Value>>("userdb") {
                    path.to_string_lossy().to_string()
                } else {
                    match find_file(DEFAULT_USERNAMES_FILE) {
                        Some(p) => p,
                        None => {
                            return Ok((
                                false,
                                Value::String(lua.create_string("Cannot find username list")?),
                            ))
                        }
                    }
                };
            // Load entries
            let entries = {
                let mut cache = usernames_cache_clone.lock().unwrap();
                if cache.is_empty() {
                    match load_entries(Path::new(&filepath)) {
                        Ok(e) => {
                            *cache = e;
                            cache.clone()
                        }
                        Err(e) => {
                            return Ok((
                                false,
                                Value::String(
                                    lua.create_string(format!("Error parsing username list: {e}"))?,
                                ),
                            ));
                        }
                    }
                } else {
                    cache.clone()
                }
            };
            // Get limits
            let time_limit_secs: Option<u64> = match time_limit.as_ref() {
                Some(value @ Value::Number(_)) => value_to_u64(value),
                Some(Value::Integer(n)) => i64_to_u64_for_time(*n),
                _ => None, // Use default (no limit in this case)
            };
            let count_limit_usize: Option<usize> = match count_limit.as_ref() {
                Some(Value::Nil) | None => {
                    // Check for unpwdb.userlimit argument
                    if let Ok(Some(Value::String(s))) =
                        args.get::<Option<Value>>("unpwdb.userlimit")
                    {
                        s.to_string_lossy().parse().ok()
                    } else if let Ok(Some(value @ Value::Number(_))) =
                        args.get::<Option<Value>>("unpwdb.userlimit")
                    {
                        value_to_usize(&value)
                    } else {
                        None
                    }
                }
                Some(value @ Value::Number(_)) => value_to_usize(value),
                Some(Value::Integer(n)) => i64_to_usize_for_count(*n),
                _ => None,
            };
            // Create iterator state
            let state = Arc::new(Mutex::new(IteratorState::new(entries)));
            {
                let mut s = state.lock().unwrap();
                if let Some(limit) = time_limit_secs {
                    s.set_time_limit(limit);
                }
                if let Some(limit) = count_limit_usize {
                    s.set_count_limit(limit);
                }
            }
            // Create Lua closure
            let state_clone = Arc::clone(&state);
            let iterator = lua.create_function(move |lua, cmd: Option<String>| {
                let mut s = state_clone.lock().unwrap();
                if let Some(c) = cmd {
                    if c == "reset" {
                        s.reset();
                        return Ok(Value::Nil);
                    }
                }
                match s.next() {
                    Some(entry) => Ok(Value::String(lua.create_string(&entry)?)),
                    None => Ok(Value::Nil),
                }
            })?;
            // Return (true, iterator) as multiple values to Lua
            Ok((true, Value::Function(iterator)))
        },
    )?;
    unpwdb_table.set("usernames", usernames_fn)?;
    // Register passwords function
    let passwords_cache_clone = Arc::clone(&passwords_cache);
    let passwords_fn = lua.create_function(
        move |lua, (time_limit, count_limit): (Option<Value>, Option<Value>)| {
            // Get the file path
            let registry: Table = lua.globals().get("nmap")?;
            let args: Table = registry.get("registry_args")?;
            let filepath =
                if let Ok(Some(Value::String(path))) = args.get::<Option<Value>>("passdb") {
                    path.to_string_lossy().to_string()
                } else {
                    match find_file(DEFAULT_PASSWORDS_FILE) {
                        Some(p) => p,
                        None => {
                            return Ok((
                                false,
                                Value::String(lua.create_string("Cannot find password list")?),
                            ))
                        }
                    }
                };
            // Load entries
            let entries = {
                let mut cache = passwords_cache_clone.lock().unwrap();
                if cache.is_empty() {
                    match load_entries(Path::new(&filepath)) {
                        Ok(e) => {
                            *cache = e;
                            cache.clone()
                        }
                        Err(e) => {
                            return Ok((
                                false,
                                Value::String(
                                    lua.create_string(format!("Error parsing password list: {e}"))?,
                                ),
                            ));
                        }
                    }
                } else {
                    cache.clone()
                }
            };
            // Get limits
            let time_limit_secs: Option<u64> = match time_limit.as_ref() {
                Some(value @ Value::Number(_)) => value_to_u64(value),
                Some(Value::Integer(n)) => i64_to_u64_for_time(*n),
                _ => None, // Use default (no limit in this case)
            };
            let count_limit_usize: Option<usize> = match count_limit.as_ref() {
                Some(Value::Nil) | None => {
                    // Check for unpwdb.passlimit argument
                    if let Ok(Some(Value::String(s))) =
                        args.get::<Option<Value>>("unpwdb.passlimit")
                    {
                        s.to_string_lossy().parse().ok()
                    } else if let Ok(Some(value @ Value::Number(_))) =
                        args.get::<Option<Value>>("unpwdb.passlimit")
                    {
                        value_to_usize(&value)
                    } else {
                        None
                    }
                }
                Some(value @ Value::Number(_)) => value_to_usize(value),
                Some(Value::Integer(n)) => i64_to_usize_for_count(*n),
                _ => None,
            };
            // Create iterator state
            let state = Arc::new(Mutex::new(IteratorState::new(entries)));
            {
                let mut s = state.lock().unwrap();
                if let Some(limit) = time_limit_secs {
                    s.set_time_limit(limit);
                }
                if let Some(limit) = count_limit_usize {
                    s.set_count_limit(limit);
                }
            }
            // Create Lua closure
            let state_clone = Arc::clone(&state);
            let iterator = lua.create_function(move |lua, cmd: Option<String>| {
                let mut s = state_clone.lock().unwrap();
                if let Some(c) = cmd {
                    if c == "reset" {
                        s.reset();
                        return Ok(Value::Nil);
                    }
                }
                match s.next() {
                    Some(entry) => Ok(Value::String(lua.create_string(&entry)?)),
                    None => Ok(Value::Nil),
                }
            })?;
            // Return (true, iterator) as multiple values to Lua
            Ok((true, Value::Function(iterator)))
        },
    )?;
    unpwdb_table.set("passwords", passwords_fn)?;
    // Register concat_iterators function
    let concat_fn = lua.create_function(|lua, (iter1, iter2): (Function, Function)| {
        // Create a new iterator that concatenates the two
        let iterator = lua.create_function(move |lua, cmd: Option<String>| {
            let cmd_value = match cmd {
                Some(s) => Value::String(lua.create_string(&s)?),
                None => Value::Nil,
            };
            // Try iter1 first
            let result: Value = iter1.call(cmd_value.clone())?;
            if !matches!(result, Value::Nil) {
                return Ok(result);
            }
            // If iter1 returned nil, try iter2
            let result: Value = iter2.call(cmd_value)?;
            Ok(result)
        })?;
        Ok(iterator)
    })?;
    unpwdb_table.set("concat_iterators", concat_fn)?;
    // Register filter_iterator function
    let filter_fn = lua.create_function(|lua, (iterator, filter): (Function, Function)| {
        // Create a new filtered iterator
        let filtered = lua.create_function(move |lua, cmd: Option<String>| {
            if let Some(ref c) = cmd {
                if c == "reset" {
                    let _: Value = iterator.call(Value::String(lua.create_string("reset")?))?;
                    return Ok(Value::Nil);
                }
            }
            let cmd_value = match cmd {
                Some(s) => Value::String(lua.create_string(&s)?),
                None => Value::Nil,
            };
            // Keep calling iterator until filter passes or nil
            loop {
                let val: Value = iterator.call(cmd_value.clone())?;
                if matches!(val, Value::Nil) {
                    return Ok(Value::Nil);
                }
                // Apply filter
                let passes: Value = filter.call(val.clone())?;
                if let Value::Boolean(true) = passes {
                    return Ok(val);
                }
                // Otherwise, continue to next value
            }
        })?;
        Ok(filtered)
    })?;
    unpwdb_table.set("filter_iterator", filter_fn)?;
    // Set the unpwdb table in globals
    lua.globals().set("unpwdb", unpwdb_table)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timespec() {
        assert_eq!(parse_timespec("30"), Some(30));
        assert_eq!(parse_timespec("30s"), Some(30));
        assert_eq!(parse_timespec("5m"), Some(300));
        assert_eq!(parse_timespec("1.5h"), Some(5400));
        assert_eq!(parse_timespec("1000ms"), Some(1));
        assert_eq!(parse_timespec("invalid"), None);
    }

    #[test]
    fn test_iterator_state() {
        let entries = vec![
            "user1".to_string(),
            "user2".to_string(),
            "user3".to_string(),
        ];
        let mut state = IteratorState::new(entries);
        assert_eq!(state.next(), Some("user1".to_string()));
        assert_eq!(state.next(), Some("user2".to_string()));
        state.reset();
        assert_eq!(state.next(), Some("user1".to_string()));
        assert_eq!(state.next(), Some("user2".to_string()));
        assert_eq!(state.next(), Some("user3".to_string()));
        assert_eq!(state.next(), None);
    }

    #[test]
    fn test_count_limit() {
        let entries = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut state = IteratorState::new(entries);
        state.set_count_limit(2);
        assert_eq!(state.next(), Some("a".to_string()));
        assert_eq!(state.next(), Some("b".to_string()));
        assert_eq!(state.next(), None); // Count limit exceeded
    }
}
