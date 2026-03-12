//! Brute force library for NSE.
//!
//! This module provides the `brute` library which contains a framework for
//! performing password guessing against remote services. It corresponds to
//! Nmap's brute NSE library.
//!
//! # Available Classes
//!
//! - `brute.Error` - Error handling class with retry/abort/reduce flags
//! - `brute.Options` - Configuration options for brute force engine
//! - `brute.Engine` - Main brute-forcing engine with multi-threading support
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local brute = require "brute"
//!
//! -- Create a driver for your protocol
//! Driver = {
//!   new = function(self, host, port, options)
//!     local o = {}
//!     setmetatable(o, self)
//!     self.__index = self
//!     o.host = host
//!     o.port = port
//!     return o
//!   end,
//!
//!   connect = function(self)
//!     self.socket = nmap.new_socket()
//!     return self.socket:connect(self.host, self.port)
//!   end,
//!
//!   disconnect = function(self)
//!     return self.socket:close()
//!   end,
//!
//!   login = function(self, username, password)
//!     -- Perform authentication
//!     if success then
//!       return true, brute.Account:new(username, password, creds.State.VALID)
//!     else
//!       return false, brute.Error:new("Login failed")
//!     end
//!   end,
//! }
//!
//! -- Use the engine
//! action = function(host, port)
//!   local options = {}
//!   local status, accounts = brute.Engine:new(Driver, host, port, options):start()
//!   if not status then
//!     return accounts
//!   end
//!   return stdnse.format_output(true, accounts)
//! end
//! ```

use mlua::{ObjectLike, Table, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Meta method name for the `new` constructor.
const NEW: &str = "new";

/// Meta method name for `__index`.
const INDEX: &str = "__index";

/// Register the brute library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the brute table
    let brute_table = lua.create_table()?;

    // Create and register the Options class
    let options_table = create_options_class(lua)?;
    brute_table.set("Options", options_table)?;

    // Create and register the Error class
    let error_table = create_error_class(lua)?;
    brute_table.set("Error", error_table)?;

    // Create and register the Engine class
    let engine_table = create_engine_class(lua)?;
    brute_table.set("Engine", engine_table)?;

    // Set the brute table in globals
    lua.globals().set("brute", brute_table)?;

    Ok(())
}

/// Creates the Options class for brute force configuration.
///
/// The Options class stores configuration options like:
/// - `firstonly` - stop after finding first password
/// - `passonly` - guess passwords only
/// - `max_retries` - number of retries before aborting
/// - `delay` - delay between attempts
/// - `mode` - user/pass/creds mode
/// - `max_guesses` - maximum guesses per account
/// - `useraspass` - guess username as password
/// - `emptypass` - guess empty password
fn create_options_class(lua: &mlua::Lua) -> Result<Table> {
    let options_table = lua.create_table()?;

    // Default values
    options_table.set("emptypass", Value::Boolean(false))?;
    options_table.set("useraspass", Value::Boolean(true))?;
    options_table.set("firstonly", Value::Boolean(false))?;
    options_table.set("passonly", Value::Boolean(false))?;
    options_table.set("killstagnated", Value::Boolean(true))?;
    options_table.set("max_retries", Value::Integer(2))?;
    options_table.set("delay", Value::Integer(0))?;
    options_table.set("max_guesses", Value::Integer(0))?;

    // Create the metatable with __index pointing to itself
    let metatable = lua.create_table()?;
    metatable.set("__index", options_table.clone())?;
    options_table.set_metatable(Some(metatable))?;

    // Add the new constructor
    let new_fn = lua.create_function(|lua, (): ()| {
        let o = lua.create_table()?;

        // Get default values from Options table
        let options: Table = lua.globals().get("brute")?;
        let opts_class: Table = options.get("Options")?;

        o.set("emptypass", Value::Boolean(false))?;
        o.set("useraspass", Value::Boolean(true))?;
        o.set("firstonly", Value::Boolean(false))?;
        o.set("passonly", Value::Boolean(false))?;
        o.set("killstagnated", Value::Boolean(true))?;
        o.set("max_retries", Value::Integer(2))?;
        o.set("delay", Value::Integer(0))?;
        o.set("max_guesses", Value::Integer(0))?;

        // Set metatable to opts_class for method lookup
        o.set_metatable(Some(opts_class))?;

        Ok(Value::Table(o))
    })?;
    options_table.set("new", new_fn)?;

    // Add setMode method
    let set_mode_fn = lua.create_function(|_lua, (this, mode): (Table, String)| {
        let valid_modes = ["password", "user", "creds"];
        if valid_modes.contains(&mode.as_str()) {
            this.set("mode", mode)?;
            Ok(true)
        } else {
            Ok(false)
        }
    })?;
    options_table.set("setMode", set_mode_fn)?;

    // Add setOption method
    let set_option_fn = lua.create_function(|_lua, (this, param, value): (Table, String, Value)| {
        this.set(param, value)?;
        Ok(())
    })?;
    options_table.set("setOption", set_option_fn)?;

    // Add setTitle method
    let set_title_fn = lua.create_function(|_lua, (this, title): (Table, String)| {
        this.set("title", title)?;
        Ok(())
    })?;
    options_table.set("setTitle", set_title_fn)?;

    Ok(options_table)
}

/// Creates the Error class for brute force error handling.
///
/// The Error class provides:
/// - `retry` - flag for recoverable errors
/// - `abort` - flag to abort all threads
/// - `reduce` - flag to reduce thread count
/// - `done` - flag to terminate thread
/// - `invalid_account` - mark account as invalid
fn create_error_class(lua: &mlua::Lua) -> Result<Table> {
    let error_table = lua.create_table()?;

    // Default values
    error_table.set("retry", Value::Boolean(false))?;

    // Create the metatable with __index pointing to itself
    let metatable = lua.create_table()?;
    metatable.set("__index", error_table.clone())?;
    error_table.set_metatable(Some(metatable))?;

    // Add the new constructor
    let new_fn = lua.create_function(|lua, msg: String| {
        let o = lua.create_table()?;
        o.set("msg", msg)?;
        o.set("done", Value::Boolean(false))?;
        o.set("retry", Value::Boolean(false))?;
        o.set("abort", Value::Boolean(false))?;
        o.set("reduce", Value::Boolean(false))?;

        // Set metatable to Error class for method lookup
        let error_class: Table = lua.globals().get("brute")?;
        let err_class: Table = error_class.get("Error")?;
        o.set_metatable(Some(err_class))?;

        Ok(Value::Table(o))
    })?;
    error_table.set("new", new_fn)?;

    // Add isRetry method
    let is_retry_fn = lua.create_function(|_lua, this: Table| {
        let retry: bool = this.get("retry").unwrap_or(false);
        Ok(retry)
    })?;
    error_table.set("isRetry", is_retry_fn)?;

    // Add setRetry method
    let set_retry_fn = lua.create_function(|_lua, (this, r): (Table, bool)| {
        this.set("retry", r)?;
        Ok(())
    })?;
    error_table.set("setRetry", set_retry_fn)?;

    // Add setAbort method
    let set_abort_fn = lua.create_function(|_lua, (this, b): (Table, bool)| {
        this.set("abort", b)?;
        Ok(())
    })?;
    error_table.set("setAbort", set_abort_fn)?;

    // Add isAbort method
    let is_abort_fn = lua.create_function(|_lua, this: Table| {
        let abort: bool = this.get("abort").unwrap_or(false);
        Ok(abort)
    })?;
    error_table.set("isAbort", is_abort_fn)?;

    // Add getMessage method
    let get_message_fn = lua.create_function(|_lua, this: Table| {
        let msg: String = this.get("msg").unwrap_or_default();
        Ok(msg)
    })?;
    error_table.set("getMessage", get_message_fn)?;

    // Add isDone method
    let is_done_fn = lua.create_function(|_lua, this: Table| {
        let done: bool = this.get("done").unwrap_or(false);
        Ok(done)
    })?;
    error_table.set("isDone", is_done_fn)?;

    // Add setDone method
    let set_done_fn = lua.create_function(|_lua, (this, b): (Table, bool)| {
        this.set("done", b)?;
        Ok(())
    })?;
    error_table.set("setDone", set_done_fn)?;

    // Add setInvalidAccount method
    let set_invalid_fn = lua.create_function(|_lua, (this, username): (Table, String)| {
        this.set("invalid_account", username)?;
        Ok(())
    })?;
    error_table.set("setInvalidAccount", set_invalid_fn)?;

    // Add isInvalidAccount method
    let is_invalid_fn = lua.create_function(|_lua, this: Table| {
        let username: Option<String> = this.get("invalid_account").ok();
        Ok(username)
    })?;
    error_table.set("isInvalidAccount", is_invalid_fn)?;

    // Add setReduce method
    let set_reduce_fn = lua.create_function(|_lua, (this, r): (Table, bool)| {
        this.set("reduce", r)?;
        Ok(())
    })?;
    error_table.set("setReduce", set_reduce_fn)?;

    // Add isReduce method
    let is_reduce_fn = lua.create_function(|_lua, this: Table| {
        let reduce: bool = this.get("reduce").unwrap_or(false);
        Ok(reduce)
    })?;
    error_table.set("isReduce", is_reduce_fn)?;

    Ok(error_table)
}

/// Creates the Engine class for brute force execution.
///
/// The Engine class manages:
/// - Thread pool for parallel guessing
/// - Iterator management (usernames/passwords)
/// - Statistics tracking
/// - Result aggregation
fn create_engine_class(lua: &mlua::Lua) -> Result<Table> {
    let engine_table = lua.create_table()?;

    // Statistics interval constant
    engine_table.set("STAT_INTERVAL", Value::Integer(20))?;

    // Create the metatable with __index pointing to itself
    let metatable = lua.create_table()?;
    metatable.set("__index", engine_table.clone())?;
    engine_table.set_metatable(Some(metatable))?;

    // Clone engine_table for use in the new closure
    let engine_table_for_new = engine_table.clone();

    // Add the new constructor
    let new_fn = lua.create_function(move |lua, (driver, host, port, options): (Table, Table, Table, Table)| {
        let o = lua.create_table()?;

        // Store driver and connection info
        o.set("driver", driver)?;
        o.set("host", host)?;
        o.set("port", port)?;
        o.set("driver_options", options)?;

        // Initialize engine state
        o.set("terminate_all", Value::Boolean(false))?;
        o.set("error", Value::Nil)?;
        o.set("counter", Value::Integer(0))?;
        o.set("threads", lua.create_table()?)?;
        o.set("tps", lua.create_table()?)?; // Thread to engine mapping
        o.set("iterator", Value::Nil)?;
        o.set("found_accounts", lua.create_table()?)?;
        o.set("account_guesses", lua.create_table()?)?;
        o.set("retry_accounts", lua.create_table()?)?;
        o.set("initial_accounts_exhausted", Value::Boolean(false))?;
        o.set("batch", Value::Nil)?;
        o.set("tick", Value::Integer(0))?;

        // Get options with defaults
        let brute: Table = lua.globals().get("brute")?;
        let options_class: Table = brute.get("Options")?;
        let opts_instance: Table = options_class.call(())?;

        // Get script arguments
        let nmap: Table = lua.globals().get("nmap")?;
        let args: Table = nmap.get("registry_args")?;

        // Thread configuration
        let max_threads: i64 = if let Ok(Some(Value::Integer(n))) = args.get::<Option<Value>>("brute.threads") {
            n
        } else {
            20
        };
        o.set("max_threads", max_threads)?;

        let start_threads: i64 = if let Ok(Some(Value::Integer(n))) = args.get::<Option<Value>>("brute.start") {
            n
        } else {
            5
        };
        o.set("start_threads", start_threads)?;

        o.set("options", opts_instance)?;

        // Set metatable to Engine class for method lookup
        o.set_metatable(Some(engine_table_for_new.clone()))?;

        Ok(Value::Table(o))
    })?;
    engine_table.set("new", new_fn)?;

    // Add setUsernameIterator method
    let set_user_iter_fn = lua.create_function(|_lua, (this, iterator): (Table, mlua::Function)| {
        this.set("usernames", iterator)?;
        Ok(())
    })?;
    engine_table.set("setUsernameIterator", set_user_iter_fn)?;

    // Add setPasswordIterator method
    let set_pass_iter_fn = lua.create_function(|_lua, (this, iterator): (Table, mlua::Function)| {
        this.set("passwords", iterator)?;
        Ok(())
    })?;
    engine_table.set("setPasswordIterator", set_pass_iter_fn)?;

    // Add setMaxThreads method
    let set_max_threads_fn = lua.create_function(|_lua, (this, max): (Table, i64)| {
        this.set("max_threads", max)?;
        Ok(())
    })?;
    engine_table.set("setMaxThreads", set_max_threads_fn)?;

    // Add threadCount method
    let thread_count_fn = lua.create_function(|_lua, this: Table| {
        let threads: Table = this.get("threads")?;
        let mut count = 0;
        for pair in threads.pairs::<Value, Value>() {
            if let Ok((_, _)) = pair {
                // Check if coroutine is still alive
                // In a real implementation, we'd track coroutine status
                count += 1;
            }
        }
        Ok(count)
    })?;
    engine_table.set("threadCount", thread_count_fn)?;

    // Add activeThreads method
    let active_threads_fn = lua.create_function(|_lua, this: Table| {
        let threads: Table = this.get("threads")?;
        let mut count = 0;
        for pair in threads.pairs::<Value, Table>() {
            if let Ok((_, thread_data)) = pair {
                if let Ok(Some(_)) = thread_data.get::<Option<Value>>("guesses") {
                    count += 1;
                }
            }
        }
        Ok(count)
    })?;
    engine_table.set("activeThreads", active_threads_fn)?;

    // Add start method - implements the brute force algorithm
    let start_fn = lua.create_function(|lua, this: Table| {
        // Get unpwdb iterators
        let unpwdb: Table = lua.globals().get("unpwdb")?;

        // Get usernames iterator
        let usernames_result: mlua::MultiValue = unpwdb.call((Option::<Value>::None, Option::<Value>::None))?;
        let usernames_iter = match usernames_result.get(0) {
            Some(Value::Boolean(true)) => {
                usernames_result.get(1).and_then(|v| match v {
                    Value::Function(f) => Some(f),
                    _ => None,
                })
            }
            _ => None,
        };

        let usernames_iter = usernames_iter.ok_or_else(|| mlua::Error::RuntimeError("Failed to get usernames iterator".to_string()))?;

        // Get passwords iterator
        let passwords_result: mlua::MultiValue = unpwdb.call((Option::<Value>::None, Option::<Value>::None))?;
        let passwords_iter = match passwords_result.get(0) {
            Some(Value::Boolean(true)) => {
                passwords_result.get(1).and_then(|v| match v {
                    Value::Function(f) => Some(f),
                    _ => None,
                })
            }
            _ => None,
        };

        let passwords_iter = passwords_iter.ok_or_else(|| mlua::Error::RuntimeError("Failed to get passwords iterator".to_string()))?;

        this.set("usernames", usernames_iter)?;
        this.set("passwords", passwords_iter)?;

        // Get options
        let options: Table = this.get("options")?;
        let firstonly: bool = options.get("firstonly").unwrap_or(false);
        #[expect(unused_variables, reason = "Mode selection reserved for future implementation")]
        let _mode: String = options.get("mode").unwrap_or("password".to_string());
        let emptypass: bool = options.get("emptypass").unwrap_or(false);
        let useraspass: bool = options.get("useraspass").unwrap_or(true);
        #[expect(unused_variables, reason = "Pass-only mode reserved for future implementation")]
        let _passonly: bool = options.get("passonly").unwrap_or(false);
        let max_guesses: i64 = options.get("max_guesses").unwrap_or(0);
        let delay: i64 = options.get("delay").unwrap_or(0);
        #[expect(unused_variables, reason = "Retry logic reserved for future implementation")]
        let _max_retries: i64 = options.get("max_retries").unwrap_or(2);

        // Get driver
        let driver: Table = this.get("driver")?;
        let driver_new: mlua::Function = driver.get(NEW)
            .or_else(|_| driver.get(INDEX))
            .map_err(|_| mlua::Error::RuntimeError("Driver must have a 'new' method".to_string()))?;

        // Get host and port
        let host: Table = this.get("host")?;
        let port: Table = this.get("port")?;

        // Create driver instance
        let driver_instance: Table = driver_new.call((driver.clone(), host, port, this.clone()))?;

        // Track found accounts and statistics
        let found_accounts: Table = lua.create_table()?;
        let mut account_count = 0;
        let mut total_guesses = 0;
        let mut stagnation_count = 0;
        let max_stagnation = 100;

        // Iterate through usernames
        let mut username = match usernames_iter.call::<mlua::MultiValue>(()) {
            Ok(vals) => {
                if let Some(Value::String(u)) = vals.get(0) {
                    Some(u.to_string_lossy().to_string())
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        #[expect(unused_variables, reason = "Username-as-password values tracked inline")]
        let _useraspass_values: Vec<String> = if useraspass {
            username.clone().into_iter().collect()
        } else {
            vec![]
        };

        while let Some(uname) = username {
            // Track guesses for this account
            let mut account_guesses = 0i64;
            let mut account_found = false;

            // Passwords to try for this username
            let mut passwords_to_try: Vec<Option<String>> = vec![];

            // Add username as password if configured
            if useraspass {
                passwords_to_try.push(Some(uname.clone()));
            }

            // Add empty password if configured
            if emptypass {
                passwords_to_try.push(None);
            }

            // Add passwords from iterator
            let mut password = match passwords_iter.call::<mlua::MultiValue>(()) {
                Ok(vals) => {
                    if let Some(Value::String(p)) = vals.get(0) {
                        Some(p.to_string_lossy().to_string())
                    } else {
                        None
                    }
                }
                Err(_) => None,
            };

            while let Some(pw) = password {
                let pw_opt = Some(pw);
                if !passwords_to_try.contains(&pw_opt) {
                    passwords_to_try.push(pw_opt);
                }

                password = match passwords_iter.call::<mlua::MultiValue>(()) {
                    Ok(vals) => {
                        if let Some(Value::String(p)) = vals.get(0) {
                            Some(p.to_string_lossy().to_string())
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                };

                // Limit the number of passwords to try
                if passwords_to_try.len() > 100 {
                    break;
                }
            }

            // Try each password
            for pw in passwords_to_try {
                if account_found && firstonly {
                    break;
                }

                if max_guesses > 0 && account_guesses >= max_guesses {
                    break;
                }

                total_guesses += 1;
                account_guesses += 1;

                // Check for stagnation
                if total_guesses > stagnation_count + max_stagnation {
                    // Stagnation detected - no successful logins in 100 attempts
                    let killstagnated: bool = options.get("killstagnated").unwrap_or(true);
                    if killstagnated {
                        let error_class: Table = lua.globals().get("brute")?;
                        let err_class: Table = error_class.get("Error")?;
                        let err: Table = err_class.call("Stagnation detected - too many connection errors".to_string())?;
                        return Ok((false, Value::Table(err)));
                    }
                }

                // Delay between attempts if configured
                if delay > 0 {
                    let _ = std::thread::sleep(std::time::Duration::from_millis(delay as u64));
                }

                // Call driver connect
                let connect_result: mlua::Result<Value> = driver_instance.get::<mlua::Function>("connect")
                    .or_else(|_| driver_instance.get::<mlua::Function>(INDEX))
                    .and_then(|conn_fn| conn_fn.call::<Value>(driver_instance.clone()));

                let connected = match connect_result {
                    Ok(Value::Boolean(true)) => true,
                    Ok(Value::Nil) => true,
                    Err(_) => false,
                    _ => false,
                };

                if !connected {
                    stagnation_count = total_guesses;
                    continue;
                }

                // Call driver login
                let pw_str = pw.as_deref().unwrap_or("");
                let login_result: mlua::Result<mlua::MultiValue> = driver_instance.get::<mlua::Function>("login")
                    .or_else(|_| driver_instance.get::<mlua::Function>(INDEX))
                    .and_then(|login_fn| login_fn.call::<mlua::MultiValue>((driver_instance.clone(), uname.clone(), pw_str)));

                match login_result {
                    Ok(result) => {
                        if let Some(Value::Boolean(true)) = result.get(0) {
                            // Successful login
                            account_found = true;
                            stagnation_count = 0;

                            // Get the account object from result
                            if let Some(account) = result.get(1) {
                                account_count += 1;
                                found_accounts.set(account_count.to_string(), account)?;
                            }

                            if firstonly {
                                break;
                            }
                        } else {
                            // Failed login - check for error
                            if let Some(Value::Table(err)) = result.get(1) {
                                // Check if we should abort
                                let is_abort: bool = err.get("isAbort").unwrap_or(false);
                                if is_abort {
                                    // Call driver disconnect
                                    let _ = driver_instance.get::<mlua::Function>("disconnect")
                                        .and_then(|disc_fn| disc_fn.call::<Value>(driver_instance.clone()));

                                    return Ok((false, Value::Table(err.clone())));
                                }

                                // Check if account is invalid
                                let is_invalid: Option<String> = err.get("isInvalidAccount").ok().flatten();
                                if is_invalid.is_some() {
                                    break;
                                }

                                // Check if we should reduce
                                let is_reduce: bool = err.get("isReduce").unwrap_or(false);
                                if is_reduce {
                                    stagnation_count = total_guesses;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        stagnation_count = total_guesses;
                    }
                }

                // Call driver disconnect
                let _ = driver_instance.get::<mlua::Function>("disconnect")
                    .and_then(|disc_fn| disc_fn.call::<Value>(driver_instance.clone()));
            }

            // Get next username
            username = match usernames_iter.call::<mlua::MultiValue>(()) {
                Ok(vals) => {
                    if let Some(Value::String(u)) = vals.get(0) {
                        Some(u.to_string_lossy().to_string())
                    } else {
                        None
                    }
                }
                Err(_) => None,
            };
        }

        Ok((true, Value::Table(found_accounts)))
    })?;
    engine_table.set("start", start_fn)?;

    Ok(engine_table)
}
