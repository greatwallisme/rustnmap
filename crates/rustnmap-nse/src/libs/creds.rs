//! Credentials library for NSE.
//!
//! This module provides the `creds` library which stores found credentials
//! in the Nmap registry. It corresponds to Nmap's creds NSE library.
//!
//! # Available Classes
//!
//! - `creds.State` - Account state constants (LOCKED, VALID, DISABLED, etc.)
//! - `creds.StateMsg` - State to message mapping
//! - `creds.Account` - Represents a single account with username, password, and state
//! - `creds.Credentials` - Main interface for credential management
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local creds = require "creds"
//!
//! -- Create a new Credentials object
//! local c = creds.Credentials:new({"myapp"}, host, port)
//!
//! -- Add a discovered credential
//! c:add("patrik", "secret", creds.State.VALID)
//!
//! -- Get all credentials
//! local all = c:getTable()
//!
//! -- Return formatted output
//! return tostring(c)
//! ```

use mlua::{Function, ObjectLike, Table, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Meta method name for the `new` constructor.
const NEW: &str = "new";

/// Meta method name for `__index`.
const INDEX: &str = "__index";

/// Meta method name for `__tostring`.
const TOSTRING: &str = "__tostring";

/// Meta method name for `__lt`.
const LT: &str = "__lt";

/// Special tag for accessing all credentials.
#[expect(dead_code, reason = "Reserved for future use")]
const ALL_DATA: &[&str] = &[];

/// Account state constants.
pub mod state {
    /// Account is locked.
    pub const LOCKED: u32 = 1;

    /// Valid credentials.
    pub const VALID: u32 = 2;

    /// Account is disabled.
    pub const DISABLED: u32 = 4;

    /// Valid credentials, password must be changed at next logon.
    pub const CHANGEPW: u32 = 8;

    /// Credentials passed to script during Nmap execution.
    pub const PARAM: u32 = 16;

    /// Valid credentials, account expired.
    pub const EXPIRED: u32 = 32;

    /// Valid credentials, account cannot log in at current time.
    pub const TIME_RESTRICTED: u32 = 64;

    /// Valid credentials, account cannot log in from current host.
    pub const HOST_RESTRICTED: u32 = 128;

    /// Valid credentials, account locked.
    pub const LOCKED_VALID: u32 = 256;

    /// Valid credentials, account disabled.
    pub const DISABLED_VALID: u32 = 512;

    /// Hashed valid or invalid credentials.
    pub const HASHED: u32 = 1024;
}

/// State message mapping.
fn state_msg(state: u32) -> &'static str {
    match state {
        state::LOCKED => "Account is locked",
        state::VALID => "Valid credentials",
        state::DISABLED => "Account is disabled",
        state::CHANGEPW => "Valid credentials, password must be changed at next logon",
        state::PARAM => "Credentials passed to script during Nmap execution",
        state::EXPIRED => "Valid credentials, account expired",
        state::TIME_RESTRICTED => "Valid credentials, account cannot log in at current time",
        state::HOST_RESTRICTED => "Valid credentials, account cannot log in from current host",
        state::LOCKED_VALID => "Valid credentials, account locked",
        state::DISABLED_VALID => "Valid credentials, account disabled",
        state::HASHED => "Hashed valid or invalid credentials",
        _ => "Unknown state",
    }
}

/// Registry storage for credentials.
///
/// This structure is shared across all Credentials instances and stores
/// credentials in the nmap registry.
#[derive(Debug, Clone)]
struct RegStorage;

impl RegStorage {
    /// Add credentials to storage.
    #[expect(
        clippy::too_many_arguments,
        reason = "All parameters are needed for credential storage"
    )]
    #[allow(clippy::manual_let_else)]
    #[allow(clippy::allow_attributes_without_reason)]
    fn add_to_registry(
        lua: &mlua::Lua,
        tags: Table,
        host: Table,
        port: Option<u16>,
        service: Option<String>,
        user: Option<String>,
        pass: Option<String>,
        state: u32,
    ) -> Result<()> {
        // Get or create the creds registry
        let globals = lua.globals();
        let nmap: Value = globals.get("nmap")?;
        let Value::Table(nmap_table) = nmap else {
            return Ok(()); // nmap not available, skip
        };

        #[allow(
            clippy::manual_let_else,
            reason = "if let pattern with early return is clearer here"
        )]
        let registry: Value = nmap_table.get("registry")?;
        let registry_table = if let Value::Table(t) = registry {
            t
        } else {
            let new_table = lua.create_table()?;
            nmap_table.set("registry", new_table.clone())?;
            new_table
        };

        #[allow(
            clippy::manual_let_else,
            reason = "if let pattern with early return is clearer here"
        )]
        let creds_value: Value = registry_table.get("creds")?;
        let creds_array = if let Value::Table(t) = creds_value {
            t
        } else {
            let new_array = lua.create_table()?;
            registry_table.set("creds", new_array.clone())?;
            new_array
        };

        // Create credential table
        let cred = lua.create_table()?;
        cred.set("tags", tags)?;
        cred.set("host", host)?;
        if let Some(p) = port {
            cred.set("port", p)?;
        }
        if let Some(s) = service {
            cred.set("service", s)?;
        }
        if let Some(u) = user {
            cred.set("user", u)?;
        }
        if let Some(p) = pass {
            cred.set("pass", p)?;
        }
        cred.set("state", state)?;

        // Add to array
        let len = creds_array.raw_len();
        creds_array.raw_set(len + 1, cred)?;

        Ok(())
    }
}

/// Register the creds library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the creds table
    let creds_table = lua.create_table()?;

    // Add State constants
    let state_table = lua.create_table()?;
    state_table.set("LOCKED", state::LOCKED)?;
    state_table.set("VALID", state::VALID)?;
    state_table.set("DISABLED", state::DISABLED)?;
    state_table.set("CHANGEPW", state::CHANGEPW)?;
    state_table.set("PARAM", state::PARAM)?;
    state_table.set("EXPIRED", state::EXPIRED)?;
    state_table.set("TIME_RESTRICTED", state::TIME_RESTRICTED)?;
    state_table.set("HOST_RESTRICTED", state::HOST_RESTRICTED)?;
    state_table.set("LOCKED_VALID", state::LOCKED_VALID)?;
    state_table.set("DISABLED_VALID", state::DISABLED_VALID)?;
    state_table.set("HASHED", state::HASHED)?;
    creds_table.set("State", state_table)?;

    // Add StateMsg table
    let statemsg_table = lua.create_table()?;
    statemsg_table.set(state::LOCKED, state_msg(state::LOCKED))?;
    statemsg_table.set(state::VALID, state_msg(state::VALID))?;
    statemsg_table.set(state::DISABLED, state_msg(state::DISABLED))?;
    statemsg_table.set(state::CHANGEPW, state_msg(state::CHANGEPW))?;
    statemsg_table.set(state::PARAM, state_msg(state::PARAM))?;
    statemsg_table.set(state::EXPIRED, state_msg(state::EXPIRED))?;
    statemsg_table.set(state::TIME_RESTRICTED, state_msg(state::TIME_RESTRICTED))?;
    statemsg_table.set(state::HOST_RESTRICTED, state_msg(state::HOST_RESTRICTED))?;
    statemsg_table.set(state::LOCKED_VALID, state_msg(state::LOCKED_VALID))?;
    statemsg_table.set(state::DISABLED_VALID, state_msg(state::DISABLED_VALID))?;
    statemsg_table.set(state::HASHED, state_msg(state::HASHED))?;
    creds_table.set("StateMsg", statemsg_table)?;

    // Add ALL_DATA constant
    creds_table.set("ALL_DATA", lua.create_table()?)?;

    // Create and register the Account class
    let account_table = create_account_class(lua)?;
    creds_table.set("Account", account_table)?;

    // Create and register the Credentials class
    let credentials_table = create_credentials_class(lua)?;
    creds_table.set("Credentials", credentials_table)?;

    // Set the creds table in globals
    lua.globals().set("creds", creds_table)?;

    Ok(())
}

/// Creates the Account class for representing individual credentials.
fn create_account_class(lua: &mlua::Lua) -> Result<Table> {
    let account_table = lua.create_table()?;

    // Create the metatable with __index pointing to account_table
    let metatable = lua.create_table()?;
    metatable.set(INDEX, account_table.clone())?;
    account_table.set_metatable(Some(metatable))?;

    // __tostring metamethod
    let tostring_fn = lua.create_function(|_, account: Table| {
        let username: Option<String> = account.get("username")?;
        let password: Option<String> = account.get("password")?;
        let state: Option<String> = account.get("state")?;

        let mut result = String::new();
        if let Some(u) = username {
            result.push_str(&u);
            result.push(':');
        }
        if let Some(p) = password {
            if p.is_empty() {
                result.push_str("<empty>");
            } else {
                result.push_str(&p);
            }
        } else {
            result.push_str("<empty>");
        }
        if let Some(s) = state {
            result.push_str(" - ");
            result.push_str(&s);
        }
        Ok(result)
    })?;
    account_table.set(TOSTRING, tostring_fn)?;

    // __lt metamethod for sorting
    let lt_fn = lua.create_function(|_, (a, b): (Table, Table)| {
        let a_user: Option<String> = a.get("username")?;
        let b_user: Option<String> = b.get("username")?;
        let a_pass: Option<String> = a.get("password")?;
        let b_pass: Option<String> = b.get("password")?;
        let a_state: Option<String> = a.get("state")?;
        let b_state: Option<String> = b.get("state")?;

        // Lexicographic comparison by user, pass, and state
        if let (Some(au), Some(bu)) = (a_user, b_user) {
            if au >= bu {
                return Ok(false);
            }
        }
        if let (Some(ap), Some(bp)) = (a_pass, b_pass) {
            if ap >= bp {
                return Ok(false);
            }
        }
        if let (Some(as_), Some(bs)) = (a_state, b_state) {
            if as_ >= bs {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    account_table.set(LT, lt_fn)?;

    // Account:new(username, password, state)
    let new_fn = lua.create_function(
        |lua, (username, password, state): (Option<String>, Option<String>, u32)| {
            let account = lua.create_table()?;
            account.set("username", username)?;
            account.set("password", password)?;
            account.set("state", state_msg(state))?;

            // Get Account class from globals and set as metatable
            let creds_table: Table = lua.globals().get("creds")?;
            let account_class: Table = creds_table.get("Account")?;
            account.set_metatable(Some(account_class))?;

            Ok(account)
        },
    )?;

    account_table.set(NEW, new_fn)?;

    Ok(account_table)
}

/// Creates the Credentials class for credential management.
#[expect(clippy::too_many_lines, reason = "Complex class with multiple methods")]
fn create_credentials_class(lua: &mlua::Lua) -> Result<Table> {
    let credentials_table = lua.create_table()?;

    // Create the metatable with __index pointing to credentials_table
    let metatable = lua.create_table()?;
    metatable.set(INDEX, credentials_table.clone())?;
    credentials_table.set_metatable(Some(metatable))?;

    // Define the add method
    let add_fn = lua.create_function(
        |lua, (this, user, pass, state): (Table, Option<String>, Option<String>, u32)| {
            let host: Table = this.get("_host")?;
            let port_number: Option<u16> = this.get("_port_number")?;
            let _service: Option<String> = this.get("_service")?;
            let tags: Table = this.get("_tags")?;

            // Handle empty password
            let pass = if pass.as_ref().is_some_and(String::is_empty) {
                Some("<empty>".to_string())
            } else {
                pass
            };

            // Add to registry if we have user or pass
            if user.is_some() || pass.is_some() {
                RegStorage::add_to_registry(lua, tags, host, port_number, None, user, pass, state)
                    .map_err(mlua::Error::external)?;
            }

            Ok(())
        },
    )?;
    credentials_table.set("add", add_fn)?;

    // Define the getCredentials method
    // Returns an iterator function that yields one credential per call.
    // Matches Nmap's coroutine.wrap-based pattern:
    //   for cred in c:getCredentials(creds.State.VALID) do ... end
    //   local cred = c:getCredentials(state)()  -- get first credential
    #[allow(
        clippy::manual_let_else,
        reason = "if let pattern with early return is clearer here"
    )]
    let get_credentials_fn = lua.create_function(|lua, (this, state): (Table, Option<u32>)| {
        let host: Table = this.get("_host")?;
        let port_number: Option<u16> = this.get("_port_number")?;
        let _service: Option<String> = this.get("_service")?;
        let tags: Table = this.get("_tags")?;

        // Get credentials from registry
        let globals = lua.globals();
        let nmap: Value = globals.get("nmap")?;
        let nmap_table = if let Value::Table(t) = nmap {
            t
        } else {
            let empty_iter = lua.create_function(|_, (): ()| Ok(Value::Nil))?;
            return Ok(empty_iter);
        };

        let registry: Value = nmap_table.get("registry")?;
        let registry_table = if let Value::Table(t) = registry {
            t
        } else {
            let empty_iter = lua.create_function(|_, (): ()| Ok(Value::Nil))?;
            return Ok(empty_iter);
        };

        let creds_value: Value = registry_table.get("creds")?;
        let creds_array = if let Value::Table(t) = creds_value {
            t
        } else {
            let empty_iter = lua.create_function(|_, (): ()| Ok(Value::Nil))?;
            return Ok(empty_iter);
        };

        // Filter credentials based on host, port, service, tags, and state
        // Collect matching credentials into a Lua table (array)
        let filtered = lua.create_table()?;

        for pair in creds_array.pairs::<Value, Table>() {
            let (_, cred) = pair?;
            let cred_host: Value = cred.get("host")?;
            let cred_port: Option<u16> = cred.get("port").ok().flatten();
            let _cred_service: Option<String> = cred.get("service").ok().flatten();
            let cred_tags: Table = cred
                .get("tags")
                .ok()
                .unwrap_or_else(|| lua.create_table().unwrap());
            let cred_state: u32 = cred.get("state").ok().unwrap_or(0);

            // Check state filter
            if let Some(s) = state {
                if cred_state != s && (cred_state & s) == 0 {
                    continue;
                }
            }

            // Check host match
            let host_ip: Option<String> = host.get("ip").ok().flatten();
            let host_str: Option<String> = host_ip.clone();
            let cred_host_ip: Option<String> = if let Value::Table(t) = cred_host {
                t.get("ip").ok().flatten()
            } else if let Value::String(s) = cred_host {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            };

            let host_match = match (host_str, cred_host_ip) {
                (Some(h), Some(ch)) => h == ch,
                (None, _) => true,
                _ => false,
            };

            if !host_match {
                continue;
            }

            // Check port match
            let port_match = match (port_number, cred_port) {
                (Some(p1), Some(p2)) => p1 == p2,
                (None, _) => true,
                _ => false,
            };

            if !port_match {
                continue;
            }

            // Check tags match
            let tags_match =
                check_tags_match(lua, &tags, &cred_tags).map_err(mlua::Error::external)?;
            if !tags_match {
                continue;
            }

            // Add to filtered array
            let len = filtered.raw_len();
            filtered.raw_set(len + 1, cred.clone())?;
        }

        // Return an iterator function that yields one credential per call.
        // Each call returns the next credential table, or nil when exhausted.
        let iter = lua.create_function(move |_lua, (): ()| {
            let idx_key: i64 = filtered.get("_iter_idx")?;
            let idx: usize = if idx_key == 0 {
                1
            } else {
                usize::try_from(idx_key + 1).unwrap_or(usize::MAX)
            };

            match filtered.get::<Option<Table>>(idx)? {
                Some(cred) => {
                    filtered.set("_iter_idx", i64::try_from(idx).unwrap_or(i64::MAX))?;
                    Ok(Value::Table(cred))
                }
                None => Ok(Value::Nil),
            }
        })?;

        Ok(iter)
    })?;
    credentials_table.set("getCredentials", get_credentials_fn)?;

    // Define the getTable method
    // Uses the iterator returned by getCredentials to collect all credentials
    // into a host -> service -> accounts table structure.
    let get_table_fn = lua.create_function(|lua, this: Table| {
        let credentials_iter_fn: Function = this.get("getCredentials")?;
        let iter: Function = credentials_iter_fn.call((this.clone(),))?;
        let all = lua.create_table()?;

        // Call the iterator repeatedly until it returns nil
        loop {
            let cred_val: Value = iter.call(())?;
            let cred = match cred_val {
                Value::Table(t) => t,
                Value::Nil => break,
                _ => continue,
            };

            let host: Value = cred.get("host")?;
            let host_str = if let Value::Table(t) = host {
                t.get("ip").ok().flatten()
            } else if let Value::String(s) = host {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            };

            if let Some(h) = host_str {
                if !all.contains_key(h.clone())? {
                    all.set(h.clone(), lua.create_table()?)?;
                }
                let host_table: Table = all.get(h.clone())?;

                let port: u16 = cred.get("port")?;
                let service: String = cred
                    .get("service")
                    .ok()
                    .unwrap_or_else(|| String::from("unknown"));
                let svc_key = format!("{port}/{service}");

                if !host_table.contains_key(svc_key.clone())? {
                    host_table.set(svc_key.clone(), lua.create_table()?)?;
                }
                let svc_table: Table = host_table.get(svc_key.clone())?;

                // Create Account object
                let user: Option<String> = cred.get("user").ok().flatten();
                let pass: Option<String> = cred.get("pass").ok().flatten();
                let state: u32 = cred.get("state").ok().unwrap_or(0);

                let creds_table: Table = lua.globals().get("creds")?;
                let account_class: Table = creds_table.get("Account")?;
                let new_fn: Function = account_class.get(NEW)?;
                let account: Table = new_fn.call((user, pass, state))?;

                let len = svc_table.raw_len();
                svc_table.raw_set(len + 1, account)?;
            }
        }

        Ok(all)
    })?;
    credentials_table.set("getTable", get_table_fn)?;

    // Define the __tostring metamethod
    let tostring_fn = lua.create_function(|_lua, this: Table| {
        let get_table_fn: Function = this.get("getTable")?;
        let all: Value = get_table_fn.call((this.clone(),))?;

        match all {
            Value::Table(t) => {
                // Format the table as string
                let mut result = String::new();
                for host_pair in t.pairs::<String, Table>() {
                    let (_, host_table) = host_pair?;
                    for svc_pair in host_table.pairs::<String, Table>() {
                        let (_, svc_table) = svc_pair?;
                        for acc_pair in svc_table.pairs::<Value, Table>() {
                            let (_, account) = acc_pair?;
                            let account_str: String = account.to_string()?;
                            if !result.is_empty() {
                                result.push('\n');
                            }
                            result.push_str(&account_str);
                        }
                    }
                }
                Ok(result)
            }
            _ => Ok(String::new()),
        }
    })?;
    credentials_table.set(TOSTRING, tostring_fn)?;

    // Credentials:new(tags, host, port)
    let new_fn =
        lua.create_function(|lua, (tags, host, port): (Value, Table, Option<Table>)| {
            let credentials = lua.create_table()?;

            // Normalize tags to a table
            let tags_table = match tags {
                Value::Table(t) => t,
                Value::String(s) => {
                    let t = lua.create_table()?;
                    let s_str = s.to_str()?;
                    t.set(1, s_str)?;
                    t
                }
                _ => lua.create_table()?,
            };

            // Extract service from port if available
            let service: Option<String> =
                port.as_ref().and_then(|p| p.get("service").ok().flatten());

            // Extract port number if available
            let port_number: Option<u16> =
                port.as_ref().and_then(|p| p.get("number").ok().flatten());

            credentials.set("tags", tags_table.clone())?;
            credentials.set("host", host.clone())?;
            if let Some(ref p) = port {
                credentials.set("port", p.clone())?;
            }
            if let Some(ref s) = service {
                credentials.set("service", s.as_str())?;
            }
            if let Some(ref pn) = port_number {
                credentials.set("port_number", *pn)?;
            }

            // Get Credentials class from globals and set as metatable
            let creds_table: Table = lua.globals().get("creds")?;
            let credentials_class: Table = creds_table.get("Credentials")?;
            credentials.set_metatable(Some(credentials_class))?;

            // Store internal state
            credentials.set("_tags", tags_table)?;
            credentials.set("_host", host)?;
            credentials.set("_service", service)?;
            credentials.set("_port_number", port_number)?;

            Ok(credentials)
        })?;

    credentials_table.set(NEW, new_fn)?;

    Ok(credentials_table)
}

/// Check if any tag in tags matches any tag in `cred_tags`.
fn check_tags_match(_lua: &mlua::Lua, tags: &Table, cred_tags: &Table) -> Result<bool> {
    // Check if tags is ALL_DATA (empty table)
    let tags_len = tags.raw_len();
    if tags_len == 0 {
        return Ok(true);
    }

    // Check each tag in tags against each tag in cred_tags
    for pair in tags.pairs::<Value, Value>() {
        let (_, tag_value) = pair?;
        let tag_str = match tag_value {
            Value::String(s) => s.to_str()?.to_string(),
            _ => continue,
        };

        for cred_pair in cred_tags.pairs::<Value, Value>() {
            let (_, cred_tag_value) = cred_pair?;
            let cred_tag_str = match cred_tag_value {
                Value::String(s) => s.to_str()?.to_string(),
                _ => continue,
            };

            if tag_str == cred_tag_str {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_constants() {
        assert_eq!(state::LOCKED, 1);
        assert_eq!(state::VALID, 2);
        assert_eq!(state::DISABLED, 4);
        assert_eq!(state::CHANGEPW, 8);
        assert_eq!(state::PARAM, 16);
        assert_eq!(state::EXPIRED, 32);
        assert_eq!(state::TIME_RESTRICTED, 64);
        assert_eq!(state::HOST_RESTRICTED, 128);
        assert_eq!(state::LOCKED_VALID, 256);
        assert_eq!(state::DISABLED_VALID, 512);
        assert_eq!(state::HASHED, 1024);
    }

    #[test]
    fn test_state_msg() {
        assert_eq!(state_msg(state::LOCKED), "Account is locked");
        assert_eq!(state_msg(state::VALID), "Valid credentials");
        assert_eq!(state_msg(state::DISABLED), "Account is disabled");
        assert_eq!(
            state_msg(state::CHANGEPW),
            "Valid credentials, password must be changed at next logon"
        );
        assert_eq!(
            state_msg(state::PARAM),
            "Credentials passed to script during Nmap execution"
        );
        assert_eq!(
            state_msg(state::EXPIRED),
            "Valid credentials, account expired"
        );
        assert_eq!(
            state_msg(state::TIME_RESTRICTED),
            "Valid credentials, account cannot log in at current time"
        );
        assert_eq!(
            state_msg(state::HOST_RESTRICTED),
            "Valid credentials, account cannot log in from current host"
        );
        assert_eq!(
            state_msg(state::LOCKED_VALID),
            "Valid credentials, account locked"
        );
        assert_eq!(
            state_msg(state::DISABLED_VALID),
            "Valid credentials, account disabled"
        );
        assert_eq!(
            state_msg(state::HASHED),
            "Hashed valid or invalid credentials"
        );
        assert_eq!(state_msg(9999), "Unknown state");
    }
}
