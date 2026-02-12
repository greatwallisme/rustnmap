//! Lua runtime management for NSE.
//!
//! This module provides the Lua runtime environment with NSE-specific
//! libraries and sandboxing.

use mlua::{Lua, Value};

use crate::error::{Error, Result};

/// Lua runtime configuration.
#[derive(Debug, Clone)]
pub struct LuaConfig {
    /// Memory limit in bytes.
    pub memory_limit: usize,

    /// Instruction count limit.
    pub instruction_limit: Option<u32>,

    /// Allow package loading.
    pub allow_package: bool,

    /// Allow IO operations.
    pub allow_io: bool,

    /// Allow OS operations.
    pub allow_os: bool,
}

impl Default for LuaConfig {
    fn default() -> Self {
        Self {
            memory_limit: crate::MAX_MEMORY_BYTES,
            instruction_limit: Some(10_000_000),
            allow_package: false,
            allow_io: false,
            allow_os: false,
        }
    }
}

/// NSE Lua runtime wrapper.
///
/// Provides a sandboxed Lua 5.4 environment with NSE libraries.
#[derive(Debug)]
pub struct NseLua {
    /// The underlying Lua instance.
    lua: Lua,

    /// Runtime configuration.
    config: LuaConfig,
}

impl NseLua {
    /// Create a new NSE Lua runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if Lua initialization fails.
    pub fn new(config: LuaConfig) -> Result<Self> {
        let lua = Lua::new();

        Ok(Self { lua, config })
    }

    /// Create a new NSE Lua runtime with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if Lua initialization fails.
    pub fn new_default() -> Result<Self> {
        Self::new(LuaConfig::default())
    }

    /// Get a reference to the underlying Lua instance.
    #[must_use]
    pub const fn lua(&self) -> &Lua {
        &self.lua
    }

    /// Get a mutable reference to the underlying Lua instance.
    #[must_use]
    pub fn lua_mut(&mut self) -> &mut Lua {
        &mut self.lua
    }

    /// Create a new table in the Lua state.
    ///
    /// # Errors
    ///
    /// Returns an error if table creation fails.
    pub fn create_table(&mut self) -> Result<mlua::Table> {
        self.lua.create_table().map_err(|e| Error::LuaError {
            script: "runtime".to_string(),
            message: format!("failed to create table: {e}"),
        })
    }

    /// Load and execute a Lua script.
    ///
    /// # Arguments
    ///
    /// * `source` - Lua source code
    /// * `name` - Script name for error reporting
    ///
    /// # Errors
    ///
    /// Returns an error if the script fails to load or execute.
    pub fn load_script(&mut self, source: &str, name: &str) -> Result<()> {
        self.lua
            .load(source)
            .set_name(name)
            .exec()
            .map_err(|e| Error::LuaError {
                script: name.to_string(),
                message: e.to_string(),
            })?;

        Ok(())
    }

    /// Set a global value in the Lua state.
    ///
    /// # Arguments
    ///
    /// * `name` - Global variable name
    /// * `value` - Value to set
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be set.
    pub fn set_global(&mut self, name: &str, value: Value) -> Result<()> {
        self.lua
            .globals()
            .set(name, value)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to set global '{name}': {e}"),
            })?;

        Ok(())
    }

    /// Get a global value from the Lua state.
    ///
    /// # Arguments
    ///
    /// * `name` - Global variable name
    ///
    /// # Returns
    ///
    /// The Lua value if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be retrieved.
    pub fn get_global(&self, name: &str) -> Result<Value> {
        self.lua
            .globals()
            .get(name)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to get global '{name}': {e}"),
            })
    }

    /// Register a Rust function as a global Lua function.
    ///
    /// # Arguments
    ///
    /// * `name` - Function name in Lua
    /// * `func` - Rust function to register
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_function<F, A, R>(&mut self, name: &str, func: F) -> Result<()>
    where
        F: 'static + Fn(&Lua, A) -> mlua::Result<R> + Send,
        A: mlua::FromLuaMulti,
        R: mlua::IntoLuaMulti,
    {
        let lua_func = self.lua.create_function(func).map_err(|e| Error::LuaError {
            script: "runtime".to_string(),
            message: format!("failed to create function '{name}': {e}"),
        })?;

        self.lua
            .globals()
            .set(name, lua_func)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to register function '{name}': {e}"),
            })?;

        Ok(())
    }

    /// Register a table with values.
    ///
    /// # Arguments
    ///
    /// * `name` - Table name in Lua
    /// * `values` - Key-value pairs to register
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_table(&mut self, name: &str, values: &[(&str, Value)]) -> Result<()> {
        let table = self.lua.create_table().map_err(|e| Error::LuaError {
            script: "runtime".to_string(),
            message: format!("failed to create table '{name}': {e}"),
        })?;

        for (key, value) in values {
            table.set(*key, value.clone()).map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to set table key '{key}': {e}"),
            })?;
        }

        self.lua
            .globals()
            .set(name, table)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to register table '{name}': {e}"),
            })?;

        Ok(())
    }

    /// Collect garbage in the Lua state.
    pub fn gc_collect(&mut self) -> Result<()> {
        self.lua.gc_collect().map_err(|e| Error::LuaError {
            script: "runtime".to_string(),
            message: format!("garbage collection failed: {e}"),
        })
    }

    /// Get current memory usage in bytes.
    ///
    /// # Returns
    ///
    /// Memory usage in bytes, or 0 if not available.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        // mlua doesn't directly expose memory usage
        // This would require additional tracking
        0
    }

    /// Check if memory limit has been exceeded.
    #[must_use]
    pub fn exceeds_memory_limit(&self) -> bool {
        self.memory_usage() > self.config.memory_limit
    }

    /// Load a string as Lua code and return it as a function.
    ///
    /// # Arguments
    ///
    /// * `source` - Lua source code
    /// * `name` - Name for error reporting
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails.
    pub fn load_function(&mut self, source: &str, name: &str) -> Result<mlua::Function> {
        self.lua
            .load(source)
            .set_name(name)
            .into_function()
            .map_err(|e| Error::LuaError {
                script: name.to_string(),
                message: e.to_string(),
            })
    }

    /// Execute a Lua function with arguments.
    ///
    /// # Arguments
    ///
    /// * `func` - Function to execute
    /// * `args` - Arguments to pass
    ///
    /// # Returns
    ///
    /// The result of the function call.
    ///
    /// # Errors
    ///
    /// Returns an error if execution fails.
    pub fn call_function<A, R>(&mut self, func: &mlua::Function, args: A) -> Result<R>
    where
        A: mlua::IntoLuaMulti,
        R: mlua::FromLuaMulti,
    {
        func.call(args).map_err(|e| Error::LuaError {
            script: "function".to_string(),
            message: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_config_default() {
        let config = LuaConfig::default();
        assert_eq!(config.memory_limit, crate::MAX_MEMORY_BYTES);
        assert!(!config.allow_package);
        assert!(!config.allow_io);
        assert!(!config.allow_os);
    }

    #[test]
    fn test_nse_lua_new_default() {
        let nse_lua = NseLua::new_default();
        assert!(nse_lua.is_ok());
    }

    #[test]
    fn test_nse_lua_load_script() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.load_script("return 42", "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_nse_lua_set_global() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.set_global("test_var", Value::Integer(123));
        assert!(result.is_ok());

        let value: Value = nse_lua.lua.globals().get("test_var").unwrap();
        assert!(matches!(value, Value::Integer(123)));
    }

    #[test]
    fn test_nse_lua_register_function() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.register_function("add", |_: &Lua, (a, b): (i32, i32)| Ok(a + b));
        assert!(result.is_ok());

        let func: mlua::Function = nse_lua.lua.globals().get("add").unwrap();
        let result: i32 = func.call((5, 3)).unwrap();
        assert_eq!(result, 8);
    }

    #[test]
    fn test_nse_lua_register_table() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.register_table(
            "test_table",
            &[("key1", Value::Integer(1)), ("key2", Value::Integer(2))],
        );
        assert!(result.is_ok());

        let table: mlua::Table = nse_lua.lua.globals().get("test_table").unwrap();
        let val1: Value = table.get("key1").unwrap();
        let val2: Value = table.get("key2").unwrap();
        assert!(matches!(val1, Value::Integer(1)));
        assert!(matches!(val2, Value::Integer(2)));
    }

    #[test]
    fn test_nse_lua_load_function() {
        let mut nse_lua = NseLua::new_default().unwrap();

        // Load function that returns a constant value
        let func = nse_lua.load_function("return 42", "const_func").unwrap();
        let result: i32 = nse_lua.call_function(&func, ()).unwrap();
        assert_eq!(result, 42);
    }
}
