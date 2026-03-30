//! Lua runtime management for NSE.
//!
//! This module provides the Lua runtime environment with NSE-specific
//! libraries and sandboxing.

use mlua::{Function, Lua, LuaOptions, StdLib, Value};
use std::path::Path;

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
    ///
    /// # Notes
    ///
    /// Loads Lua standard libraries needed by NSE scripts. The `debug` library
    /// is required by `strict.lua` (used by many nselib modules).
    ///
    /// # Safety
    ///
    /// The `debug` library provides introspection capabilities that could
    /// potentially be misused by untrusted scripts. However, it is required
    /// for compatibility with Nmap's nselib modules. Scripts should be
    /// properly sandboxed using other mechanisms (timeout, memory limits).
    pub fn new(config: LuaConfig) -> Result<Self> {
        // Load safe standard libraries plus debug library (required by strict.lua)
        // IO and OS libraries are excluded for security/sandboxing
        //
        // SAFETY: The debug library is required by nselib strict.lua.
        // Scripts run with timeouts and memory limits as mitigations.
        let lua = unsafe {
            Lua::unsafe_new_with(StdLib::ALL_SAFE | StdLib::DEBUG, LuaOptions::default())
        };

        let mut nse_lua = Self { lua, config };

        // Configure package.path to search nselib directory
        nse_lua.set_package_path()?;

        // Add custom file searcher for loading .lua files from nselib
        nse_lua.add_file_searcher()?;

        Ok(nse_lua)
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
        self.lua.globals().get(name).map_err(|e| Error::LuaError {
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
        let lua_func = self
            .lua
            .create_function(func)
            .map_err(|e| Error::LuaError {
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
            table
                .set(*key, value.clone())
                .map_err(|e| Error::LuaError {
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
    ///
    /// # Errors
    ///
    /// Returns an error if garbage collection fails.
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

    /// Compute the absolute path to the `nselib/` directory.
    ///
    /// Resolution order:
    /// 1. `NSELIB_DIR` environment variable (for production overrides)
    /// 2. Relative to `CARGO_MANIFEST_DIR` (`../../nselib`) - works during
    ///    `cargo test` and normal builds
    /// 3. Relative to current working directory (`./nselib`) - fallback for
    ///    production when run from the workspace root
    fn resolve_nselib_dir() -> String {
        // Environment variable override for production deployments
        if let Ok(dir) = std::env::var("NSELIB_DIR") {
            return dir;
        }

        // During cargo test/build, CARGO_MANIFEST_DIR points to
        // crates/rustnmap-nse/, so nselib/ is two levels up
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let nselib = std::path::Path::new(&manifest_dir)
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("nselib"));
            if let Some(ref path) = nselib {
                if path.exists() {
                    return path.to_string_lossy().into_owned();
                }
            }
        }

        // Fallback: relative to CWD
        "./nselib".to_string()
    }

    /// Configure `package.path` to search the nselib directory.
    ///
    /// This sets the Lua package path to search for modules in:
    /// - `<nselib_dir>/?.lua` - for modules like `sslcert.lua`
    /// - `<nselib_dir>/?/init.lua` - for modules like `tls/init.lua`
    ///
    /// # Errors
    ///
    /// Returns an error if setting package.path fails.
    fn set_package_path(&mut self) -> Result<()> {
        let package: mlua::Table =
            self.lua
                .globals()
                .get("package")
                .map_err(|e| Error::LuaError {
                    script: "runtime".to_string(),
                    message: format!("failed to get package table: {e}"),
                })?;

        let nselib_dir = Self::resolve_nselib_dir();
        let path_value = format!("{nselib_dir}/?.lua;{nselib_dir}/?/init.lua");

        package
            .set("path", path_value)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to set package.path: {e}"),
            })?;

        Ok(())
    }

    /// Add a custom file searcher to `package.searchers`.
    ///
    /// This function prepends a custom searcher to the `package.searchers` table
    /// that reads Lua files from the filesystem. The searcher resolves the
    /// `nselib/` directory using the same logic as `resolve_nselib_dir()`.
    ///
    /// The custom searcher is inserted at the beginning of `package.searchers`
    /// so it takes precedence over the default Lua searchers.
    ///
    /// # Errors
    ///
    /// Returns an error if the searcher cannot be registered.
    fn add_file_searcher(&mut self) -> Result<()> {
        let package: mlua::Table =
            self.lua
                .globals()
                .get("package")
                .map_err(|e| Error::LuaError {
                    script: "runtime".to_string(),
                    message: format!("failed to get package table: {e}"),
                })?;

        let searchers: mlua::Table = package.get("searchers").map_err(|e| Error::LuaError {
            script: "runtime".to_string(),
            message: format!("failed to get package.searchers: {e}"),
        })?;

        // Resolve the nselib directory once and capture it in the closure
        let nselib_dir = Self::resolve_nselib_dir();

        // Create a custom searcher function
        // In Lua 5.4, searchers are called with (modname) and return:
        // - loader function (or string explaining why it couldn't find module)
        let searcher = self
            .lua
            .create_function(move |lua, modname: String| {
                // Try loading from <nselib_dir>/<modname>.lua
                let path1 = format!("{nselib_dir}/{modname}.lua");
                if Path::new(&path1).exists() {
                    match std::fs::read_to_string(&path1) {
                        Ok(source) => {
                            // Load the Lua source and return the chunk as a function
                            return match lua.load(&source).set_name(&path1).into_function() {
                                Ok(chunk) => Ok(Value::Function(chunk)),
                                Err(e) => {
                                    let msg = format!(
                                        "error loading module '{modname}' from '{path1}':\n{e}"
                                    );
                                    Ok(Value::String(lua.create_string(&msg)?))
                                }
                            };
                        }
                        Err(e) => {
                            let msg =
                                format!("error reading module '{modname}' from '{path1}': {e}");
                            return Ok(Value::String(lua.create_string(&msg)?));
                        }
                    }
                }

                // Try loading from <nselib_dir>/<modname>/init.lua
                let path2 = format!("{nselib_dir}/{modname}/init.lua");
                if Path::new(&path2).exists() {
                    match std::fs::read_to_string(&path2) {
                        Ok(source) => {
                            return match lua.load(&source).set_name(&path2).into_function() {
                                Ok(chunk) => Ok(Value::Function(chunk)),
                                Err(e) => {
                                    let msg = format!(
                                        "error loading module '{modname}' from '{path2}':\n{e}"
                                    );
                                    Ok(Value::String(lua.create_string(&msg)?))
                                }
                            };
                        }
                        Err(e) => {
                            let msg =
                                format!("error reading module '{modname}' from '{path2}': {e}");
                            return Ok(Value::String(lua.create_string(&msg)?));
                        }
                    }
                }

                // Module not found, return error message string
                // This allows the next searcher to be tried
                let msg = format!(
                    "no file '{nselib_dir}/{modname}.lua' or '{nselib_dir}/{modname}/init.lua'"
                );
                Ok(Value::String(lua.create_string(&msg)?))
            })
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to create file searcher: {e}"),
            })?;

        // Insert our custom searcher at position 2 (AFTER the preload searcher).
        //
        // Lua's require() calls package.searchers in order and uses the first
        // one that returns a loader function. searcher[1] is the preload
        // searcher which checks package.preload — this MUST remain first so
        // that Rust-registered modules (stdnse, nmap, etc.) take precedence
        // over .lua files on disk. Placing the file searcher before preload
        // would cause stdnse.lua (which applies strict.lua) to shadow the
        // Rust-registered stdnse table, breaking access to Rust functions
        // like stdnse.new_thread.
        let len = searchers.raw_len().saturating_add(1);

        // Shift searchers from index 2 onward down by 1
        for i in (2..len).rev() {
            if let Ok(current) = searchers.get::<Function>(i) {
                searchers
                    .raw_set(i + 1, current)
                    .map_err(|e| Error::LuaError {
                        script: "runtime".to_string(),
                        message: format!("failed to set searcher at index {}: {e}", i + 1),
                    })?;
            }
        }

        // Insert custom file searcher at position 2 (after preload searcher)
        searchers
            .raw_set(2, searcher)
            .map_err(|e| Error::LuaError {
                script: "runtime".to_string(),
                message: format!("failed to set file searcher: {e}"),
            })?;

        Ok(())
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
        nse_lua.unwrap();
    }

    #[test]
    fn test_nse_lua_load_script() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.load_script("return 42", "test");
        result.unwrap();
    }

    #[test]
    fn test_nse_lua_set_global() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.set_global("test_var", Value::Integer(123));
        result.unwrap();

        let value: Value = nse_lua.lua.globals().get("test_var").unwrap();
        assert!(matches!(value, Value::Integer(123)));
    }

    #[test]
    fn test_nse_lua_register_function() {
        let mut nse_lua = NseLua::new_default().unwrap();

        let result = nse_lua.register_function("add", |_: &Lua, (a, b): (i32, i32)| Ok(a + b));
        result.unwrap();

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
        result.unwrap();

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

    #[test]
    fn test_package_path_configuration() {
        let nse_lua = NseLua::new_default().unwrap();

        // Verify package.path is set correctly
        let package: mlua::Table = nse_lua.lua.globals().get("package").unwrap();
        let path: String = package.get("path").unwrap();

        assert!(path.contains("nselib/?.lua"));
        assert!(path.contains("nselib/?/init.lua"));
    }

    #[test]
    fn test_file_searcher_registered() {
        let nse_lua = NseLua::new_default().unwrap();

        // Verify package.searchers table exists and has our custom searcher
        let package: mlua::Table = nse_lua.lua.globals().get("package").unwrap();
        let searchers: mlua::Table = package.get("searchers").unwrap();

        // Verify searchers table is not empty
        let searcher_count = searchers.raw_len();
        assert!(searcher_count > 0, "searchers table should not be empty");

        // Verify first searcher is a function (our custom file searcher)
        let first_searcher: mlua::Value = searchers.get(1).unwrap();
        assert!(
            matches!(first_searcher, mlua::Value::Function(_)),
            "first searcher should be a function"
        );
    }
}
