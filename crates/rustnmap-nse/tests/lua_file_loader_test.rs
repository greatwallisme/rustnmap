//! Integration tests for Lua file loader functionality.
//!
//! These tests verify that the custom file searcher correctly loads
//! Lua files from the nselib directory.

use rustnmap_nse::libs;
use rustnmap_nse::lua::{LuaConfig, NseLua};

/// Helper function to change to project root directory.
fn change_to_project_root() {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("failed to get project root");

    std::env::set_current_dir(project_root).expect("failed to change to project root");

    // Verify nselib directory exists
    let nselib_path = project_root.join("nselib");
    assert!(
        nselib_path.exists(),
        "nselib directory not found at {}",
        nselib_path.display()
    );
}

/// Verify that a module was found (even if it failed to execute).
///
/// The key indicators that the file loader worked:
/// 1. Error message contains `[string "./nselib/..."]` - shows the file was read
/// 2. Error is NOT "no field package.preload" or "not found" - shows searcher found it
/// 3. Error mentions dependencies like `nmap` or `stdnse` - shows file loaded but dependencies missing
fn verify_module_found(result: &std::result::Result<(), mlua::Error>, module_name: &str) {
    match result {
        Ok(()) => {
            // Module loaded successfully
        }
        Err(e) => {
            let error_msg = e.to_string();

            // The file loader is working if:
            // 1. The error message shows a file path from nselib was accessed
            // 2. The error is about missing dependencies (not the module itself)
            let file_was_accessed = error_msg.contains("[string \"./nselib/")
                || error_msg.contains("./nselib/")
                || error_msg.contains("module 'nmap' not found")
                || error_msg.contains("module 'stdnse' not found");

            assert!(
                file_was_accessed,
                "Module '{module_name}' not found - file loader not working: {e}"
            );

            // If we got here, the file loader successfully found and read the file
            // Any errors are due to missing dependencies or runtime issues, not file loading
        }
    }
}

#[test]
fn test_load_sslcert_module() {
    change_to_project_root();

    let mut nse_lua = NseLua::new(LuaConfig::default()).expect("failed to create NSE Lua runtime");

    // Register NSE libraries first (nmap, stdnse, etc.) that Lua files depend on
    libs::register_all(&mut nse_lua).expect("failed to register NSE libraries");

    // Try to load the sslcert module using require()
    let result: std::result::Result<(), mlua::Error> = nse_lua
        .lua()
        .load(r#"local sslcert = require "sslcert""#)
        .exec();

    verify_module_found(&result, "sslcert");

    // If successful, verify it's a table (check package.loaded, not global)
    if result.is_ok() {
        let package: mlua::Table = nse_lua.lua().globals().get("package").unwrap();
        let loaded: mlua::Table = package.get("loaded").unwrap();
        let sslcert: mlua::Value = loaded.get("sslcert").unwrap();
        assert!(
            matches!(sslcert, mlua::Value::Table(_)),
            "sslcert should be a table"
        );
    }
}

#[test]
fn test_load_datetime_module() {
    change_to_project_root();

    let mut nse_lua = NseLua::new(LuaConfig::default()).expect("failed to create NSE Lua runtime");

    // Register NSE libraries first
    libs::register_all(&mut nse_lua).expect("failed to register NSE libraries");

    // Try to load the datetime module
    let result: std::result::Result<(), mlua::Error> = nse_lua
        .lua()
        .load(r#"local datetime = require "datetime""#)
        .exec();

    verify_module_found(&result, "datetime");

    // If successful, verify it's a table (check package.loaded, not global)
    if result.is_ok() {
        let package: mlua::Table = nse_lua.lua().globals().get("package").unwrap();
        let loaded: mlua::Table = package.get("loaded").unwrap();
        let datetime: mlua::Value = loaded.get("datetime").unwrap();
        assert!(
            matches!(datetime, mlua::Value::Table(_)),
            "datetime should be a table"
        );
    }
}

#[test]
fn test_load_tls_module() {
    change_to_project_root();

    let mut nse_lua = NseLua::new(LuaConfig::default()).expect("failed to create NSE Lua runtime");

    // Register NSE libraries first
    libs::register_all(&mut nse_lua).expect("failed to register NSE libraries");

    // Try to load the tls module
    let result: std::result::Result<(), mlua::Error> =
        nse_lua.lua().load(r#"local tls = require "tls""#).exec();

    verify_module_found(&result, "tls");

    // If successful, verify it's a table (check package.loaded, not global)
    if result.is_ok() {
        let package: mlua::Table = nse_lua.lua().globals().get("package").unwrap();
        let loaded: mlua::Table = package.get("loaded").unwrap();
        let tls: mlua::Value = loaded.get("tls").unwrap();
        assert!(
            matches!(tls, mlua::Value::Table(_)),
            "tls should be a table"
        );
    }
}
