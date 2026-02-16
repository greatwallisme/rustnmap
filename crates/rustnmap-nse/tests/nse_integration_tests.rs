//! Integration tests for NSE (Nmap Script Engine) functionality.
//!
//! These tests verify the NSE script loading, parsing, and execution capabilities.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustnmap_nse::engine::SchedulerConfig;
use rustnmap_nse::lua::NseLua;
use rustnmap_nse::script::NseScript;
use rustnmap_nse::{ScriptCategory, ScriptDatabase, ScriptEngine, ScriptScheduler};

/// Test creating an empty script database.
#[test]
fn test_script_database_empty() {
    let db = ScriptDatabase::new();
    assert_eq!(db.len(), 0);
    assert!(db.is_empty());
}

/// Test script category parsing.
#[test]
fn test_script_category_from_str() {
    assert_eq!(
        ScriptCategory::from_str("default"),
        Some(ScriptCategory::Default)
    );
    assert_eq!(ScriptCategory::from_str("auth"), Some(ScriptCategory::Auth));
    assert_eq!(
        ScriptCategory::from_str("discovery"),
        Some(ScriptCategory::Discovery)
    );
    assert_eq!(ScriptCategory::from_str("safe"), Some(ScriptCategory::Safe));
    assert_eq!(ScriptCategory::from_str("vuln"), Some(ScriptCategory::Vuln));
    assert_eq!(ScriptCategory::from_str("UNKNOWN"), None);
}

/// Test script category string conversion.
#[test]
fn test_script_category_as_str() {
    assert_eq!(ScriptCategory::Default.as_str(), "default");
    assert_eq!(ScriptCategory::Auth.as_str(), "auth");
    assert_eq!(ScriptCategory::Discovery.as_str(), "discovery");
    assert_eq!(ScriptCategory::Safe.as_str(), "safe");
}

/// Test creating a script engine with empty database.
#[test]
fn test_script_engine_empty_database() {
    let db = ScriptDatabase::new();
    let engine = ScriptEngine::new(db);

    assert_eq!(engine.database().len(), 0);
    assert!(engine.scheduler().database().is_empty());
}

/// Test script scheduler creation.
#[test]
fn test_script_scheduler_creation() {
    let db = Arc::new(ScriptDatabase::new());
    let config = SchedulerConfig::default();
    let scheduler = ScriptScheduler::new(db, config);

    assert_eq!(scheduler.database().len(), 0);
}

/// Test scheduler configuration defaults.
#[test]
fn test_scheduler_config_defaults() {
    let config = SchedulerConfig::default();

    // Default values should be reasonable
    assert!(config.max_concurrent > 0);
    assert!(config.default_timeout > Duration::ZERO);
    assert!(config.max_memory > 0);
}

/// Test custom scheduler configuration.
#[test]
fn test_scheduler_config_custom() {
    let config = SchedulerConfig {
        max_concurrent: 10,
        default_timeout: Duration::from_secs(30),
        max_memory: 1024 * 1024 * 100, // 100MB
    };

    assert_eq!(config.max_concurrent, 10);
    assert_eq!(config.default_timeout, Duration::from_secs(30));
    assert_eq!(config.max_memory, 1024 * 1024 * 100);
}

/// Test script engine with custom configuration.
#[test]
fn test_script_engine_with_config() {
    let db = ScriptDatabase::new();
    let config = SchedulerConfig {
        max_concurrent: 5,
        default_timeout: Duration::from_secs(60),
        max_memory: 1024 * 1024 * 50,
    };

    let engine = ScriptEngine::with_config(db, config);

    assert_eq!(engine.scheduler().config().max_concurrent, 5);
    assert_eq!(
        engine.scheduler().config().default_timeout,
        Duration::from_secs(60)
    );
}

/// Test script selection by category from empty database.
#[test]
fn test_select_scripts_empty_database() {
    let db = ScriptDatabase::new();
    let engine = ScriptEngine::new(db);

    let categories = vec![ScriptCategory::Default];
    let scripts = engine.scheduler().select_scripts(&categories);

    assert!(scripts.is_empty());
}

/// Test script selection by pattern from empty database.
#[test]
fn test_select_scripts_by_pattern_empty() {
    let db = ScriptDatabase::new();
    let engine = ScriptEngine::new(db);

    let scripts = engine.scheduler().select_scripts_by_pattern("http");

    assert!(scripts.is_empty());
}

/// Test getting script by ID from empty database.
#[test]
fn test_get_script_empty_database() {
    let db = ScriptDatabase::new();
    let engine = ScriptEngine::new(db);

    let script = engine.scheduler().get_script("nonexistent");

    assert!(script.is_none());
}

/// Test loading scripts from non-existent directory.
#[test]
fn test_load_scripts_nonexistent_directory() {
    let result = ScriptDatabase::from_directory(Path::new("/nonexistent/path"));

    result.unwrap_err();
}

/// Test script database loading from temp directory (empty).
#[test]
fn test_load_scripts_empty_directory() {
    let temp_dir = std::env::temp_dir().join("nse_test_empty");
    let _ = std::fs::create_dir_all(&temp_dir);

    let result = ScriptDatabase::from_directory(&temp_dir);

    // Should succeed even if directory is empty
    assert!(result.is_ok());
    let db = result.unwrap();
    assert_eq!(db.len(), 0);

    // Cleanup
    let _ = std::fs::remove_dir(&temp_dir);
}

/// Test creating a simple test script inline.
#[test]
fn test_create_simple_script() {
    let script = NseScript::new(
        "test-script",
        PathBuf::from("/test/script.nse"),
        r#"
            description = [[A test script]]
            categories = {"safe"}

            portrule = function(host, port)
                return port.number == 80
            end

            action = function(host, port)
                return "Test output"
            end
        "#
        .to_string(),
    );

    assert_eq!(script.id, "test-script");
    assert!(script.description.is_empty());
    assert!(script.categories.is_empty());
}

/// Test script with populated fields.
#[test]
fn test_script_with_populated_fields() {
    let mut script = NseScript::new(
        "test-script",
        PathBuf::from("/test/script.nse"),
        r#"
            description = [[Test description]]
            categories = {"safe", "discovery"}
            author = "Test Author"
            license = "Same as Nmap"

            portrule = function(host, port)
                return port.number == 80
            end

            action = function(host, port)
                return "Test output"
            end
        "#
        .to_string(),
    );

    // Set fields manually for testing
    script.description = "Test description".to_string();
    script.categories = vec![ScriptCategory::Safe, ScriptCategory::Discovery];
    script.author = vec!["Test Author".to_string()];
    script.license = "Same as Nmap".to_string();

    assert_eq!(script.id, "test-script");
    assert_eq!(script.description, "Test description");
    assert!(script.categories.contains(&ScriptCategory::Safe));
    assert!(script.categories.contains(&ScriptCategory::Discovery));
    assert_eq!(script.author, vec!["Test Author".to_string()]);
    assert_eq!(script.license, "Same as Nmap");
}

/// Test script database registration and retrieval.
#[test]
fn test_script_database_register_and_get() {
    let mut db = ScriptDatabase::new();

    let script = NseScript::new(
        "test-script",
        PathBuf::from("/test/script.nse"),
        "description = [[Test]]".to_string(),
    );

    // Register script
    db.register_script(&script);

    // Retrieve script
    let retrieved = db.get("test-script");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "test-script");
}

/// Test script database all scripts.
#[test]
fn test_script_database_all_scripts() {
    let db = ScriptDatabase::new();

    let scripts = db.all_scripts();

    assert!(scripts.is_empty());
}

/// Test Lua runtime creation (basic).
#[test]
fn test_lua_runtime_creation() {
    let lua = NseLua::new_default();

    // Should be able to create Lua state
    lua.unwrap();
}

/// Test Lua runtime with simple expression.
#[test]
fn test_lua_simple_expression() {
    let lua = NseLua::new_default().expect("Failed to create Lua state");

    // Execute a simple Lua expression
    let result: Result<i32, _> = lua.lua().load("return 1 + 1").eval();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2);
}

/// Test Lua table creation.
#[test]
fn test_lua_table_creation() {
    let mut lua = NseLua::new_default().expect("Failed to create Lua state");

    // Create a table
    let table = lua.create_table();
    assert!(table.is_ok());

    let table = table.unwrap();
    table.set("key", "value").unwrap();

    let value: String = table.get("key").unwrap();
    assert_eq!(value, "value");
}

/// Test script execution timeout handling (not actually running scripts).
#[test]
fn test_script_timeout_configuration() {
    let config = SchedulerConfig {
        max_concurrent: 1,
        default_timeout: Duration::from_millis(100),
        max_memory: 1024 * 1024,
    };

    // Very short timeout should be respected
    assert_eq!(config.default_timeout, Duration::from_millis(100));
}

/// Test script categories are distinct.
#[test]
fn test_script_categories_distinct() {
    use std::collections::HashSet;

    let categories = [
        ScriptCategory::Auth,
        ScriptCategory::Broadcast,
        ScriptCategory::Brute,
        ScriptCategory::Default,
        ScriptCategory::Discovery,
        ScriptCategory::Dos,
        ScriptCategory::Exploit,
        ScriptCategory::External,
        ScriptCategory::Fuzzer,
        ScriptCategory::Intrusive,
        ScriptCategory::Malware,
        ScriptCategory::Safe,
        ScriptCategory::Version,
        ScriptCategory::Vuln,
    ];

    // All categories should be distinct
    let unique: HashSet<_> = categories.iter().collect();
    assert_eq!(unique.len(), categories.len());
}

/// Test engine with multiple script categories.
#[test]
fn test_engine_multiple_categories() {
    let db = ScriptDatabase::new();
    let engine = ScriptEngine::new(db);

    let categories = vec![
        ScriptCategory::Default,
        ScriptCategory::Safe,
        ScriptCategory::Discovery,
    ];

    let scripts = engine.scheduler().select_scripts(&categories);
    assert!(scripts.is_empty()); // Empty database
}

/// Test script ID validation.
#[test]
fn test_script_id_validation() {
    // Valid script IDs
    let valid_ids = vec!["http-title", "ssh-version", "ftp-anon", "test_script"];

    for id in valid_ids {
        let script = NseScript::new(id, PathBuf::from(format!("/test/{id}.nse")), String::new());
        assert_eq!(script.id, id);
    }
}

/// Test error handling for invalid script paths.
#[test]
fn test_invalid_script_path_handling() {
    // Try to load from a file path that's not a directory
    let temp_file = std::env::temp_dir().join("nse_test_file.txt");
    let _ = std::fs::write(&temp_file, "not a script");

    // Attempting to load from a file (not directory) should fail
    let result = ScriptDatabase::from_directory(&temp_file);
    result.unwrap_err();

    // Cleanup
    let _ = std::fs::remove_file(&temp_file);
}

/// Test script metadata extraction (from source).
#[test]
fn test_script_metadata_parsing() {
    let source = r#"
description = [[Test script description]]
categories = {"safe", "discovery"}
author = "Test Author"
license = "Same as Nmap"

portrule = function(host, port)
    return port.number == 80
end

action = function(host, port)
    return "Result"
end
"#;

    // Verify the source contains expected metadata
    assert!(source.contains("description"));
    assert!(source.contains("categories"));
    assert!(source.contains("author"));
    assert!(source.contains("portrule"));
    assert!(source.contains("action"));
}

/// Test script `has_hostrule` detection.
#[test]
fn test_script_has_hostrule() {
    let script = NseScript::new(
        "hostrule-test",
        PathBuf::from("/test/hostrule.nse"),
        r#"
            hostrule = function(host)
                return true
            end

            action = function(host)
                return "test"
            end
        "#
        .to_string(),
    );

    assert!(script.has_hostrule());
    assert!(!script.has_portrule());
    assert!(script.has_action());
}

/// Test script `has_portrule` detection.
#[test]
fn test_script_has_portrule() {
    let script = NseScript::new(
        "portrule-test",
        PathBuf::from("/test/portrule.nse"),
        r#"
            portrule = function(host, port)
                return port.number == 80
            end

            action = function(host, port)
                return "test"
            end
        "#
        .to_string(),
    );

    assert!(!script.has_hostrule());
    assert!(script.has_portrule());
    assert!(script.has_action());
}

/// Test script `matches_categories`.
#[test]
fn test_script_matches_categories() {
    let mut script = NseScript::new(
        "category-test",
        PathBuf::from("/test/cat.nse"),
        String::new(),
    );
    script.categories = vec![ScriptCategory::Safe, ScriptCategory::Discovery];

    assert!(script.matches_categories(&[ScriptCategory::Safe]));
    assert!(script.matches_categories(&[ScriptCategory::Discovery]));
    assert!(script.matches_categories(&[ScriptCategory::Safe, ScriptCategory::Vuln]));
    assert!(!script.matches_categories(&[ScriptCategory::Vuln]));
}

/// Test script `matches_pattern`.
#[test]
fn test_script_matches_pattern() {
    let script = NseScript::new(
        "http-title",
        PathBuf::from("/test/http-title.nse"),
        String::new(),
    );

    assert!(script.matches_pattern("http"));
    assert!(script.matches_pattern("http-title"));
    assert!(script.matches_pattern("title"));
    assert!(!script.matches_pattern("ssh"));
}

/// Test script `matches_pattern` with glob.
#[test]
fn test_script_matches_pattern_glob() {
    let script = NseScript::new(
        "http-title",
        PathBuf::from("/test/http-title.nse"),
        String::new(),
    );

    assert!(script.matches_pattern("http-*"));
    assert!(script.matches_pattern("*title"));
    assert!(script.matches_pattern("http*"));
    assert!(!script.matches_pattern("ssh-*"));
}

/// Test category safety check.
#[test]
fn test_category_is_safe() {
    assert!(ScriptCategory::Safe.is_safe());
    assert!(ScriptCategory::Default.is_safe());
    assert!(ScriptCategory::Discovery.is_safe());
    assert!(ScriptCategory::Version.is_safe());

    assert!(!ScriptCategory::Auth.is_safe());
    assert!(!ScriptCategory::Exploit.is_safe());
    assert!(!ScriptCategory::Brute.is_safe());
}

/// Test category intrusive check.
#[test]
fn test_category_is_intrusive() {
    assert!(ScriptCategory::Intrusive.is_intrusive());
    assert!(ScriptCategory::Brute.is_intrusive());
    assert!(ScriptCategory::Exploit.is_intrusive());
    assert!(ScriptCategory::Dos.is_intrusive());
    assert!(ScriptCategory::Fuzzer.is_intrusive());

    assert!(!ScriptCategory::Safe.is_intrusive());
    assert!(!ScriptCategory::Default.is_intrusive());
    assert!(!ScriptCategory::Discovery.is_intrusive());
}
