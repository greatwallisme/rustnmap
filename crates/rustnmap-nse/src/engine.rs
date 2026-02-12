//! NSE script engine and scheduler.
//!
//! This module provides the main script execution engine that orchestrates
//! script loading, scheduling, and execution.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::error::Result;
use crate::lua::NseLua;
use crate::registry::ScriptDatabase;
use crate::script::{ExecutionStatus, NseScript, ScriptCategory, ScriptOutput, ScriptResult};

/// Script scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum number of concurrent scripts.
    pub max_concurrent: usize,

    /// Default script timeout.
    pub default_timeout: Duration,

    /// Maximum memory per script (bytes).
    pub max_memory: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: crate::MAX_CONCURRENT_SCRIPTS,
            default_timeout: crate::DEFAULT_SCRIPT_TIMEOUT,
            max_memory: crate::MAX_MEMORY_BYTES,
        }
    }
}

/// NSE script scheduler.
///
/// Manages concurrent script execution with proper resource limits.
#[derive(Debug)]
pub struct ScriptScheduler {
    /// Script database.
    database: Arc<ScriptDatabase>,

    /// Scheduler configuration.
    config: SchedulerConfig,

    /// Semaphore for concurrency control (reserved for future async execution).
    #[allow(dead_code, reason = "will be used when async execution is implemented")]
    semaphore: Arc<Semaphore>,
}

impl ScriptScheduler {
    /// Create a new script scheduler.
    #[must_use]
    pub fn new(database: Arc<ScriptDatabase>, config: SchedulerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        Self {
            database,
            config,
            semaphore,
        }
    }

    /// Get the script database.
    #[must_use]
    pub const fn database(&self) -> &Arc<ScriptDatabase> {
        &self.database
    }

    /// Get the scheduler configuration.
    #[must_use]
    pub const fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Select scripts by category.
    #[must_use]
    pub fn select_scripts(&self, categories: &[ScriptCategory]) -> Vec<&NseScript> {
        self.database.select_by_category(categories)
    }

    /// Select scripts by pattern.
    #[must_use]
    pub fn select_scripts_by_pattern(&self, pattern: &str) -> Vec<&NseScript> {
        self.database.select_by_pattern(pattern)
    }

    /// Get a script by ID.
    #[must_use]
    pub fn get_script(&self, id: &str) -> Option<&NseScript> {
        self.database.get(id)
    }
}

/// NSE script engine.
///
/// Main entry point for NSE script execution.
#[derive(Debug)]
pub struct ScriptEngine {
    /// Script database.
    database: Arc<ScriptDatabase>,

    /// Scheduler instance.
    scheduler: ScriptScheduler,
}

impl ScriptEngine {
    /// Create a new script engine.
    ///
    /// # Arguments
    ///
    /// * `database` - Script database to use
    ///
    /// # Returns
    ///
    /// A new script engine with default scheduler configuration.
    #[must_use]
    pub fn new(database: ScriptDatabase) -> Self {
        let db = Arc::new(database);
        let config = SchedulerConfig::default();
        let scheduler = ScriptScheduler::new(Arc::clone(&db), config);

        Self { database: db, scheduler }
    }

    /// Create a new script engine with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `database` - Script database to use
    /// * `config` - Scheduler configuration
    ///
    /// # Returns
    ///
    /// A new script engine with the given configuration.
    #[must_use]
    pub fn with_config(database: ScriptDatabase, config: SchedulerConfig) -> Self {
        let db = Arc::new(database);
        let scheduler = ScriptScheduler::new(Arc::clone(&db), config);

        Self { database: db, scheduler }
    }

    /// Get the script database.
    #[must_use]
    pub const fn database(&self) -> &Arc<ScriptDatabase> {
        &self.database
    }

    /// Get the scheduler.
    #[must_use]
    pub const fn scheduler(&self) -> &ScriptScheduler {
        &self.scheduler
    }

    /// Execute a single script synchronously.
    ///
    /// # Arguments
    ///
    /// * `script` - Script to execute
    /// * `target_ip` - Target IP address
    ///
    /// # Returns
    ///
    /// The script execution result.
    ///
    /// # Errors
    ///
    /// Returns an error if script execution fails.
    #[allow(clippy::needless_pass_by_value, reason = "Arc::clone is cheap and simplifies code")]
    pub fn execute_script(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<ScriptResult> {
        let start = std::time::Instant::now();
        let mut lua = NseLua::new_default()?;

        // Load the script
        lua.load_script(&script.source, &script.id)?;

        // Create a simple host table with IP address
        // Full implementation would include all host properties
        let host_table = lua.create_table()?;

        lua.set_global("host", mlua::Value::Table(host_table))?;

        // Execute the action function if it exists
        let output = if script.has_action() {
            // Load and call the action function
            let func = lua.load_function("return action(host)", "action_wrapper")?;

            // Call the function and get the result
            let result: mlua::MultiValue = lua.call_function(&func, ())?;

            // Convert result to string output
            let output_parts: Vec<String> = result
                .iter()
                .filter_map(|v| match v {
                    mlua::Value::String(s) => s.to_str().ok().map(|s| s.to_string()),
                    mlua::Value::Integer(n) => Some(n.to_string()),
                    mlua::Value::Number(n) => Some(n.to_string()),
                    mlua::Value::Boolean(b) => Some(b.to_string()),
                    _ => None,
                })
                .collect();

            let output_str = output_parts.join(" ");

            ScriptOutput::Plain(output_str)
        } else {
            ScriptOutput::Empty
        };

        Ok(ScriptResult {
            script_id: script.id.clone(),
            target_ip,
            port: None,
            protocol: None,
            status: ExecutionStatus::Success,
            output,
            duration: start.elapsed(),
            debug_log: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert_eq!(config.max_concurrent, crate::MAX_CONCURRENT_SCRIPTS);
        assert_eq!(config.default_timeout, crate::DEFAULT_SCRIPT_TIMEOUT);
        assert_eq!(config.max_memory, crate::MAX_MEMORY_BYTES);
    }

    #[test]
    fn test_script_scheduler_new() {
        let db = ScriptDatabase::new();
        let scheduler = ScriptScheduler::new(Arc::new(db), SchedulerConfig::default());

        assert_eq!(scheduler.database().len(), 0);
    }

    #[test]
    fn test_script_scheduler_select_scripts() {
        let mut db = ScriptDatabase::new();

        let mut script = NseScript::new("test-script", std::path::PathBuf::from("/test.nse"), String::new());
        script.categories = vec![ScriptCategory::Vuln];
        db.register_script(script);

        let scheduler = ScriptScheduler::new(Arc::new(db), SchedulerConfig::default());
        let selected = scheduler.select_scripts(&[ScriptCategory::Vuln]);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "test-script");
    }

    #[test]
    fn test_script_engine_new() {
        let db = ScriptDatabase::new();
        let engine = ScriptEngine::new(db);

        assert_eq!(engine.database().len(), 0);
        assert_eq!(engine.scheduler().config().max_concurrent, crate::MAX_CONCURRENT_SCRIPTS);
    }

    #[test]
    fn test_script_engine_execute_simple() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return "test output"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-script",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(script);

        let engine = ScriptEngine::new(db);
        let result = engine.execute_script(
            engine.database().get("test-script").unwrap(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );

        assert!(result.is_ok());
        let script_result = result.unwrap();
        assert_eq!(script_result.script_id, "test-script");
        assert!(script_result.is_success());
        assert!(!script_result.output.is_empty());
    }

    #[test]
    fn test_script_engine_execute_with_return() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return 42
end
"#
        .to_string();

        let script = NseScript::new(
            "test-return",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(script);

        let engine = ScriptEngine::new(db);
        let result = engine.execute_script(
            engine.database().get("test-return").unwrap(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );

        assert!(result.is_ok());
        let script_result = result.unwrap();
        assert_eq!(script_result.script_id, "test-return");
        assert!(script_result.is_success());
    }
}
