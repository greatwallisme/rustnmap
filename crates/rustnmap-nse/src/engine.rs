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

    /// Semaphore for concurrency control during async script execution.
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

        Self {
            database: db,
            scheduler,
        }
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

        Self {
            database: db,
            scheduler,
        }
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

    /// Create a full Nmap host table with all properties.
    ///
    /// # Arguments
    ///
    /// * `lua` - Lua state
    /// * `target_ip` - Target IP address
    ///
    /// # Returns
    ///
    /// The host table.
    ///
    /// # Errors
    ///
    /// Returns an error if host table creation fails.
    fn create_host_table(
        lua: &mut crate::lua::NseLua,
        target_ip: std::net::IpAddr,
    ) -> Result<mlua::Table> {
        let host_table = lua.create_table()?;

        // host.ip - IP address string
        host_table.set("ip", target_ip.to_string())?;

        // host.name - Hostname (empty for now, would require DNS lookup)
        host_table.set("name", "")?;

        // host.targetname - The original target specification
        host_table.set("targetname", target_ip.to_string())?;

        // host.directly_connected - Whether target is on same subnet
        host_table.set("directly_connected", false)?;

        // host.mac_addr - MAC address if available
        host_table.set("mac_addr", mlua::Value::Nil)?;

        // host.os - OS fingerprint results (table)
        host_table.set("os", lua.create_table()?)?;

        // host.hostnames - Array of hostnames
        let hostnames_table = lua.create_table()?;
        host_table.set("hostnames", hostnames_table)?;

        // host.traceroute - Route information
        host_table.set("traceroute", mlua::Value::Nil)?;

        // host.extraports - Extra ports info
        let extraports_table = lua.create_table()?;
        host_table.set("extraports", extraports_table)?;

        // host.reason - Why host is considered up
        host_table.set("reason", "user-set")?;

        // host.reason_ttl - TTL of response that determined host is up
        host_table.set("reason_ttl", mlua::Value::Nil)?;

        // host.interface - Network interface used
        host_table.set("interface", "")?;

        // host.bin_ip - IP address as binary string
        let bin_ip = match target_ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        host_table.set("bin_ip", bin_ip)?;

        // host.bin_ip_mask - Network mask (empty for single host)
        host_table.set("bin_ip_mask", mlua::Value::Nil)?;

        // host.options - IP options used
        let options_table = lua.create_table()?;
        host_table.set("options", options_table)?;

        // host.id_ttl - Initial TTL guess
        host_table.set("id_ttl", 64)?;

        // host.scan_time - When host was scanned (POSIX timestamp)
        let now: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().try_into().unwrap_or(i64::MAX))
            .unwrap_or(0);
        host_table.set("scan_time", now)?;

        // host.registry - Host-specific registry
        let registry_table = lua.create_table()?;
        host_table.set("registry", registry_table)?;

        // host.times - Timing statistics
        let times_table = lua.create_table()?;
        times_table.set("srtt", 0)?;
        times_table.set("rttvar", 0)?;
        times_table.set("to", 0)?;
        host_table.set("times", times_table)?;

        Ok(host_table)
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "Arc::clone is cheap and simplifies code"
    )]
    pub fn execute_script(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<ScriptResult> {
        let start = std::time::Instant::now();
        let mut lua = NseLua::new_default()?;

        // Load the script
        lua.load_script(&script.source, &script.id)?;

        // Create full Nmap host table with all properties
        let host_table = Self::create_host_table(&mut lua, target_ip)?;

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

    /// Execute a single script asynchronously with concurrency control and timeout.
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
    /// Returns an error if script execution fails or times out.
    pub async fn execute_script_async(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<ScriptResult> {
        let start = std::time::Instant::now();

        // Acquire semaphore permit for concurrency control
        let _permit = self
            .scheduler
            .semaphore
            .acquire()
            .await
            .map_err(|e| crate::error::Error::ExecutionError {
                script_id: script.id.clone(),
                message: format!("Failed to acquire execution permit: {e}"),
            })?;

        // Execute script with timeout
        let timeout = self.scheduler.config.default_timeout;
        let script_id = script.id.clone();
        let script_source = script.source.clone();
        let has_action = script.has_action();

        let result = tokio::time::timeout(timeout, async move {
            let mut lua = NseLua::new_default()?;

            // Load the script
            lua.load_script(&script_source, &script_id)?;

            // Create full Nmap host table with all properties
            let host_table = ScriptEngine::create_host_table(&mut lua, target_ip)?;
            lua.set_global("host", mlua::Value::Table(host_table))?;

            // Execute action function if exists
            let output = if has_action {
                let func = lua.load_function("return action(host)", "action_wrapper")?;
                let result: mlua::MultiValue = lua.call_function(&func, ())?;

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

                ScriptOutput::Plain(output_parts.join(" "))
            } else {
                ScriptOutput::Empty
            };

            Result::<ScriptOutput>::Ok(output)
        })
        .await;

        match result {
            Ok(Ok(output)) => Ok(ScriptResult {
                script_id: script.id.clone(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Success,
                output,
                duration: start.elapsed(),
                debug_log: vec![],
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(ScriptResult {
                script_id: script.id.clone(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Timeout,
                output: ScriptOutput::Empty,
                duration: timeout,
                debug_log: vec!["Script execution timed out".to_string()],
            }),
        }
    }

    /// Execute multiple scripts asynchronously with concurrency control.
    ///
    /// # Arguments
    ///
    /// * `scripts` - Scripts to execute
    /// * `target_ip` - Target IP address
    ///
    /// # Returns
    ///
    /// Vector of script execution results.
    pub async fn execute_scripts_async(
        &self,
        scripts: &[&NseScript],
        target_ip: std::net::IpAddr,
    ) -> Vec<Result<ScriptResult>> {
        let mut handles = Vec::new();

        for script in scripts {
            let result = self.execute_script_async(script, target_ip).await;
            handles.push(result);
        }

        handles
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

        let mut script = NseScript::new(
            "test-script",
            std::path::PathBuf::from("/test.nse"),
            String::new(),
        );
        script.categories = vec![ScriptCategory::Vuln];
        db.register_script(&script);

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
        assert_eq!(
            engine.scheduler().config().max_concurrent,
            crate::MAX_CONCURRENT_SCRIPTS
        );
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

        let script = NseScript::new("test-script", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

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

        let source = r"
action = function(host)
    return 42
end
"
        .to_string();

        let script = NseScript::new("test-return", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

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
