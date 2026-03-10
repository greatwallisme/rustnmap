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

        // host.name - Hostname from DNS reverse lookup
        let hostname = Self::resolve_hostname(target_ip);
        host_table.set("name", hostname.as_deref().unwrap_or(""))?;

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

    /// Resolve hostname via DNS reverse lookup.
    ///
    /// Uses blocking DNS lookup wrapped in `block_in_place` to avoid
    /// blocking the async runtime. Returns None if not in a Tokio context
    /// or if DNS lookup fails.
    fn resolve_hostname(ip: std::net::IpAddr) -> Option<String> {
        use rustnmap_target::dns::DnsResolver;

        // Check if we're in a Tokio context
        let handle = tokio::runtime::Handle::try_current().ok()?;

        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let resolver = DnsResolver::new().ok()?;
                resolver.reverse_lookup(ip).await.ok().flatten()
            })
        })
    }

    /// Create a full Nmap port table with all properties.
    ///
    /// # Arguments
    ///
    /// * `lua` - Lua state
    /// * `port_number` - Port number
    /// * `protocol` - Protocol (tcp/udp/sctp)
    /// * `state` - Port state (open/closed/filtered/etc)
    /// * `service` - Service name (optional)
    ///
    /// # Returns
    ///
    /// The port table.
    ///
    /// # Errors
    ///
    /// Returns an error if port table creation fails.
    fn create_port_table(
        lua: &mut crate::lua::NseLua,
        port_number: u16,
        protocol: &str,
        state: &str,
        service: Option<&str>,
        version: Option<&str>,
    ) -> Result<mlua::Table> {
        let port_table = lua.create_table()?;

        // port.number - Port number
        port_table.set("number", port_number)?;

        // port.protocol - Protocol (tcp/udp/sctp)
        port_table.set("protocol", protocol)?;

        // port.state - Port state
        port_table.set("state", state)?;

        // port.service - Service name
        port_table.set("service", service.unwrap_or(""))?;

        // port.version - Version info table
        let version_table = lua.create_table()?;
        if let Some(ver) = version {
            version_table.set("version", ver)?;
        }
        version_table.set("name", service.unwrap_or(""))?;
        version_table.set("product", "")?;
        version_table.set("extrainfo", "")?;
        version_table.set("hostname", "")?;
        version_table.set("ostype", "")?;
        version_table.set("devicetype", "")?;
        version_table.set("service_tunnel", "none")?;
        version_table.set("cpe", lua.create_table()?)?;
        port_table.set("version", version_table)?;

        // port.reason - Why port is in this state
        port_table.set("reason", "syn-ack")?;

        // port.reason_ttl - TTL of response
        port_table.set("reason_ttl", mlua::Value::Nil)?;

        Ok(port_table)
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
    pub fn execute_script(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<ScriptResult> {
        let start = std::time::Instant::now();
        let mut lua = NseLua::new_default()?;

        // Register NSE standard libraries (nmap, stdnse, comm, shortport)
        // These libraries are implemented in Rust and exposed to Lua via mlua FFI
        // This MUST be done before loading the script, as scripts use require() to access them
        crate::libs::register_all(&mut lua)?;

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
    /// Uses process-based isolation to ensure reliable timeout handling.
    /// Scripts that exceed the timeout are reliably terminated via OS-level
    /// process killing, preventing resource leaks from infinite loops.
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
    /// Returns an error if the runner process cannot be spawned.
    pub async fn execute_script_async(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<ScriptResult> {
        // Acquire semaphore permit for concurrency control
        let _permit = self.scheduler.semaphore.acquire().await.map_err(|e| {
            crate::error::Error::ExecutionError {
                script_id: script.id.clone(),
                message: format!("Failed to acquire execution permit: {e}"),
            }
        })?;

        // Use process-based executor for reliable timeout handling
        let executor = crate::process_executor::ProcessExecutor::with_timeout(
            self.scheduler.config.default_timeout,
        )?;

        // Execute in spawn_blocking to avoid blocking async runtime
        let script_source = script.source.clone();
        let script_id = script.id.clone();
        let timeout = self.scheduler.config.default_timeout;

        let result = tokio::task::spawn_blocking(move || {
            executor.execute(&script_source, &script_id, target_ip, timeout)
        })
        .await;

        match result {
            Ok(Ok(script_result)) => Ok(script_result),
            Ok(Err(e)) => Err(e),
            Err(join_error) => Err(crate::error::Error::ExecutionError {
                script_id: script.id.clone(),
                message: format!("Process executor task failed: {join_error}"),
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

    /// Execute a port script against a specific port.
    ///
    /// # Arguments
    ///
    /// * `script` - Script to execute
    /// * `target_ip` - Target IP address
    /// * `port` - Target port number
    /// * `protocol` - Protocol (tcp/udp)
    /// * `port_state` - Port state
    /// * `service` - Service name (optional)
    ///
    /// # Returns
    ///
    /// The script execution result.
    ///
    /// # Errors
    ///
    /// Returns an error if script execution fails.
    pub fn execute_port_script(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
        port: u16,
        protocol: &str,
        port_state: &str,
        service: Option<&str>,
    ) -> Result<ScriptResult> {
        let start = std::time::Instant::now();
        let mut lua = NseLua::new_default()?;

        // Load the script
        lua.load_script(&script.source, &script.id)?;

        // Create host table
        let host_table = Self::create_host_table(&mut lua, target_ip)?;
        lua.set_global("host", mlua::Value::Table(host_table))?;

        // Create port table
        let port_table =
            Self::create_port_table(&mut lua, port, protocol, port_state, service, None)?;
        lua.set_global("port", mlua::Value::Table(port_table))?;

        // Execute the action function if it exists
        let output = if script.has_action() {
            // Load and call the action function with host and port
            let func = lua.load_function("return action(host, port)", "action_wrapper")?;

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

            ScriptOutput::Plain(output_parts.join(" "))
        } else {
            ScriptOutput::Empty
        };

        Ok(ScriptResult {
            script_id: script.id.clone(),
            target_ip,
            port: Some(port),
            protocol: Some(protocol.to_string()),
            status: ExecutionStatus::Success,
            output,
            duration: start.elapsed(),
            debug_log: vec![],
        })
    }

    /// Evaluate a script's hostrule against a target.
    ///
    /// # Arguments
    ///
    /// * `script` - Script to evaluate
    /// * `target_ip` - Target IP address
    ///
    /// # Returns
    ///
    /// `true` if the hostrule matches, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if rule evaluation fails.
    pub fn evaluate_hostrule(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
    ) -> Result<bool> {
        if !script.has_hostrule() {
            // No hostrule means it doesn't match (port scripts need portrule)
            return Ok(false);
        }

        let mut lua = NseLua::new_default()?;

        // Load the script
        lua.load_script(&script.source, &script.id)?;

        // Create host table
        let host_table = Self::create_host_table(&mut lua, target_ip)?;
        lua.set_global("host", mlua::Value::Table(host_table.clone()))?;

        // Evaluate the hostrule
        let rule_func = lua.load_function("return hostrule(host)", "hostrule_wrapper")?;
        let result: bool = lua.call_function(&rule_func, ())?;

        Ok(result)
    }

    /// Evaluate a script's portrule against a target port.
    ///
    /// # Arguments
    ///
    /// * `script` - Script to evaluate
    /// * `target_ip` - Target IP address
    /// * `port` - Target port number
    /// * `protocol` - Protocol (tcp/udp)
    /// * `port_state` - Port state
    /// * `service` - Service name (optional)
    ///
    /// # Returns
    ///
    /// `true` if the portrule matches, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if rule evaluation fails.
    pub fn evaluate_portrule(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
        port: u16,
        protocol: &str,
        port_state: &str,
        service: Option<&str>,
    ) -> Result<bool> {
        if !script.has_portrule() {
            // No portrule means it doesn't match
            return Ok(false);
        }

        let mut lua = NseLua::new_default()?;

        // Load the script
        lua.load_script(&script.source, &script.id)?;

        // Create host table
        let host_table = Self::create_host_table(&mut lua, target_ip)?;
        lua.set_global("host", mlua::Value::Table(host_table.clone()))?;

        // Create port table
        let port_table =
            Self::create_port_table(&mut lua, port, protocol, port_state, service, None)?;
        lua.set_global("port", mlua::Value::Table(port_table.clone()))?;

        // Evaluate the portrule
        let rule_func = lua.load_function("return portrule(host, port)", "portrule_wrapper")?;
        let result: bool = lua.call_function(&rule_func, ())?;

        Ok(result)
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

    // Tests for execute_script with different Lua return types

    #[test]
    fn test_execute_script_returns_number() {
        let mut db = ScriptDatabase::new();

        let source = r"
action = function(host)
    return 3.14159
end
"
        .to_string();

        let script = NseScript::new("test-number", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script(
                engine.database().get("test-number").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "3.14159");
    }

    #[test]
    fn test_execute_script_returns_boolean_true() {
        let mut db = ScriptDatabase::new();

        let source = r"
action = function(host)
    return true
end
"
        .to_string();

        let script = NseScript::new(
            "test-bool-true",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script(
                engine.database().get("test-bool-true").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "true");
    }

    #[test]
    fn test_execute_script_returns_boolean_false() {
        let mut db = ScriptDatabase::new();

        let source = r"
action = function(host)
    return false
end
"
        .to_string();

        let script = NseScript::new(
            "test-bool-false",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script(
                engine.database().get("test-bool-false").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "false");
    }

    #[test]
    fn test_execute_script_returns_nil() {
        let mut db = ScriptDatabase::new();

        let source = r"
action = function(host)
    return nil
end
"
        .to_string();

        let script = NseScript::new("test-nil", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script(
                engine.database().get("test-nil").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result.is_success());
        // When script returns nil, output should be empty (nil values are filtered out)
        assert!(result.output.to_display().is_empty());
    }

    #[test]
    fn test_execute_script_returns_mixed_values() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return "result", 42, true, nil, "end"
end
"#
        .to_string();

        let script = NseScript::new("test-mixed", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script(
                engine.database().get("test-mixed").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "result 42 true end");
    }

    // Tests for create_host_table with IPv6

    #[test]
    fn test_create_host_table_ipv6() {
        let mut lua = NseLua::new_default().unwrap();
        let ipv6_addr = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ));

        let host_table = ScriptEngine::create_host_table(&mut lua, ipv6_addr).unwrap();

        assert_eq!(
            host_table.get::<String>("ip").unwrap(),
            "2001:db8:85a3::8a2e:370:7334"
        );

        let bin_ip: Vec<u8> = host_table.get("bin_ip").unwrap();
        assert_eq!(bin_ip.len(), 16);
        assert_eq!(
            bin_ip,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34
            ]
        );
    }

    #[test]
    fn test_create_host_table_ipv6_loopback() {
        let mut lua = NseLua::new_default().unwrap();
        let ipv6_addr = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

        let host_table = ScriptEngine::create_host_table(&mut lua, ipv6_addr).unwrap();

        assert_eq!(host_table.get::<String>("ip").unwrap(), "::1");

        let bin_ip: Vec<u8> = host_table.get("bin_ip").unwrap();
        assert_eq!(bin_ip.len(), 16);
        let expected = {
            let mut v = vec![0u8; 15];
            v.push(1);
            v
        };
        assert_eq!(bin_ip, expected);
    }

    // Tests for execute_script_async

    #[tokio::test]
    async fn test_execute_script_async_success() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return "async result"
end
"#
        .to_string();

        let script = NseScript::new("test-async", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_script_async(
                engine.database().get("test-async").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "async result");
    }

    #[tokio::test]
    async fn test_execute_script_async_timeout() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    while true do
    end
    return "never reached"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-timeout",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let config = SchedulerConfig {
            max_concurrent: crate::MAX_CONCURRENT_SCRIPTS,
            default_timeout: Duration::from_millis(50),
            max_memory: crate::MAX_MEMORY_BYTES,
        };

        let engine = ScriptEngine::with_config(db, config);

        let result = engine
            .execute_script_async(
                engine.database().get("test-timeout").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .await
            .unwrap();

        assert!(result.is_timeout());
        assert!(result.output.is_empty());
        assert!(!result.debug_log.is_empty());
        assert!(result.debug_log[0].contains("timed out"));
    }

    #[tokio::test]
    async fn test_execute_script_async_semaphore_concurrency() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return "done"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-concurrent",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let config = SchedulerConfig {
            max_concurrent: 1,
            default_timeout: Duration::from_secs(5),
            max_memory: crate::MAX_MEMORY_BYTES,
        };

        let engine = ScriptEngine::with_config(db, config);
        let script_ref = engine.database().get("test-concurrent").unwrap();

        let handle1 = engine.execute_script_async(
            script_ref,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        let handle2 = engine.execute_script_async(
            script_ref,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );

        let (result1, result2) = tokio::join!(handle1, handle2);

        assert!(result1.unwrap().is_success());
        assert!(result2.unwrap().is_success());
    }

    // Tests for execute_scripts_async

    #[tokio::test]
    async fn test_execute_scripts_async_multiple() {
        let mut db = ScriptDatabase::new();

        let source1 = r#"
action = function(host)
    return "script1 output"
end
"#
        .to_string();

        let source2 = r#"
action = function(host)
    return "script2 output"
end
"#
        .to_string();

        let script1 = NseScript::new(
            "test-multi-1",
            std::path::PathBuf::from("/test1.nse"),
            source1,
        );
        let script2 = NseScript::new(
            "test-multi-2",
            std::path::PathBuf::from("/test2.nse"),
            source2,
        );
        db.register_script(&script1);
        db.register_script(&script2);

        let engine = ScriptEngine::new(db);
        let script_refs: Vec<&NseScript> = vec![
            engine.database().get("test-multi-1").unwrap(),
            engine.database().get("test-multi-2").unwrap(),
        ];

        let results = engine
            .execute_scripts_async(
                &script_refs,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .await;

        assert_eq!(results.len(), 2);
        assert!(results[0].as_ref().unwrap().is_success());
        assert!(results[1].as_ref().unwrap().is_success());
        assert_eq!(
            results[0].as_ref().unwrap().output.to_display(),
            "script1 output"
        );
        assert_eq!(
            results[1].as_ref().unwrap().output.to_display(),
            "script2 output"
        );
    }

    #[tokio::test]
    async fn test_execute_scripts_async_empty() {
        let db = ScriptDatabase::new();
        let engine = ScriptEngine::new(db);

        let results: Vec<Result<ScriptResult>> = engine
            .execute_scripts_async(&[], std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .await;

        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_execute_scripts_async_mixed_results() {
        let mut db = ScriptDatabase::new();

        let source1 = r#"
action = function(host)
    return "success"
end
"#
        .to_string();

        let source2 = r"
action = function(host)
    while true do end
end
"
        .to_string();

        let script1 = NseScript::new(
            "test-mix-1",
            std::path::PathBuf::from("/test1.nse"),
            source1,
        );
        let script2 = NseScript::new(
            "test-mix-2",
            std::path::PathBuf::from("/test2.nse"),
            source2,
        );
        db.register_script(&script1);
        db.register_script(&script2);

        let config = SchedulerConfig {
            max_concurrent: crate::MAX_CONCURRENT_SCRIPTS,
            default_timeout: Duration::from_millis(100),
            max_memory: crate::MAX_MEMORY_BYTES,
        };

        let engine = ScriptEngine::with_config(db, config);
        let script_refs: Vec<&NseScript> = vec![
            engine.database().get("test-mix-1").unwrap(),
            engine.database().get("test-mix-2").unwrap(),
        ];

        let results = engine
            .execute_scripts_async(
                &script_refs,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .await;

        assert_eq!(results.len(), 2);
        assert!(results[0].as_ref().unwrap().is_success());
        assert!(results[1].as_ref().unwrap().is_timeout());
    }

    // Tests for execute_port_script

    #[test]
    fn test_execute_port_script_with_service() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    return port.number .. " " .. port.protocol .. " " .. port.service
end
"#
        .to_string();

        let script = NseScript::new(
            "test-port-script",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_port_script(
                engine.database().get("test-port-script").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "open",
                Some("http"),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.port, Some(80));
        assert_eq!(result.protocol, Some("tcp".to_string()));
        assert_eq!(result.output.to_display(), "80 tcp http");
    }

    #[test]
    fn test_execute_port_script_with_version() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    return port.version.name .. ": " .. (port.version.version or "unknown")
end
"#
        .to_string();

        let script = NseScript::new(
            "test-version",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_port_script(
                engine.database().get("test-version").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                443,
                "tcp",
                "open",
                Some("https"),
            )
            .unwrap();

        assert!(result.is_success());
        // When version is None, port.version.version is nil, so "or" returns "unknown"
        assert_eq!(result.output.to_display(), "https: unknown");
    }

    #[test]
    fn test_execute_port_script_udp_protocol() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    return port.protocol .. " " .. port.state
end
"#
        .to_string();

        let script = NseScript::new("test-udp", std::path::PathBuf::from("/test.nse"), source);
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_port_script(
                engine.database().get("test-udp").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                53,
                "udp",
                "open",
                Some("dns"),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "udp open");
    }

    #[test]
    fn test_execute_port_script_no_service() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    return "port " .. port.number .. " service: '" .. port.service .. "'"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-no-service",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_port_script(
                engine.database().get("test-no-service").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                12345,
                "tcp",
                "filtered",
                None,
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "port 12345 service: ''");
    }

    #[test]
    fn test_execute_port_script_filtered_state() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    if port.state == "filtered" then
        return "filtered detected"
    end
    return "other state"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-filtered",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .execute_port_script(
                engine.database().get("test-filtered").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                445,
                "tcp",
                "filtered",
                Some("smb"),
            )
            .unwrap();

        assert!(result.is_success());
        assert_eq!(result.output.to_display(), "filtered detected");
    }

    // Tests for evaluate_hostrule

    #[test]
    fn test_evaluate_hostrule_returns_false() {
        let mut db = ScriptDatabase::new();

        let source = r#"
hostrule = function(host)
    return false
end

action = function(host)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-hostrule-false",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_hostrule(
                engine.database().get("test-hostrule-false").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn test_evaluate_hostrule_returns_true() {
        let mut db = ScriptDatabase::new();

        let source = r#"
hostrule = function(host)
    return true
end

action = function(host)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-hostrule-true",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_hostrule(
                engine.database().get("test-hostrule-true").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(result);
    }

    #[test]
    fn test_evaluate_hostrule_no_hostrule() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-no-hostrule",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_hostrule(
                engine.database().get("test-no-hostrule").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn test_evaluate_hostrule_checks_host_ip() {
        let mut db = ScriptDatabase::new();

        let source = r#"
hostrule = function(host)
    return host.ip == "127.0.0.1"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-hostrule-ip",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);

        let result_localhost = engine
            .evaluate_hostrule(
                engine.database().get("test-hostrule-ip").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap();
        assert!(result_localhost);

        let result_other = engine
            .evaluate_hostrule(
                engine.database().get("test-hostrule-ip").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            )
            .unwrap();
        assert!(!result_other);
    }

    // Tests for evaluate_portrule

    #[test]
    fn test_evaluate_portrule_returns_false() {
        let mut db = ScriptDatabase::new();

        let source = r#"
portrule = function(host, port)
    return false
end

action = function(host, port)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-portrule-false",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-false").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "open",
                Some("http"),
            )
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn test_evaluate_portrule_returns_true() {
        let mut db = ScriptDatabase::new();

        let source = r#"
portrule = function(host, port)
    return true
end

action = function(host, port)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-portrule-true",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-true").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                443,
                "tcp",
                "open",
                Some("https"),
            )
            .unwrap();

        assert!(result);
    }

    #[test]
    fn test_evaluate_portrule_no_portrule() {
        let mut db = ScriptDatabase::new();

        let source = r#"
action = function(host, port)
    return "executed"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-no-portrule",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);
        let result = engine
            .evaluate_portrule(
                engine.database().get("test-no-portrule").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "open",
                Some("http"),
            )
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn test_evaluate_portrule_checks_port_number() {
        let mut db = ScriptDatabase::new();

        let source = r"
portrule = function(host, port)
    return port.number == 80
end
"
        .to_string();

        let script = NseScript::new(
            "test-portrule-port",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);

        let result_80 = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-port").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "open",
                Some("http"),
            )
            .unwrap();
        assert!(result_80);

        let result_443 = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-port").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                443,
                "tcp",
                "open",
                Some("https"),
            )
            .unwrap();
        assert!(!result_443);
    }

    #[test]
    fn test_evaluate_portrule_checks_port_state() {
        let mut db = ScriptDatabase::new();

        let source = r#"
portrule = function(host, port)
    return port.state == "open"
end
"#
        .to_string();

        let script = NseScript::new(
            "test-portrule-state",
            std::path::PathBuf::from("/test.nse"),
            source,
        );
        db.register_script(&script);

        let engine = ScriptEngine::new(db);

        let result_open = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-state").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "open",
                Some("http"),
            )
            .unwrap();
        assert!(result_open);

        let result_closed = engine
            .evaluate_portrule(
                engine.database().get("test-portrule-state").unwrap(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
                "tcp",
                "closed",
                None,
            )
            .unwrap();
        assert!(!result_closed);
    }
}
