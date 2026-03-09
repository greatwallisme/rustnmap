//! NSE Script Runner Binary
//!
//! Isolated process for executing NSE scripts with resource limits.
//! This binary is spawned by the main rustnmap process to ensure that
//! misbehaving scripts (infinite loops, memory leaks) can be reliably
//! terminated via OS-level process killing.
//!
//! # Exit Codes
//!
//! - 0: Script executed successfully
//! - 1: Script execution error
//! - 2: Script timeout (killed by resource limit)
//! - 3: Invalid arguments

use std::io::{self, Read};
use std::net::IpAddr;
use std::process::ExitCode;

use mlua::Lua;
use serde::{Deserialize, Serialize};

/// Runner process execution status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum RunnerStatus {
    /// Script executed successfully.
    Success,
    /// Script execution failed.
    Failed,
    /// Script timed out.
    Timeout,
}

/// Runner process output.
#[derive(Debug, Serialize, Deserialize)]
struct RunnerOutput {
    /// Execution status.
    status: RunnerStatus,
    /// Script output (if successful).
    output: Option<String>,
    /// Error message (if failed).
    error: Option<String>,
}

/// Parse command line arguments.
fn parse_args() -> Option<(IpAddr, Option<u64>, Option<String>)> {
    let args: Vec<String> = std::env::args().collect();

    let mut target_ip: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut script_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target_ip = args.get(i).cloned();
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).and_then(|s| s.parse().ok());
            }
            "--file" => {
                i += 1;
                script_file = args.get(i).cloned();
            }
            "--help" | "-h" => {
                eprintln!("Usage: rustnmap-nse-runner --target IP [--timeout-ms MS] [--file SCRIPT]");
                eprintln!("       Reads script from stdin if --file not specified.");
                return None;
            }
            _ => {}
        }
        i += 1;
    }

    let target = target_ip?;
    let ip: IpAddr = target.parse().ok()?;
    Some((ip, timeout_ms, script_file))
}

/// Set CPU time limit for the process.
fn set_cpu_limit(timeout_ms: u64) {
    // Set CPU time limit to timeout + 5 seconds margin
    let cpu_limit: u64 = timeout_ms / 1000 + 5;
    // SAFETY: setrlimit is is a POSIX system call that sets resource limits.
    // We use it to limit CPU time to prevent runaway scripts from
    // consuming unlimited CPU resources. The call is safe because:
    // 1. We only call it once at process startup
    // 2. The rlimit structure is properly initialized
    // 3. We check the return value for errors
    #[expect(clippy::borrow_as_ptr, reason = "libc::setrlimit requires raw pointer")]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: cpu_limit,
            rlim_max: cpu_limit,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &rlim) != 0 {
            eprintln!("Warning: Failed to set CPU time limit");
        }
    }
}

/// Read script source from file or stdin.
fn read_script_source(script_file: Option<&String>) -> io::Result<String> {
    if let Some(file) = script_file {
        std::fs::read_to_string(file)
    } else {
        let mut source = String::new();
        io::stdin().read_to_string(&mut source)?;
        Ok(source)
    }
}

/// Output result as JSON to stdout.
fn output_result(result: &RunnerOutput) {
    match serde_json::to_string(result) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Failed to serialize result: {e}"),
    }
}

/// Execute an NSE script and Returns output string on success.
fn execute_script(source: &str, script_id: &str, target_ip: IpAddr) -> Result<String, String> {
    let lua = Lua::new();

    // Load the script
    lua.load(source)
        .set_name(script_id)
        .exec()
        .map_err(|e| format!("Failed to load script: {e}"))?;

    // Create host table
    let host_table = create_host_table(&lua, target_ip)?;
    lua.globals()
        .set("host", host_table)
        .map_err(|e| format!("Failed to set host table: {e}"))?;

    // Check if action function exists
    let has_action = source.contains("action")
        && (source.contains("action =") || source.contains("function action"));

    if !has_action {
        return Ok(String::new());
    }

    // Execute action function
    let func = lua
        .load("return action(host)")
        .set_name("action_wrapper")
        .into_function()
        .map_err(|e| format!("Failed to load action function: {e}"))?;

    let result: mlua::MultiValue = func
        .call(())
        .map_err(|e| format!("Script execution failed: {e}"))?;

    // Convert result to string
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

    Ok(output_parts.join(" "))
}

/// Create the NSE host table.
fn create_host_table(lua: &Lua, target_ip: IpAddr) -> Result<mlua::Table, String> {
    let host_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create host table: {e}"))?;

    // Set IP address
    let ip_str = target_ip.to_string();
    host_table
        .set("ip", ip_str.clone())
        .map_err(|e| format!("Failed to set host.ip: {e}"))?;

    // Set canonical IP (same as ip for now)
    host_table
        .set("canonical_ip", ip_str)
        .map_err(|e| format!("Failed to set host.canonical_ip: {e}"))?;

    // Set target to a table with ip
    let target_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create target table: {e}"))?;
    target_table
        .set("ip", target_ip.to_string())
        .map_err(|e| format!("Failed to set target.ip: {e}"))?;

    host_table
        .set("target", target_table)
        .map_err(|e| format!("Failed to set host.target: {e}"))?;

    // Set name (empty for IP-only targets)
    host_table
        .set("name", "")
        .map_err(|e| format!("Failed to set host.name: {e}"))?;

    Ok(host_table)
}

fn main() -> ExitCode {
    let Some((target_ip, timeout_ms, script_file)) = parse_args() else {
        return ExitCode::from(3);
    };

    // Set CPU time limit if timeout specified
    if let Some(timeout) = timeout_ms {
        set_cpu_limit(timeout);
    }

    // Read script source
    let script_source = match read_script_source(script_file.as_ref()) {
        Ok(source) => source,
        Err(e) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Failed,
                output: None,
                error: Some(format!("Failed to read script: {e}")),
            });
            return ExitCode::from(1);
        }
    };

    // Execute the script
    match execute_script(&script_source, "runner_script", target_ip) {
        Ok(output) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Success,
                output: Some(output),
                error: None,
            });
            ExitCode::SUCCESS
        }
        Err(e) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Failed,
                output: None,
                error: Some(e),
            });
            ExitCode::from(1)
        }
    }
}
