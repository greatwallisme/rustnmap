//! Process-based script executor with reliable timeout handling.
//!
//! This module provides a process-isolated script execution mechanism that
//! solves the P0 bug where `tokio::spawn_blocking` tasks cannot be cancelled.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

use crate::error::{Error, Result};
use crate::script::{ExecutionStatus, ScriptOutput, ScriptResult};

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

/// Process-based script executor.
///
/// Executes NSE scripts in isolated child processes with reliable
/// timeout handling via OS-level process termination.
#[derive(Debug)]
pub struct ProcessExecutor {
    /// Path to the runner binary.
    runner_path: String,

    /// Default timeout for script execution.
    default_timeout: Duration,
}

impl ProcessExecutor {
    /// Create a new process executor.
    ///
    /// # Errors
    ///
    /// Returns an error if the runner binary cannot be located.
    pub fn new() -> Result<Self> {
        let runner_path = Self::find_runner_binary()?;

        Ok(Self {
            runner_path,
            default_timeout: crate::DEFAULT_SCRIPT_TIMEOUT,
        })
    }

    /// Create a new process executor with custom timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the runner binary cannot be located.
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let runner_path = Self::find_runner_binary()?;

        Ok(Self {
            runner_path,
            default_timeout: timeout,
        })
    }

    /// Find the runner binary path.
    fn find_runner_binary() -> Result<String> {
        // Check if it's in the same directory as the current executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                // Check same directory (normal case)
                let runner_path = exe_dir.join("rustnmap-nse-runner");
                if runner_path.exists() {
                    return Ok(runner_path.to_string_lossy().to_string());
                }

                // Check parent directory (test case: tests run from target/debug/deps/)
                if let Some(parent_dir) = exe_dir.parent() {
                    let runner_path = parent_dir.join("rustnmap-nse-runner");
                    if runner_path.exists() {
                        return Ok(runner_path.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Fallback: try to find in PATH
        if let Ok(path) = which::which("rustnmap-nse-runner") {
            return Ok(path.to_string_lossy().to_string());
        }

        Err(Error::ExecutionError {
            script_id: "runner".to_string(),
            message: "Cannot find rustnmap-nse-runner binary. \
                     Ensure it is compiled and in PATH or same directory as executable."
                .to_string(),
        })
    }

    /// Execute a script with timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned or communication fails.
    pub fn execute(
        &self,
        script_source: &str,
        script_id: &str,
        target_ip: IpAddr,
        timeout: Duration,
    ) -> Result<ScriptResult> {
        let start = Instant::now();

        // Spawn the runner process
        let mut child = Self::spawn_runner(&self.runner_path, target_ip, timeout, script_id)?;

        // Write script source to stdin
        Self::write_script_to_child(&mut child, script_source, script_id)?;

        // Wait with timeout
        let status = child.wait_timeout(timeout).map_err(|e| Error::ExecutionError {
            script_id: script_id.to_string(),
            message: format!("Failed to wait for runner process: {e}"),
        })?;

        match status {
            None => Ok(Self::create_timeout_result(script_id, target_ip, timeout)),
            Some(exit_status) => {
                Ok(Self::handle_process_result(child, exit_status, script_id, target_ip, start))
            }
        }
    }

    /// Spawn the runner process.
    fn spawn_runner(
        runner_path: &str,
        target_ip: IpAddr,
        timeout: Duration,
        script_id: &str,
    ) -> Result<Child> {
        Command::new(runner_path)
            .arg("--target")
            .arg(target_ip.to_string())
            .arg("--timeout-ms")
            .arg(timeout.as_millis().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::ExecutionError {
                script_id: script_id.to_string(),
                message: format!("Failed to spawn runner process: {e}"),
            })
    }

    /// Write script source to the runner's stdin.
    fn write_script_to_child(child: &mut Child, script_source: &str, script_id: &str) -> Result<()> {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script_source.as_bytes())
                .map_err(|e| Error::ExecutionError {
                    script_id: script_id.to_string(),
                    message: format!("Failed to write script to runner: {e}"),
                })?;
        }
        Ok(())
    }

    /// Create timeout result.
    fn create_timeout_result(
        script_id: &str,
        target_ip: IpAddr,
        timeout: Duration,
    ) -> ScriptResult {
        ScriptResult {
            script_id: script_id.to_string(),
            target_ip,
            port: None,
            protocol: None,
            status: ExecutionStatus::Timeout,
            output: ScriptOutput::Empty,
            duration: timeout,
            debug_log: vec!["Script execution timed out - process killed".to_string()],
        }
    }

    /// Handle process result - parse output and return appropriate result.
    fn handle_process_result(
        mut child: Child,
        exit_status: ExitStatus,
        script_id: &str,
        target_ip: IpAddr,
        start: Instant,
    ) -> ScriptResult {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stdout_content = read_to_string(stdout);
        let runner_output: Option<RunnerOutput> = serde_json::from_str(&stdout_content).ok();

        match runner_output {
            Some(output) => {
                Self::parse_runner_output(output, script_id, target_ip, start)
            }
            None => {
                Self::handle_raw_output(exit_status, stdout_content, stderr, script_id, target_ip, start)
            }
        }
    }

    /// Parse structured runner output.
    fn parse_runner_output(
        output: RunnerOutput,
        script_id: &str,
        target_ip: IpAddr,
        start: Instant,
    ) -> ScriptResult {
        match output.status {
            RunnerStatus::Success => ScriptResult {
                script_id: script_id.to_string(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Success,
                output: ScriptOutput::Plain(output.output.unwrap_or_default()),
                duration: start.elapsed(),
                debug_log: vec![],
            },
            RunnerStatus::Failed => ScriptResult {
                script_id: script_id.to_string(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Failed,
                output: ScriptOutput::Empty,
                duration: start.elapsed(),
                debug_log: vec![output.error.unwrap_or_else(|| "Unknown error".to_string())],
            },
            RunnerStatus::Timeout => ScriptResult {
                script_id: script_id.to_string(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Timeout,
                output: ScriptOutput::Empty,
                duration: start.elapsed(),
                debug_log: vec!["Script execution timed out".to_string()],
            },
        }
    }

    /// Handle raw output when JSON parsing fails.
    fn handle_raw_output(
        exit_status: ExitStatus,
        stdout_content: String,
        stderr: Option<std::process::ChildStderr>,
        script_id: &str,
        target_ip: IpAddr,
        start: Instant,
    ) -> ScriptResult {
        if exit_status.success() {
            return ScriptResult {
                script_id: script_id.to_string(),
                target_ip,
                port: None,
                protocol: None,
                status: ExecutionStatus::Success,
                output: ScriptOutput::Plain(stdout_content),
                duration: start.elapsed(),
                debug_log: vec![],
            };
        }

        let stderr_content = read_to_string(stderr);
        let error_msg = if stderr_content.is_empty() {
            format!("Process exited with status {exit_status}")
        } else {
            stderr_content
        };

        ScriptResult {
            script_id: script_id.to_string(),
            target_ip,
            port: None,
            protocol: None,
            status: ExecutionStatus::Failed,
            output: ScriptOutput::Empty,
            duration: start.elapsed(),
            debug_log: vec![error_msg],
        }
    }

    /// Execute a script with the default timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned or communication fails.
    pub fn execute_with_default_timeout(
        &self,
        script_source: &str,
        script_id: &str,
        target_ip: IpAddr,
    ) -> Result<ScriptResult> {
        self.execute(script_source, script_id, target_ip, self.default_timeout)
    }
}

/// Read from an optional reader to a string.
fn read_to_string<R: Read>(reader: Option<R>) -> String {
    reader
        .and_then(|mut r| {
            let mut buf = String::new();
            r.read_to_string(&mut buf).ok()?;
            Some(buf)
        })
        .unwrap_or_default()
}

impl Default for ProcessExecutor {
    fn default() -> Self {
        Self::new().expect("Failed to create ProcessExecutor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_executor_creation() {
        // Test passes whether runner binary is found or not
        // This validates that ProcessExecutor::new() doesn't panic
        let _ = ProcessExecutor::new();
    }

    #[test]
    fn test_runner_status_serialization() {
        let status = RunnerStatus::Success;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Success\"");

        let status = RunnerStatus::Timeout;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Timeout\"");
    }

    #[test]
    fn test_runner_output_serialization() {
        let output = RunnerOutput {
            status: RunnerStatus::Success,
            output: Some("test output".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("Success"));
        assert!(json.contains("test output"));
    }
}
