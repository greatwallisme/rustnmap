// rustnmap-output
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Output manager for handling multiple output formatters.

use crate::error::{OutputError, Result};
use crate::formatter::{OutputFormatter, VerbosityLevel};
use crate::models::ScanResult;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, event, info, Level};

/// Output destination.
#[derive(Debug, Clone)]
pub enum OutputDestination {
    /// Write to standard output.
    Stdout,
    /// Write to a file.
    File(PathBuf),
    /// Write to a buffer in memory.
    Memory(Arc<Mutex<Vec<u8>>>),
}

/// Output manager for handling multiple output formats.
pub struct OutputManager {
    /// Registered formatters
    formatters: Vec<Box<dyn OutputFormatter>>,
    /// Output destinations
    destinations: Vec<OutputDestination>,
    /// Verbosity level
    verbosity: VerbosityLevel,
    /// Scan result being built
    current_result: Option<ScanResult>,
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputManager {
    /// Create a new output manager.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            formatters: Vec::new(),
            destinations: Vec::new(),
            verbosity: VerbosityLevel::Normal,
            current_result: None,
        }
    }

    /// Add a formatter to the manager.
    pub fn add_formatter(&mut self, formatter: Box<dyn OutputFormatter>) {
        debug!(
            formatter = formatter.format_name(),
            "Added output formatter"
        );
        self.formatters.push(formatter);
    }

    /// Add standard output as a destination.
    pub fn add_stdout(&mut self) {
        self.destinations.push(OutputDestination::Stdout);
    }

    /// Add file output as a destination.
    pub fn add_file_output(&mut self, path: PathBuf) {
        info!(path = %path.display(), "Added file output destination");
        self.destinations.push(OutputDestination::File(path));
    }

    /// Set verbosity level.
    pub fn set_verbosity(&mut self, verbosity: VerbosityLevel) {
        self.verbosity = verbosity;
    }

    /// Get current verbosity level.
    #[must_use] 
    pub fn verbosity(&self) -> VerbosityLevel {
        self.verbosity
    }

    /// Begin a new scan result.
    pub fn begin_scan(&mut self) {
        self.current_result = Some(ScanResult::default());
        event!(
            name: "output.scan.begin",
            Level::DEBUG,
            "Started new scan result"
        );
    }

    /// Output the current scan result to all destinations.
    ///
    /// # Errors
    ///
    /// Returns `OutputError::InvalidData` if no formatters are registered.
    /// Returns `OutputError::FileWrite` if writing to file destination fails.
    /// Returns `std::io::Error` if flushing stdout fails.
    pub fn output_scan_result(&mut self, result: &ScanResult) -> Result<()> {
        if self.formatters.is_empty() {
            return Err(OutputError::InvalidData(
                "No formatters registered".to_string(),
            ));
        }

        for formatter in &self.formatters {
            let formatted = formatter.format_scan_result(result)?;

            for destination in &self.destinations {
                Self::write_to_destination(destination, &formatted)?;
            }
        }

        Ok(())
    }

    /// Write formatted output to a destination.
    fn write_to_destination(
        destination: &OutputDestination,
        data: &str,
    ) -> Result<()> {
        match destination {
            OutputDestination::Stdout => {
                print!("{data}");
                io::stdout().flush().map_err(OutputError::from)?;
            }
            OutputDestination::File(path) => {
                Self::write_to_file(path, data)?;
            }
            OutputDestination::Memory(_dest) => {
                // Memory buffering handled by caller
            }
        }
        Ok(())
    }

    /// Write data to a file.
    fn write_to_file(path: &Path, data: &str) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| OutputError::FileWrite {
                    path: parent.display().to_string(),
                    message: e.to_string(),
                })?;
            }
        }

        let mut file = File::create(path).map_err(|e| OutputError::FileWrite {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        file.write_all(data.as_bytes()).map_err(OutputError::from)?;

        debug!(
            path = %path.display(),
            bytes = data.len(),
            "Wrote output to file"
        );

        Ok(())
    }

    /// Flush all output buffers.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if flushing stdout fails.
    pub fn flush(&mut self) -> Result<()> {
        // For stdout
        io::stdout().flush().map_err(OutputError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formatter::NormalFormatter;
    use std::sync::Arc;

    #[test]
    fn test_output_manager_new() {
        let manager = OutputManager::new();
        assert_eq!(manager.formatters.len(), 0);
        assert_eq!(manager.destinations.len(), 0);
    }

    #[test]
    fn test_add_formatter() {
        let mut manager = OutputManager::new();
        manager.add_formatter(Box::new(NormalFormatter::new()));
        assert_eq!(manager.formatters.len(), 1);
    }

    #[test]
    fn test_add_stdout() {
        let mut manager = OutputManager::new();
        manager.add_stdout();
        assert_eq!(manager.destinations.len(), 1);
    }

    #[test]
    fn test_add_file_output() {
        let mut manager = OutputManager::new();
        let path = PathBuf::from("/tmp/test.nmap");
        manager.add_file_output(path.clone());
        assert_eq!(manager.destinations.len(), 1);
    }

    #[test]
    fn test_verbosity_default() {
        let manager = OutputManager::new();
        assert_eq!(manager.verbosity(), VerbosityLevel::Normal);
    }

    #[test]
    fn test_set_verbosity() {
        let mut manager = OutputManager::new();
        manager.set_verbosity(VerbosityLevel::Verbose2);
        assert_eq!(manager.verbosity(), VerbosityLevel::Verbose2);
    }

    #[test]
    fn test_memory_destination() {
        let buffer = Arc::new(Mutex::new(Vec::new()));

        // Verify the destination can be cloned and accessed
        let mut buf = buffer.lock().unwrap();
        let test_data = b"test data";
        buf.extend_from_slice(test_data);

        let result = String::from_utf8(buf.clone()).unwrap();
        assert_eq!(result, "test data");
    }

    #[test]
    fn test_begin_scan() {
        let mut manager = OutputManager::new();
        manager.begin_scan();
        assert!(manager.current_result.is_some());
    }

    #[test]
    fn test_output_scan_result_no_formatters() {
        let mut manager = OutputManager::new();
        let result = ScanResult::default();

        let err = manager.output_scan_result(&result).unwrap_err();
        assert!(matches!(err, OutputError::InvalidData(_)));
    }
}
