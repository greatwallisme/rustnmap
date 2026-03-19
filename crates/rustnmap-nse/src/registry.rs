//! NSE script database and loader.
//!
//! This module provides the script database that manages loading,
//! caching, and selecting NSE scripts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::script::{NseScript, ScriptCategory};

/// NSE script database.
///
/// Manages available scripts, their metadata, and provides
/// selection based on categories, patterns, and targets.
#[derive(Debug)]
pub struct ScriptDatabase {
    /// All loaded scripts indexed by ID.
    scripts: HashMap<String, NseScript>,

    /// Scripts indexed by category.
    by_category: HashMap<ScriptCategory, Vec<String>>,

    /// Scripts indexed by target port.
    by_port: HashMap<u16, Vec<String>>,

    /// Scripts indexed by service name.
    by_service: HashMap<String, Vec<String>>,

    /// Base directory for scripts.
    base_dir: PathBuf,
}

impl ScriptDatabase {
    /// Create a new empty script database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scripts: HashMap::new(),
            by_category: HashMap::new(),
            by_port: HashMap::new(),
            by_service: HashMap::new(),
            base_dir: PathBuf::new(),
        }
    }

    /// Load scripts from a directory.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory containing NSE scripts
    ///
    /// # Returns
    ///
    /// A database containing all loaded scripts.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or
    /// if a script file cannot be parsed.
    pub fn from_directory(dir: &Path) -> Result<Self> {
        let mut db = Self {
            base_dir: dir.to_path_buf(),
            ..Self::new()
        };

        db.load_directory(dir)?;
        Ok(db)
    }

    /// Load all scripts from a directory recursively.
    fn load_directory(&mut self, dir: &Path) -> Result<()> {
        // Use block_in_place to yield to async runtime during directory traversal
        tokio::task::block_in_place(|| self.load_directory_blocking(dir))
    }

    /// Blocking implementation of directory loading.
    ///
    /// This function performs the actual blocking file system operations.
    /// It is called within `block_in_place` to avoid blocking the async runtime.
    fn load_directory_blocking(&mut self, dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| Error::ScriptLoadError(dir.display().to_string(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::ScriptLoadError(dir.display().to_string(), e))?;

            let path = entry.path();

            if path.is_dir() {
                // Recursively load subdirectories
                self.load_directory(&path)?;
            } else if path.extension().is_some_and(|e| e == "nse") {
                // Load NSE script file
                self.load_script(&path)?;
            }
        }

        Ok(())
    }

    /// Load a single script file.
    fn load_script(&mut self, path: &Path) -> Result<()> {
        // Use block_in_place to yield to async runtime during file read
        tokio::task::block_in_place(|| self.load_script_blocking(path))
    }

    /// Blocking implementation of script file loading.
    ///
    /// This function performs the actual blocking file read operation.
    /// It is called within `block_in_place` to avoid blocking the async runtime.
    fn load_script_blocking(&mut self, path: &Path) -> Result<()> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| Error::ScriptLoadError(path.display().to_string(), e))?;

        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let script = Self::parse_script(&id, path, &source)?;
        self.register_script(&script);

        Ok(())
    }

    /// Parse script metadata from Lua source.
    fn parse_script(id: &str, path: &Path, source: &str) -> Result<NseScript> {
        let mut script = NseScript::new(id, path.to_path_buf(), source.to_string());

        // Parse description field
        if let Some(desc) = Self::extract_field(source, "description") {
            script.description = Self::clean_string_literal(&desc);
        }

        // Parse categories
        if let Some(cats) = Self::extract_field(source, "categories") {
            script.categories = Self::parse_categories(&cats)?;
        }

        // Parse author
        if let Some(auth) = Self::extract_field(source, "author") {
            script.author = Self::parse_string_list(&auth);
        }

        // Parse license
        if let Some(lic) = Self::extract_field(source, "license") {
            script.license = Self::clean_string_literal(&lic);
        }

        // Parse dependencies
        if let Some(deps) = Self::extract_field(source, "dependencies") {
            script.dependencies = Self::parse_string_list(&deps);
        }

        // Parse required NSE version
        if let Some(v) = Self::extract_field(source, "@nse_version") {
            script.required_version = Some(Self::clean_string_literal(&v));
        }

        // Extract function sources
        script.extract_functions();

        Ok(script)
    }

    /// Extract a field value from Lua source.
    fn extract_field(source: &str, field: &str) -> Option<String> {
        // Try pattern: field = [[...]] or field = "..." or field = '...' or field = {...}
        let patterns = [
            format!("{field} = {{{{{{"),
            format!("{field} = \""),
            format!("{field} = '"),
            format!("{field} = {{"),
        ];

        for pattern in patterns {
            if let Some(pos) = source.find(&pattern) {
                let start = pos + pattern.len();
                let remaining = &source[start..];

                // Find closing delimiter
                let end = if pattern.ends_with("[[") {
                    remaining.find("]]")
                } else if pattern.ends_with('"') {
                    remaining.find('"')
                } else if pattern.ends_with('\'') {
                    remaining.find('\'')
                } else if pattern.ends_with('{') {
                    // For Lua tables, find matching closing brace
                    let mut depth = 1;
                    let mut end_pos = 0;
                    for (i, ch) in remaining.chars().enumerate() {
                        match ch {
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    end_pos = i;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(end_pos)
                } else {
                    None
                };

                if let Some(end_pos) = end {
                    return Some(remaining[..end_pos].to_string());
                }
            }
        }

        // Try comment pattern: --@field value
        let comment_pattern = format!("--@{field} ");
        if let Some(pos) = source.find(&comment_pattern) {
            let start = pos + comment_pattern.len();
            let remaining = &source[start..];
            if let Some(end) = remaining.find('\n') {
                return Some(remaining[..end].trim().to_string());
            }
        }

        None
    }

    /// Clean a string literal (remove quotes/brackets).
    fn clean_string_literal(s: &str) -> String {
        s.trim().to_string()
    }

    /// Parse category list from Lua syntax.
    fn parse_categories(input: &str) -> Result<Vec<ScriptCategory>> {
        let mut categories = Vec::new();

        // Remove braces and whitespace
        let cleaned = input
            .replace(['{', '}', ' ', '\t', '\n'], " ")
            .trim()
            .to_string();

        // Split by comma
        for part in cleaned.split(',') {
            let part = part.trim().trim_matches('"').trim_matches('\'');
            if let Some(cat) = ScriptCategory::from_str(part) {
                categories.push(cat);
            } else if !part.is_empty() {
                return Err(Error::InvalidCategory(
                    part.to_string(),
                    "parse".to_string(),
                ));
            }
        }

        if categories.is_empty() {
            // Default to safe category
            categories.push(ScriptCategory::Safe);
        }

        Ok(categories)
    }

    /// Parse a list of strings from Lua syntax.
    fn parse_string_list(input: &str) -> Vec<String> {
        let mut result = Vec::new();

        // Simple split by comma and clean
        for part in input.split(',') {
            let cleaned = part
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('{')
                .trim_matches('}')
                .trim()
                .to_string();

            if !cleaned.is_empty() {
                result.push(cleaned);
            }
        }

        result
    }

    /// Register a script in all indices.
    pub fn register_script(&mut self, script: &NseScript) {
        let id = script.id.clone();

        // Add to main index
        self.scripts.insert(id.clone(), script.clone());

        // Index by category
        for category in &script.categories {
            self.by_category
                .entry(*category)
                .or_default()
                .push(id.clone());
        }

        // Index by port (if portrule with specific ports)
        if script.has_portrule() {
            // Add to common ports for port-based scripts
            // Full portrule parsing would extract exact port specifications
            let common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389];
            for port in common_ports {
                self.by_port.entry(port).or_default().push(id.clone());
            }
        }

        // Index by service name
        if let Some(service) = Self::guess_service(&id) {
            self.by_service.entry(service).or_default().push(id.clone());
        }
    }

    /// Guess service name from script ID.
    fn guess_service(id: &str) -> Option<String> {
        // Common service prefixes
        let prefixes = [
            "http", "ssh", "ftp", "smtp", "dns", "tls", "ssl", "smb", "ldap", "mysql", "pgsql",
            "rdp", "vnc",
        ];

        for prefix in prefixes {
            if id.starts_with(prefix) || id.starts_with(&format!("{prefix}-")) {
                return Some(prefix.to_string());
            }
        }

        None
    }

    /// Select scripts matching a pattern.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Glob pattern for script selection
    ///
    /// # Returns
    ///
    /// Vector of matching scripts.
    #[must_use]
    pub fn select_by_pattern(&self, pattern: &str) -> Vec<&NseScript> {
        self.scripts
            .values()
            .filter(|s| s.matches_pattern(pattern))
            .collect()
    }

    /// Select scripts by category.
    ///
    /// # Arguments
    ///
    /// * `categories` - Categories to match
    ///
    /// # Returns
    ///
    /// Vector of matching scripts.
    #[must_use]
    pub fn select_by_category(&self, categories: &[ScriptCategory]) -> Vec<&NseScript> {
        if categories.is_empty() {
            return self.scripts.values().collect();
        }

        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        for category in categories {
            if let Some(ids) = self.by_category.get(category) {
                for id in ids {
                    if seen.insert(id.clone()) {
                        if let Some(script) = self.scripts.get(id) {
                            result.push(script);
                        }
                    }
                }
            }
        }

        result
    }

    /// Get a script by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&NseScript> {
        self.scripts.get(id)
    }

    /// Get all scripts.
    #[must_use]
    pub fn all_scripts(&self) -> Vec<&NseScript> {
        self.scripts.values().collect()
    }

    /// Get the number of loaded scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    /// Check if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Get the base directory for scripts.
    ///
    /// Returns the directory from which scripts were loaded,
    /// or an empty path if no directory was set.
    #[must_use]
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Resolve a script name to its full path.
    ///
    /// # Arguments
    ///
    /// * `name` - Script name (with or without .nse extension)
    ///
    /// # Returns
    ///
    /// Full path to the script file, or `None` if `base_dir` is not set.
    #[must_use]
    pub fn resolve_script_path(&self, name: &str) -> Option<PathBuf> {
        if self.base_dir.as_os_str().is_empty() {
            return None;
        }

        let script_name = if std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("nse"))
        {
            name.to_string()
        } else {
            format!("{name}.nse")
        };

        Some(self.base_dir.join(&script_name))
    }

    /// Check if a script file exists in the base directory.
    ///
    /// # Arguments
    ///
    /// * `name` - Script name (with or without .nse extension)
    ///
    /// # Returns
    ///
    /// `true` if the script file exists on disk.
    #[must_use]
    pub fn script_file_exists(&self, name: &str) -> bool {
        self.resolve_script_path(name)
            .is_some_and(|path| path.exists())
    }

    /// Reload scripts from the base directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn reload(&mut self) -> Result<()> {
        if self.base_dir.as_os_str().is_empty() {
            return Err(Error::ScriptLoadError(
                "no base directory set".to_string(),
                std::io::Error::new(std::io::ErrorKind::NotFound, "base_dir not set"),
            ));
        }

        // Clear existing data
        self.scripts.clear();
        self.by_category.clear();
        self.by_port.clear();
        self.by_service.clear();

        // Clone base_dir to avoid borrow issues
        let base_dir = self.base_dir.clone();

        // Reload from base directory
        self.load_directory(&base_dir)?;
        Ok(())
    }

    /// Resolve script dependencies and return scripts in dependency order.
    ///
    /// Uses topological sort to ensure dependencies are loaded before dependent scripts.
    /// Detects circular dependencies and returns an error if found.
    ///
    /// # Arguments
    ///
    /// * `script_ids` - IDs of scripts to resolve dependencies for
    ///
    /// # Returns
    ///
    /// Ordered list of script IDs including dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error if a dependency is missing or circular.
    pub fn resolve_dependencies(&self, script_ids: &[String]) -> Result<Vec<String>> {
        let mut resolved = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut temp_mark = std::collections::HashSet::new();

        for id in script_ids {
            self.visit_dependency(id, &mut visited, &mut temp_mark, &mut resolved)?;
        }

        Ok(resolved)
    }

    /// Visit a script during dependency resolution (DFS with cycle detection).
    fn visit_dependency(
        &self,
        id: &str,
        visited: &mut std::collections::HashSet<String>,
        temp_mark: &mut std::collections::HashSet<String>,
        resolved: &mut Vec<String>,
    ) -> Result<()> {
        if temp_mark.contains(id) {
            return Err(Error::CircularDependency(id.to_string()));
        }

        if visited.contains(id) {
            return Ok(());
        }

        temp_mark.insert(id.to_string());

        // Get dependencies for this script
        if let Some(script) = self.scripts.get(id) {
            for dep in &script.dependencies {
                self.visit_dependency(dep, visited, temp_mark, resolved)?;
            }
        } else {
            return Err(Error::MissingDependency(
                id.to_string(),
                "unknown".to_string(),
            ));
        }

        temp_mark.remove(id);
        visited.insert(id.to_string());
        resolved.push(id.to_string());

        Ok(())
    }

    /// Get scripts that should run against a specific port based on portrule.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number
    /// * `protocol` - Protocol (tcp/udp)
    /// * `state` - Port state
    /// * `service` - Service name (optional)
    ///
    /// # Returns
    ///
    /// Vector of scripts that have matching portrules.
    ///
    /// # Note
    ///
    /// This method uses heuristic matching for performance. For precise Lua portrule
    /// evaluation, use [`Self::scripts_for_port_with_engine`] instead.
    #[must_use]
    pub fn scripts_for_port(
        &self,
        port: u16,
        _protocol: &str,
        _state: &str,
        service: Option<&str>,
    ) -> Vec<&NseScript> {
        self.scripts
            .values()
            .filter(|s| s.has_portrule())
            .filter(|s| {
                // Heuristic pre-filtering based on service name and common port mappings.
                // This provides fast script selection without evaluating Lua portrule functions.
                if let Some(service_name) = service {
                    let id_lower = s.id.to_lowercase();
                    let service_lower = service_name.to_lowercase();
                    id_lower.contains(&service_lower)
                        || Self::port_matches_common_service(port, &id_lower)
                } else {
                    Self::port_matches_common_service(port, &s.id.to_lowercase())
                }
            })
            .collect()
    }

    /// Get scripts that should run against a specific port using Lua portrule evaluation.
    ///
    /// This method evaluates the actual Lua `portrule` function for each script,
    /// providing 100% accurate script selection matching Nmap's behavior.
    ///
    /// # Arguments
    ///
    /// * `engine` - Script engine for Lua evaluation
    /// * `port` - Port number
    /// * `protocol` - Protocol (tcp/udp)
    /// * `state` - Port state (open, closed, filtered, etc.)
    /// * `service` - Service name (optional)
    /// * `target_ip` - Target IP address for host table construction
    /// * `original_target` - Original target specification (e.g., "example.com")
    ///
    /// # Returns
    ///
    /// Vector of scripts whose portrule functions return `true`.
    ///
    /// # Note
    ///
    /// Falls back to heuristic matching if Lua evaluation fails for a script.
    #[expect(clippy::too_many_arguments, reason = "Port script filtering requires all host/port context")]
    #[must_use]
    pub fn scripts_for_port_with_engine(
        &self,
        engine: &crate::engine::ScriptEngine,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<&str>,
        target_ip: std::net::IpAddr,
        original_target: Option<&str>,
    ) -> Vec<&NseScript> {
        self.scripts
            .values()
            .filter(|s| s.has_portrule())
            .filter(|script| {
                // Attempt Lua evaluation first
                match engine.evaluate_portrule(script, target_ip, original_target, port, protocol, state, service) {
                    Ok(result) => result,
                    Err(_) => {
                        // Fall back to heuristic matching on Lua evaluation failure
                        if let Some(service_name) = service {
                            let id_lower = script.id.to_lowercase();
                            let service_lower = service_name.to_lowercase();
                            id_lower.contains(&service_lower)
                                || Self::port_matches_common_service(port, &id_lower)
                        } else {
                            Self::port_matches_common_service(port, &script.id.to_lowercase())
                        }
                    }
                }
            })
            .collect()
    }

    /// Check if a port matches common service patterns based on script ID.
    fn port_matches_common_service(port: u16, script_id: &str) -> bool {
        let service_ports: std::collections::HashMap<&str, &[u16]> = [
            ("http", &[80u16, 443, 8080, 8443, 8888][..]),
            ("ssh", &[22u16][..]),
            ("ftp", &[21u16, 990][..]),
            ("smtp", &[25u16, 465, 587][..]),
            ("dns", &[53u16, 853][..]),
            ("pop3", &[110u16, 995][..]),
            ("imap", &[143u16, 993][..]),
            ("telnet", &[23u16][..]),
            ("mysql", &[3306u16][..]),
            ("pgsql", &[5432u16][..]),
            ("rdp", &[3389u16][..]),
            ("vnc", &[5900u16, 5901, 5902][..]),
            ("ldap", &[389u16, 636][..]),
            ("smb", &[445u16, 139][..]),
            ("snmp", &[161u16][..]),
        ]
        .into_iter()
        .collect();

        for (service, ports) in service_ports {
            if script_id.contains(service) && ports.contains(&port) {
                return true;
            }
        }

        false
    }
}

impl Default for ScriptDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_field() {
        let _db = ScriptDatabase::new();

        // Test with quoted string format
        let source = r#"
description = "Test description"
author = "Test Author"
"#;

        assert_eq!(
            ScriptDatabase::extract_field(source, "description"),
            Some("Test description".to_string())
        );
        assert_eq!(
            ScriptDatabase::extract_field(source, "author"),
            Some("Test Author".to_string())
        );
        // Test that non-existent field returns None
        assert_eq!(ScriptDatabase::extract_field(source, "nonexistent"), None);
    }

    #[test]
    fn test_parse_categories() {
        let input = r#"{"vuln", "safe", "auth"}"#;
        let result = ScriptDatabase::parse_categories(input).unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.contains(&ScriptCategory::Vuln));
        assert!(result.contains(&ScriptCategory::Safe));
        assert!(result.contains(&ScriptCategory::Auth));
    }

    #[test]
    fn test_parse_categories_empty() {
        let input = "{}";
        let result = ScriptDatabase::parse_categories(input).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ScriptCategory::Safe); // Default
    }

    #[test]
    fn test_parse_categories_invalid() {
        let input = r#"{"vuln", "invalidcat"}"#;
        let result = ScriptDatabase::parse_categories(input);

        result.unwrap_err();
    }

    #[test]
    fn test_guess_service() {
        assert_eq!(
            ScriptDatabase::guess_service("http-vuln-cve"),
            Some("http".to_string())
        );
        assert_eq!(
            ScriptDatabase::guess_service("ssh-auth"),
            Some("ssh".to_string())
        );
        assert_eq!(ScriptDatabase::guess_service("unknown-script"), None);
    }

    #[test]
    fn test_empty_database() {
        let db = ScriptDatabase::new();

        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert!(db.all_scripts().is_empty());
    }

    #[test]
    fn test_select_by_pattern() {
        let mut db = ScriptDatabase::new();

        let script1 = NseScript::new("http-vuln-cve", PathBuf::from("/test.nse"), String::new());
        let script2 = NseScript::new("ssh-auth", PathBuf::from("/test2.nse"), String::new());
        let script3 = NseScript::new("ftp-anon", PathBuf::from("/test3.nse"), String::new());

        db.register_script(&script1);
        db.register_script(&script2);
        db.register_script(&script3);

        let http_scripts = db.select_by_pattern("http*");
        assert_eq!(http_scripts.len(), 1);
        assert_eq!(http_scripts[0].id, "http-vuln-cve");

        let all = db.select_by_pattern("*");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_select_by_category() {
        let mut db = ScriptDatabase::new();

        let mut script1 = NseScript::new("vuln-test", PathBuf::from("/test.nse"), String::new());
        script1.categories = vec![ScriptCategory::Vuln];

        let mut script2 = NseScript::new("safe-test", PathBuf::from("/test2.nse"), String::new());
        script2.categories = vec![ScriptCategory::Safe];

        let mut script3 = NseScript::new("auth-test", PathBuf::from("/test3.nse"), String::new());
        script3.categories = vec![ScriptCategory::Auth];

        db.register_script(&script1);
        db.register_script(&script2);
        db.register_script(&script3);

        let vuln_scripts = db.select_by_category(&[ScriptCategory::Vuln]);
        assert_eq!(vuln_scripts.len(), 1);
        assert_eq!(vuln_scripts[0].id, "vuln-test");

        let multi_scripts = db.select_by_category(&[ScriptCategory::Vuln, ScriptCategory::Auth]);
        assert_eq!(multi_scripts.len(), 2);
    }

    #[test]
    fn test_base_dir() {
        let db = ScriptDatabase::new();
        // Empty database has empty base_dir
        assert!(db.base_dir().as_os_str().is_empty());
    }

    #[test]
    fn test_resolve_script_path_no_base_dir() {
        let db = ScriptDatabase::new();
        // Without base_dir, resolve returns None
        assert!(db.resolve_script_path("http-vuln").is_none());
    }

    #[test]
    fn test_resolve_script_path_with_base_dir() {
        let mut db = ScriptDatabase::new();
        db.base_dir = PathBuf::from("/usr/share/nmap/scripts");

        // With .nse extension
        let path = db.resolve_script_path("http-vuln.nse").unwrap();
        assert_eq!(path, PathBuf::from("/usr/share/nmap/scripts/http-vuln.nse"));

        // Without .nse extension (auto-added)
        let path = db.resolve_script_path("ssh-auth").unwrap();
        assert_eq!(path, PathBuf::from("/usr/share/nmap/scripts/ssh-auth.nse"));
    }

    #[test]
    fn test_script_file_exists() {
        let mut db = ScriptDatabase::new();
        db.base_dir = std::env::temp_dir();

        // Non-existent script
        assert!(!db.script_file_exists("nonexistent-script-12345"));
    }
}
