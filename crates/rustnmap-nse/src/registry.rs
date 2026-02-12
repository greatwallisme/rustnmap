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
    #[expect(dead_code, reason = "used for future path resolution")]
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
        let entries = std::fs::read_dir(dir)
            .map_err(|e| Error::ScriptLoadError(dir.display().to_string(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::ScriptLoadError(dir.display().to_string(), e)
            })?;

            let path = entry.path();

            if path.is_dir() {
                // Recursively load subdirectories
                self.load_directory(&path)?;
            } else if path.extension().is_some_and( |e| e == "nse") {
                // Load NSE script file
                self.load_script(&path)?;
            }
        }

        Ok(())
    }

    /// Load a single script file.
    fn load_script(&mut self, path: &Path) -> Result<()> {
        let source = std::fs::read_to_string(path).map_err(|e| {
            Error::ScriptLoadError(path.display().to_string(), e)
        })?;

        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let script = self.parse_script(&id, path, &source)?;
        self.register_script(&script);

        Ok(())
    }

    /// Parse script metadata from Lua source.
    fn parse_script(
        &self,
        id: &str,
        path: &Path,
        source: &str,
    ) -> Result<NseScript> {
        let mut script = NseScript::new(id, path.to_path_buf(), source.to_string());

        // Parse description field
        if let Some(desc) = self.extract_field(source, "description") {
            script.description = self.clean_string_literal(&desc);
        }

        // Parse categories
        if let Some(cats) = self.extract_field(source, "categories") {
            script.categories = self.parse_categories(&cats)?;
        }

        // Parse author
        if let Some(auth) = self.extract_field(source, "author") {
            script.author = self.parse_string_list(&auth);
        }

        // Parse license
        if let Some(lic) = self.extract_field(source, "license") {
            script.license = self.clean_string_literal(&lic);
        }

        // Parse dependencies
        if let Some(deps) = self.extract_field(source, "dependencies") {
            script.dependencies = self.parse_string_list(&deps);
        }

        // Parse required NSE version
        if let Some(v) = self.extract_field(source, "@nse_version") {
            script.required_version = Some(self.clean_string_literal(&v));
        }

        Ok(script)
    }

    /// Extract a field value from Lua source.
    fn extract_field(&self, source: &str, field: &str) -> Option<String> {
        // Try pattern: field = [[...]] or field = "..." or field = '...'
        let patterns = [
            format!("{field} = {{{{{{"),
            format!("{field} = \""),
            format!("{field} = '"),
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
                } else {
                    remaining.find('\'')
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
    fn clean_string_literal(&self, s: &str) -> String {
        s.trim().to_string()
    }

    /// Parse category list from Lua syntax.
    fn parse_categories(&self, input: &str) -> Result<Vec<ScriptCategory>> {
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
                return Err(Error::InvalidCategory(part.to_string(), "parse".to_string()));
            }
        }

        if categories.is_empty() {
            // Default to safe category
            categories.push(ScriptCategory::Safe);
        }

        Ok(categories)
    }

    /// Parse a list of strings from Lua syntax.
    fn parse_string_list(&self, input: &str) -> Vec<String> {
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
        if let Some(service) = self.guess_service(&id) {
            self.by_service
                .entry(service)
                .or_default()
                .push(id.clone());
        }
    }

    /// Guess service name from script ID.
    fn guess_service(&self, id: &str) -> Option<String> {
        // Common service prefixes
        let prefixes = [
            "http", "ssh", "ftp", "smtp", "dns", "tls", "ssl",
            "smb", "ldap", "mysql", "pgsql", "rdp", "vnc",
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
        let db = ScriptDatabase::new();

        // Test with quoted string format
        let source = r#"
description = "Test description"
author = "Test Author"
"#;

        assert_eq!(
            db.extract_field(source, "description"),
            Some("Test description".to_string())
        );
        assert_eq!(
            db.extract_field(source, "author"),
            Some("Test Author".to_string())
        );
        // Test that non-existent field returns None
        assert_eq!(
            db.extract_field(source, "nonexistent"),
            None
        );
    }

    #[test]
    fn test_parse_categories() {
        let db = ScriptDatabase::new();

        let input = r#"{"vuln", "safe", "auth"}"#;
        let result = db.parse_categories(input).unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.contains(&ScriptCategory::Vuln));
        assert!(result.contains(&ScriptCategory::Safe));
        assert!(result.contains(&ScriptCategory::Auth));
    }

    #[test]
    fn test_parse_categories_empty() {
        let db = ScriptDatabase::new();

        let input = "{}";
        let result = db.parse_categories(input).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ScriptCategory::Safe); // Default
    }

    #[test]
    fn test_parse_categories_invalid() {
        let db = ScriptDatabase::new();

        let input = r#"{"vuln", "invalidcat"}"#;
        let result = db.parse_categories(input);

        assert!(result.is_err());
    }

    #[test]
    fn test_guess_service() {
        let db = ScriptDatabase::new();

        assert_eq!(db.guess_service("http-vuln-cve"), Some("http".to_string()));
        assert_eq!(db.guess_service("ssh-auth"), Some("ssh".to_string()));
        assert_eq!(db.guess_service("unknown-script"), None);
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
}
