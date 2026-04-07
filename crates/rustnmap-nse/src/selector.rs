//! NSE script selector with nmap-compatible syntax.
//!
//! Supports the full nmap --script argument syntax:
//! - Script names: `http-title`, `banner`
//! - Categories: `default`, `vuln`, `auth`
//! - Wildcards: `http-*`, `*ssl*`
//! - Boolean expressions: `http-title or banner`, `vuln and not intrusive`
//! - All scripts: `all`
//!
//! # Example
//!
//! ```
//! use rustnmap_nse::ScriptSelector;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let selector = ScriptSelector::parse("http-title or banner")?;
//! # Ok(())
//! # }
//! ```

use crate::registry::ScriptIndexEntry;
use crate::script::match_pattern;
use crate::{ScriptCategory, ScriptDatabase};

/// Error during script selector parsing.
#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    /// Invalid syntax in selector expression.
    #[error("invalid selector syntax: {0}")]
    InvalidSyntax(String),

    /// Unknown script category.
    #[error("unknown script category: {0}")]
    UnknownCategory(String),

    /// Empty selector expression.
    #[error("empty selector expression")]
    EmptyExpression,
}

/// Script selector with nmap-compatible syntax.
///
/// Parses and evaluates --script argument expressions.
#[derive(Debug, Clone)]
pub enum ScriptSelector {
    /// Select all scripts.
    All,

    /// Select scripts by category.
    Category(Vec<ScriptCategory>),

    /// Select scripts by name pattern.
    Pattern(String),

    /// Boolean AND expression.
    And(Box<ScriptSelector>, Box<ScriptSelector>),

    /// Boolean OR expression.
    Or(Box<ScriptSelector>, Box<ScriptSelector>),

    /// Boolean NOT expression.
    Not(Box<ScriptSelector>),
}

impl ScriptSelector {
    /// Parse a selector expression.
    ///
    /// # Arguments
    ///
    /// * `expr` - Selector expression (e.g., "http-title", "default,vuln", "http-* or banner")
    ///
    /// # Errors
    ///
    /// Returns `SelectorError` if the expression has invalid syntax.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_nse::ScriptSelector;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Single script
    /// let selector = ScriptSelector::parse("http-title")?;
    ///
    /// // Multiple scripts (comma-separated = OR)
    /// let selector = ScriptSelector::parse("http-title,banner")?;
    ///
    /// // Category
    /// let selector = ScriptSelector::parse("vuln")?;
    ///
    /// // Wildcard
    /// let selector = ScriptSelector::parse("http-*")?;
    ///
    /// // Boolean expression
    /// let selector = ScriptSelector::parse("http-title or banner")?;
    /// let selector = ScriptSelector::parse("vuln and not intrusive")?;
    ///
    /// // All scripts
    /// let selector = ScriptSelector::parse("all")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(expr: &str) -> Result<Self, SelectorError> {
        let expr = expr.trim();
        if expr.is_empty() {
            return Err(SelectorError::EmptyExpression);
        }

        // Check for "all"
        if expr.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }

        // Try parsing as boolean expression
        Self::parse_or(expr)
    }

    /// Parse OR expressions (lowest precedence).
    fn parse_or(expr: &str) -> Result<Self, SelectorError> {
        // Handle comma-separated values (equivalent to OR in nmap)
        if expr.contains(',') {
            let parts: Vec<&str> = expr.split(',').map(str::trim).collect();
            if parts.is_empty() {
                return Err(SelectorError::EmptyExpression);
            }

            let mut result = Self::parse_and(parts[0])?;
            for part in &parts[1..] {
                result = Self::Or(Box::new(result), Box::new(Self::parse_and(part)?));
            }
            return Ok(result);
        }

        // Handle explicit "or"
        let tokens = Self::tokenize(expr)?;
        if tokens.contains(&Token::Or) {
            return Self::parse_or_from_tokens(&tokens);
        }

        Self::parse_and(expr)
    }

    /// Parse OR from token list.
    fn parse_or_from_tokens(tokens: &[Token]) -> Result<Self, SelectorError> {
        let or_pos = tokens
            .iter()
            .position(|t| matches!(t, Token::Or))
            .ok_or_else(|| SelectorError::InvalidSyntax("Missing OR token".to_string()))?;

        let left_tokens = &tokens[..or_pos];
        let right_tokens = &tokens[or_pos + 1..];

        let left = Self::parse_and_from_tokens(left_tokens)?;
        let right = Self::parse_and_from_tokens(right_tokens)?;

        Ok(Self::Or(Box::new(left), Box::new(right)))
    }

    /// Parse AND expressions (medium precedence).
    fn parse_and(expr: &str) -> Result<Self, SelectorError> {
        let tokens = Self::tokenize(expr)?;
        Self::parse_and_from_tokens(&tokens)
    }

    /// Parse AND from token list.
    fn parse_and_from_tokens(tokens: &[Token]) -> Result<Self, SelectorError> {
        if let Some(and_pos) = tokens.iter().position(|t| matches!(t, Token::And)) {
            let left_tokens = &tokens[..and_pos];
            let right_tokens = &tokens[and_pos + 1..];

            let left = Self::parse_not_from_tokens(left_tokens)?;
            let right = Self::parse_not_from_tokens(right_tokens)?;

            return Ok(Self::And(Box::new(left), Box::new(right)));
        }

        Self::parse_not_from_tokens(tokens)
    }

    /// Parse NOT expressions (highest precedence).
    fn parse_not_from_tokens(tokens: &[Token]) -> Result<Self, SelectorError> {
        if tokens.is_empty() {
            return Err(SelectorError::EmptyExpression);
        }

        if let Some(Token::Not) = tokens.first() {
            if tokens.len() == 1 {
                return Err(SelectorError::InvalidSyntax(
                    "NOT requires an operand".to_string(),
                ));
            }
            let operand = Self::parse_not_from_tokens(&tokens[1..])?;
            return Ok(Self::Not(Box::new(operand)));
        }

        Self::parse_primary_from_tokens(tokens)
    }

    /// Parse primary expression (atom).
    fn parse_primary_from_tokens(tokens: &[Token]) -> Result<Self, SelectorError> {
        if tokens.len() != 1 {
            return Err(SelectorError::InvalidSyntax(
                "Expected single atom".to_string(),
            ));
        }

        match &tokens[0] {
            Token::Identifier(id) => Ok(Self::parse_identifier(id)),
            _ => Err(SelectorError::InvalidSyntax(
                "Expected identifier".to_string(),
            )),
        }
    }

    /// Parse an identifier (category or pattern).
    fn parse_identifier(id: &str) -> Self {
        // Check if it's a known category
        if let Ok(category) = Self::parse_category(id) {
            return Self::Category(vec![category]);
        }

        // Otherwise treat as pattern
        Self::Pattern(id.to_string())
    }

    /// Parse a category name.
    fn parse_category(name: &str) -> Result<ScriptCategory, SelectorError> {
        match name.to_lowercase().as_str() {
            "auth" => Ok(ScriptCategory::Auth),
            "broadcast" => Ok(ScriptCategory::Broadcast),
            "brute" => Ok(ScriptCategory::Brute),
            "default" => Ok(ScriptCategory::Default),
            "discovery" => Ok(ScriptCategory::Discovery),
            "dos" => Ok(ScriptCategory::Dos),
            "exploit" => Ok(ScriptCategory::Exploit),
            "external" => Ok(ScriptCategory::External),
            "fuzzer" => Ok(ScriptCategory::Fuzzer),
            "intrusive" => Ok(ScriptCategory::Intrusive),
            "malware" => Ok(ScriptCategory::Malware),
            "info" => Ok(ScriptCategory::Info),
            "safe" => Ok(ScriptCategory::Safe),
            "version" => Ok(ScriptCategory::Version),
            "vuln" => Ok(ScriptCategory::Vuln),
            _ => Err(SelectorError::UnknownCategory(name.to_string())),
        }
    }

    /// Tokenize an expression.
    fn tokenize(expr: &str) -> Result<Vec<Token>, SelectorError> {
        let mut tokens = Vec::new();
        let mut current = String::new();

        for ch in expr.chars() {
            match ch {
                ' ' | '\t' | '\n' | '\r' => {
                    if !current.is_empty() {
                        tokens.push(Token::Identifier(current.clone()));
                        current.clear();
                    }
                }
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '*' | '_' | '.' => {
                    current.push(ch);
                }
                _ => {
                    return Err(SelectorError::InvalidSyntax(format!(
                        "Invalid character: {ch}"
                    )))
                }
            }
        }

        if !current.is_empty() {
            tokens.push(Token::Identifier(current));
        }

        // Second pass: identify operators
        let mut result = Vec::new();

        for token in tokens {
            match token {
                Token::Identifier(ref id) if id.eq_ignore_ascii_case("and") => {
                    result.push(Token::And);
                }
                Token::Identifier(ref id) if id.eq_ignore_ascii_case("or") => {
                    result.push(Token::Or);
                }
                Token::Identifier(ref id) if id.eq_ignore_ascii_case("not") => {
                    result.push(Token::Not);
                }
                _ => {
                    result.push(token);
                }
            }
        }

        Ok(result)
    }

    /// Select scripts from database using this selector.
    ///
    /// # Arguments
    ///
    /// * `db` - Script database to select from
    ///
    /// # Returns
    ///
    /// Vector of selected scripts.
    #[must_use]
    pub fn select<'a>(&'a self, db: &'a ScriptDatabase) -> Vec<&'a crate::NseScript> {
        match self {
            Self::All => db.all_scripts(),
            Self::Category(categories) => db.select_by_category(categories),
            Self::Pattern(pattern) => db.select_by_pattern(pattern),
            Self::And(left, right) => {
                let left_set: std::collections::HashSet<_> =
                    left.select(db).into_iter().map(|s| s.id.clone()).collect();
                let right_set: std::collections::HashSet<_> =
                    right.select(db).into_iter().map(|s| s.id.clone()).collect();

                left_set
                    .intersection(&right_set)
                    .filter_map(|id| db.get(id.as_str()))
                    .collect()
            }
            Self::Or(left, right) => {
                let mut result = std::collections::HashSet::new();

                for script in left.select(db) {
                    result.insert(script.id.clone());
                }
                for script in right.select(db) {
                    result.insert(script.id.clone());
                }

                result
                    .into_iter()
                    .filter_map(|id| db.get(id.as_str()))
                    .collect()
            }
            Self::Not(operand) => {
                let excluded: std::collections::HashSet<_> = operand
                    .select(db)
                    .into_iter()
                    .map(|s| s.id.clone())
                    .collect();

                db.all_scripts()
                    .into_iter()
                    .filter(|s| !excluded.contains(&s.id))
                    .collect()
            }
        }
    }

    /// Select index entries matching this selector (nmap-style script.db).
    ///
    /// Works like [`Self::select`] but on the lightweight index instead
    /// of the full database. Used during Phase 2 to decide which scripts
    /// to lazy-load.
    ///
    /// # Arguments
    ///
    /// * `index` - Lightweight script index built during Phase 1
    ///
    /// # Returns
    ///
    /// Vector of references to matching index entries.
    #[must_use]
    pub fn select_from_index<'a>(
        &self,
        index: &'a [ScriptIndexEntry],
    ) -> Vec<&'a ScriptIndexEntry> {
        match self {
            Self::All => index.iter().collect(),
            Self::Category(categories) => index
                .iter()
                .filter(|entry| entry.matches_categories(categories))
                .collect(),
            Self::Pattern(pattern) => index
                .iter()
                .filter(|entry| entry.matches_pattern(pattern))
                .collect(),
            Self::And(left, right) => {
                let left_set: std::collections::HashSet<_> = left
                    .select_from_index(index)
                    .into_iter()
                    .map(|e| e.basename.clone())
                    .collect();
                let right_set: std::collections::HashSet<_> = right
                    .select_from_index(index)
                    .into_iter()
                    .map(|e| e.basename.clone())
                    .collect();

                left_set
                    .intersection(&right_set)
                    .filter_map(|basename| index.iter().find(|e| e.basename == *basename))
                    .collect()
            }
            Self::Or(left, right) => {
                let mut result = std::collections::HashSet::new();

                for entry in left.select_from_index(index) {
                    result.insert(entry.basename.clone());
                }
                for entry in right.select_from_index(index) {
                    result.insert(entry.basename.clone());
                }

                result
                    .into_iter()
                    .filter_map(|basename| index.iter().find(|e| e.basename == basename))
                    .collect()
            }
            Self::Not(operand) => {
                let excluded: std::collections::HashSet<_> = operand
                    .select_from_index(index)
                    .into_iter()
                    .map(|e| e.basename.clone())
                    .collect();

                index
                    .iter()
                    .filter(|entry| !excluded.contains(&entry.basename))
                    .collect()
            }
        }
    }
}

/// Pattern matching helpers for [`ScriptIndexEntry`].
impl ScriptIndexEntry {
    /// Check if the index entry matches any of the given categories.
    fn matches_categories(&self, categories: &[ScriptCategory]) -> bool {
        if categories.is_empty() {
            return true;
        }
        self.categories.iter().any(|c| categories.contains(c))
    }

    /// Check if the index entry basename matches a name pattern.
    ///
    /// Mirrors [`crate::NseScript::matches_pattern`] logic: strips `.nse`,
    /// supports glob wildcards (`*`, `?`), and falls back to exact/substring.
    fn matches_pattern(&self, pattern: &str) -> bool {
        let normalized = pattern.strip_suffix(".nse").unwrap_or(pattern);

        if normalized.contains('*') || normalized.contains('?') {
            match_pattern(&self.basename, normalized)
        } else {
            self.basename == normalized || self.basename.contains(normalized)
        }
    }
}

/// Token in selector expression.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// Identifier (script name, category, or pattern).
    Identifier(String),

    /// AND operator.
    And,

    /// OR operator.
    Or,

    /// NOT operator.
    Not,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_entry(basename: &str, categories: &[ScriptCategory]) -> ScriptIndexEntry {
        ScriptIndexEntry {
            file_path: PathBuf::from(format!("/scripts/{basename}.nse")),
            basename: basename.to_string(),
            categories: categories.to_vec(),
        }
    }

    #[test]
    fn test_parse_all() {
        let selector = ScriptSelector::parse("all").unwrap();
        assert!(matches!(selector, ScriptSelector::All));
    }

    #[test]
    fn test_parse_category() {
        let selector = ScriptSelector::parse("vuln").unwrap();
        assert!(matches!(selector, ScriptSelector::Category(_)));
    }

    #[test]
    fn test_parse_pattern() {
        let selector = ScriptSelector::parse("http-title").unwrap();
        assert!(matches!(selector, ScriptSelector::Pattern(_)));

        let selector = ScriptSelector::parse("http-*").unwrap();
        assert!(matches!(selector, ScriptSelector::Pattern(_)));
    }

    #[test]
    fn test_parse_or() {
        let selector = ScriptSelector::parse("http-title or banner").unwrap();
        assert!(matches!(selector, ScriptSelector::Or(_, _)));
    }

    #[test]
    fn test_parse_and() {
        let selector = ScriptSelector::parse("vuln and safe").unwrap();
        assert!(matches!(selector, ScriptSelector::And(_, _)));
    }

    #[test]
    fn test_parse_not() {
        let selector = ScriptSelector::parse("not intrusive").unwrap();
        assert!(matches!(selector, ScriptSelector::Not(_)));
    }

    #[test]
    fn test_parse_comma_separated() {
        let selector = ScriptSelector::parse("http-title,banner,auth").unwrap();
        assert!(matches!(selector, ScriptSelector::Or(_, _)));
    }

    #[test]
    fn test_parse_complex() {
        let selector = ScriptSelector::parse("vuln and not intrusive").unwrap();
        assert!(matches!(selector, ScriptSelector::And(_, _)));
    }

    #[test]
    fn test_parse_empty() {
        let result = ScriptSelector::parse("");
        assert!(matches!(result, Err(SelectorError::EmptyExpression)));
    }

    #[test]
    fn test_parse_unknown_category() {
        // Should be treated as pattern, not error
        let selector = ScriptSelector::parse("unknown-script").unwrap();
        assert!(matches!(selector, ScriptSelector::Pattern(_)));
    }

    #[test]
    fn test_select_from_index_all() {
        let index = vec![
            make_entry("banner", &[ScriptCategory::Default]),
            make_entry(
                "http-title",
                &[ScriptCategory::Default, ScriptCategory::Discovery],
            ),
        ];
        let selector = ScriptSelector::parse("all").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_select_from_index_category() {
        let index = vec![
            make_entry(
                "vuln-script",
                &[ScriptCategory::Vuln, ScriptCategory::Intrusive],
            ),
            make_entry("safe-script", &[ScriptCategory::Safe]),
            make_entry("auth-script", &[ScriptCategory::Auth]),
        ];
        let selector = ScriptSelector::parse("vuln").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].basename, "vuln-script");
    }

    #[test]
    fn test_select_from_index_pattern() {
        let index = vec![
            make_entry("http-title", &[ScriptCategory::Default]),
            make_entry("http-headers", &[ScriptCategory::Discovery]),
            make_entry("ssh-auth", &[ScriptCategory::Auth]),
        ];
        let selector = ScriptSelector::parse("http-*").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_select_from_index_not() {
        let index = vec![
            make_entry("safe-one", &[ScriptCategory::Safe]),
            make_entry("safe-two", &[ScriptCategory::Safe]),
            make_entry("vuln-one", &[ScriptCategory::Vuln]),
        ];
        let selector = ScriptSelector::parse("not vuln").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_select_from_index_and() {
        let index = vec![
            make_entry("vuln-safe", &[ScriptCategory::Vuln, ScriptCategory::Safe]),
            make_entry("vuln-only", &[ScriptCategory::Vuln]),
            make_entry("safe-only", &[ScriptCategory::Safe]),
        ];
        let selector = ScriptSelector::parse("vuln and safe").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].basename, "vuln-safe");
    }

    #[test]
    fn test_select_from_index_or() {
        let index = vec![
            make_entry("auth-script", &[ScriptCategory::Auth]),
            make_entry("vuln-script", &[ScriptCategory::Vuln]),
            make_entry("safe-script", &[ScriptCategory::Safe]),
        ];
        let selector = ScriptSelector::parse("auth,vuln").unwrap();
        let result = selector.select_from_index(&index);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_index_entry_matches_pattern_exact() {
        let entry = make_entry("http-title", &[ScriptCategory::Default]);
        assert!(entry.matches_pattern("http-title"));
        assert!(entry.matches_pattern("http-title.nse"));
        assert!(entry.matches_pattern("http"));
        assert!(!entry.matches_pattern("ssh-auth"));
    }

    #[test]
    fn test_index_entry_matches_pattern_glob() {
        let entry = make_entry("http-vuln-cve2020", &[ScriptCategory::Vuln]);
        assert!(entry.matches_pattern("http-*"));
        assert!(entry.matches_pattern("*cve*"));
        assert!(!entry.matches_pattern("ssh-*"));
    }
}
