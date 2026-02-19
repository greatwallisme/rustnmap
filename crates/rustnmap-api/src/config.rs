//! API configuration

use std::time::Duration;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// API keys for authentication
    pub api_keys: Vec<String>,

    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,

    /// Scan result retention duration
    pub result_retention: Duration,

    /// Enable SSE streaming
    pub enable_sse: bool,

    /// Listen address
    pub listen_addr: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            api_keys: vec![generate_api_key()],
            max_concurrent_scans: 5,
            result_retention: Duration::from_secs(24 * 60 * 60), // 24 hours
            enable_sse: true,
            listen_addr: "127.0.0.1:8080".to_string(),
        }
    }
}

impl ApiConfig {
    /// Create new config with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set API keys
    #[must_use]
    pub fn with_api_keys(mut self, keys: Vec<String>) -> Self {
        self.api_keys = keys;
        self
    }

    /// Set max concurrent scans
    #[must_use]
    pub fn with_max_concurrent_scans(mut self, max: usize) -> Self {
        self.max_concurrent_scans = max;
        self
    }

    /// Set listen address
    #[must_use]
    pub fn with_listen_addr(mut self, addr: String) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Check if an API key is valid
    #[must_use]
    pub fn is_valid_key(&self, key: &str) -> bool {
        self.api_keys.iter().any(|k| k == key)
    }
}

/// Generate a random API key
#[must_use]
pub fn generate_api_key() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.max_concurrent_scans, 5);
        assert_eq!(config.result_retention, Duration::from_secs(86400));
        assert!(config.enable_sse);
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.api_keys.len(), 1);
    }

    #[test]
    fn test_api_config_builder() {
        let config = ApiConfig::new()
            .with_api_keys(vec!["test-key".to_string()])
            .with_max_concurrent_scans(10)
            .with_listen_addr("0.0.0.0:9090".to_string());

        assert!(config.is_valid_key("test-key"));
        assert!(!config.is_valid_key("invalid-key"));
        assert_eq!(config.max_concurrent_scans, 10);
        assert_eq!(config.listen_addr, "0.0.0.0:9090");
    }

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        // Should be hex encoded 32 bytes = 64 chars
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);

        // Should be unique
        assert_ne!(key1, key2);
    }
}
