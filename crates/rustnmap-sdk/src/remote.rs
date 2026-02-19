//! Remote scanner API client

use serde::{Deserialize, Serialize};

use crate::error::{ScanError, ScanResult};
use crate::models::ScanOutput;

/// API configuration for remote scanning
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Base URL of the API server
    pub base_url: String,

    /// API key for authentication
    pub api_key: String,
}

impl ApiConfig {
    /// Create a new API config
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
        }
    }

    /// Create from environment variables
    #[must_use] 
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("RUSTNMAP_API_URL").ok()?;
        let api_key = std::env::var("RUSTNMAP_API_KEY").ok()?;
        Some(Self::new(base_url, api_key))
    }
}

/// Remote scanner for API-based scanning
#[derive(Debug)]
pub struct RemoteScanner {
    config: ApiConfig,
    client: reqwest::Client,
}

impl RemoteScanner {
    /// Create a new remote scanner
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(config: ApiConfig) -> ScanResult<Self> {
        let client = reqwest::Client::builder()
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", config.api_key)
                        .parse()
                        .map_err(|e| ScanError::ApiError(format!("Invalid header: {e}")))?,
                );
                Ok::<_, ScanError>(headers)
            }?)
            .build()
            .map_err(|e| ScanError::ApiError(format!("Failed to create client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Create a scan task
    #[must_use] 
    pub fn create_scan(&self) -> RemoteScanBuilder<'_> {
        RemoteScanBuilder::new(self)
    }

    /// Get scan status
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the scan is not found.
    pub async fn get_status(&self, scan_id: &str) -> ScanResult<RemoteScanStatus> {
        let url = format!("{}/api/v1/scans/{}", self.config.base_url, scan_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::ApiError(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ScanError::ApiError(format!(
                "API error: {}",
                response.status()
            )));
        }

        let result: ApiResponse<RemoteScanStatus> = response
            .json()
            .await
            .map_err(|e| ScanError::ApiError(format!("Failed to parse response: {e}")))?;

        result.data.ok_or_else(|| ScanError::ApiError("No data in response".to_string()))
    }

    /// Get scan results
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response is invalid.
    pub async fn get_results(&self, scan_id: &str) -> ScanResult<ScanOutput> {
        let url = format!("{}/api/v1/scans/{}/results", self.config.base_url, scan_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::ApiError(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ScanError::ApiError(format!(
                "API error: {}",
                response.status()
            )));
        }

        let result: ApiResponse<ScanOutput> = response
            .json()
            .await
            .map_err(|e| ScanError::ApiError(format!("Failed to parse response: {e}")))?;

        result.data.ok_or_else(|| ScanError::ApiError("No data in response".to_string()))
    }

    /// Cancel a scan
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn cancel_scan(&self, scan_id: &str) -> ScanResult<()> {
        let url = format!("{}/api/v1/scans/{}", self.config.base_url, scan_id);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| ScanError::ApiError(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ScanError::ApiError(format!(
                "API error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// List scans
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response is invalid.
    pub async fn list_scans(&self) -> ScanResult<Vec<RemoteScanStatus>> {
        let url = format!("{}/api/v1/scans", self.config.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::ApiError(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ScanError::ApiError(format!(
                "API error: {}",
                response.status()
            )));
        }

        let result: ApiResponse<ListScansResponse> = response
            .json()
            .await
            .map_err(|e| ScanError::ApiError(format!("Failed to parse response: {e}")))?;

        Ok(result.data.map(|r| r.scans).unwrap_or_default())
    }
}

/// Builder for remote scan creation
#[derive(Debug)]
pub struct RemoteScanBuilder<'a> {
    scanner: &'a RemoteScanner,
    targets: Vec<String>,
    ports: Option<String>,
    scan_type: String,
    service_detection: bool,
    os_detection: bool,
    vulnerability_scan: bool,
}

impl<'a> RemoteScanBuilder<'a> {
    fn new(scanner: &'a RemoteScanner) -> Self {
        Self {
            scanner,
            targets: vec![],
            ports: None,
            scan_type: "syn".to_string(),
            service_detection: false,
            os_detection: false,
            vulnerability_scan: false,
        }
    }

    /// Set targets
    #[must_use]
    pub fn targets<T: IntoIterator<Item = S>, S: Into<String>>(mut self, targets: T) -> Self {
        self.targets = targets.into_iter().map(std::convert::Into::into).collect();
        self
    }

    /// Set ports
    #[must_use]
    pub fn ports<S: Into<String>>(mut self, ports: S) -> Self {
        self.ports = Some(ports.into());
        self
    }

    /// Set scan type
    #[must_use]
    pub fn scan_type<S: Into<String>>(mut self, scan_type: S) -> Self {
        self.scan_type = scan_type.into();
        self
    }

    /// Enable service detection
    #[must_use] 
    pub fn service_detection(mut self, enable: bool) -> Self {
        self.service_detection = enable;
        self
    }

    /// Enable OS detection
    #[must_use] 
    pub fn os_detection(mut self, enable: bool) -> Self {
        self.os_detection = enable;
        self
    }

    /// Enable vulnerability scanning
    #[must_use] 
    pub fn vulnerability_scan(mut self, enable: bool) -> Self {
        self.vulnerability_scan = enable;
        self
    }

    /// Submit the scan
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response is invalid.
    pub async fn submit(self) -> ScanResult<RemoteScanTask> {
        let url = format!("{}/api/v1/scans", self.scanner.config.base_url);

        let request = CreateScanRequest {
            targets: self.targets,
            scan_type: self.scan_type,
            options: ScanOptions {
                ports: self.ports,
                service_detection: self.service_detection,
                os_detection: self.os_detection,
                vulnerability_scan: self.vulnerability_scan,
                timing: None,
            },
        };

        let response = self
            .scanner
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| ScanError::ApiError(format!("Request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ScanError::ApiError(format!(
                "API error: {}",
                response.status()
            )));
        }

        let result: ApiResponse<RemoteScanTask> = response
            .json()
            .await
            .map_err(|e| ScanError::ApiError(format!("Failed to parse response: {e}")))?;

        result.data.ok_or_else(|| ScanError::ApiError("No data in response".to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateScanRequest {
    targets: Vec<String>,
    scan_type: String,
    options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanOptions {
    ports: Option<String>,
    service_detection: bool,
    os_detection: bool,
    vulnerability_scan: bool,
    timing: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteScanTask {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteScanStatus {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub targets: Vec<String>,
    pub progress: Option<ScanProgress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total_hosts: Option<usize>,
    pub completed_hosts: Option<usize>,
    pub percentage: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListScansResponse {
    scans: Vec<RemoteScanStatus>,
    total: usize,
    limit: usize,
    offset: usize,
}
