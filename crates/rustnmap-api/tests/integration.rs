//! Integration tests for rustnmap-api
//!
//! These tests verify the full API lifecycle including:
//! - Authentication flow
//! - Scan creation and management
//! - Error handling
//! - Concurrent scan limits

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustnmap_api::{ApiConfig, ApiServer};
use serde_json::json;
use std::net::SocketAddr;

/// Test client for making HTTP requests
struct TestClient {
    base_url: String,
    api_key: String,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
}

impl TestClient {
    fn new(addr: SocketAddr, api_key: String) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            base_url: format!("http://{addr}"),
            api_key,
            client,
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        with_auth: bool,
    ) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
        let url = format!("{}{path}", self.base_url);
        let body_bytes = if let Some(json) = body {
            serde_json::to_vec(&json)?
        } else {
            Vec::new()
        };

        let mut req = Request::builder().method(method).uri(url);

        if with_auth {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }

        if !body_bytes.is_empty() {
            req = req.header("Content-Type", "application/json");
        }

        let req = req.body(Full::new(Bytes::from(body_bytes)))?;

        let response = self.client.request(req).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body.to_vec())?;

        Ok((status, body_str))
    }

    async fn get(
        &self,
        path: &str,
        with_auth: bool,
    ) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
        self.request(Method::GET, path, None, with_auth).await
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
        with_auth: bool,
    ) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
        self.request(Method::POST, path, Some(body), with_auth)
            .await
    }

    async fn delete(
        &self,
        path: &str,
        with_auth: bool,
    ) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
        self.request(Method::DELETE, path, None, with_auth).await
    }
}

/// Start test server and return address and API key
async fn start_test_server() -> Result<(SocketAddr, String), Box<dyn std::error::Error>> {
    let config = ApiConfig::default();
    let api_key = config.api_keys[0].clone();
    let server = ApiServer::new(&config)?;

    // Bind to random port
    let addr = server.run_with_addr("127.0.0.1:0".parse()?).await?;

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    Ok((addr, api_key))
}

// ==================== Health Check Tests ====================

#[tokio::test]
async fn test_health_check_no_auth_required() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let (status, body) = client.get("/api/v1/health", false).await.unwrap();

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "healthy");
    assert!(json["version"].is_string());
    assert!(json["uptime_seconds"].is_number());
}

#[tokio::test]
async fn test_health_check_with_auth_also_works() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let (status, body) = client.get("/api/v1/health", true).await.unwrap();

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "healthy");
}

// ==================== Authentication Tests ====================

#[tokio::test]
async fn test_create_scan_requires_auth() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "syn"
    });

    let (status, _) = client.post("/api/v1/scans", body, false).await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_scan_with_invalid_key() {
    let (addr, _) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, "invalid-key-12345".to_string());

    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "syn"
    });

    let (status, _) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_scan_with_valid_key() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "syn"
    });

    let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::CREATED);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], true);
    assert!(json["data"]["id"].is_string());
    assert_eq!(json["data"]["status"], "queued");
}

// ==================== Scan Lifecycle Tests ====================

#[tokio::test]
async fn test_full_scan_lifecycle() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    // 1. Create scan
    let create_body = json!({
        "targets": ["192.168.1.1", "192.168.1.2"],
        "scan_type": "syn",
        "options": {
            "timing": "T4"
        }
    });

    let (status, response) = client
        .post("/api/v1/scans", create_body, true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::CREATED);

    let create_json: serde_json::Value = serde_json::from_str(&response).unwrap();
    let scan_id = create_json["data"]["id"].as_str().unwrap();

    // 2. Get scan status
    let (status, response) = client
        .get(&format!("/api/v1/scans/{scan_id}"), true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    let status_json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(status_json["success"], true);
    assert_eq!(status_json["data"]["id"], scan_id);
    assert_eq!(status_json["data"]["scan_type"], "syn");
    assert_eq!(status_json["data"]["targets"][0], "192.168.1.1");
    assert_eq!(status_json["data"]["targets"][1], "192.168.1.2");

    // 3. List scans
    let (status, response) = client.get("/api/v1/scans", true).await.unwrap();
    assert_eq!(status, StatusCode::OK);

    let list_json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(list_json["success"], true);
    assert!(list_json["data"]["total"].as_u64().unwrap() >= 1);

    // 4. Cancel scan
    let (status, response) = client
        .delete(&format!("/api/v1/scans/{scan_id}"), true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    let cancel_json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(cancel_json["id"], scan_id);
    assert_eq!(cancel_json["status"], "cancelled");
}

// ==================== Validation Tests ====================

#[tokio::test]
async fn test_create_scan_empty_targets() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": [],
        "scan_type": "syn"
    });

    let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"].as_str().unwrap().contains("No targets"));
}

#[tokio::test]
async fn test_create_scan_invalid_scan_type() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "invalid_type"
    });

    let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Invalid scan_type"));
}

#[tokio::test]
async fn test_create_scan_invalid_timing() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "syn",
        "options": {
            "timing": "T9"
        }
    });

    let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Invalid timing template"));
}

#[tokio::test]
async fn test_create_scan_invalid_target_format() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let body = json!({
        "targets": ["127.0.0.1"],  // Loopback rejected
        "scan_type": "syn"
    });

    let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"].as_str().unwrap().contains("loopback"));
}

// ==================== List Scans Tests ====================

#[tokio::test]
async fn test_list_scans_pagination() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    // Create multiple scans
    for i in 1..=5 {
        let body = json!({
            "targets": [format!("192.168.1.{i}")],
            "scan_type": "syn"
        });
        client.post("/api/v1/scans", body, true).await.unwrap();
    }

    // Test pagination
    let (status, response) = client
        .get("/api/v1/scans?limit=2&offset=0", true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["data"]["limit"], 2);
    assert_eq!(json["data"]["offset"], 0);
    assert!(json["data"]["total"].as_u64().unwrap() >= 5);
    assert_eq!(json["data"]["scans"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_scans_status_filter() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    // Create scan
    let body = json!({
        "targets": ["192.168.1.1"],
        "scan_type": "syn"
    });
    client.post("/api/v1/scans", body, true).await.unwrap();

    // Filter by status
    let (status, response) = client
        .get("/api/v1/scans?status=queued", true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    let scans = json["data"]["scans"].as_array().unwrap();
    for scan in scans {
        assert_eq!(scan["status"], "queued");
    }
}

// ==================== Error Handling Tests ====================

#[tokio::test]
async fn test_get_nonexistent_scan() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let (status, response) = client
        .get("/api/v1/scans/nonexistent_id", true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);

    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_cancel_nonexistent_scan() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let (status, _) = client
        .delete("/api/v1/scans/nonexistent_id", true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_results_nonexistent_scan() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    let (status, _) = client
        .get("/api/v1/scans/nonexistent_id/results", true)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ==================== Concurrent Scan Limit Tests ====================

#[tokio::test]
async fn test_concurrent_scan_limit() {
    let (addr, api_key) = start_test_server().await.unwrap();
    let client = TestClient::new(addr, api_key);

    // Create scans up to limit (default is 5)
    let mut scan_ids = Vec::new();
    for i in 1..=6 {
        let body = json!({
            "targets": [format!("192.168.1.{i}")],
            "scan_type": "syn"
        });

        let (status, response) = client.post("/api/v1/scans", body, true).await.unwrap();

        if i <= 5 {
            // First 5 should succeed
            assert_eq!(status, StatusCode::CREATED);
            let json: serde_json::Value = serde_json::from_str(&response).unwrap();
            scan_ids.push(json["data"]["id"].as_str().unwrap().to_string());
        } else {
            // 6th should fail due to limit
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Cancel one scan to free up slot
    if let Some(scan_id) = scan_ids.first() {
        client
            .delete(&format!("/api/v1/scans/{scan_id}"), true)
            .await
            .unwrap();
    }

    // Now should be able to create another
    let body = json!({
        "targets": ["192.168.1.100"],
        "scan_type": "syn"
    });

    let (status, _) = client.post("/api/v1/scans", body, true).await.unwrap();
    assert_eq!(status, StatusCode::CREATED);
}
