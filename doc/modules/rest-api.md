# REST API Module (rustnmap-api)

> **Version**: 2.0.0 (in development)
> **Corresponding Phase**: Phase 5 (Week 12)
> **Priority**: P1

---

## Overview

The REST API module upgrades RustNmap from a command-line tool to a platform service, supporting scan initiation, status querying, and result retrieval via HTTP API. This is the core component of RustNmap 2.0 platformization.

---

## Features

### 1. Daemon Mode

- Runs in the background, listening on a specified port
- Supports API Key authentication
- Concurrent access from multiple clients

### 2. RESTful API

- Conforms to REST architectural style
- JSON request/response format
- SSE (Server-Sent Events) streaming

### 3. Scan Task Management

- Create scan tasks
- Query scan status
- Cancel scan tasks
- Retrieve scan results

### 4. Streaming Result Push

- SSE real-time scan progress push
- Push results immediately as each host completes
- Supports NDJSON streaming format

---

## API Endpoints

### Authentication

All API requests require an API Key in the Header:

```http
Authorization: Bearer <api_key>
```

### POST /api/v1/scans

Create a scan task.

**Request Example**:

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "scan_type": "syn",
    "options": {
      "service_detection": true,
      "os_detection": true,
      "vulnerability_scan": true
    }
  }'
```

**Response Example**:

```json
{
  "id": "scan_001",
  "status": "queued",
  "created_at": "2026-02-17T10:00:00Z",
  "targets": ["192.168.1.0/24"],
  "scan_type": "syn",
  "progress": {
    "total_hosts": 256,
    "completed_hosts": 0,
    "percentage": 0.0
  }
}
```

### GET /api/v1/scans/{id}

Query scan task status.

**Response Example**:

```json
{
  "id": "scan_001",
  "status": "running",
  "progress": {
    "total_hosts": 256,
    "completed_hosts": 128,
    "percentage": 50.0,
    "current_phase": "service_detection",
    "pps": 12500,
    "eta_seconds": 45
  },
  "started_at": "2026-02-17T10:00:05Z"
}
```

### GET /api/v1/scans/{id}/results

Retrieve scan results (complete).

**Response Example**:

```json
{
  "scan_id": "scan_001",
  "status": "completed",
  "completed_at": "2026-02-17T10:02:00Z",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "status": "up",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "ssh",
            "version": "OpenSSH 8.9p1",
            "cpe": ["cpe:2.3:a:openbsd:openssh:8.9p1"]
          }
        }
      ],
      "os": {
        "name": "Linux",
        "accuracy": 95
      },
      "vulnerabilities": []
    }
  ],
  "statistics": {
    "total_hosts": 256,
    "hosts_up": 45,
    "open_ports": 123,
    "elapsed_seconds": 115
  }
}
```

### DELETE /api/v1/scans/{id}

Cancel a scan task.

**Response Example**:

```json
{
  "id": "scan_001",
  "status": "cancelled",
  "message": "Scan cancelled by user"
}
```

### GET /api/v1/scans/{id}/stream

SSE streaming result push.

**Response Format** (text/event-stream):

```
event: progress
data: {"type":"progress","completed_hosts":10,"total_hosts":256}

event: host_found
data: {"type":"host","ip":"192.168.1.1","status":"up"}

event: port_found
data: {"type":"port","ip":"192.168.1.1","port":22,"state":"open","service":"ssh"}

event: vulnerability
data: {"type":"vuln","ip":"192.168.1.1","cve":"CVE-2024-XXXXX","cvss":7.5}

event: done
data: {"type":"done","scan_id":"scan_001","status":"completed"}
```

### GET /api/v1/scans

List all scan tasks (supports pagination and filtering).

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status (queued/running/completed/cancelled) |
| `limit` | number | Items per page (default: 20) |
| `offset` | number | Offset (default: 0) |

### GET /api/v1/health

Health check.

**Response Example**:

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "uptime_seconds": 3600,
  "active_scans": 2,
  "queued_scans": 1
}
```

---

## Architecture Design

### Module Structure

```
rustnmap-api/
├── src/
│   ├── lib.rs           # Public API
│   ├── server.rs        # HTTP server
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── scans.rs     # Scan-related routes
│   │   └── health.rs    # Health check routes
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── create_scan.rs
│   │   ├── get_scan.rs
│   │   └── cancel_scan.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs      # API Key authentication
│   │   └── logging.rs   # Request logging
│   ├── sse/
│   │   ├── mod.rs
│   │   └── emitter.rs   # SSE event emitter
│   └── config.rs        # Configuration management
└── tests/
    └── integration.rs   # API integration tests
```

### Dependencies

```
rustnmap-api
│
├── rustnmap-core      # Scan orchestration
├── rustnmap-vuln      # Vulnerability intelligence (optional)
├── rustnmap-output    # Output models
│
└── External dependencies
    ├── axum           # Web framework
    ├── tower          # Middleware
    ├── tokio          # Async runtime
    ├── serde          # Serialization
    ├── serde_json     # JSON processing
    └── uuid           # Task ID generation
```

---

## Core API

### ApiServer

```rust
/// REST API server
pub struct ApiServer {
    config: ApiConfig,
    scan_manager: Arc<ScanManager>,
}

impl ApiServer {
    /// Create server instance
    pub fn new(config: ApiConfig) -> Result<Self>;

    /// Start the server
    pub async fn run(self, addr: SocketAddr) -> Result<()>;

    /// Get listening address
    pub fn local_addr(&self) -> SocketAddr;
}

/// API configuration
pub struct ApiConfig {
    /// API Key list
    pub api_keys: Vec<String>,

    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,

    /// Scan result retention period
    pub result_retention: Duration,

    /// Enable SSE streaming
    pub enable_sse: bool,
}
```

### ScanManager

```rust
/// Scan task manager
pub struct ScanManager {
    tasks: DashMap<String, ScanTask>,
    executor: Arc<ScanExecutor>,
}

impl ScanManager {
    /// Create scan task
    pub fn create_scan(&self, request: CreateScanRequest) -> Result<ScanTask>;

    /// Get scan status
    pub fn get_status(&self, id: &str) -> Option<ScanStatus>;

    /// Cancel scan
    pub fn cancel_scan(&self, id: &str) -> Result<()>;

    /// Get scan results
    pub fn get_results(&self, id: &str) -> Option<ScanResults>;

    /// List scan tasks
    pub fn list_scans(&self, filter: Option<ScanFilter>) -> Vec<ScanSummary>;
}
```

---

## Authentication and Authorization

### API Key Generation

```bash
# Generate random API Key
openssl rand -hex 32
# Output: e8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
```

### Configuration File

```yaml
# /etc/rustnmap/api-config.yaml
api:
  listen_addr: "127.0.0.1:8080"
  api_keys:
    - "e8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
  max_concurrent_scans: 5
  enable_sse: true
```

---

## CLI Options

### Starting Daemon Mode

```bash
# Basic start
rustnmap --daemon

# Specify listen address
rustnmap --daemon --listen 0.0.0.0:8080

# Use configuration file
rustnmap --daemon --config /etc/rustnmap/api-config.yaml

# Generate API Key
rustnmap --generate-api-key
```

---

## Usage Examples

### Python Client

```python
import requests

API_KEY = "your_api_key"
BASE_URL = "http://localhost:8080/api/v1"

headers = {"Authorization": f"Bearer {API_KEY}"}

# Create scan
response = requests.post(
    f"{BASE_URL}/scans",
    headers=headers,
    json={
        "targets": ["192.168.1.0/24"],
        "options": {"service_detection": True}
    }
)
scan_id = response.json()["id"]

# Query status
response = requests.get(
    f"{BASE_URL}/scans/{scan_id}",
    headers=headers
)
print(response.json())

# Get results
response = requests.get(
    f"{BASE_URL}/scans/{scan_id}/results",
    headers=headers
)
print(response.json())
```

### Streaming Consumption (SSE)

```python
import sseclient

response = requests.get(
    f"{BASE_URL}/scans/{scan_id}/stream",
    headers=headers,
    stream=True
)

client = sseclient.SSEClient(response)
for event in client.events():
    data = json.loads(event.data)
    print(f"Event: {event.type}, Data: {data}")
```

---

## Performance Considerations

### Concurrency Control

- Use semaphores to limit concurrent scan count
- Scan queue management (FIFO)
- Priority queue (optional)

### Memory Management

- Paginated storage of scan results
- Periodic cleanup of expired results
- Use streaming responses to avoid high memory usage

---

## Security Considerations

### 1. API Key Protection

- API Keys transmitted only over HTTPS
- **Constant-time comparison**: Use `subtle::ConstantTimeEq` to prevent timing attacks
- Periodic API Key rotation

```rust
// Safe comparison to prevent timing attacks
pub fn is_valid_key(&self, key: &str) -> bool {
    self.api_keys.iter().any(|k| {
        k.as_bytes().ct_eq(key.as_bytes()).into()
    })
}
```

### 2. Input Validation

- Target IP/CIDR validation
- Scan option whitelist
- Rate limiting (abuse prevention)
- **Loopback address allowed**: 127.0.0.1 and ::1 allowed for testing (consistent with nmap behavior)
- **Multicast/Link-local address rejected**: 224.x.x.x, 169.254.x.x and other reserved addresses are rejected

### 3. Concurrency Limits

- Maximum concurrent scans configurable (default: 5)
- Returns HTTP 429 (TOO_MANY_REQUESTS) when limit exceeded

### 4. Audit Logging

```rust
/// Audit log record
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub api_key_hash: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub client_ip: String,
}
```

---

## Testing

### Shell Test Script

```bash
# Run shell test script
./benchmarks/api_test.sh

# With custom options
./benchmarks/api_test.sh --server-addr 127.0.0.1:9090 --api-key YOUR-api-key
```

**Test Results**:
- 7 tests executed
- 100% pass rate expected### API Integration Tests

```rust
#[tokio::test]
async fn test_create_scan() {
    let server = ApiServer::test().await;
    let client = TestClient::new(&server);

    let response = client
        .post("/api/v1/scans")
        .json(&json!({
            "targets": ["127.0.0.1"],
            "scan_type": "connect"
        }))
        .send()
        .await;

    assert_eq!(response.status(), 201);
    assert!(response.json::<ScanTask>().await.id.starts_with("scan_"));
}
```

---

## Alignment with RETHINK.md

| Section | Corresponding Content |
|---------|----------------------|
| 7.2.1 REST API | POST/GET/DELETE endpoints |
| 12.3 Phase 5 | Platformization minimum viable loop (Week 12) |
| 13.1 New Crate | rustnmap-api |
| 14.3 Phase 4-5 | phase/progress query interface |

---

## Dependencies

```toml
[dependencies]
# Web framework
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# Async
tokio = { version = "1", features = ["full"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Utilities
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }

# Internal dependencies
rustnmap-core = { path = "../rustnmap-core" }
rustnmap-output = { path = "../rustnmap-output" }
```

---

## Next Steps

1. **Week 12**: Implement basic HTTP endpoints (create/query/cancel scans)
2. **Week 12**: Implement SSE streaming push
3. **Week 12**: Add authentication middleware and audit logging
4. **Week 12**: Write integration tests and API documentation

---

## Reference Links

- [axum Documentation](https://docs.rs/axum)
- [OpenAPI Specification](https://swagger.io/specification/)
- [SSE Specification](https://html.spec.whatwg.org/multipage/server-sent-events.html)
