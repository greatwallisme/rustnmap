# rustnmap-api

REST API / daemon mode for RustNmap.

## Purpose

Provides an Axum-based HTTP server for submitting scans, checking status, streaming results via SSE, and managing scan history.

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `Server` | `server.rs` | Axum server setup and lifecycle |
| `ApiConfig` | `config.rs` | Server configuration (bind addr, auth) |
| `ScanManager` | `manager.rs` | In-memory scan state management |
| Routes | `handlers/` | REST endpoints (create, list, get, cancel, health) |
| Auth middleware | `middleware/auth.rs` | API key authentication |
| SSE streaming | `sse/` | Server-Sent Events for live scan progress |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scans` | Create and start a scan |
| GET | `/scans` | List all scans |
| GET | `/scans/:id` | Get scan status |
| GET | `/scans/:id/results` | Get scan results |
| DELETE | `/scans/:id` | Cancel a scan |
| GET | `/health` | Health check |

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-core | Scan orchestration |
| rustnmap-output | Output formatting |
| rustnmap-scan-management | Persistence |
| axum / tower | HTTP framework |
| dashmap | Concurrent scan map |
| uuid | Scan ID generation |

## Testing

```bash
cargo test -p rustnmap-api
```
