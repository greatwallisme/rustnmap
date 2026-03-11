# REST API 模块 (rustnmap-api)

> **版本**: 2.0.0 (开发中)
> **对应 Phase**: Phase 5 (Week 12)
> **优先级**: P1

---

## 概述

REST API 模块将 RustNmap 从命令行工具升级为平台化服务，支持通过 HTTP API 发起扫描、查询状态和获取结果。这是 RustNmap 2.0 平台化的核心组件。

---

## 功能特性

### 1. Daemon 模式

- 后台运行，监听指定端口
- 支持 API Key 认证
- 多客户端并发访问

### 2. RESTful API

- 符合 REST 架构风格
- JSON 请求/响应格式
- SSE (Server-Sent Events) 流式推送

### 3. 扫描任务管理

- 创建扫描任务
- 查询扫描状态
- 取消扫描任务
- 获取扫描结果

### 4. 流式结果推送

- SSE 实时推送扫描进度
- 每完成一个主机立即推送结果
- 支持 NDJSON 流式格式

---

## API 端点

### 认证

所有 API 请求需要在 Header 中携带 API Key：

```http
Authorization: Bearer <api_key>
```

### POST /api/v1/scans

创建扫描任务。

**请求示例**:

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

**响应示例**:

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

查询扫描任务状态。

**响应示例**:

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

获取扫描结果（完整）。

**响应示例**:

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

取消扫描任务。

**响应示例**:

```json
{
  "id": "scan_001",
  "status": "cancelled",
  "message": "Scan cancelled by user"
}
```

### GET /api/v1/scans/{id}/stream

SSE 流式结果推送。

**响应格式** (text/event-stream):

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

列出所有扫描任务（支持分页和过滤）。

**查询参数**:

| 参数 | 类型 | 描述 |
|------|------|------|
| `status` | string | 过滤状态 (queued/running/completed/cancelled) |
| `limit` | number | 每页数量 (默认 20) |
| `offset` | number | 偏移量 (默认 0) |

### GET /api/v1/health

健康检查。

**响应示例**:

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

## 架构设计

### 模块结构

```
rustnmap-api/
├── src/
│   ├── lib.rs           # 公共 API
│   ├── server.rs        # HTTP 服务器
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── scans.rs     # 扫描相关路由
│   │   └── health.rs    # 健康检查路由
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── create_scan.rs
│   │   ├── get_scan.rs
│   │   └── cancel_scan.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs      # API Key 认证
│   │   └── logging.rs   # 请求日志
│   ├── sse/
│   │   ├── mod.rs
│   │   └── emitter.rs   # SSE 事件发射器
│   └── config.rs        # 配置管理
└── tests/
    └── integration.rs   # API 集成测试
```

### 依赖关系

```
rustnmap-api
│
├── rustnmap-core      # 扫描编排
├── rustnmap-vuln      # 漏洞情报 (可选)
├── rustnmap-output    # 输出模型
│
└── 外部依赖
    ├── axum           # Web 框架
    ├── tower          # 中间件
    ├── tokio          # 异步运行时
    ├── serde          # 序列化
    ├── serde_json     # JSON 处理
    └── uuid           # 任务 ID 生成
```

---

## 核心 API

### ApiServer

```rust
/// REST API 服务器
pub struct ApiServer {
    config: ApiConfig,
    scan_manager: Arc<ScanManager>,
}

impl ApiServer {
    /// 创建服务器实例
    pub fn new(config: ApiConfig) -> Result<Self>;

    /// 启动服务器
    pub async fn run(self, addr: SocketAddr) -> Result<()>;

    /// 获取监听地址
    pub fn local_addr(&self) -> SocketAddr;
}

/// API 配置
pub struct ApiConfig {
    /// API Key 列表
    pub api_keys: Vec<String>,

    /// 最大并发扫描数
    pub max_concurrent_scans: usize,

    /// 扫描结果保留时间
    pub result_retention: Duration,

    /// 启用 SSE 流式推送
    pub enable_sse: bool,
}
```

### ScanManager

```rust
/// 扫描任务管理器
pub struct ScanManager {
    tasks: DashMap<String, ScanTask>,
    executor: Arc<ScanExecutor>,
}

impl ScanManager {
    /// 创建扫描任务
    pub fn create_scan(&self, request: CreateScanRequest) -> Result<ScanTask>;

    /// 获取扫描状态
    pub fn get_status(&self, id: &str) -> Option<ScanStatus>;

    /// 取消扫描
    pub fn cancel_scan(&self, id: &str) -> Result<()>;

    /// 获取扫描结果
    pub fn get_results(&self, id: &str) -> Option<ScanResults>;

    /// 列出扫描任务
    pub fn list_scans(&self, filter: Option<ScanFilter>) -> Vec<ScanSummary>;
}
```

---

## 认证与授权

### API Key 生成

```bash
# 生成随机 API Key
openssl rand -hex 32
# 输出：e8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
```

### 配置文件

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

## CLI 选项

### 启动 Daemon 模式

```bash
# 基本启动
rustnmap --daemon

# 指定监听地址
rustnmap --daemon --listen 0.0.0.0:8080

# 使用配置文件
rustnmap --daemon --config /etc/rustnmap/api-config.yaml

# 生成 API Key
rustnmap --generate-api-key
```

---

## 使用示例

### Python 客户端

```python
import requests

API_KEY = "your_api_key"
BASE_URL = "http://localhost:8080/api/v1"

headers = {"Authorization": f"Bearer {API_KEY}"}

# 创建扫描
response = requests.post(
    f"{BASE_URL}/scans",
    headers=headers,
    json={
        "targets": ["192.168.1.0/24"],
        "options": {"service_detection": True}
    }
)
scan_id = response.json()["id"]

# 查询状态
response = requests.get(
    f"{BASE_URL}/scans/{scan_id}",
    headers=headers
)
print(response.json())

# 获取结果
response = requests.get(
    f"{BASE_URL}/scans/{scan_id}/results",
    headers=headers
)
print(response.json())
```

### 流式消费 (SSE)

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

## 性能考虑

### 并发控制

- 使用信号量限制并发扫描数
- 扫描队列管理（FIFO）
- 优先级队列（可选）

### 内存管理

- 扫描结果分页存储
- 定期清理过期结果
- 使用流式响应避免大内存占用

---

## 安全考虑

### 1. API Key 保护

- API Key 仅通过 HTTPS 传输
- **常量时间比较**: 使用 `subtle::ConstantTimeEq` 防止时序攻击 (Timing Attack)
- 定期轮换 API Key

```rust
// 防止时序攻击的安全比较
pub fn is_valid_key(&self, key: &str) -> bool {
    self.api_keys.iter().any(|k| {
        k.as_bytes().ct_eq(key.as_bytes()).into()
    })
}
```

### 2. 输入验证

- 目标 IP/CIDR 验证
- 扫描选项白名单
- 速率限制（防滥用）
- **Loopback 地址允许**: 127.0.0.1 和 ::1 允许用于测试（与 nmap 行为一致）
- **Multicast/Link-local 地址拒绝**: 224.x.x.x, 169.254.x.x 等保留地址被拒绝

### 3. 并发限制

- 最大并发扫描数可配置（默认: 5）
- 超出限制返回 HTTP 429 (TOO_MANY_REQUESTS)

### 4. 审计日志

```rust
/// 审计日志记录
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

## 测试

### Shell 测试脚本

```bash
# Run shell test script
./benchmarks/api_test.sh

# With custom options
./benchmarks/api_test.sh --server-addr 127.0.0.1:9090 --api-key YOUR-api-key
```

**测试结果**:
- 7 tests executed
- 100% pass rate expected### API 集成测试

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

## 与 RETHINK.md 对齐

| 章节 | 对应内容 |
|------|---------|
| 7.2.1 REST API | POST/GET/DELETE 端点 |
| 12.3 Phase 5 | 平台化最小闭环（Week 12） |
| 13.1 新增 Crate | rustnmap-api |
| 14.3 Phase 4-5 | phase/progress 查询接口 |

---

## 依赖关系

```toml
[dependencies]
# Web 框架
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# 异步
tokio = { version = "1", features = ["full"] }

# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# 工具
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }

# 内部依赖
rustnmap-core = { path = "../rustnmap-core" }
rustnmap-output = { path = "../rustnmap-output" }
```

---

## 下一步

1. **Week 12**: 实现基本 HTTP 端点（创建/查询/取消扫描）
2. **Week 12**: 实现 SSE 流式推送
3. **Week 12**: 添加认证中间件和审计日志
4. **Week 12**: 编写集成测试和 API 文档

---

## 参考链接

- [axum 文档](https://docs.rs/axum)
- [OpenAPI 规范](https://swagger.io/specification/)
- [SSE 规范](https://html.spec.whatwg.org/multipage/server-sent-events.html)
