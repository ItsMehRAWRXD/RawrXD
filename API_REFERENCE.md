# Sovereign Substrate - API Reference

## REST API

### Base URL
```
http://localhost:8080/api/v1
```

### Authentication

All API requests require an API key in the header:
```
X-API-Key: your-api-key-here
```

---

## System Endpoints

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

### GET /status
Get system status.

**Response:**
```json
{
  "version": "1.0.0",
  "environment": "production",
  "components": {
    "kernel": "running",
    "security": "active",
    "memory_graph": "loaded"
  },
  "metrics": {
    "intents_executed": 150,
    "tools_executed": 300,
    "memory_usage_mb": 45
  }
}
```

### GET /metrics
Prometheus-compatible metrics.

**Response:**
```
sovereign_intents_total 150
sovereign_tools_total 300
sovereign_memory_usage_bytes 47185920
```

---

## Intent Endpoints

### POST /intents/execute
Execute an intent.

**Request:**
```json
{
  "action": "analyze_code",
  "params": {
    "target": "src/main.cpp",
    "type": "complexity"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis complete",
  "data": {
    "complexity": 12,
    "lines": 450
  },
  "execution_time_ms": 150
}
```

### POST /intents/validate
Validate an intent without executing.

**Request:**
```json
{
  "action": "write_file",
  "params": {
    "file_path": "test.txt"
  }
}
```

**Response:**
```json
{
  "valid": true,
  "warnings": ["File will be overwritten"]
}
```

---

## Tool Endpoints

### GET /tools
List available tools.

**Response:**
```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read file contents",
      "parameters": ["file_path"]
    },
    {
      "name": "write_file",
      "description": "Write to file",
      "parameters": ["file_path", "content"]
    }
  ]
}
```

### POST /tools/execute
Execute a tool.

**Request:**
```json
{
  "tool_name": "read_file",
  "params": {
    "file_path": "README.md"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "output": "# Sovereign Substrate...",
  "execution_time_ms": 5
}
```

---

## Memory Graph Endpoints

### GET /memory/graph
Get the repository memory graph.

**Response:**
```json
{
  "nodes": 1500,
  "edges": 3200,
  "last_updated": "2026-07-20T10:00:00Z"
}
```

### POST /memory/query
Query the memory graph.

**Request:**
```json
{
  "query": "functions in main"
}
```

**Response:**
```json
{
  "results": [
    {"name": "main", "type": "function", "file": "src/main.cpp"},
    {"name": "initialize", "type": "function", "file": "src/main.cpp"}
  ]
}
```

### POST /memory/save
Save memory graph to disk.

**Request:**
```json
{
  "path": "project.graph"
}
```

**Response:**
```json
{
  "success": true,
  "bytes_written": 1048576
}
```

### POST /memory/load
Load memory graph from disk.

**Request:**
```json
{
  "path": "project.graph"
}
```

**Response:**
```json
{
  "success": true,
  "nodes_loaded": 1500
}
```

---

## Telemetry Endpoints

### GET /telemetry
Get telemetry data.

**Query Parameters:**
- `since` - ISO timestamp (optional)

**Response:**
```json
{
  "events": [
    {
      "timestamp": "2026-07-20T10:00:00Z",
      "type": "intent_executed",
      "data": {...}
    }
  ]
}
```

### POST /telemetry/subscribe
Subscribe to telemetry events.

**Request:**
```json
{
  "event_types": ["intent_executed", "tool_executed"]
}
```

**Response:**
```json
{
  "subscription_id": "sub_123",
  "websocket_url": "ws://localhost:8081/telemetry"
}
```

---

## Security Endpoints

### POST /security/validate_path
Validate a file path.

**Request:**
```json
{
  "path": "../etc/passwd"
}
```

**Response:**
```json
{
  "valid": false,
  "reason": "Path traversal detected"
}
```

### POST /security/check_permission
Check if action is permitted.

**Request:**
```json
{
  "action": "write_file",
  "resource": "src/main.cpp"
}
```

**Response:**
```json
{
  "permitted": true,
  "required_capabilities": ["file_write"]
}
```

---

## WebSocket API

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8081');
```

### Events

#### intent_executed
```json
{
  "type": "intent_executed",
  "data": {
    "action": "analyze_code",
    "success": true,
    "execution_time_ms": 150
  }
}
```

#### tool_executed
```json
{
  "type": "tool_executed",
  "data": {
    "tool_name": "read_file",
    "status": "success"
  }
}
```

#### telemetry
```json
{
  "type": "telemetry",
  "data": {
    "metric": "memory_usage",
    "value": 45.2,
    "unit": "MB"
  }
}
```

### Request/Response Pattern

**Send:**
```json
{
  "requestId": "req_123",
  "type": "execute_intent",
  "data": {
    "action": "analyze_code",
    "params": {...}
  }
}
```

**Receive:**
```json
{
  "requestId": "req_123",
  "data": {
    "success": true,
    "message": "Analysis complete"
  }
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "invalid_request",
  "message": "Missing required parameter: action"
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Invalid API key"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Permission denied"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Tool not found: unknown_tool"
}
```

### 429 Too Many Requests
```json
{
  "error": "rate_limited",
  "message": "Rate limit exceeded",
  "retry_after": 60
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_error",
  "message": "An unexpected error occurred"
}
```

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| /intents/* | 60/minute |
| /tools/* | 100/minute |
| /memory/* | 120/minute |
| /telemetry | 1000/minute |

---

## SDK Examples

### Python
```python
import requests

headers = {"X-API-Key": "your-key"}
response = requests.post(
    "http://localhost:8080/api/v1/intents/execute",
    headers=headers,
    json={"action": "analyze_code", "params": {...}}
)
result = response.json()
```

### JavaScript
```javascript
const response = await fetch('http://localhost:8080/api/v1/intents/execute', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your-key',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({action: 'analyze_code', params: {...}})
});
const result = await response.json();
```

### cURL
```bash
curl -X POST http://localhost:8080/api/v1/intents/execute \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"action": "analyze_code", "params": {}}'
```
