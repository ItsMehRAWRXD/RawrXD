# RawrXD API Reference

## Phase I Batch 1/5: API Documentation

Complete API documentation for RawrXD Sovereign v1.0.0

---

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All API requests require authentication via Bearer token:

```http
Authorization: Bearer <your-api-token>
```

---

## Endpoints

### Inference

#### POST /inference

Submit an inference request.

**Request:**
```json
{
  "model": "llama-3-8b",
  "prompt": "Hello, how are you?",
  "max_tokens": 256,
  "temperature": 0.7,
  "stream": false
}
```

**Response:**
```json
{
  "id": "inf_1234567890",
  "model": "llama-3-8b",
  "content": "I'm doing well, thank you for asking!",
  "usage": {
    "prompt_tokens": 5,
    "completion_tokens": 10,
    "total_tokens": 15
  },
  "latency_ms": 245
}
```

#### POST /inference/stream

Stream inference responses.

**Request:**
```json
{
  "model": "llama-3-8b",
  "prompt": "Tell me a story",
  "stream": true
}
```

**Response:** Server-Sent Events (SSE)

```
data: {"token": "Once", "index": 0}

data: {"token": " upon", "index": 1}

data: {"token": " a", "index": 2}

data: {"token": " time", "index": 3}

data: [DONE]
```

---

### Models

#### GET /models

List available models.

**Response:**
```json
{
  "models": [
    {
      "id": "llama-3-8b",
      "name": "Llama 3 8B",
      "size": "8B",
      "quantization": "Q4_K_M",
      "loaded": true
    },
    {
      "id": "llama-3-70b",
      "name": "Llama 3 70B",
      "size": "70B",
      "quantization": "Q4_K_M",
      "loaded": false
    }
  ]
}
```

#### POST /models/load

Load a model into memory.

**Request:**
```json
{
  "model_id": "llama-3-70b",
  "gpu_layers": 81
}
```

**Response:**
```json
{
  "success": true,
  "model": "llama-3-70b",
  "load_time_ms": 4500,
  "memory_used_mb": 42000
}
```

#### POST /models/unload

Unload a model from memory.

**Request:**
```json
{
  "model_id": "llama-3-70b"
}
```

---

### System

#### GET /health

Check system health.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "components": {
    "inference": "healthy",
    "models": "healthy",
    "memory": "healthy",
    "gpu": "healthy"
  }
}
```

#### GET /metrics

Get performance metrics.

**Response:**
```json
{
  "tps": 45.2,
  "latency_avg_ms": 125,
  "latency_p95_ms": 245,
  "latency_p99_ms": 380,
  "active_requests": 12,
  "queue_depth": 3,
  "memory_used_mb": 16384,
  "gpu_utilization_percent": 78
}
```

---

### Administration

#### POST /admin/config

Update runtime configuration.

**Request:**
```json
{
  "batch_size": 512,
  "max_concurrent_requests": 64
}
```

**Response:**
```json
{
  "success": true,
  "config_applied": {
    "batch_size": 512,
    "max_concurrent_requests": 64
  }
}
```

#### POST /admin/cache/clear

Clear model cache.

**Response:**
```json
{
  "success": true,
  "cleared_mb": 2048
}
```

#### POST /admin/scale

Scale inference workers.

**Request:**
```json
{
  "workers": 8
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing token |
| 404 | Not Found - Model or resource not found |
| 429 | Rate Limited - Too many requests |
| 500 | Internal Server Error |
| 503 | Service Unavailable - Model loading |

---

## Rate Limits

- **Inference**: 100 requests/minute
- **Model Load**: 10 requests/hour
- **Admin**: 60 requests/minute

---

## SDK Examples

### Python

```python
import requests

response = requests.post(
    "http://localhost:8080/api/v1/inference",
    headers={"Authorization": "Bearer your-token"},
    json={
        "model": "llama-3-8b",
        "prompt": "Hello!",
        "max_tokens": 100
    }
)

print(response.json()["content"])
```

### JavaScript

```javascript
const response = await fetch('http://localhost:8080/api/v1/inference', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer your-token',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    model: 'llama-3-8b',
    prompt: 'Hello!',
    max_tokens: 100
  })
});

const data = await response.json();
console.log(data.content);
```

---

*RawrXD API Reference v1.0.0 | Last Updated: 2026-07-13*
