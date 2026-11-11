# RawrXD OMEGA-1 API Reference

## Overview

RawrXD OMEGA-1 provides both local IPC and HTTP APIs for integration with external tools and automation.

---

## IPC Protocol

### Named Pipe

**Pipe Name:** `\\.\pipe\RawrXD_Omega1_v2`

**Protocol:** Binary wire protocol with JSON payloads

### Message Header

```cpp
struct O1MessageHeader {
    uint32_t magic;        // 0x4F314F4D ('O1OM')
    uint16_t version;      // Protocol version (2)
    uint16_t type;         // Message type
    uint32_t payloadLen;   // Payload length in bytes
    uint32_t requestId;    // Unique request ID
    uint32_t checksum;     // CRC32 of payload
};
```

**Header Size:** 32 bytes

### Message Types

#### Requests (Client → Server)

| Type | Value | Description |
|------|-------|-------------|
| REQUEST_COMPLETION | 0x01 | Request code completion |
| REQUEST_PREDICT | 0x02 | Request token prediction |
| REQUEST_EMBEDDING | 0x03 | Request text embedding |

#### Responses (Server → Client)

| Type | Value | Description |
|------|-------|-------------|
| RESPONSE_COMPLETION | 0x81 | Completion response |
| RESPONSE_PREDICT | 0x82 | Prediction response |
| RESPONSE_EMBEDDING | 0x83 | Embedding response |

### Request Format

#### Completion Request

```json
{
  "model": "llama-2-7b-q4_0",
  "prompt": "def fibonacci(n):",
  "max_tokens": 256,
  "temperature": 0.7,
  "top_p": 0.9,
  "stream": true
}
```

#### Prediction Request

```json
{
  "model": "mistral-7b-q4_0",
  "context": "The quick brown",
  "max_tokens": 10
}
```

### Response Format

#### Completion Response

```json
{
  "request_id": 12345,
  "status": "success",
  "text": "def fibonacci(n):\n    if n <= 1:\n        return n\n    return fibonacci(n-1) + fibonacci(n-2)",
  "tokens_generated": 45,
  "generation_time_ms": 234,
  "tps": 192.3
}
```

---

## HTTP API

### Base URL

```
http://localhost:8080
```

### Endpoints

#### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "gpu_count": 2,
  "models_loaded": 1
}
```

#### Create Completion

```http
POST /v1/completions
Content-Type: application/json

{
  "model": "llama-2-7b-q4_0",
  "prompt": "def hello_world():",
  "max_tokens": 256,
  "temperature": 0.7
}
```

---

## Command Line Interface

### InferenceEngine Options

| Option | Description | Default |
|--------|-------------|---------|
| `--model` | Path to GGUF model | Required |
| `--prompt` | Input prompt | Required |
| `--max-tokens` | Maximum tokens | 256 |
| `--temperature` | Sampling temperature | 0.7 |
| `--top-p` | Nucleus sampling | 0.9 |
| `--gpu-layers` | GPU layers | 0 |
| `--port` | HTTP port | 8080 |
| `--daemon` | Run as daemon | false |

---

## PowerShell API

### Model Management

```powershell
# List models
.\scripts\model_manager.ps1 -Action list

# Download model
.\scripts\model_manager.ps1 -Action download -ModelName "llama-2-7b-q4_0"
```

### Health Monitoring

```powershell
# Start monitoring
.\scripts\health_monitor.ps1 -RefreshInterval 5
```

---

## Error Codes

| Code | Description |
|------|-------------|
| `MODEL_NOT_LOADED` | Model not loaded |
| `GPU_OUT_OF_MEMORY` | GPU memory exhausted |
| `INVALID_REQUEST` | Malformed request |
| `TIMEOUT` | Request timed out |

---

*API Reference v1.0.0*
