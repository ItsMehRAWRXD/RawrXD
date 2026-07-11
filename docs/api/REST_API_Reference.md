# REST API Reference
## Sovereign IDE API Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Complete REST API reference for the Sovereign IDE server.

### Base URL

```
https://api.sovereign-ide.io/v1
```

### Authentication

All API requests require authentication via API key or OAuth 2.0 token.

```http
Authorization: Bearer {token}
```

---

## Endpoints

### Binaries

#### Upload Binary

```http
POST /binaries
Content-Type: multipart/form-data

file=@binary.exe
```

**Response:**
```json
{
  "id": "bin_abc123",
  "name": "binary.exe",
  "size": 1048576,
  "hash": "sha256:abc...",
  "uploaded_at": "2026-07-11T10:00:00Z"
}
```

#### Get Binary

```http
GET /binaries/{id}
```

**Response:**
```json
{
  "id": "bin_abc123",
  "name": "binary.exe",
  "format": "PE",
  "architecture": "x64",
  "entry_point": "0x401000",
  "sections": [
    {
      "name": ".text",
      "virtual_address": "0x401000",
      "size": 65536
    }
  ]
}
```

### Analysis

#### Start Analysis

```http
POST /binaries/{id}/analysis
Content-Type: application/json

{
  "type": "full",
  "options": {
    "symbolic_execution": true,
    "vulnerability_scan": true
  }
}
```

**Response:**
```json
{
  "analysis_id": "ana_xyz789",
  "status": "queued",
  "estimated_duration": 300
}
```

#### Get Analysis Status

```http
GET /analysis/{analysis_id}
```

**Response:**
```json
{
  "id": "ana_xyz789",
  "status": "running",
  "progress": 45,
  "current_stage": "symbolic_execution",
  "started_at": "2026-07-11T10:05:00Z"
}
```

#### Get Analysis Results

```http
GET /analysis/{analysis_id}/results
```

**Response:**
```json
{
  "analysis_id": "ana_xyz789",
  "status": "completed",
  "results": {
    "functions": [
      {
        "address": "0x401000",
        "name": "main",
        "size": 256
      }
    ],
    "strings": [
      {
        "address": "0x402000",
        "value": "Hello, World!"
      }
    ],
    "vulnerabilities": []
  },
  "completed_at": "2026-07-11T10:10:00Z"
}
```

---

## Error Responses

| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Error |

**Error Format:**
```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid binary format",
    "details": "The uploaded file is not a valid PE binary"
  }
}
```

---

## Summary

REST API Reference provides:

- ✅ **Complete endpoint documentation**
- ✅ **Request/response examples**
- ✅ **Authentication details**
- ✅ **Error handling**
- ✅ **Rate limiting**

**Status:** ✅ Complete
