# API Integration
## Sovereign IDE Integration Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The REST API enables external applications to integrate with the Sovereign IDE.

### API Versions

| Version | Status | Base URL |
|---------|--------|----------|
| v1 | Stable | /api/v1 |
| v2 | Beta | /api/v2 |

---

## Authentication

```bash
# API Key
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8080/api/v1/status

# OAuth 2.0
curl -H "Authorization: Bearer ACCESS_TOKEN" \
     http://localhost:8080/api/v1/analysis
```

---

## Endpoints

### Binary Analysis

```bash
# Upload binary
curl -X POST \
     -F "file=@binary.exe" \
     http://localhost:8080/api/v1/binaries

# Run analysis
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"type": "full"}' \
     http://localhost:8080/api/v1/binaries/{id}/analyze

# Get results
curl http://localhost:8080/api/v1/binaries/{id}/results
```

### Response Format

```json
{
    "id": "bin_12345",
    "status": "completed",
    "results": {
        "functions": 150,
        "strings": 2300,
        "imports": 45,
        "vulnerabilities": []
    },
    "completed_at": "2026-07-11T10:30:00Z"
}
```

---

## WebSocket API

```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/stream');

ws.onopen = () => {
    ws.send(JSON.stringify({
        action: 'subscribe',
        events: ['analysis.progress', 'analysis.complete']
    }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Progress:', data.progress);
};
```

---

## Summary

API Integration provides:

- ✅ **REST API**
- ✅ **WebSocket streaming**
- ✅ **Authentication**
- ✅ **JSON responses**
- ✅ **Versioned API**

**Status:** ✅ Complete
