# WebSocket API
## Sovereign IDE API Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

WebSocket API for real-time communication with the Sovereign IDE.

### Connection URL

```
wss://api.sovereign-ide.io/v1/stream
```

### Authentication

Include authentication token in connection query parameter:

```
wss://api.sovereign-ide.io/v1/stream?token={access_token}
```

---

## Message Format

All messages are JSON-encoded.

### Client to Server

```json
{
  "type": "subscribe",
  "channel": "analysis.updates",
  "data": {
    "analysis_id": "ana_xyz789"
  }
}
```

### Server to Client

```json
{
  "type": "analysis.progress",
  "timestamp": "2026-07-11T10:05:30Z",
  "data": {
    "analysis_id": "ana_xyz789",
    "progress": 45,
    "stage": "symbolic_execution"
  }
}
```

---

## Channels

### Analysis Updates

Subscribe to analysis progress and completion events.

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "analysis.updates",
  "data": {
    "analysis_id": "ana_xyz789"
  }
}
```

**Events:**
- `analysis.started`
- `analysis.progress`
- `analysis.stage_changed`
- `analysis.completed`
- `analysis.failed`

### Binary Events

Subscribe to binary loading and modification events.

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "binary.events",
  "data": {
    "binary_id": "bin_abc123"
  }
}
```

**Events:**
- `binary.loaded`
- `binary.modified`
- `binary.analysis_complete`

### System Events

Subscribe to system-wide events.

**Subscribe:**
```json
{
  "type": "subscribe",
  "channel": "system.events"
}
```

**Events:**
- `system.status`
- `system.error`
- `system.maintenance`

---

## Example Client

```javascript
const ws = new WebSocket('wss://api.sovereign-ide.io/v1/stream?token=xxx');

ws.onopen = () => {
  console.log('Connected');
  
  // Subscribe to analysis updates
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'analysis.updates',
    data: { analysis_id: 'ana_xyz789' }
  }));
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
  
  if (message.type === 'analysis.progress') {
    updateProgressBar(message.data.progress);
  }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected');
};
```

---

## Summary

WebSocket API provides:

- ✅ **Real-time communication**
- ✅ **Event subscription**
- ✅ **Multiple channels**
- ✅ **JSON messaging**
- ✅ **Client examples**

**Status:** ✅ Complete
