# Copilot Throttle Extension

Prevents "Response too long" errors when using local models (RawrXD/Ollama) with GitHub Copilot.

## Quick Start

```powershell
# Install and test everything
.\install-and-test.ps1 -All
```

## What It Does

1. **Intercepts local model requests** to RawrXD/Ollama
2. **Limits max_tokens** to 2048 (configurable)
3. **Forces streaming** for chat completions
4. **Limits context window** to 4096 tokens

## Configuration

In VS Code settings:

```json
{
  "copilotThrottle.enabled": true,
  "copilotThrottle.maxTokens": 2048,
  "copilotThrottle.maxChars": 8000,
  "copilotThrottle.streamChunkSize": 512
}
```

## Architecture

```
Copilot Chat
     ↓
VS Code Extension (throttle settings)
     ↓
Proxy Server (port 9091) ← Throttling happens here
     ↓
RawrXD (port 9090)
```

## Commands

- `Toggle Copilot Throttle` - Enable/disable
- `Show Throttle Status` - Show current settings

## Manual Setup

If the extension doesn't work:

1. Start RawrXD: `.\bin\RawrXD-Win32IDE.exe`
2. Start proxy: `node proxy-server.js`
3. Configure Copilot to use `http://127.0.0.1:9091`
