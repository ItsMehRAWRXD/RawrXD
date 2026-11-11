# RawrXD Gateway v1.0

## Overview

RawrXD Gateway is a native HTTP API server that bridges your `ide_chatbot.html` frontend with the RawrXD backend services. It implements the missing endpoints that the HTML IDE expects.

## Architecture

```
ide_chatbot.html (Browser)
        |
        | HTTP/WebSocket
        v
RawrXDGateway.exe :11435
        |
        +-- /health, /status, /models
        +-- /v1/chat/completions, /api/generate, /ask
        +-- /api/workspace/*
        +-- /api/read-file, /api/write-file
        +-- /api/agent/*, /api/tool
        +-- /api/tags, /api/chat (Ollama compat)
        |
        v
   Ollama :11434 (for actual inference)
```

## Build

```batch
cd d:\RawrXD\gateway
compile_env.bat
```

Output: `d:\RawrXD\build\RawrXDGateway.exe`

## Run

```batch
:: Default (port 11435, workspace D:\RawrXD)
d:\RawrXD\build\RawrXDGateway.exe

:: Custom port
d:\RawrXD\build\RawrXDGateway.exe --port 8080

:: Custom workspace
d:\RawrXD\build\RawrXDGateway.exe --workspace D:\MyProject

:: Full options
d:\RawrXD\build\RawrXDGateway.exe --port 11435 --workspace D:\RawrXD --ollama http://127.0.0.1:11434
```

## API Endpoints

### Core
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/status` | GET | Server status + stats |
| `/models` | GET | List available models |

### Chat/Completion
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | OpenAI-compatible chat |
| `/api/generate` | POST | Ollama-compatible generate |
| `/ask` | POST | Simple Q&A endpoint |

### Workspace
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/workspace/open` | POST | Open workspace at path |
| `/api/workspace/tree` | GET | Get file tree |

### File Operations
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/read-file` | POST | Read file content |
| `/api/write-file` | POST | Write file content |
| `/api/delete-file` | POST | Delete file/directory |
| `/api/search-files` | POST | Search files by name |

### Agent
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agent/chat` | POST | Agent chat endpoint |
| `/api/tool` | POST | Tool execution |

### Ollama Compatibility
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tags` | GET | List models (Ollama format) |
| `/api/chat` | POST | Chat (Ollama format) |

## Testing

```bash
# Health check
curl http://localhost:11435/health

# Status
curl http://localhost:11435/status

# Models
curl http://localhost:11435/models

# Ask a question
curl -X POST -H "Content-Type: application/json" \
  -d '{"question":"Hello"}' \
  http://localhost:11435/ask

# Get workspace tree
curl http://localhost:11435/api/workspace/tree

# Read a file
curl -X POST -H "Content-Type: application/json" \
  -d '{"path":"README.md"}' \
  http://localhost:11435/api/read-file

# Write a file
curl -X POST -H "Content-Type: application/json" \
  -d '{"path":"test.txt","content":"Hello World"}' \
  http://localhost:11435/api/write-file
```

## Integration with ide_chatbot.html

1. Start the gateway:
   ```batch
   d:\RawrXD\build\RawrXDGateway.exe
   ```

2. Open `ide_chatbot.html` in your browser

3. The HTML will automatically connect to `http://localhost:11435`

4. All endpoints will now work:
   - Health checks ✅
   - Model listing ✅
   - File operations ✅
   - Chat/completion ✅
   - Agent tools ✅

## Next Steps

### Phase 2 - Full IDE Platform

```
RawrXD/
├── gateway/           ✅ RawrXDGateway.exe (DONE)
├── workspace/         🔄 WorkspaceManager (partial)
├── agent/           ⏳ AgentController
├── tools/           ⏳ Tool implementations
├── model/           ⏳ ModelRouter
├── ide/             ⏳ Win32IDE.exe
└── cli/             ⏳ rawrxd.exe
```

### Phase 3 - Features to Add

1. **WebSocket Server** - Real-time events
2. **File Watcher** - Auto-refresh on changes
3. **Agent Loop** - Autonomous execution
4. **Git Integration** - Source control
5. **Build System** - Compile/test
6. **Debug Adapter** - Debugging support

## Files Created

- `gateway/RawrXDGateway_simple.cpp` - Main source
- `gateway/compile_env.bat` - Build script
- `build/RawrXDGateway.exe` - Executable

## Technical Details

- **Language**: C++17
- **Networking**: WinSock2
- **JSON**: Manual (no external deps)
- **Filesystem**: std::filesystem
- **Port**: 11435 (configurable)
- **CORS**: Enabled for browser access

## Troubleshooting

### Port already in use
```batch
netstat -ano | findstr 11435
taskkill /PID <PID> /F
```

### Cannot connect from browser
- Check Windows Firewall
- Ensure CORS headers are working
- Try `curl` first to verify

### File operations fail
- Check workspace path exists
- Verify permissions
- Use absolute paths

## License

RawrXD Project - Proprietary
