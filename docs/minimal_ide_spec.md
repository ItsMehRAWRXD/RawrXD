# RawrXD Minimal IDE Specification

## Overview
A lightweight IDE client that connects to RawrEngine via HTTP API, replacing the broken Win32IDE with a maintainable architecture.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IDE Client (Any Stack)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Editor  │  │ Terminal │  │  Agent   │  │  Model   │ │
│  │ (Monaco) │  │          │  │  Panel   │  │  Panel   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       │             │             │             │        │
│       └─────────────┴──────┬──────┴─────────────┘        │
│                            │                                │
│                     HTTP Client                            │
└────────────────────────────┬───────────────────────────────┘
                             │
                    localhost:8080
                             │
┌────────────────────────────┼───────────────────────────────┐
│                    RawrEngine.exe                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  HTTP Server │  │    Agent     │  │   GPU/ML     │   │
│  │              │  │   Runtime    │  │   Backend    │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Required API Endpoints

### Core IDE Functions

| Feature | Endpoint | Method | Purpose |
|---------|----------|--------|---------|
| **Status** | `/status` | GET | Check engine health |
| **Generate** | `/api/generate` | POST | Code completion |
| **Chat** | `/v1/chat/completions` | POST | AI chat |
| **Agent** | `/api/agent/wish` | POST | Execute task |
| **Subagent** | `/api/subagent` | POST | Parallel work |
| **GPU** | `/api/gpu/status` | GET | GPU monitoring |
| **Models** | `/api/tags` | GET | List models |
| **Backends** | `/api/backends` | GET | Switch backend |

### Agent Execution Flow

```javascript
// 1. Send task to agent
POST /api/agent/wish
{
  "prompt": "Analyze D:\\RawrXD\\src for build issues"
}

// 2. Get response
{
  "agent_id": "agent_123",
  "status": "completed",
  "result": "Found 47 compilation errors...",
  "actions_taken": [...]
}

// 3. Check agent status
GET /api/agents/status

// 4. View history
GET /api/agents/history
```

## Client Implementation Options

### Option A: WebView2 + TypeScript (Recommended)

**Stack:**
- WebView2 (Edge Chromium)
- TypeScript/React
- Monaco Editor
- WebSocket for real-time updates

**Advantages:**
- ✅ Fast iteration
- ✅ Monaco integration (VS Code editor)
- ✅ Easy agent visualization
- ✅ 240Hz capable
- ✅ Modern tooling

**Structure:**
```
RawrXD-IDE-Web/
├── src/
│   ├── components/
│   │   ├── Editor.tsx        # Monaco wrapper
│   │   ├── Terminal.tsx      # xterm.js
│   │   ├── AgentPanel.tsx    # Agent status
│   │   ├── ModelPanel.tsx    # Model management
│   │   └── GpuMonitor.tsx    # GPU telemetry
│   ├── api/
│   │   └── rawrClient.ts     # HTTP client
│   └── App.tsx
├── package.json
└── index.html
```

### Option B: Qt6 + C++

**Stack:**
- Qt6 Widgets/QML
- Custom editor component
- Native performance

**Advantages:**
- ✅ Native look & feel
- ✅ Better Windows integration
- ✅ Lower memory than WebView2

**Disadvantages:**
- ❌ Slower iteration
- ❌ Editor component inferior to Monaco

### Option C: Repair Win32IDE (Not Recommended)

**Issues:**
- 579 compilation units with drift
- Header/cpp mismatches
- Resource ID conflicts
- Unicode migration incomplete
- Estimated 4-8 hours repair

## Minimal Feature Set (MVP)

### Phase 1: Editor + Agent (Week 1)
- [ ] Monaco editor integration
- [ ] File tree (basic)
- [ ] Agent panel (send/receive)
- [ ] Terminal output display

### Phase 2: Model Management (Week 2)
- [ ] Model list
- [ ] Model load/unload
- [ ] GPU status monitor

### Phase 3: Advanced Features (Week 3-4)
- [ ] Git integration
- [ ] Symbol search (via agent)
- [ ] Build integration
- [ ] Debug integration

## API Contract

See `src/api_contract.json` for complete endpoint specification.

## Migration Path from Win32IDE

1. **Keep RawrEngine.exe** (working backend)
2. **Create new IDE client** (WebView2 recommended)
3. **Test parallel operation**
4. **Gradually migrate features**
5. **Deprecate Win32IDE** when new client stable

## Success Criteria

- [ ] Can open/edit/save files
- [ ] Can send agent tasks
- [ ] Can view agent responses
- [ ] Can monitor GPU status
- [ ] Can switch models
- [ ] 240Hz UI capable
- [ ] <100ms agent task latency

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| RawrEngine.exe | ✅ Working | HTTP API ready |
| Agent Runtime | ✅ Working | Via HTTP endpoints |
| GPU Backend | ✅ Working | RDNA3 verified |
| Win32IDE | 🔴 Broken | 579 errors, not worth fixing |
| New IDE Client | 🟡 Not started | WebView2 recommended |

## Recommendation

**Build WebView2 IDE client.** The backend is solid. A modern web-based frontend will be faster to develop, easier to maintain, and provide better user experience than repairing the legacy Win32 code.
