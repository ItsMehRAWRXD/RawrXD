# Backend Consolidation Log
# Date: 2026-06-01
# Action: Consolidated to single authoritative backend

## Authoritative Backend
- **File**: `mock_backend.py`
- **Port**: 11435 (default, matches frontend VITE_ENGINE_PORT)
- **Purpose**: HTTP API server for Sovereign Inference IDE
- **Endpoints**: /status, /control/*, /tool/*, /inference/sse, /model/*
- **Status**: ✅ ACTIVE

## Legacy Backends (Archived)
- **server.js** → `server.js.legacy` (Node.js backend, port 8080, DLL-dependent)
- **backend/rawrxd_backend.py** → Python backend (port 8080, GGUF scan)
- **masm_backend.asm** → Unbuilt MASM HTTP server
- **rawrxd_backend.asm** → Unbuilt MASM HTTP server

## Rationale
The frontend `EngineService.ts` expects port 11435. `mock_backend.py` already binds to 11435
and implements all required endpoints. The Node.js `server.js` required a DLL (`Phase3_Agent_Kernel.dll`)
that is not part of the Sovereign build pipeline. Consolidating to `mock_backend.py` eliminates
port conflicts and simplifies the CI/CD gate.

## To Restore Legacy (if needed)
```powershell
Rename-Item server.js.legacy server.js
# Then update frontend .env to VITE_ENGINE_PORT=8080
```
