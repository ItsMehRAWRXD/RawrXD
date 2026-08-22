# RAWRXD-AUDIT-03 — Runtime Boundary & Stub Elimination Plan

## Status: IN PROGRESS — Step 1 & 2 Complete (Architecture Proven, Build Pending)

**Revised Estimate (post-AUDIT-03):**
- **~1–2 weeks** for functional Ollama replacement (compile-clean + end-to-end Deep2 agent invocation)
- **~2–4 weeks** for production sovereign runtime (tokenizer correctness, streaming, stress certification)

**Critical distinction:** AUDIT-03 proves the architecture is moving toward Ollama independence. It does not yet prove the runtime is operationally independent. The interface migration was performed before the full build/runtime path was proven.

---

## 1. Objective

Establish a single authoritative model runtime interface (`IModelRuntime`) and migrate all agent/IDE inference calls through it, eliminating the Ollama dependency from the production path.

---

## 2. Verified Interface Inventory

### 2.1 Deep2 Runtime (Production)

| Component | File | Role | Status |
|-----------|------|------|--------|
| `Deep2Engine` | `src/deep2/Deep2Engine.h` | Core inference engine | ✅ Real |
| `Deep2ModelLoader` | `src/deep2/Deep2IDEIntegration.hpp` | GGUF shard loading | ✅ Real |
| `Deep2InferenceSession` | `src/deep2/Deep2IDEIntegration.hpp` | Session wrapper | ✅ Real |
| `GGUFShardRouter` | `src/deep2/GGUFShardRouter.hpp` | Multi-shard routing | ✅ Real |
| `FabricTensorTable` | `src/deep2/FabricTensorTable.hpp` | Tensor residency | ✅ Real |
| `Deep2IDEIntegration` | `src/deep2/Deep2IDEIntegration.cpp` | IDE bridge | ✅ Real |

### 2.2 Agent Layer (Currently Ollama-Backed)

| Component | File | Role | Status |
|-----------|------|------|--------|
| `OrchestratorBridge` | `src/agentic/OrchestratorBridge.h` | Agent entry point | ⚠️ Stub in rawrxd_link_stubs.cpp |
| `AgentOllamaClient` | `src/agentic/AgentOllamaClient.h` | Ollama HTTP client | ⚠️ Stub in rawrxd_link_stubs.cpp |
| `AgenticBridge` | `src/win32app/Win32IDE_AgenticBridge.h` | IDE agent bridge | ⚠️ Calls Ollama via AgenticBridge |

### 2.3 Stub Files (1,285 lines total)

| File | Lines | Classification | Action |
|------|-------|----------------|--------|
| `src/core/link_stubs.cpp` | 41 | SAFE — test/legacy codec | Keep (or delete if unused) |
| `src/core/link_stubs_production.cpp` | 458 | REPLACE — Scheduler/GPU/Tensor | Replace with real impls |
| `src/rawrxd_link_stubs.cpp` | 465 | REPLACE — OrchestratorBridge/AgentOllamaClient | **Delete after migration** |
| `src/deep2/deep2_link_stubs.cpp` | 321 | REPLACE — Deep2 internals | Replace with real impls |

---

## 3. IModelRuntime Contract

**File:** `src/runtime/IModelRuntime.hpp`

```
IModelRuntime (pure virtual)
├── LoadModel(path) → bool
├── UnloadModel()
├── IsLoaded() → bool
├── GetModelInfo() → ModelInfo
├── Tokenize(text) → vector<int32_t>
├── Detokenize(tokens) → string
├── Generate(request) → GenerationResult
├── GenerateStream(request, callback) → bool
├── CancelGeneration()
├── IsGenerating() → bool
├── GenerateFIM(request) → GenerationResult
├── GenerateFIMStream(request, callback) → bool
├── SupportsToolCalling() → bool
├── SupportsFIM() → bool
├── HealthCheck(status) → bool
└── GetBackendName() → string
```

**Implementations:**
- `Deep2ModelRuntime` — wraps Deep2Engine (production)
- `OllamaModelRuntime` — wraps AgentOllamaClient (compatibility)
- `MockModelRuntime` — test stub

---

## 4. Migration Steps

### Step 1: Create IModelRuntime + Deep2ModelRuntime ✅
- [x] `src/runtime/IModelRuntime.hpp` — interface definition
- [x] `src/deep2/Deep2ModelRuntime.cpp` — Deep2 adapter

### Step 2: Update OrchestratorBridge to use IModelRuntime ✅
- [x] Replace `std::unique_ptr<AgentOllamaClient> m_ollamaClient` with `std::unique_ptr<IModelRuntime> m_runtime`
- [x] Update `Initialize()` to create `Deep2ModelRuntime` by default
- [x] Update `RunAgent()` to call `m_runtime->GenerateStream()`
- [x] Update `RequestGhostText()` to call `m_runtime->GenerateFIMStream()`
- [x] Remove OllamaConfig from public API (keep internally for fallback)
- [ ] **PENDING:** Build verification — `RawrXD-Win32IDE.exe` must compile and link

### Step 3: Update AgenticBridge (Win32IDE)
- [ ] Replace `SetOllamaServer()` with `SetModelRuntime()`
- [ ] Route `ExecuteAgentCommand()` through IModelRuntime
- [ ] Route ghost text through IModelRuntime::GenerateFIMStream()

### Step 4: Update CMakeLists.txt
- [ ] Add `src/runtime/IModelRuntime.hpp` to WIN32IDE_SOURCES
- [ ] Add `src/deep2/Deep2ModelRuntime.cpp` to WIN32IDE_SOURCES
- [ ] Remove `src/rawrxd_link_stubs.cpp` from rawrxd target (after migration)

### Step 5: Delete rawrxd_link_stubs.cpp stubs
- [ ] Verify OrchestratorBridge and AgentOllamaClient are no longer referenced from stubs
- [ ] Delete `src/rawrxd_link_stubs.cpp` or reduce to only truly unreachable symbols

### Step 6: Replace deep2_link_stubs.cpp
- [ ] Implement real `ReverseIntegration` (or wire to existing `src/deep2/ReverseIntegration.cpp`)
- [ ] Implement real `MARS::MARSController` (or wire to existing `src/deep2/mars/MARSController.cpp`)
- [ ] Implement real `ThreadPool` (or wire to existing `src/deep2/ThreadPool.cpp`)
- [ ] Implement real `KVCache` (or wire to existing `src/deep2/KVCache.cpp`)
- [ ] Implement real `MoERouter` (or wire to existing `src/deep2/MoERouter.cpp`)
- [ ] Implement real `QuantKernelRegistry` (or wire to existing `src/deep2/QuantKernelRegistry.cpp`)

---

## 5. Critical Decision: Tokenize/Detokenize Exposure

**Problem:** `Deep2InferenceSession` does not expose `tokenize()` / `detokenize()`. These methods exist on `Deep2Engine` but are not accessible through the session wrapper.

**Options:**
1. **Expose through Deep2InferenceSession** — add `Tokenize()`/`Detokenize()` methods
2. **Access engine directly** — make `Deep2InferenceSession` expose a const reference to its engine
3. **Defer** — return empty from `Deep2ModelRuntime::Tokenize()` until needed

**Recommendation:** Option 1. Add tokenize/detokenize to `Deep2InferenceSession` so the session is the complete inference facade.

---

## 6. Build Verification Checklist

After each step, verify:

```powershell
# Configure with Win32IDE enabled
cmake -B build -S . -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF

# Build
cmake --build build --target RawrXD-Win32IDE

# Verify no stub violations in build output
# (EnforceNoStubs should pass)

# Run smoke test
.\build\bin\RawrXD-Win32IDE.exe --smoke-test
```

---

## 7. Regression Protection

**D2-K2-08 baseline must remain intact:**
- 13 shards
- 1096 tensors
- Cross-shard resolution
- Deep2IDEIntegration loading path

**Do not modify:**
- `Deep2IDEIntegration.cpp` loading logic
- `GGUFShardRouter` scan/resolve logic
- `FabricTensorTable` ingestion logic

**Safe to modify:**
- `OrchestratorBridge` (currently stub)
- `AgentOllamaClient` (currently stub)
- `rawrxd_link_stubs.cpp` (delete after migration)

---

## 8. Success Criteria

1. `RawrXD-Win32IDE.exe` links with `RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF`
2. `EnforceNoStubs(RawrXD-Win32IDE)` passes
3. Agent chat panel can load K2 and generate tokens without Ollama
4. Ghost text works via `IModelRuntime::GenerateFIMStream()`
5. `rawrxd_link_stubs.cpp` is deleted or reduced to <50 lines

---

## 9. Files Created/Modified

| File | Action | Status |
|------|--------|--------|
| `src/runtime/IModelRuntime.hpp` | Created | ✅ |
| `src/deep2/Deep2ModelRuntime.cpp` | Created | ✅ |
| `src/agentic/OrchestratorBridge.h` | Modify to use IModelRuntime | ⬜ |
| `src/agentic/OrchestratorBridge.cpp` | Modify to use IModelRuntime | ⬜ |
| `src/win32app/Win32IDE_AgenticBridge.h` | Modify to use IModelRuntime | ⬜ |
| `src/win32app/Win32IDE_AgenticBridge.cpp` | Modify to use IModelRuntime | ⬜ |
| `src/rawrxd_link_stubs.cpp` | Delete or reduce | ⬜ |
| `src/deep2/deep2_link_stubs.cpp` | Replace with real impls | ⬜ |
| `src/deep2/Deep2IDEIntegration.hpp` | Add tokenize/detokenize to session | ⬜ |
| `CMakeLists.txt` | Add new sources, remove stubs | ⬜ |

---

## 10. Sovereign Runtime Milestone Definition (Revised)

**Ollama replacement =** criteria 1–8 pass:
1. `IModelRuntime` compiles and links.
2. `Deep2ModelRuntime` loads a real GGUF.
3. Actual tokenizer vocabulary is wired.
4. `Generate()` produces correct tokens.
5. `GenerateStream()` produces incremental tokens.
6. Agent tool loop works end-to-end.
7. IDE receives the response.
8. No Ollama process/API is involved.

**Production sovereign runtime =** criteria 9–10 also pass:
9. No production link stubs are supplying the inference path.
10. Repeated generation survives a meaningful stress test.

**Current position:** Step 1 complete (interface created). Step 2 complete (OrchestratorBridge migrated). Build verification pending.

---

*Audit started: 2026-08-22*
*Next milestone: Build verification — compile and link RawrXD-Win32IDE with AUDIT-03 changes*
