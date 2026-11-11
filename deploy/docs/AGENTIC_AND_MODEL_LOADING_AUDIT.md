# Agentic + Model Loading Audit — Why Local/Cloud Model + Agentic Work Don’t Behave Like Cursor

**Date:** 2026-03-08  
**Scope:** RawrXD IDE — loading local/cloud models and getting agentic autonomous behavior (like Cursor with project context and tools).

---

## Executive summary

RawrXD has the right building blocks (BackendSwitcher for Ollama/cloud, AgenticBridge, tool dispatch, workspace UI) but **three gaps** prevent “load project folder and have the agent work like Cursor”:

1. **Backend manager only starts after a local GGUF is loaded** — Ollama/cloud are never used for chat unless you first load a GGUF.
2. **Agentic path is local-only** — Tool use and agent loop always go through `CPUInferenceEngine`; they never use Ollama or cloud.
3. **Workspace/project context is not passed to the agent** — The agent prompt does not receive project root or file list, so it can’t “see” the opened folder.

Below is the evidence and the concrete code changes needed to fix each.

---

## 1. Backend manager only after GGUF load

**Observation:** `initBackendManager()` (and `initLLMRouter()`) are only called from `loadModelFromPath()` when a **local GGUF** is successfully loaded (`loadGGUFModel(filepath)` returns true).

**Location:** `src/win32app/Win32IDE.cpp` (around 4429–4436):

```cpp
bool ggufOk = loadGGUFModel(filepath);
if (ggufOk) {
    initializeInference();
    initBackendManager();
    initLLMRouter();
}
```

**Effect:** If the user never does “File > Load Model” with a GGUF file:

- `m_backendManagerInitialized` stays `false`.
- `sendMessageToModel()` never uses `routeWithIntelligence()`.
- Chat falls through to `trySendToOllama()` (only if `m_ollamaBaseUrl` is set) or to `ExecuteAgentCommand()` with the local engine (which has no model).

So “use Ollama or cloud without ever loading a GGUF” never engages the BackendSwitcher.

**Fix:**

- Call `initBackendManager()` (and optionally `initLLMRouter()`) during IDE startup (e.g. in `onCreate` or after the main window is ready), **independent** of loading a GGUF.
- Optionally: when the user selects “Ollama” (or another cloud backend) in the Backend Switcher UI, ensure backend manager (and router) are initialized if not already.

---

## 2. Agentic path is local-only

**Observation:** All agent execution goes through `AgenticBridge::ExecuteAgentCommand()` → `g_agentEngine->chat()` → `AgenticEngine::chat()` → `CPUInferenceEngine` (local GGUF only). There is no branch that uses the active backend (Ollama/OpenAI/Claude/etc.) for the **agent** path.

**Locations:**

- `src/win32app/Win32IDE_AgenticBridge.cpp`: `ExecuteAgentCommand()` uses `g_agentEngine->chat(refinedPrompt)` only.
- `src/agentic_engine.cpp`: `chat()` uses `m_inferenceEngine` (and `dynamic_cast<CPUInferenceEngine>`) or an injected `m_chatProvider`; there is no use of Win32IDE’s `routeInferenceRequest()` or BackendSwitcher.

**Effect:** Even when chat works via Ollama (e.g. after you fix §1 or after a GGUF was loaded once and backend was inited), **agentic** behavior (tool calls, multi-step agent loop) does not use Ollama/cloud. So you get “Copilot-style” single-turn chat from the backend, but not “Cursor-style” agent that can use tools and iterate.

**Fix:**

- **Option A (recommended):** When the **local** model is not loaded (`!g_cpuEngine || !g_cpuEngine->IsModelLoaded()`), route the agent prompt through the **active backend** (same as chat):
  - From `AgenticBridge::ExecuteAgentCommand()`, call into Win32IDE’s `routeInferenceRequest(prompt)` (or the same path used by `sendMessageToModel` when backend is initialized).
  - Keep the existing tool-call parsing and `DispatchModelToolCalls()` on the string returned from that backend; then feed tool results back (e.g. re-prompt) for the next turn. That way one agent loop can use Ollama/cloud.
- **Option B:** Set `AgenticEngine::setChatProvider()` to a lambda that calls Win32IDE’s `routeInferenceRequest()`. Then `ExecuteAgentCommand` → `g_agentEngine->chat()` would use that provider when the bridge is configured for “use backend for agent”. Option A is simpler and keeps backend routing in one place.

Implementing Option A means:

- In `ExecuteAgentCommand()` (or a small helper used by it), if local engine has no model, call `m_ide->routeInferenceRequest(refinedPrompt)` (or the appropriate public method that performs backend routing).
- Use the returned string as `response`, then run the same `DispatchModelToolCalls(response, toolResult)` and re-prompt logic as today.

---

## 3. Workspace / project context not in agent prompt

**Observation:** The agent’s system prompt is built in `NativeAgent::BuildPrompt()` (and the code path that uses it). It receives:

- `m_languageContext`, `m_fileContext` (current file)
- No **workspace root**, no **project path**, no **list of files** in the opened folder.

`Win32IDE` has:

- `m_explorerRootPath` — set only at sidebar creation to the exe directory.
- `m_projectRoot` — declared but **never set** when the user opens a folder (e.g. in `handleWelcomeOpenFolder()`).

**Location:** `handleWelcomeOpenFolder()` (e.g. `Win32IDE_Tier1Cosmetics.cpp`) sets `m_settings.workingDirectory` and calls `refreshFileTree()`, but:

- It does **not** set `m_explorerRootPath` or `m_projectRoot`.
- `refreshFileTree()` uses `m_explorerRootPath`; since that’s never updated, the tree does not switch to the newly opened folder.

So:

- The UI doesn’t consistently show “the opened project” in the explorer.
- The agent never receives “workspace: D:\rawrxd” or “files: src/..., include/...”.

**Fix:**

- In `handleWelcomeOpenFolder()` (or wherever “open folder” is committed):
  - Set `m_explorerRootPath = folderPath` and `m_projectRoot = folderPath` so the explorer and the rest of the IDE share the same “workspace root”.
- When calling the agent (e.g. when building the prompt for `ExecuteAgentCommand` or when setting up `AgenticBridge`/`NativeAgent`):
  - Pass the current workspace root (e.g. `m_projectRoot` or `m_explorerRootPath`) into the bridge.
  - Extend the system prompt (or the first user message) to include:
    - “Workspace root: &lt;path&gt;”
    - Optionally: a short list of top-level paths (or a small file tree) under that root so the model can “see” the project (same idea as Cursor’s project context).

That way “load project file(s)/folder(s)/drive(s)” actually sets the workspace and the agent can work in that context.

---

## 4. Summary of required changes

| # | Issue | Fix |
|---|--------|-----|
| 1 | Backend manager only inited after GGUF load | Call `initBackendManager()` (and optionally `initLLMRouter()`) at IDE startup, not only in `loadModelFromPath()` when GGUF loads. |
| 2 | Agentic path never uses Ollama/cloud | In `ExecuteAgentCommand()`, when local model is not loaded, route the prompt through the active backend (e.g. `m_ide->routeInferenceRequest(refinedPrompt)`), then run existing tool parsing and dispatch on the result. |
| 3 | Workspace not set or passed to agent | In “open folder” handler, set `m_explorerRootPath` and `m_projectRoot`. Pass workspace root (and optionally a small file list) into the agent prompt so the model has project context. |

After these, “load a local or cloud model and have agentic autonomous work” should align with “load project folder and have it work like Cursor” (same backend for both chat and agent, plus workspace-aware prompts).

---

## 5. References (file locations)

- Backend init only after GGUF: `Win32IDE.cpp` ~4430–4436.
- Chat path and fallbacks: `Win32IDE.cpp` `sendMessageToModel()` ~5140–5198.
- Agent path: `Win32IDE_AgenticBridge.cpp` `ExecuteAgentCommand()` ~101–212; `agentic_engine.cpp` `chat()` ~867–887.
- Backend routing: `Win32IDE_BackendSwitcher.cpp` `routeInferenceRequest()`, `routeToOllama()`, etc.
- Open folder: `Win32IDE_Tier1Cosmetics.cpp` `handleWelcomeOpenFolder()` ~1655–1674.
- Explorer root and refresh: `Win32IDE_Sidebar.cpp` (e.g. ~832, 842–882).
- Agent prompt: `native_agent.hpp` `BuildPrompt()` ~166–219.
