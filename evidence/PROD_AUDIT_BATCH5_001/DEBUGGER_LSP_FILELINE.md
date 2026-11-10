# Debugger simulated eval + LSP — file:line status

```
PROMOTE=0
NATIVE_TARGET=RawrXD-Win32IDE-Native
```

## Gate 62 — Debugger

| Item | Location | Status |
|------|----------|--------|
| Simulated expression eval | `src/win32app/Win32IDE_Debugger.cpp:758-761` | Emits `" Evaluate: " + expression + " = <value>"` — **no real debuggee eval** |
| Attach (UI-only flag) | `src/win32app/Win32IDE_Debugger.cpp:282-292` | Sets `m_debuggerAttached=true`; **no** `DEBUG_PROCESS` / `WaitForDebugEvent` |
| Duplicate Debugger TU | `RawrXD-ModelLoader/src/win32app/Win32IDE_Debugger.cpp` | Parallel tree; not Native link set |

**Verdict:** Partial (UI exists) — real debuggee **Unverified / not implemented** on Native path.

## Gate 61 — Real LSP JSON-RPC lifecycle

| Item | Location | Status |
|------|----------|--------|
| Qt LSP JSON-RPC client | `src/lsp_client.h` / `src/lsp_client.cpp` | Real JSON-RPC `initialize` (~L70–105) via `QProcess`/`QObject` — **Qt-only** |
| CMake Native sources | `CMakeLists.txt` RAWRXD_NATIVE_IDE_SOURCES (~L3788–3827) | **Does not** include `lsp_client.cpp` or `LanguageServerIntegration.cpp` |
| Win32IDE native headers | `src/win32app/Win32IDE.h` | **No** LSP / clangd symbols |
| Simulated LSP facade | `src/LanguageServerIntegration.cpp:331-342` | `initialize()` sets capability flags locally — **not** a server process lifecycle |

**Verdict:** Unverified on Native product path. Qt LSP exists but is out of scope for no-Qt shipping authority.
