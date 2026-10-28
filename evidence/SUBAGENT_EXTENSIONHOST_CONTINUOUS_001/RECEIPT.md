# RECEIPT — SUBAGENT_EXTENSIONHOST_CONTINUOUS_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
MOTD_ACK=1
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
ASOF_UTC=2026-10-28T21:35:00Z
WORKSPACE=G:\~dev\rawrxd
PATH=evidence/SUBAGENT_EXTENSIONHOST_CONTINUOUS_001
```

## Verdict

ExtensionHost companion IPC is **SOURCE_WIRED** and smoke-exercised (pipe
roundtrip PASS). Product tip ExtensionHost remains **GATED_OMIT / NOT_RUN**.
Tip `748B` `/api/subagent` exercised and exposed journal-only `success:true`
fiction; HeadlessIDE fail-close + real `SubAgentManager` spawn is **SOURCE_WIRED**
but tip **RUNTIME of that fix is NOT_RUN** (candidate relink blocked). No invent
PASS. No new tip freeze. **PROMOTE=0**.

## Tip exercise (748B)

| Field | Value |
|-------|-------|
| EXE | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Port | `18951` headless |
| `/api/subagent` | HTTP **202** `success:true` `status:spawned` (journal-only on tip) |
| `/api/agent/run` | HTTP **503** `model_not_loaded` |

## ExtensionHost companion

| Field | Value |
|-------|-------|
| Binary | `evidence/SUBAGENT_EXTENSIONHOST_CONTINUOUS_001/bin/RawrXD-ExtensionHost.exe` |
| No server | exit **101** FAIL_CLOSED |
| Pipe roundtrip | **OK BYTES=40 companion_exit=0** (smoke) |
| Product link | **GATED_OMIT** (not in WIN32IDE_SOURCES) |

## Source touch

- `src/win32app/Win32IDE_ChatIpcProtocol.h` (restored)
- `src/win32app/ExtensionHostIpcBridge.hpp` / `.cpp` (real client IPC)
- `src/win32app/HeadlessIDE.cpp` (SubAgentManager spawn; no `success:true`)
- `src/win32app/Win32IDE.cpp` (void `SetCompletionBackendNative` compile unblock)

## Relink

| Field | Value |
|-------|-------|
| Candidate rebuild | **NOT_RUN** |
| Blocker | `Win32TerminalManager.cpp` + `Win32IDE_CaretAnimation.cpp` compile fail |
| New freeze | **NOT performed** (preserve 748B authority) |

## Next OPEN

1. Fix TerminalManager/CaretAnimation compile → relink → new freeze → re-exercise subagent
2. Tip AgentRunLoop `model_not_loaded` (503)
3. Product ExtensionHost server path (still omit)

## Explicit non-claims

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PRODUCT_EXTENSIONHOST_PASS=0
TIP_SUBAGENT_FIX_RUNTIME=0
COMPANION_SMOKE != PRODUCT_PASS
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
```
