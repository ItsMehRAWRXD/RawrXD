# RECEIPT — SWARM_16_RUNTIME_002_PATH_B

```
ASOF_UTC=2026-10-28T11:35:00Z
WORKSPACE=G:\~dev\rawrxd
PATH=B_GUI (not Path A headless)
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1
```

## Root cause (diagnosed + source-fixed)

`SettingsManager::Initialize` holds non-recursive `std::mutex m_mutex` then calls
`Load()`/`Save()` which also `lock_guard` the same mutex → self-deadlock / SEH
abort immediately after `[STARTUP] before SettingsManager`.

`createWindowWithSEH` returned false → exit 2. Prior tip stderr blamed
"no interactive window station" for **any** createWindow failure (misleading;
host was WinSta0 interactive).

Historical tip **6832F439…** left immutable.

## Source changes (pre-rebuild)

| File | Change |
|------|--------|
| `src/SettingsManager.h/.cpp` | `LoadUnlocked`/`SaveUnlocked`; Initialize/Shutdown use unlocked bodies |
| `src/win32app/main_win32.cpp` | SEH prints `GetExceptionCode`; honest fail stderr |
| `src/win32app/Win32IDE_Core.cpp` | SettingsManager CALL/RETURN stderr breadcrumbs |

## Gates (fail-closed)

| Gate | Result |
|------|--------|
| ROOT_CAUSE | **CLOSED** (source) |
| TIP_REBUILD / NEW_SHA | **BLOCKED_ENV** |
| MAIN_HWND ≠ 0 | **NOT_RUN** (tip still 6832F439) |
| INVOKED onSubAgentSwarm | **0 / NOT_RUN** |
| resolveSwarmModelOrchPlan | **NOT_RUN** |
| executeSwarm | **NOT_RUN** |
| RUNTIME_PASS | **0** |
| PROMOTE | **0** |

## Blocker

Agent Shell harness hung (echo/Get-Process/ninja all no-output >15–19m).
`.ninja_log` never gained a new SettingsManager rebuild line. Cannot claim NEW SHA
or INVOKED. Harness ready: `harness_path_b_wm4111.ps1`.

## Explicit non-claims

```
SOURCE_FIX_LANDED != TIP_REBUILT
LINKED != INVOKED
NOT_RUN != PASS
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
```
