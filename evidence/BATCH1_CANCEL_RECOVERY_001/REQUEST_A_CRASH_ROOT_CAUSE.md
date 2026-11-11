# REQUEST_A_CRASH_ROOT_CAUSE

ASOF_UTC=2026-11-03T06:35:00Z
PROMOTE=0
CERTIFIED=0
SEAL_CB34EF4E_UNTOUCHED=1
GATES_04_08=FAIL
CANCELLATION_RECOVERY=NOT_PROVEN

## Exception / exit (locked)

| Field | Value |
|------:|-------|
| Exception | `0xC0000005` ACCESS_VIOLATION (write) |
| Process exit | `-1073740771` = `0xC000041D` STATUS_FATAL_USER_CALLBACK_EXCEPTION |
| Fault module | **comctl32.dll** |
| Fault RVA | `0xBD02` (stable across dumps) |
| Fault RIP example | `0x7FFC7BE7BD02` |
| Evidence tool | `parse_modules_dbghelp.ps1` + `last_crash.txt` |
| Dumps | `rawrxd-20261103-004332`, `010807`, `012239`, `012916`, … |

Two `comctl32.dll` images are loaded in the process (v5 + v6 paths visible in ModuleList).

## Last Request A event

```
REQUEST_A_SUBMITTED
~600–950ms
critical crash [] unhandled exception; minidump written
CRASH_DURING_ARM exit=-1073740771
FAIL_CLOSED_CRASH_ON_REQUEST_A
```

Stop never armed from harness POV. Request B never sent.

## Boundary

```
ORIGIN=NATIVE_UI / COMCTL32 (user callback)
NOT_PROVEN_PRIMARY=OLLAMA_HTTP_RECEIVE
NOT_PROVEN_PRIMARY=LATE_CHAT_UI_CALLBACK
```

Timing (~650ms) is **not** an immediate first-line Send-stack fault; it matches a deferred UI/COMCTL touch (discovery publish, GhostText/timer, or heap corruption surfacing in comctl32).

## Candidate repairs attempted (tip only; still FAIL)

| Change | Result |
|--------|--------|
| Dismiss chat GhostText timer on Send | Still CRASH |
| Disarm thought LISTBOX timer on Send | Still CRASH |
| Defer discovery while `m_inferenceRunning` | Already present; still CRASH |
| `m_blockModelDiscoveryUi` fence + cancel discovery | Still CRASH on `251BF1E4…` |
| Strip checkpoint/transcript/status/clear from Send | Still CRASH on `A868C778…` |
| Skip `onModelSelectionChanged` when route set | Still CRASH on `A868C778…` |

Minimal Send path still dies in **comctl32.dll+0xBD02** ⇒ remaining hypotheses:

1. Heap corruption earlier (layout/ODR after Win32IDE.h member add — **clean rebuild in flight**)
2. Dual comctl32 v5/v6 interaction on themed controls
3. Model-combo subclass / `WM_APP+106` still touching COMCTL despite fence
4. Worker-side corruption manifested on next UI COMCTL call

## Tip SHA trail (crash evidence; not seal)

- Historical reported: `74678E5A…` (user disposition)
- Intermediate: `ED7A476A…`, `C95B951D…`, `251BF1E4…`, `A868C778…`
- Seal `CB34EF4E…` untouched

## Law

```
REQUEST_A_CRASH=UNRESOLVED_AT_RUNTIME
SOURCE_WIRED_REPAIRS!=RUNTIME_PASS
NOT_RUN!=PASS
NEXT=FULL_CLEAN_REBUILD_THEN_RETEST_04_08
PROMOTE=0
CERTIFIED=0
```
