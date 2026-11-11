# BATCH1 Request A crash — root cause (tip)

ASOF_UTC=2026-11-03
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
SEAL_AUTHORITY_TOUCHED=0
DUMP=C:\Users\Garrett\AppData\Local\RawrXD\crashes\rawrxd-20261103-004332.dmp
TESTED_SHA_AT_CRASH=74678E5AB75D3BEAA952D1A0EE8EFD3370B6B6678711EF0D0F95DA3DAE754BAB

## Exception

- Code: `0xC0000005` ACCESS_VIOLATION (write)
- Fault module: `comctl32.dll` v5.82 (WinSxS), RIP offset `+0xBD02`
- Fault address written: `0x5FC310E2E0`
- Timing: ~0.9s after `REQUEST_A_SUBMITTED` (harness_console)
- Ollama worker had logged `MODEL_LOAD=PASS` then was mid-WinHTTP; UI thread faulted concurrently

## Root cause (product path)

Nested common-controls / UI work on the Request A send path:

1. **Agent step strip** (`AgentStepTimeline`) used `LISTBOX` with `LBS_NOTIFY`.
   `LB_ADDSTRING` / `LB_DELETESTRING` (thought row + mirror) emitted `LBN_*`
   into the subclassed secondary sidebar, which forwards `WM_COMMAND` to the
   main window. Nested StatusBar (`SB_SETTEXTA`) / TabCtrl work under an
   in-flight ListBox `SendMessage` faults comctl32 (`0xC000041D` / raw AV).
2. **Thought timer** (`IDT_AGENT_THOUGHT` @ 250ms) refreshed the listbox while
   Ollama ran — amplifying nested LISTBOX traffic (already disabled in tip
   source: skip `armAgentThoughtTimer` on send; stop Debug RichEdit mirror
   from `appendCopilotChatUtf8`).
3. **`updateChatSessionTabs`** (`TabCtrl_DeleteAllItems` / `InsertItem`) can
   re-enter via `TCN_SELCHANGE` → `switchChatSession` → nested rebuild during
   `checkpointActiveChat` on send.

## Source fix (tip only — not seal CB34EF4E / a5ae60ef)

- Remove `LBS_NOTIFY` from step-strip listbox; `IsWindow` guards on row ops.
- `m_updatingChatSessionTabs` fence; ignore `TCN_SELCHANGE` while rebuilding.
- Retain prior tip mitigations: no thought timer on send; no Debug RichEdit
  mirror from chat append; defer model-discovery COMCTL teardown while
  `m_inferenceRunning`; early busy claim in `HandleCopilotSend`.

## Rebuild / runtime

Rebuild of `RawrXD-Win32IDE-Native` (Release / `build_modelroute`) was started
after the fix. Agent shell backend became unavailable before link completion
and before Batch1 harness re-run. **Do not invent PASS.**

`SOURCE_WIRED` (cancel path + crash fix) ≠ `RUNTIME_REACHED` until harness
exercises Stop → Request B on a named tip SHA without crash.
