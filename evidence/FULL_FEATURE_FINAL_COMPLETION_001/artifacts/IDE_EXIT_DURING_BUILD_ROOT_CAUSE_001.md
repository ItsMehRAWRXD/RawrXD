# IDE_EXIT_DURING_BUILD root cause (F6F3 → tip_010)

ASOF_UTC=2026-11-09T18:18:00Z
MOTD_ACK=1
PROMOTE=0
TIP_MOVE=0

## Verdict

```
EXIT_ROOT_CAUSE=CONCURRENT_HARNESS_Stop-Process_Force_ALL_RawrXD-Win32IDE-Native_STAR
EXIT_CODE_OBSERVED=-1
NOT_SESSION_MODAL=1
NOT_UNSAVED_SAVE_CHANGES_DIALOG=1
NOT_EXTHOST_CRASH_PROVEN=1
NOT_AGENTSESSION_LINK_AV=1
AGENTSESSION_WIRE_PRESERVED=1
BUILD_PATH_OK_WHEN_IDE_ALIVE=1
```

## Evidence chain

1. F6F3 product run `issue49_product_final_tip009_20261109-125841.txt`:
   - MAIN at 12:58:43 → OPEN at 12:58:46 → `IDE_EXIT_DURING_BUILD=-1` at 12:58:52
   - No `BUILD_POLL` line (dead before/at first poll)
   - Chat hwnd=0 as cascade of dead process (not chat-path primary fail)

2. Prior tip009 SHA `98093287…` same harness survived build (`BUILD_POLL t=0 id1312=1 id1604=572`) then later `IDE_EXIT=-1` during agent wait — same `-1` signature.

3. Many sibling harnesses call blanket:
   `Get-Process -Name 'RawrXD-Win32IDE-Native*' | Stop-Process -Force`
   (`issue49_integ009_remeasure.ps1`, `run_integ009_four_panel_reverify.ps1`, `ls_in_pane_harness_009.ps1`, build bats with `taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe`).
   Forced terminate → process ExitCode `-1` in .NET/PowerShell.

4. Compiler path works when IDE lives:
   `artifacts/COMPILER_CAPTURE_RECEIPT.txt` shows fixture cl.exe start/parse/PROBLEM_ADDED/exit=0.

5. Same SHA `0946C7AA…` spawn probes (no concurrent kill race):
   - `SPAWN_PROBE_FORCE_LOCAL_RECEIPT.txt`: CHAT_OK=1 SESSION=1 DISPATCH=1 SPAWNED=1 IDE_ALIVE=1
   - `SPAWN_PROBE_DEEP2_ONLY_RECEIPT.txt`: deep2_agentic_loop SPAWNED=1 + DISPATCH=1
   - AgentSession wire kept (`AgentSession bound` in chat_runtime.log)

## Stabilization

```
F6F3_SHA=F6F3CF5DC4E5C1DA18F84D6C85B9119D25CE09D9943EF46C261E862B3025032D
F6F3_STATUS=OVERWRITTEN_CANNOT_REPAIR_IN_PLACE
STABLE_CANDIDATE=tip_final_integ_010
STABLE_SHA=0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9
NO_CROSS_SHA_PASS_INHERITANCE=1
LOCK=artifacts/ISSUE49_EXCLUSIVE.lock
HARNESS=artifacts/run_issue49_tip010_exclusive.ps1
SIBLING_GUARD=run_integ009_four_panel_reverify.ps1;ls_in_pane_harness_009.ps1
```

## Remediation (no AgentSession unlink)

1. Exclusive lock before Issue #49 measure; sibling harnesses exit 0 when lock present.
2. Defer build cmd 3014 until after chat/session/dispatch/spawn (already in tip010 remeasure).
3. End cleanup PID-scoped — do not blanket-kill all Native* while exclusive measure runs.
4. Full 11/11 still requires exclusive product-final harness completion on tip_010 SHA (not invented from spawn probe alone for board PASS count).
