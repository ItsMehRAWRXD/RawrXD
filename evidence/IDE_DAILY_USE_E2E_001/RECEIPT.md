# RECEIPT — IDE_DAILY_USE_E2E_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1 MINIMAX_FULL_LOAD=0
ASOF_UTC=2026-11-13T19:35:37Z
WORKSPACE=G:\~dev\rawrxd
PATH=evidence/IDE_DAILY_USE_E2E_001
EXE_SHA256=D9589D9A665E07F93E906A637B9D4ADB80D99BFD9604103A882E6AC79078BC08
```

## Product surfaces located

| Surface | Owner path |
|---------|------------|
| Win32IDE / Deep IDE | `src/win32app/Win32IDE*.cpp`, `HeadlessIDE*.cpp`, `build_win32ide_link001/bin/RawrXD-Win32IDE.exe` |
| Debugger | `src/core/native_debugger_engine.cpp`, `Win32IDE_NativeDebugPanel.cpp`, `Win32IDE_Debugger*.cpp` |
| Terminal | `Win32TerminalManager.cpp`, ConPTY harness under `FOUR_PANEL_COMPLETION_001` |
| Editor / tools | `HeadlessIDE_ToolRoutes.cpp` `/api/tool` |
| Agent lifecycle | headless `/api/tool` + LocalServer `/api/agent/run` (GUI-only) |
| Recovery | kill/respawn + MOTD re-ack (`g_headlessMotdAcked`) |
| Sunshine | `src/voxel/main.cpp` → `build/voxel/Release/sunshine-voxel.exe` |

## Verified this run

1. **Agent lifecycle** — MOTD, inventory/list, editor write/read/diff, accept/rollback (write_file), execute_command, cancel, shutdown: **PASS** (`AGENT_LIFECYCLE_SUMMARY.txt`).
2. **Recovery** — kill headless → respawn → MOTD → `read_file`: **PASS**.
3. **Sunshine** — headless capture seed=42, `drew_terrain=true`, exit=0 (`logs/sunshine_retry.out.txt`).
4. **Output/Problems logic harnesses** — **PASS** (HWND still NOT_RUN).
5. **Debugger gate** — dbgeng present; product HWND E2E **NOT_RUN** → **RUNTIME_PARTIAL**.
6. **ConPTY terminal_gate** — **FAIL_CLOSED** (2 fails) on this re-run.

## OPEN / FAIL_CLOSED (do not invent PASS)

- ConPTY compile+run + PowerShell capture (four-panel terminal)
- Debugger HWND BP/step/vars/stack
- Output/Problems/Debug HWND product integration
- `/api/agent/run` AgentRunLoop (headless)
- CheckpointManager product rollback
- `build-win32ide-p1-candidate` EXE still ABSENT (cache has `RAWRXD_BUILD_WIN32IDE=ON` but no linked EXE)

## Laws honored

`SOURCE_WIRED != RUNTIME_REACHED != PASS` · `NOT_RUN != PASS` · tip freeze 748B untouched · no MiniMax FULL load.
