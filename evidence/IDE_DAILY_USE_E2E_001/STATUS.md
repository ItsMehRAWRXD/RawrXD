# IDE_DAILY_USE_E2E_001 — STATUS

```
ASOF_UTC=2026-11-13T19:35:37Z
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NOT_RUN!=PASS
INVENT_PASS=0
MINIMAX_FULL_LOAD=0
748B_CLOBBER=0
EXE=G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe
EXE_SHA256=D9589D9A665E07F93E906A637B9D4ADB80D99BFD9604103A882E6AC79078BC08
```

## Subsystem readiness

| Subsystem | Verified this seal | Result | Notes / OPEN |
|-----------|--------------------|--------|--------------|
| Deep IDE / Headless | Spawn + `/health` + `/api/tool` on link001 | **PASS** | Port 19892; auth via `RAWRXD_HOSTED_API_KEY` |
| Editor (file ops) | `write_file` / `read_file` / list / diff | **PASS** | Headless product path; GUI HWND editor **NOT_RUN** |
| Terminal (exec grant) | `execute_command` → `hello.cmd` | **PASS** | Product ConPTY four-panel gate **FAIL_CLOSED** (re-run) |
| Terminal (ConPTY HWND) | `terminal_gate.exe` re-run | **FAIL_CLOSED** | fail_count=2: compile+run ConPTY + PowerShell capture |
| Debugger | `debug_console_gate.exe` | **RUNTIME_PARTIAL** | dbgeng.dll=1; HWND BP/step/vars **NOT_RUN** |
| Output panel logic | `output_gate.exe` | **PASS** (harness) | HWND product path **NOT_RUN** |
| Problems panel logic | `problems_gate.exe` | **PASS** (harness) | HWND click-nav **NOT_RUN** |
| Agent lifecycle | harness `harness_agent_lifecycle.ps1` | **PASS** | `/api/agent/run` **NOT_RUN** (headless 503) |
| Agent recovery | kill + respawn + MOTD + read_file | **PASS** | Per-process MOTD re-ack required |
| Rollback product | CheckpointManager | **OPEN** | write_file restore ≠ product checkpoint |
| Sunshine workflow | `sunshine-voxel --headless` capture | **PASS** | drew_terrain=true; exit=0; adapter R9700 |
| Four-panel integration | scenarios 1–10 | **FAIL_CLOSED** | Prior `FOUR_PANEL_COMPLETION_001`; candidate relink still OPEN |
| Tip freeze 748B | untouched | **HELD** | Do not clobber |

## Explicit non-claims

```
PROMOTE=0
CERTIFIED=0
GUI_HWND_EDITOR=NOT_RUN
GUI_HWND_DEBUGGER=NOT_RUN
AGENT_RUN_LOOP=NOT_RUN
CHECKPOINT_MANAGER=NOT_RUN
CONPTY_FOUR_PANEL=FAIL_CLOSED
FOUR_PANEL_INTEGRATION=FAIL_CLOSED
CROSS_SHA_CREDIT=0
```

## Artifacts

- `LAW.txt`, `EXE_SHA256.txt`, `STATUS.md`, `RECEIPT.md`
- `AGENT_LIFECYCLE_SUMMARY.txt`, `harness_agent_lifecycle.ps1`
- `logs/*` (gates + lifecycle)
- `logs/sunshine_retry.out.txt` (PASS receipt JSON)
- Sunshine frame captures under `sunshine/` (optional binary; not required for seal text)
