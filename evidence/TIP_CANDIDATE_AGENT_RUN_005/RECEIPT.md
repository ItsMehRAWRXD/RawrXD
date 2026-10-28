# TIP_CANDIDATE_AGENT_RUN_005 / RECEIPT

```
ASOF_UTC=2026-10-28T18:22:00Z
DISPOSITION=CANDIDATE_FROZEN_REPROVED_PARTIAL
PROMOTE=0
TIP_CLIMB=HOLD
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
PRODUCT_CERTIFIED=0
REBUILD_TIP=0
NO_INVENT_PASS=1
```

## Candidate

| Field | Value |
|------|--------|
| EXE | `evidence/TIP_CANDIDATE_AGENT_RUN_005/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `8DC1406A0118AC6A2F6A1E991378A2730AAC07D5593BA3C9BF5E8852E468235B` |
| Size | 331755520 |
| PDB | present (129904640) |
| Build source | `build_win32ide_link001/bin` (non-authoritative for tip cert) |
| Link log | `logs/rebuild_j1_link.txt` (−j1 sole; C1083 late on unrelated TU after EXE present) |

## Tip (unchanged — DO NOT OVERWRITE)

| Field | Value |
|------|--------|
| EXE | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| LIVE_SHA_VERIFY | MATCH |

## Identity

- `CANDIDATE_NE_TIP=1`
- `CANDIDATE_NE_GHOSTTEXT_B421=1`
- GhostText B421 witness only; `ABSORB=NOT_AUTHORIZED`

## Runtime on candidate SHA only

| Gate | Disposition |
|------|-------------|
| AgentRunLoop `/api/agent/run` | **ENTERED_HTTP_OK** HTTP 200; GENERATED_TOKENS=16; max_tokens CALLER_OVERRIDE=16; PERFORMANCE_PASS=0 |
| Swarm Path A `/api/swarm/orch` | **HTTP_OK_NO_INFERENCE_ENGINE_STRING** HTTP 200; RUNTIME_REACHED JSON; workers still `[Agent] No model loaded` |
| PathB 4111 CmdDiag | **RUNTIME_REACHED=NOT_RUN** (GUI not launched); SOURCE_WIRED prior |
| UI Settings/TaskRunner | UI_ACCEPTANCE_PASS=0 |

Seal detail: `REPROVE_SEAL.txt` · AgentRun cite: `AGENT_RUN_LOOP_CANDIDATE_005.txt` · bodies under `logs/reprove/`

`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`
