# TIP_CANDIDATE_AGENT_RUN_005 / RECEIPT

```
ASOF_UTC=2026-10-28T18:30:00Z
DISPOSITION=CANDIDATE_FROZEN_PLUS_RUNTIME_PROVE
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
| PDB | present |
| Build source | `build_win32ide_link001/bin` (non-authoritative for tip cert) |
| Hash re-verify | MATCH |

## Tip (unchanged)

| Field | Value |
|------|--------|
| EXE | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Hash re-verify | MATCH (untouched) |

## Provenance

- `BUILD_UNBLOCKED=1` via agent 10995702 → `SUBAGENT_EXTENSIONHOST_CONTINUOUS_001/BUILD_UNBLOCK.txt`
- Push cite `b8c71ee370`
- Must-link: `CANDIDATE_INCLUDE.txt` items 1-10 (AgentRunLoop/max_tokens, swarm engine, PathB 4111, Phase7 UI, …)
- Runtime prove seal: `evidence/AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001/SEAL.txt`

## Runtime (this receipt)

| Gate | Disposition |
|------|-------------|
| AgentRunLoop on candidate | **ENTERED=1** HTTP 200 after `RUNTIME_READY=1`; `max_tokens=16`; choices present (`logs` / `prove/agent_run.body.txt`) |
| Swarm Path A (canonical n=2) | **FAIL_CLOSED_HTTP_000** — curl 56 connection reset; body empty; process alive; `"No Inference Engine"` not observed (no body) |
| Swarm supplemental n=1 | HTTP 200 `G16_A_RUNTIME_REACHED` but `[Agent] No model loaded.` — **not** Path A PASS; not invented |
| PathB 4111 | **RUNTIME_REACHED=NOT_RUN** (headless prove; GUI unavailable) |
| UI Settings/TaskRunner | UI_ACCEPTANCE_PASS=0 |

`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`

## Next gate

1. Fix `/api/swarm/orch` n≥2 executeSwarm connection-reset on this SHA  
2. Bind loaded model into AgenticEngine swarm chat (clear `No model loaded`)  
3. PathB 4111 GUI CmdDiag when GUI available  
4. Hold `PROMOTE=0` / `TIP_CLIMB=HOLD` / no tip absorb  
