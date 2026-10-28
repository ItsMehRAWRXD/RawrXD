# RECEIPT — SWARM_TIP_16_HI_AUDIT_001

```
ASOF_UTC=2026-10-28T10:35:13Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 LOCAL_ONLY=1
DISTINCT_FROM=SWARM_16_SMALL_HI_AUDIT_001|002
```

## Verdict

Tip SHA **6832F439…** confirmed (`TIP_ABSORB_SWARM_002`). Map orch symbols PRESENT.
Tip product swarm path (**onSubAgentSwarm** / `resolveSwarmModelOrchPlan`) **NOT_RUN** /
**NOT_EXPOSEABLE** via headless APIs (probe 503; not GUI orch).

Honest **N=16** local non-cloud chat (digest-dedupe; no embeddinggemma).
Tip-stamped Ollama harness: **HI_PASS=16/16**, **AUDIT_PASS=16/16**.

| Gate | Result |
|------|--------|
| TIP_SHA_MATCH | **PASS** (6832F439…) |
| MAP orch symbols | **PRESENT** (SOURCE_WIRED cite) |
| TIP_EXE_SWARM_RUNTIME | **NOT_RUN** |
| TIP_GUI_onSubAgentSwarm | **NOT_RUN** |
| TIP_ORCH_RESOLVE_EXPOSEABLE | **0** |
| N inventory | **PASS** (N=16) |
| ORCH_1_TO_N (hi all 16) | **PASS** (Ollama harness) |
| FILE_AUDIT_GATE | **PASS** (Ollama harness) |
| MATRIX_RUNTIME_REACHED_EARNED | **0** |
| G07_MET | **0** |
| PROMOTE | **0** |

## Tip probe

- `tip_probe_pre.txt` / `tip_probe_post.txt`
- Headless listen `127.0.0.1:11436` with `RAWRXD_SWARM_N=16`
- `/api/swarm/status`, `/api/tool` hexmag_swarm, `/api/subagent` → 503 /
  not `resolveSwarmModelOrchPlan`

## Artifacts

- `MODELS.tsv` `RESULTS.csv` `SUMMARY.txt` `RUNLOG.txt`
- `harness_tip_swarm16_hi_audit.ps1` `harness_console.log`
- `tip_headless_stdout.log` `tip_headless_stderr.log`
- `LAW.txt` `RECEIPT.md` `BUNDLE_SHA256.txt`

## Explicit non-claims

```
Ollama HI/AUDIT PASS != tip EXE ensemble RUNTIME_REACHED
TIP_EXE_SWARM_RUNTIME=NOT_RUN
G07 remains SOURCE_WIRED (not MET)
U02/S-002 remain SOURCE_WIRED
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
```
