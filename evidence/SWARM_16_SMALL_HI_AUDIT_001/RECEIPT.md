# RECEIPT — SWARM_16_SMALL_HI_AUDIT_001

```
ASOF_UTC=2026-10-28T09:56:21Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1
TIP_EXE_RELINK=N
```

## Verdict

N=**16** unique local non-cloud Ollama tags (digest-deduped).
Harness: `evidence/SWARM_16_SMALL_HI_AUDIT_001/harness_ollama_swarm16.ps1`
Gates earned:

| Gate | Result |
|------|--------|
| TAGS_REACHABLE | **PASS** |
| N>=1 inventory | **PASS** (N=16) |
| ORCH_1_TO_N (hi all 16) | **FAIL** (HI_PASS=9 / HI_FAIL=7) |
| FILE_AUDIT_GATE (all 16) | **FAIL** (AUDIT_PASS=9 / AUDIT_FAIL=7) |
| Win32IDE tip EXE runtime | **NOT_RUN** (absorb lock) |
| PROMOTE | **0** |

## Artifacts

- `MODELS.tsv` — selected 16 + digest + size
- `RESULTS.csv` — per-model HI/AUDIT PASS|FAIL
- `SUMMARY.txt` — numeric gates
- `RUNLOG.txt` — timed run
- `harness_ollama_swarm16.ps1`

## Explicit non-claims

```
ORCH_1_TO_N=FAIL != invent PASS
EMPTY_RESPONSE != PASS
embedding 400 != PASS
Win32IDE SOURCE_WIRED != tip EXE RUNTIME_REACHED
PROMOTE=0
```
