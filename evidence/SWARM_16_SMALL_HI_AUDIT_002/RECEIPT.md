# RECEIPT — SWARM_16_SMALL_HI_AUDIT_002

```
ASOF_UTC=2026-10-28T10:17:11Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1
TIP_EXE_RELINK=N
PRESERVE_001=1
```

## Verdict

N=**16** unique local non-cloud chat Ollama tags (digest-deduped).
Harness: `evidence/SWARM_16_SMALL_HI_AUDIT_002/harness_ollama_swarm16_v2.ps1`
(`think=false`; PASS requires non-empty `response=` only).

| Gate | Result |
|------|--------|
| TAGS_REACHABLE | **PASS** |
| N inventory | **PASS** (N=16 honest) |
| ORCH_1_TO_N (hi all 16) | **PASS** (HI_PASS=16 / HI_FAIL=0) |
| FILE_AUDIT_GATE (all 16) | **PASS** (AUDIT_PASS=16 / AUDIT_FAIL=0) |
| Win32IDE tip EXE runtime | **NOT_RUN** |
| PROMOTE | **0** |

## vs 001

| Item | 001 | 002 |
|------|-----|-----|
| HI_PASS/N | 9/16 FAIL | **16/16 PASS** |
| embeddinggemma | included → 400 | **excluded** |
| EMPTY slots | 6 models | **replaced** (see LAW) |
| Seal | preserved | this dir |

## Tip EXE

`TIP_ABSORB_RELINK_001` already produced NEW_SHA=`C4FC9AE9…`.
No relink attempted. Tip product ensemble RUNTIME remains **NOT_RUN**.

## Artifacts

- `MODELS.tsv` `RESULTS.csv` `SUMMARY.txt` `RUNLOG.txt`
- `SIZE_NOTE.txt` `harness_ollama_swarm16_v2.ps1` `LAW.txt` `RECEIPT.md`

## Explicit non-claims

```
Ollama ORCH_1_TO_N=PASS != Win32IDE tip EXE ensemble MET
TIP_EXE_RUNTIME=NOT_RUN
thinking-only was NOT scored PASS
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
```
