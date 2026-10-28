# RECEIPT — FAILDET_LOGPOINT_SIDEBAR_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T17:08:00Z
RELINK=NO
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
CANDIDATE_SHA=B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F
ABSORB=NOT_AUTHORIZED
NO_INVENT_PASS=1
```

## Verdict

FailureDetector is product-linked on tip `748B210A…` with headless
`/api/failure/stats` proving **Active** (HTTP 200) and no-key **401**.
LogpointBridge + SidebarBridge remain **GATED_OMIT** (absent from tip and
B421 candidate strings/map). Stubs stay fail-closed; no tip erase; no GhostText absorb.

## Dispositions

| Target | Disposition |
|--------|-------------|
| `Win32IDE_FailureDetector.cpp` | SOURCE_WIRED + HEADLESS_FAILDET_RUNTIME_REACHED; MET=0 |
| `Win32IDE_LogpointBridge.cpp` | GATED_OMIT; RUNTIME=NOT_RUN |
| `Win32IDE_SidebarBridge.cpp` | GATED_OMIT + GATED_STUB; RUNTIME=NOT_RUN |

## EXE authority

| Field | Value |
|-------|-------|
| Product tip | `TIP_FREEZE_001\bin` SHA `748B210A…` |
| Candidate | B421 GhostText witness only |
| Relink | NO |
| Never erase 748B | YES |

## Logs

- `logs/sha_verify.txt`
- `logs/scoreboard.txt`
- `logs/R_failure_stats.body.txt` / `.code.txt`
- `logs/R_failure_stats_nokey.*`
- `logs/strings_tip_748B.txt`
- `logs/strings_candidate_B421.txt`
- `logs/link_omit_proof.txt`
- `logs/srv_meta.txt` / `srv_out.txt`

## Held

PROMOTE=0 · TIP_CLIMB=HOLD · CERTIFIED=0 · GhostText ABSORB=NOT_AUTHORIZED
