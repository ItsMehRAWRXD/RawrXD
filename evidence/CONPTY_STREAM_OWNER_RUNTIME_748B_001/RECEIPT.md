# RECEIPT — CONPTY_STREAM_OWNER_RUNTIME_748B_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
SHA_MATCH_748B=1
RELINK_CLOSED=1
RUNTIME_REACHED=0
RUNTIME_PASS=0
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
NO_TIP_REBUILD=1
ASOF_UTC=2026-10-28T17:22:29Z
```

## Verdict

| Gate | Result |
|------|--------|
| Tip freeze SHA | **748B** match |
| ConPTY SOURCE_WIRED in tip EXE | **YES** (string wire) |
| ShellLayout phase5 SOURCE_WIRED in tip EXE | **YES** |
| RELINK gap vs prior 6832F439 seals | **CLOSED** on 748B |
| Tip GUI HWND | **NE 0** |
| PostMessage 4001 | delivered |
| NEW PowerShell / ConPTY stream witness | **NO** → fail-closed |
| CHROME_VIS PHASE=5 | **ABSENT** → no invent PHASE5_RUNTIME PASS |
| RUNTIME_PASS | **0** |
| GhostText absorb | **NOT_AUTHORIZED** |
| PROMOTE | **0** |

## Explicit non-claims

```
RUNTIME_PASS=0
CONPTY_STREAM_E2E=NOT_MET
PHASE_5_CERTIFIED=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NO_NEW_FREEZE_SHA=1
```

## Artifacts

- `LAW.txt` `DISPOSITION.txt` `MATRIX.md` `RECEIPT.md` `SUMMARY.txt` `sha.txt` `RUNLOG.txt`
- `harness_conpty_phase5.ps1`
