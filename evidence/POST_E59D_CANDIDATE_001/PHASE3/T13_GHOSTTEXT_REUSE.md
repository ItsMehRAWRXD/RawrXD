# T13 — GhostText acceptance + stale regression (REUSE)

ASOF_UTC=2026-11-03T14:45:00Z
GATE=FINISH_25_T13
RESULT=PASS
METHOD=SHA_BOUND_REUSE
RERUN=0
CONTRADICTION=0
PROMOTE=0
CERTIFIED=0
REBUILD=HELD
GHOSTTEXT_REOPEN=0

```
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
LIVE_SHA_MATCH=1
```

## Authority

| Gate | Path | Result |
| ---- | ---- | ------ |
| Accept | `EDITOR\GHOSTTEXT_ACCEPT_RECEIPT.md` | RESULT=PASS · 9/9 evidence flags |
| Stale A/B | `EDITOR\STALE_GHOSTTEXT_RECEIPT.md` | STALE_GHOSTTEXT=PASS · late A eligible=0 / not RENDERED |
| Accept harness | `EDITOR\diagnose_accept_path_v2.ps1` | sealed |
| Stale harness | `EDITOR\ghosttext_stale_proof.ps1` | sealed |

## Contradiction check

- Accept + Stale receipts both bind CERT_EXE_SHA=3B720981…2CCAD5F.
- Live SHA unchanged; no product rebuild; Cancel classification SEALED separately (does not reopen GhostText).
- No contrary GhostText FAIL on this SHA after seals.

## Law

Reuse sealed PASSes. Contradiction-only rerun; none found.
