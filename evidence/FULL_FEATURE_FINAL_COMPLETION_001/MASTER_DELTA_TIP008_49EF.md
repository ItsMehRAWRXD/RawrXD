# MASTER delta — tip_008 49EF vs CONTROLLING CC79

ASOF_UTC=2026-11-09T17:12:00Z
PROMOTE=0
TIP_MOVE=0
MATURITY=82% (unchanged; Issue #49 single-SHA product-final still open)
NO_CROSS_SHA_PASS_INHERITANCE=1

| Gate | CC79 (controlling) | tip_008 49EF (frozen candidate) | Drift E6CF (non-inheritable) |
|------|--------------------|----------------------------------|------------------------------|
| Identity | CC79F6CD… | 49EF4538… FROZEN / BINARY ABSENT | E6CF5BD2… |
| COMPILER_FEED | historical | PASS items=3 (measured 11:20) | not this seal's claim |
| NAV / B12 click | FAIL/NOT_PROVED | NAVIGATED_LINE_3 (WM_COMMAND 1312) | — |
| SESSION_REAL | — | PASS vars6043=4 | — |
| FOUR_PANEL | prior FAIL_CLOSED eras | PASS @49EF | PASS @E6CF only |
| VT / CSI | — | PASS_NO_RAW_CSI | — |
| CMD_EXEC | OPEN panel ls | POSTED_NO_CAPTURE → harness HWND fix landed; runtime NOT_RUN (ABSENT) | — |
| EXT lifecycle | — | NOT_RUN @49EF | PASS @E6CF |
| Chat 7/7 | — | NOT_RUN @49EF | PASS @E6CF |
| term-smoke | — | NOT_RUN @49EF | PASS @E6CF |
| Output GUI | — | NOT_RUN @49EF | PASS @E6CF |
| Headless debug | — | NOT_RUN @49EF (6043 was GUI SESSION_REAL) | PASS Debug UI @E6CF |
| RESEAL conjunction | — | HELD | ≠ 49EF reseal |
| TIP_MOVE | 0 | 0 (default) | 0 |

## Blockers (ordered)

1. Restore bit-identical `49EF4538…` EXE into `candidates\tip_final_integ_008\` (dockfix overwrite left no `.bak`).
2. Run CMD_EXEC prove with fixed harness (5602/5601/5610) → require `VERIFIED` visible capture.
3. Same-SHA reseal: EXT + chat Ctrl+Enter 7/7 + term-smoke + Output GUI + headless SESSION_REAL — each receipt must cite `49EF4538…`.
4. Optional: ListView 1317 enum (cheap residual; 6043 already proves SESSION_REAL).

## Law

```
NOT_RUN != PASS
ABSENT != PASS
E6CF_REQUEUE_PASS != 49EF_RESEAL
SOURCE_WIRED_HARNESS != RUNTIME_REACHED_ON_49EF
```
