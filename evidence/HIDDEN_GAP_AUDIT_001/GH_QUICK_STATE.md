# GH_QUICK_STATE — measured via gh (exit 0)

ASOF_UTC=2026-11-09T12:45:15Z
REPO=ItsMehRAWRXD/RawrXD
PROMOTE=0
CERTIFIED=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
WORKER=W2_HIDDEN_GAP_AUDIT_001

| Ref | State | Draft | Mergeable | MergeState | Title |
|-----|-------|-------|-----------|------------|-------|
| PR #75 | OPEN | true | MERGEABLE | UNSTABLE | WIP: native compiler, CMake builder and PE/COFF linker acceptance pipeline |
| PR #76 | OPEN | true | CONFLICTING | DIRTY | Consolidate Deep2 and native compiler work into main (certification pending) |
| PR #77 | OPEN | false | CONFLICTING | DIRTY | P0: IDE product path — ConPTY, inference UI, Problems/output wiring |
| PR #78 | OPEN | false | CONFLICTING | DIRTY | P1: AgentSession GUI — lifecycle, cancellation, and cleanup |
| PR #79 | OPEN | false | CONFLICTING | DIRTY | P2: ExtensionHost runtime — host/worker, IPC, shutdown, crash recovery |
| Issue #49 | OPEN | — | — | — | [LAYER-10] Product-Final Acceptance |
| Issue #50 | OPEN | — | — | — | [MASTER] RawrXD Certification Ladder — 0-to-10 Tracking |
| Issue #57 | OPEN | — | — | — | RawrXD batch 024: 45 E2E native IDE, Slingshot/compiler and GPU release gates |

URLs: https://github.com/ItsMehRAWRXD/RawrXD/pull/{75..79} · issues/{49,50,57}

## Code-search vs local (fail-closed note)

| Query | gh search code (repo) | Local under F:\rawrxd\evidence |
|-------|----------------------|--------------------------------|
| `INTEG_004` | 0 indexed code hits (search miss) | PRESENT — e.g. `FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` |
| `Finish-25` | 0 indexed code hits (search miss) | PRESENT — e.g. `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md`, `FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` |

`GITHUB_INDEX_MISS ≠ LOCAL_ABSENCE`. Finish-25 also appears in PR #77/#78/#79 **bodies** (not code index).

## Law (unchanged)

```
OPEN_PR ≠ CONFIRMED_PRODUCT_DEFECT
CONFLICTING ≠ FAIL_IMPL
PROMOTE=0
MATURITY=82_UNCHANGED
```

Deliverable: `W2_GITHUB_REQUIREMENTS.md` (this refresh).
