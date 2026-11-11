# Source Fix Drops — Guidance Catalog (not PASS)

ASOF_UTC=2026-11-09T01:13:00Z
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
CONTROLLING_SHA=55BE19B7…
T15_FOLLOWUP=CLOSED_DO_NOT_REOPEN

```
GUIDANCE_NE_VERIFIED_PATCH=1
GUIDANCE_NE_ACCEPTANCE_PASS=1
ENUMERATED_SNIPPETS=1..135
ENUMERATED_NE_DEFECT_COUNT=1
STOP_GENERIC_SNIPPETS=1
NEXT_DELIVERABLE=EXACT_REQUEST_A_CRASH_DIFF
T08_ON_323A38A0=PASS_DO_NOT_REOPEN
PRIORITY_INTEGRATE_NOW=REQUEST_A_CANCEL + T05 + T10
```

## Law

135 enumerated snippets ≠ 135 defects ≠ 135 repairs. No Finish-25 credit from catalogs.
T08 buffer sync PASS on `323A38A0…` — protect with regression; do not reopen.

## Immediate integrate (P0) — exact tip diffs only

1. T08: Save outgoing buffer before switch; transactional activate; PRESERVED unsaved content (#106–107, #91–93).
2. T07: Unicode RichEdit recreate / EM_GETTEXTEX CP 1200; no ACP.
3. Cancel: Request A→Stop→B generation + HWND lifetime (#108–110, #94–95).
4. Harness: `TCM_GETITEMCOUNT=0x1304`.

## Batches 3–10 (11–120)

Deferred hardening catalog. Check source before applying. Do not expand catalog further until T08+Cancel land on one SHA with receipts.

Adapt to `F:\rawrxd\src\win32app\`. Never rewrite `55BE19B7` seal.
