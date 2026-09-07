# P1_SCREENPILOT_MANIFEST_TRUTH_001 — Frozen

**Status:** PASS / CLOSED  
**Frozen:** 2026-08-31  
**Harness:** `tools/screenpilot-manifest/Test-P1-ScreenPilot-Manifest-Truth-001.ps1`

## Predicates (10/10 each run)

```text
CMAKE_OPTION_COUNT_MATCHES_SCAN
ENV_REGISTRY_MATCHES_SCAN
NO_HARDCODED_COUNTS_IN_UI
BUILD_PASS_NOT_RUNTIME_PASS
OPEN_GATE_REMAINS_OPEN
MISSING_GATE_NOT_PROMOTED
PROFILE_FIELDS_SOURCE_BACKED
MANIFEST_SHA_REPRODUCIBLE
UI_LOADS_GENERATED_MANIFEST
PROVENANCE_BLOCK_PRESENT
```

## Evidence logs

- `run1_20260831.log`
- `run2_20260831.log`

## Provenance note

Certified on **dirty worktree** at base commit `1b10b29de32a75083f282381d4b1c2bc3cfd4b17`.  
`manifestSha256` varies by `generatedUtc` only; inventory hashes are reproducible.  
Clean-tip rerun after commit binds evidence to immutable SHA (see `PROVENANCE-CLEAN-TIP-CHECKLIST.md`).

## Withdrawn

Earlier failure was PowerShell harness parse error (regex quote termination) — not a predicate failure.
