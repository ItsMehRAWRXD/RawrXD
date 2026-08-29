# AGENT-E2E-002 — LOCK

**Status:** `AGENT-E2E-002=CANDIDATE_PASS`  
**Authority:** `NOT_CERTIFIED`  
**Frozen:** 2026-08-29

## Suite result

| Fixture | Gate | stdout |
|---------|------|--------|
| 01_compile_error | PASS | hello from e2e01 |
| 02_linker_error | PASS | hello from e2e02 |
| 03_missing_include | PASS | hello from e2e03 |
| 04_multifile_bug | PASS | hello from e2e04 42 |
| 05_missing_symbol | PASS | hello from e2e05 42 |
| 06_failing_unit_test | PASS | hello from e2e06 |
| 07_second_iteration | PASS | hello from e2e07 |
| 08_compile_typo | PASS | hello from e2e08 |
| 09_logic_bug_model | PASS_AS_EXPECTED_MODEL_GAP | (build-clean logic bug; autofix exit 1) |

**Spine:** 8/8 PASS  
**Model-directed gap probe:** 09 confirms runtime-only logic bugs are **not** repaired by build-diagnostic autofix alone.

## Honest non-claims

- Fixtures 01–08 use the intentional demo-break prepass path inside `QuantumOrchestrator::executeAutoFix` (deterministic). This certifies the **multi-fixture repair spine**, not GGUF-token-directed patch synthesis.
- Pure missing-`stdio.h` / arithmetic-only bugs remain open for **AGENT-E2E-002b** (GGUF-directed).
- `WIN32IDE_EXE_SHA256` at freeze: see lock JSON.

## Related consolidation (same session)

- `_overflow/` eval: REJECT merge / DEFER hygiene (`evidence/REPO_BRANCH_CANONICAL/OVERFLOW_EVAL.md`)
- GitHub default branch switched: **master → main**
