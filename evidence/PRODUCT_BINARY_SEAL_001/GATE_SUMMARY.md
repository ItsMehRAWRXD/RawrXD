# GATE_SUMMARY — PRODUCT_BINARY_SEAL_001 (CLEAN-TIP CANDIDATE)

ASOF_UTC=2026-11-02T13:20:00Z
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
CANDIDATE_BYTES=1608192
PRODUCTION_BINARY_MUTATION=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED

## Stage results

| Gate | Result | Notes |
|------|--------|-------|
| 1 WIP preserve (37-path) | PASS | `WIP_PRESERVE_VERIFY.csv` 37/37 match |
| 2 Clean worktree @ a5ae60ef | NOT_VERIFIED | HEAD match + 0 diffs; untracked `src/deep2/shaders/deep2_qgemv.spv` = BUILD_GENERATED (glslc); `CLEAN_TIP_WORKTREE_OK=false` (do not invent CLEAN) |
| 3 Native CMake target | PASS | `RawrXD-Win32IDE-Native` Release/Ninja |
| 4 Candidate build | PASS | `BUILD_EXIT=0`; `CLEAN_TIP_BUILD.log` |
| 5 Candidate EXE seal | PASS | SHA-256 `CB34EF4E…` re-verified; bytes 1608192 |
| 6 Host stability prereq | PASS | 0 RawrXD-Win32IDE* UI procs; ~39GB free RAM; F: ~483GB free; prior Qt dump noted only |
| ChatWindow product E2E | FAIL | Create/show+prompt proven; response/cancel **not** proven (`FAIL_CLOSED_RESPONSE_NOT_OBSERVED`); Ollama model-load PASS for combo[0] |
| GhostText product E2E | NOT_VERIFIED | Launch+debug/editor hwnds seen; no `GHOSTTEXT_` markers in clean-tip EXE/runtime; Gate6 not transferred; `RUNTIME_PASS=0` |
| 64-token product E2E | NOT_VERIFIED | Missing candidate 64-token product path; benchmarks OFF; certify_e2e.py is CORE_DLL-only; tokens not observed |
| Production binary certify | NOT_VERIFIED | Candidate ≠ production authority |

## Audit blocker reconciliation

| Prior blocker (FULL_IDE_AUDIT_003) | After clean-tip candidate stages 6–7 |
|------------------------------------|--------------------------------------|
| Dirty SOURCE_MATERIAL vs tip | Isolated clean worktree used; WIP KEEP_BRANCH untouched; untracked spv classified BUILD_GENERATED |
| No provenance-tied Native IDE candidate | Candidate sealed `CB34EF4E…` — still **not** authority product binary |
| ChatWindow NOT_VERIFIED | Runtime **reached**; disposition **FAIL** (response/cancel unproven) — still blocks promote |
| GhostText product path | Runtime **reached**; markers absent on clean tip — **NOT_VERIFIED** / no invent PASS |
| Product 64-token E2E | Remains **NOT_VERIFIED** (missing path + no tokens) |
| Host stability | Prereq **PASS** for this candidate run sequence |
| AUTHORITY_PRODUCT_BINARY | **NOT_VERIFIED** (unchanged by design even if runtimes had passed) |

## Stop reason
`AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED` remains. ChatWindow FAIL + GhostText/64-token NOT_VERIFIED block any promote. Untracked build-generated spv keeps `CLEAN_TIP_WORKTREE_OK=false`.

## Law
`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`  
`NOT_RUN != PASS`. No invented PASS. No promote. No production binary mutation.
