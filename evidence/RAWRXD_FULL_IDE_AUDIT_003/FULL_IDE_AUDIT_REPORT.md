# FULL_IDE_AUDIT_REPORT — RAWRXD_FULL_IDE_AUDIT_003

```
MODE=READ_ONLY
SOURCE_MUTATION=0
PRODUCTION_BINARY_MUTATION=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
AUTHORITY_REPO_LOCAL=F:\rawrxd
AUTHORITY_BRANCH=fix/deep2-multimodel-safety-20261025
AUTHORITY_COMMIT=a5ae60efecac790598e2e46d9e499eb8ac7287af
COMPARE_ONLY=G:\~dev\rawrxd @ f88360e8482c330d43704cd33cda9bd019c57933 (feature/ide-agentic-product-path-20261026)
OUT=F:\rawrxd\evidence\RAWRXD_FULL_IDE_AUDIT_003\
```

## Executive verdict

Native product IDE at authority is **`RawrXD-Win32IDE-Native`** (`RAWRXD_BUILD_WIN32IDE=ON`). Legacy Qt **`RawrXD-Win32IDE`** is OFF by default and Copilot sources are ABSENT. GhostText Gate6 has a **candidate** A/B PASS with explicit `PROMOTE=0`. Debugger is **STUB**. Multiple commercial-critical runtimes remain **`NOT_VERIFIED`**. No product promote.

`SOURCE_WIRED != RUNTIME`. This audit did not build or run.

## Deliverables

| # | Path |
|---|------|
| 1 | `SOURCE_INVENTORY.csv` (+ `SOURCE_INVENTORY_INSCOPE.csv` sha1 refine; `SOURCE_INVENTORY_README.txt`) |
| 2 | `GITHUB_LOCAL_DIFF.csv` (classified SOURCE vs noise) |
| 3 | `BUILD_DEPENDENCY_GRAPH.json` (ACTIVE/LEGACY/ORPHAN/TEST/OTHER) |
| 4 | `FILE_AUDIT.csv` |
| 5 | `FEATURE_PARITY_MATRIX.csv` |
| 6 | `DEFECT_REGISTER.csv` |
| 7 | `RUNTIME_EVIDENCE_MATRIX.csv` |
| 8 | `SECURITY_STABILITY_REPORT.md` |
| 9 | `RELEASE_BLOCKERS.md` |
| 10 | `FULL_IDE_AUDIT_REPORT.md` (this file) |

Supporting: `AUDIT_LAW.txt`, `PHASE1_STATUS.md`, `WIN32APP_TRACKED_FILES.txt`, `COMPETITIVE_PARITY_SCORECARD_PROVISIONAL.md` (composite **61%** planning-only; `MEASURED=0` — does not override this audit).

## Authority / tree

- Local HEAD matches authority commit; origin+final tips reported MATCH by parent Phase1.
- Tracked inventory: **231020** rows (+ header) in `SOURCE_INVENTORY.csv`.
- In-scope with sha1: **1157** rows (`src/win32app`, `src/deep2`, `asm`, `CMakeLists.txt`).
- Porcelain: **699** rows — mostly build/evidence/log noise; **37** `SOURCE_MATERIAL` (includes dirty GhostText + Deep2 + CMakeLists + tools/shaders).

## IDE headers

| Path | Status |
|------|--------|
| `src/win32app/Win32IDE.h` / `.cpp` | IN_HEAD (active contract) |
| `src/ide/win32_ide.h` | ABSENT_AT_AUTHORITY_COMMIT / DEFAULT_BRANCH_ONLY — not a defect |
| `src/ide/Win32IDE_SovereignCLI.h` | ABSENT_AT_AUTHORITY_COMMIT — not a defect |
| CopilotIntegration / CopilotStreaming | ABSENT — Qt target excluded |

## Build graph (CMake)

- **ACTIVE native IDE:** `RawrXD-Win32IDE-Native` (line ~3834), sources complete at HEAD, links Deep2 when `deep2_engine_lib` exists, ggml, security/hardening.
- **LEGACY Qt IDE:** `RawrXD-Win32IDE` behind `RAWRXD_BUILD_WIN32IDE_QT` (default OFF).
- **ACTIVE inference tools:** deep2_* cert/parity/bench/dualgpu/gdn/agentic targets, `rawr-reap*`, etc.
- **ORPHAN/disabled:** `if(FALSE)` `test_terminal` / `RawrXD-Chat`; stub/test_ide_main family.

## Feature parity (source vs runtime)

Priority areas:

- **Editor/Workspace/Terminal:** source largely IMPLEMENTED/PARTIAL; runtime **NOT_VERIFIED** (no product soak this audit).
- **Debugger:** **STUB** (UI simulation).
- **GhostText:** source IMPLEMENTED; Gate6 candidate sealed PASS; product certify held.
- **Agentic:** partial bridges; Swarm/PathB/Rollback **NOT_PRESENT** or unverified.
- **Inference:** GGUF/CPU/Vulkan/MoE/K2/Qwen/REAP source-wired; runtime seals are tool/scope/partial — **not** IDE product promote.
- **Distribution:** installer script only; startup/recovery partial citations; Installer E2E **NOT_VERIFIED**.

### NOT_VERIFIED counts

- **FEATURE_PARITY_MATRIX.csv:** 31 of 39 features have `runtime_status=NOT_VERIFIED`.
- **RUNTIME_EVIDENCE_MATRIX.csv:** 5 rows strictly `NOT_VERIFIED` (ChatWindow, PathB_swarm, Host_stability, Product_E2E_64_token, Installer). Additional rows are cited partial/scope/held — not product PASS.

## Defects (real only)

See `DEFECT_REGISTER.csv` (D001–D015). Highest: dirty tree, no IDE product certify, debugger stub, missing 64-token/ChatWindow/host/installer seals, Qwen parity OPEN, swarm absent.

## Fail-closed

```
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
NOT_RUN != PASS
Gate6 candidate PASS != product PASS
Tool production cert != IDE binary cert
```
