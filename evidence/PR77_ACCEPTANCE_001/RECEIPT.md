# PR77_ACCEPTANCE_001 — Receipt (fail-closed)

ASOF_UTC=2026-11-09T10:58:00Z
MOTD_ACK=1
PR=77
URL=https://github.com/ItsMehRAWRXD/RawrXD/pull/77
BRANCH=feature/ide-agentic-product-path-20261026
SOURCE_COMMIT_SHORT=9edf63fed8
SOURCE_COMMIT=9edf63fed82bdf427f734591bff262282f6fe822
BASE=main
STATE=OPEN_UNMERGED
MERGEABLE=CONFLICTING
MERGE_READY=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1

## Gate matrix (this PR only)

| Gate | Verdict | Notes |
|------|---------|-------|
| Diff review (source) | **PARTIAL** | Tip lands ConPTY owner, `postOutputPanelSafe`, ProblemsAggregator wiring, WM_INFERENCE_UI marshal, four-panel evidence tree |
| Conflict vs main | **FAIL_CLOSED** | GitHub `mergeable=CONFLICTING` — must resolve before any authorized merge |
| CI / CodeQL / native-build | **FAIL** (observed on open) | Not treated as local acceptance |
| Native four-panel integration | **NOT_RUN** | Requires SHA-specific EXE from this tip |
| ConPTY stream owner | **SOURCE_WIRED** | `Win32TerminalManager` CreatePseudoConsole path present; RUNTIME=NOT_RUN on this tip EXE |
| Build output → Output HWND | **NOT_RUN** | Prior F:\ EA5D/CC79 track: Build 3014 killed IDE — different SHA; not inherited |
| Problems navigation | **SOURCE_WIRED** | Aggregator dedupe + BuildRunner→Problems; HWND E2E NOT_RUN |
| EXE_SHA256 (PR77 candidate) | **NOT_BUILT** | No PR77-tip EXE hashed yet this turn |

```
EXE_PATH=
EXE_SHA256=
FOUR_PANEL=NOT_RUN
CONPTY=SOURCE_WIRED_RUNTIME_NOT_RUN
OUTPUT_BUILD_HWND=NOT_RUN
PROBLEMS_NAV=SOURCE_WIRED_RUNTIME_NOT_RUN
MERGE_READY=0
```

## Changed focus (tip commit family)

- `src/win32app/Win32TerminalManager.{h,cpp}` — ConPTY capture/resume/job
- `src/win32app/Win32IDE.cpp/.h` — `deliverInferenceUi` / `postOutputPanelSafe` / WM_INFERENCE_UI
- `src/win32app/Win32IDE_Core.cpp` — WM_INFERENCE_UI + Output channel payload
- `src/win32app/Win32IDE_BuildRunner.cpp` — `postOutputPanelSafe(..., "Build")`
- `src/win32app/Win32IDE_VSCodeUI.cpp` — ProblemsAggregator.admit from addProblem
- `src/core/problems_aggregator.cpp` — diagnostic dedupe
- Evidence under `evidence/FOUR_PANEL_COMPLETION_001/**`, ExtensionHost* notes (docs only for this PR)

## Command-ID reconciliation (critical)

On this PR tip (`G:\~dev\rawrxd`), `3014` is **`IDM_TOOLS_GGUF_INSPECTOR`**, not Build Project.
On the F:\ oneshot tip track, `3014` was **Build Project** and that harness observed `exit=-1`.

```
DO_NOT_MAP_F_RAWRXD_3014_BUILD_CRASH_ONTO_PR77_WITHOUT_REBINDING_MENU_IDS
FOUR_PANEL_HARNESS_FOR_PR77_MUST_USE_PR77_MENU_IDS
```

## Explicit non-claims

- EA5D `FINISH25_CURRENT=4/25` ≠ this PR's acceptance.
- Historical `19/25` ≠ this PR's acceptance.
- Slim `A4F083DF…` remains immutable unrelated baseline.
- Opening/review ≠ merge authorization.
- F:\ CC79 ConPTY/EXT PASS ≠ PR77 RUNTIME PASS.

## Next for PR77

1. Resolve or document conflict surface vs `main` (no merge yet).
2. Build staged EXE from `9edf63fed8` (or successor tip on same branch).
3. Bind four-panel harness to **this tip's** Build/Output/Problems command IDs (not F:\ 3014 meaning).
4. Prove: build output HWND + Problems navigation + ConPTY on that EXE SHA.
5. Fill EXE_SHA256 + flip gate cells only with measured evidence.
6. MERGE_READY stays 0 until those gates PASS on that SHA.
