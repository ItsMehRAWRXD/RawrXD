# CANDIDATE_BUILD_PLAN

ASOF_UTC=2026-11-02T12:39:20.6878118Z
STATUS=PREPARED_NOT_EXECUTED
REBUILD=0
AUTHORIZATION_REQUIRED=1
PROMOTE=0

## Purpose
Define how to produce a **candidate-only** Native IDE binary from an explicit source manifest, distinct from authority tip `a5ae60ef`.

## Two allowed source states
### A — Authority baseline (product seal candidate)
- Exact `git checkout --force` / clean worktree at `a5ae60efecac790598e2e46d9e499eb8ac7287af`
- Confirm `git status --porcelain` empty for build inputs
- Configure: `-DRAWXD_BUILD_WIN32IDE=ON -DRAWXD_BUILD_WIN32IDE_QT=OFF` (verify exact option spellings in CMakeLists at tip)
- Target: `RawrXD-Win32IDE-Native` (name per audit; confirm in CMake at tip)
- Record: compiler, generator, config, SHA-256 of EXE, `git rev-parse HEAD`, cmake cache hash

### B — Candidate WIP baseline (non-product)
- Do **not** pretend HEAD seal
- Pin working-tree files via `WIP_HASH_MANIFEST.csv` SHA-256 list (KEEP_BRANCH set)
- Quarantine DRIFT files: do not add unless separately classified
- HOLD CMakeLists until BUILD_SURFACE_REVIEW signed off; if used, include its working SHA256 in candidate manifest
- Tools (`TOOL_NOT_PRODUCT`) may build separately; never cited as IDE product cert
- Output label: `CANDIDATE_ONLY` · `PROMOTE=0` · distinct receipt path

## KEEP_BRANCH files to pin for candidate B
- `src/deep2/Deep2Engine.cpp`
- `src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp`
- `src/deep2/K2NativeMoEFfn_Place.cpp`
- `src/deep2/modelgenie/universal_gguf.cpp`
- `src/deep2/op_gdn.cpp`
- `src/deep2/op_gdn.hpp`
- `src/deep2/runtime_graph_executor.cpp`
- `src/deep2/vulkan_compute.cpp`
- `src/deep2/vulkan_compute.h`
- `src/win32app/Win32IDE_GhostText.cpp`
- `src/win32app/Win32IDE_GhostText.h`
- `src/win32app/Win32IDE_GhostTextIntegration.cpp`

## Explicit non-goals (until authorized)
- No rebuild now
- No production EXE substitution
- No commit/push of WIP
- No transferring Gate6/tool PASS to product

## After authorized candidate build
1. Native IDE product E2E: ChatWindow, GhostText ordering/routing, 64-token path
2. Host stability soak under candidate seal
3. Debugger/swarm/rollback remain implementation gaps — do not fake runtime PASS
