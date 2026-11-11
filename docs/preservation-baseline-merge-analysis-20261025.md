# Merge-Tree & Provenance Analysis: `origin/preservation/source-baseline-20261021`

Integration branch: `integration/cert-reconciliation-20261025` (from `origin/main` @ `033a8acb`). No merges performed.

## Ancestry
- Merge-base: `8dfeeaf0b729e2d76e0f23437bb52df3c256f0ad`
- `main` is 11 commits ahead of base; branch is 355 commits ahead.

## Change inventory (vs merge-base)
- Total changed paths: ~222,982 (dominated by added build/evidence/debris files).
- Modified (M): 173
- Deleted (D): 163 (build artifacts, WebView2 caches, .pyc, binaries — all deletions are debris cleanup, not source loss)

## Conflict analysis
- `git merge-tree` timed out on full tree (repo scale). Conflict detection deferred to per-file merge in worktree.
- High-conflict-risk paths (modified on both sides): build system (`CMakeLists.txt`, `3rdparty/ggml/...`), CI workflows, `src/deep2/*`, `src/win32app/*`, `src/agent/*`. These must be reviewed file-by-file.

## Duplication
- The branch is primarily a source-preservation snapshot; ~181k of 222k added files are under `evidence/` and build directories. Treat as archive, not integration source.

## Architecture (Qt vs native)
- Modified `src/ai/streaming_gguf_loader_qt.cpp`/`.h` deleted; `src/vulkan_stubs.cpp` deleted — indicates native/Qt cleanup in progress.
- Modified `src/win32app/*`, `src/deep2/*`, `src/agent/*` — core product code.

## Risk areas (modified source)
- Inference: `src/deep2/Deep2Engine.{cpp,h}`, `src/gguf_loader.cpp`, `src/streaming_engine.cpp`, `src/vulkan_compute.cpp`
- Model loading: `src/model_loader/enhanced_model_loader.cpp`, `src/universal_model_router.*`
- Agent execution: `src/agent/*`, `src/agentic/*`, `src/autonomous_*`
- Build: `CMakeLists.txt`, `3rdparty/ggml`, workflows

## Prioritized extraction manifest (coherent units, not whole-branch)
1. Build/CI hygiene: `.github/workflows/*`, `CMakeLists.txt`, `3rdparty/ggml` CMake (verify native Win32, no Qt).
2. Deep2 engine changes: `src/deep2/Deep2Engine.{cpp,h}` + `QuantKernelRegistry.cpp`.
3. Agent/agentic core: `src/agent/*`, `src/agentic/*`.
4. Win32 IDE: `src/win32app/*`.
5. Deletions of Qt stubs/vulkan_stubs: confirm removals are safe (already absent on main? verify).

## Promotion policy
DISCOVERED → ANALYZED → EXTRACTED → BUILT → TESTED → CERTIFIED → INTEGRATED. No component promoted yet.

## Debris to exclude from integration
All `RawrXD*.exe.WebView2/`, `*.log`, `build*/`, `tmp_*`, `__pycache__/`, `Full_Source/`, `Full Source/`, `bigdaddyg-ide/`, `OrganizedPiProject/` additions. These belong to Fix 2/3 (cleanup), not Fix 1.
