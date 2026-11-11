# RawrXD Deep2 Source-to-Runtime Audit

Status: current-branch evidence record; unverified gates remain explicitly open.

Repository branch: `fix/deep2-multimodel-safety-20261025`  
Audited revision: `3773992acd4cb415beaf229add6208d10c392e20`  
Remote: `origin/fix/deep2-multimodel-safety-20261025`

## Build authority currently present

The active root `CMakeLists.txt` defines the following executable/library path:

- `rawrxd_gpu_compute` — canonical `src/deep2/vulkan_compute.cpp` adapter and GGUF loader sources.
- `deep2_engine_lib` — `src/deep2/Deep2Engine.cpp`, GPU forward path, `generic_vulkan_matmul.cpp`, `Deep2MlaLifecycleAdapter.cpp`, `MlaCertAuthority.cpp`, and the guarded Deep2 subsystem list.
- `deep2_agentic_loop` — the agent harness linked against `deep2_engine_lib` when the Vulkan/deep2 sources are available.
- `RawrXD-Win32IDE-Native` — the native IDE executable.
- `cursor_parity_registry_smoke` — dependency-light registry and permission gate test.

This supersedes the older source audit's conclusion that the root build necessarily excludes the nested Deep2 implementation. The generated build graph must still be checked for each packaged executable; source presence alone is not runtime certification.

## Residency implementation

The current `src/deep2/TensorResidencyCache.hpp` is not an empty placeholder. It contains shard handle ownership, checked range arithmetic, Windows allocation-granularity alignment, bounded mapping length checks, LRU bookkeeping, reference counts, and mmap/`MapViewOfFile` acquisition. The cache implementation still requires model-specific runtime receipts for eviction and multi-shard behavior.

## Verified runtime evidence

| Gate | Evidence | Result |
|---|---|---|
| Cursor-parity registry | `build_cursor_parity/bin-msvc/cursor_parity_registry_smoke.exe`; CTest `cursor_parity_registry_smoke` | PASS, 25 checks |
| Bridge recovery | `evidence/agentic_bridge_runtime_current.log` | PASS |
| Ollama autonomous loop | `evidence/agentic_ollama_runtime_current.log`, model `qwen3:8b` | PASS: read, edit, build/test, finish |
| Gemma CPU generation | `evidence/gemma_cpu_generation_timing_receipt.json` | PASS: finite logits and one generated token |
| Native IDE build identity | `build_ide/bin/RawrXD-Win32IDE-Native.exe` | SHA-256 `A7DA3BA6DDDEEB89DCA385490C618F608B2AB223F323E3AFABCD487920B26A5E` |
| Agent executable identity | `build_ide/bin/deep2_agentic_loop.exe` | SHA-256 `7E0D3C6D16D8DB8E88C0636BB623B35201D65B387F2BF9D99EA9D8D9248755A0` |

## Still open

- Native Deep2 agentic read/edit/build/test completion is not certified by the Ollama receipt.
- GPU forward dispatch, multi-GPU scaling, and a sustained >10% throughput improvement are not certified.
- Full Gemma multi-token quality/parity and all-local-model generation remain open.
- Physical IDE editor persistence, GhostText acceptance, and packaged UI workflow require a fresh uninterrupted run.
- REAP calibration, expert scoring, GGUF rewriting, reduced-model parity, and production `--size` admission remain fail-closed.

No model files or generated build trees are included in source publication. Uncommitted worktree content remains preserved separately and is not represented as committed or certified by this report.
