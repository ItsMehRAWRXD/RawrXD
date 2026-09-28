# RawrXD Stub Inventory — Classification Receipt

**Date:** 2026-09-28
**Scope:** `F:\~dev\rawrxd\src\**\*.cpp,*.cc,*.cxx,*.h,*.hpp`
**Method:** File-content scan (placeholder markers + one-line file detection) → CMake reachability cross-check → `dumpbin /SYMBOLS` proof against built `RawrXD-InferenceEngine.lib`

## Headline numbers

```
STUB_CANDIDATES      = 1193
LIVE_IN_CMAKE        =   83   (compiled into production targets)
DEAD_TREE            = 1110   (on disk, NOT referenced by any CMake source list)
BUILT_LIB_SYMBOLS    =    0   (all 83 live stubs contribute ZERO symbols to RawrXD-InferenceEngine.lib)
```

## Gate interpretation (fail-closed law)

- `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`
- The 83 "live" stub files ARE compiled (CMake references them) but the built `.lib` contains **zero symbols** with their stems — verified by `dumpbin /SYMBOLS` across all batch stems (batches 1-6). This means **nothing in the production link path resolves through these placeholder TUs**. They are dead weight in the source lists, not active stub fallbacks.
- The 1110 dead-tree stubs are unreferenced by CMake and cannot affect any target.

## Batch receipts (15/turn where possible)

| Batch | Range | Count | Verdict |
|---|---|:---:|---|
| 1 | stubs 1-15 (agent_explainability → benchmark_runner) | 15 | 24B comment-only files; SYMBOL_HITS=0 in built lib |
| 2 | stubs 16-30 (cloud_api_client → interpretability_panel_enhanced) | 15 | 24B comment-only; SYMBOL_HITS=0 |
| 3 | stubs 31-45 (LanguageServerIntegration → project_context) | 15 | 24B/37B comment-only; SYMBOL_HITS=0 |
| 4 | stubs 46-60 (rawrxd_inference → universal_model_router) | 15 | 24B-36B; two are header-include-only shells (#include only, no definitions); SYMBOL_HITS=0 |
| 5 | stubs 61-75 (vulkan_compute → vulkan_fwd_quant_pipe) | 15 | 24B-35B; vulkan_compute.cpp is an include-only shell; SYMBOL_HITS=0 |
| 6 | stubs 76-83 (vulkan_fwd_quant → vulkan_weight_window) | 8 | 24B-32B comment-only; SYMBOL_HITS=0 |

## Special cases flagged

1. **`src/rawrxd_inference.cpp`** (36B) — content is just `#include "core/rawrxd_inference.h"`. Not a function body; harmless, but the filename implies substance it does not have.
2. **`src/vulkan_compute.cpp`** (35B) — same include-only shell pattern.
3. **`src/streaming_gguf_loader.cpp`** (24B) — CMake comments call it a HeadlessIDE dependency, BUT the real implementation lives in `src/model_source_resolver.cpp` (`StreamingGGUFLoader::load/isLoaded/unload`, all defined with static-state, non-stub bodies). The 24B file is a decoy duplicate; the real symbol provider is wired.
4. **`src/rawrxd_link_stubs.cpp`** (24B) — the "link stubs" file is itself an empty stub; no symbol shims are actually present (confirmed: zero stub-stem symbols in the built lib, and the build links clean).
5. **`model_source_resolver.cpp`** — real implementations present but resolve = echo-the-args (`Resolve()` stores and returns args unchanged). Functional-but-thin; flagged for later hardening, NOT a stub.

## Dead-tree distribution (top folders of the 1110)

```
deep2: 328 | win32app: 181 | agentic: 84 | core: 65 | sovereign: 59 | soloide: 40
runtime: 33 | rkc: 21 | agent: 20 | inference: 17 | benchmark: 17 | swarm: 17
modules: 14 | ui: 13 | security: 12 | ... (76 folders total)
```

## Files

- `F:\~dev\_stub_inventory.csv` — all 1193 candidates (File, Lines, StubMarkers, Size)
- `F:\~dev\_stubs_reachable.txt` — the 83 CMake-reachable stubs
- `F:\~dev\_stubs_reachable_lines.txt` — CMake line numbers per reachable stub (15 shown; 83 total in file)
- `F:\~dev\_stub_batch1.txt` … `_stub_batch6.txt` — per-batch content receipts
- `F:\~dev\_batch1_linkcheck.txt`, `_batch2_symbolcheck.txt`, `_batch3_symbolcheck.txt`, `_batch456_symbolcheck.txt` — dumpbin symbol proofs (all zero)
- `F:\~dev\_stub_dead_dist.txt` — dead-tree folder distribution
- `F:\~dev\_dumpbin_locate.txt` — dumpbin path used (14.44.35207, Hostx64/x64)

## Verdict against the certification table

- **SRC-001 (Placeholder source integrity):** ⚠️ OPEN → **scope now quantified**: 1193 placeholders, 0 reachable-by-symbol in production. The P0 risk "production resolves through placeholder implementations" is **NOT PRESENT** in the current built `.lib` (SYMBOL_HITS=0 across all 83 reachable stems). Remaining work is hygiene: remove the 1110 dead files from the tree and/or prune the 83 empty TUs from source lists.
- **BUILD-003 (Stub-free production build):** evidence now exists that the production link contains no stub-stem symbols. Full certification still requires the clean-configure/rebuild proof (BUILD-001/002).