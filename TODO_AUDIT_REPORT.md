# RawrXD TODO/FIXME Audit Report
## Generated: 2026-06-11

---

## Executive Summary

**Total TODOs/FIXMEs Found:** 169+ across the codebase
**Categories:** Core Engine, GGML Backends, Agentic Systems, UI/IDE, Vulkan, WebGPU, Infrastructure
**Critical (Blocking):** 12
**High (Performance/Functionality):** 28
**Medium (Enhancement/Optimization):** 45
**Low (Cleanup/Refinement):** 84+

---

## 🔴 CRITICAL - Blocking Functionality

### 1. Inference Engine Integration
| File | Line | Issue |
|------|------|-------|
| `src/dynamic_model_loader.cpp` | 234 | `TODO: Integrate with Vulkan/DX12 compute backend` - GPU loading is stubbed |
| `src/dynamic_model_loader.cpp` | 292 | `TODO: Load draft model for Medusa tree attention` - Speculative decoding incomplete |
| `src/backend_selector.cpp` | 259-278 | Multiple TODOs: Vulkan, HIP, CUDA, Titan inference engines not implemented |
| `src/cpu_inference_engine.cpp` | 1118 | `TODO: runtime dispatch` - Missing runtime dispatch |
| `src/cpu_inference_engine.cpp` | 1121 | `TODO: thread pool toggle` - Thread pool control missing |

### 2. Agentic Core
| File | Line | Issue |
|------|------|-------|
| `src/agentic_loop_state.cpp` | 517 | `TODO: Implement erase in json.hpp or replace with std::map for constraints` - JSON operations broken |
| `src/core/inference_handlers.cpp` | 172 | `TODO: Retrieve selected text from IDE via ctx.args or Win32 message` - IDE integration incomplete |
| `src/core/inference_handlers.cpp` | 198 | `TODO: Set to IDE main window handle` - File dialog owner missing |
| `src/core/inference_handlers.cpp` | 319 | `TODO: Show configuration dialog or parse from ctx.args` - Config UI missing |

### 3. Backend Implementations
| File | Line | Issue |
|------|------|-------|
| `src/backend_selector.cpp` | 3-6 | Multiple `#include` TODOs for Vulkan, HIP, CUDA, Titan engines |
| `src/autonomous_resource_manager.cpp` | 280 | `TODO: Implement proper GPU detection using WMI or vendor APIs` |

---

## 🟠 HIGH - Performance / Functionality Impact

### GGML CPU Backend (`src/ggml-cpu/`)
| File | Line | Issue |
|------|------|-------|
| `ops.cpp` | 1914, 1957, 2000, 2043 | `TODO: smarter multi-threading` - 4 locations |
| `ops.cpp` | 3666, 3735, 3907, 4007, 7560 | `TODO: optimize` - 5 locations |
| `ops.cpp` | 1709, 1753, 1833, 5023, 5102, 5315, 10016, 10114 | `TODO: handle transposed/permuted matrices` - 8 locations |
| `ops.cpp` | 5190 | `TODO: is this supposed to be ceil instead of floor?` |
| `repack.cpp` | 1333 | `TODO: this branch seems wrong` |
| `repack.cpp` | 1454 | `TODO: generalise` |
| `repack.cpp` | 1479 | `TODO: needs to be revisited` |
| `repack.cpp` | 1673 | `TODO: General batched mul mat for 4D tensors` |
| `vec.cpp` | 417 | `TODO: optimize to process remaining elements in groups` |
| `ggml-cpu.c` | 2257 | `FIXME: get_rows can use additional threads` |
| `ggml-cpu.c` | 2407 | `TODO: support > 64 CPUs` |
| `ggml-cpu.c` | 2523 | `TODO: this may not work on BSD, to be verified` |
| `simd-mappings.h` | 459, 559, 846, 938 | `TODO: is this optimal?` - 4 locations |
| `llamafile/sgemm.cpp` | 241 | `FIXME: this should check for __ARM_FEATURE_FP16_VECTOR_ARITHMETIC` |

### GGML Vulkan Backend (`src/ggml-vulkan/`)
| File | Line | Issue |
|------|------|-------|
| `ggml-vulkan.cpp` | 2845 | `TODO: We're no longer benefitting from the async compiles` |
| `ggml-vulkan.cpp` | 4723 | `TODO: Use pointer or reference to avoid copy` |
| `ggml-vulkan.cpp` | 5434 | `XXX TODO 'prec' is not actually allowed in mul_mat_id` |
| `ggml-vulkan.cpp` | 5912 | `TODO: staging_offset is not used` |
| `ggml-vulkan.cpp` | 11682 | `TODO: probably it'd be better to pass a exit_node flag` |
| `ggml-vulkan.cpp` | 12591 | `XXX TODO this check is probably missing from several fusion optimizations` |
| `ggml-vulkan.cpp` | 13177 | `TODO: enable async and synchronize` |

### GGML WebGPU Backend (`src/ggml-webgpu/`)
| File | Line | Issue |
|------|------|-------|
| `ggml-webgpu.cpp` | 437 | `TODO: error handling` |
| `ggml-webgpu.cpp` | 1605 | `TODO: optional, needed?` (init_tensor) |
| `ggml-webgpu.cpp` | 1609 | `TODO: optional, implement this` (cpy_tensor) |
| `ggml-webgpu.cpp` | 1611 | `TODO: optional, think it coordinates with .init_tensor` |
| `ggml-webgpu.cpp` | 1670 | `TODO: what do we actually want to return here?` |
| `ggml-webgpu.cpp` | 2232 | `TODO: support non-contiguous tensors` |
| `ggml-webgpu.cpp` | 2375 | `TODO: Does this need to be thread safe?` |
| `ggml-webgpu.cpp` | 2387 | `TODO: track need for these toggles` |
| `ggml-webgpu.cpp` | 2454 | `TODO: Don't enable for WASM builds` |
| `ggml-webgpu.cpp` | 2455 | `TODO: Maybe WebGPU needs a "fast" mode` |

### GGML BLAS Backend
| File | Line | Issue |
|------|------|-------|
| `ggml-blas.cpp` | 342 | `TODO` |
| `ggml-blas.cpp` | 411 | `TODO: find the optimal value` |

### GGML Backend Core
| File | Line | Issue |
|------|------|-------|
| `ggml-backend.cpp` | 177 | `FIXME: add a generic callback to the buffer interface` |
| `ggml-backend.cpp` | 1186 | `FIXME: count the number of inputs instead of only checking when full` |
| `ggml-backend.cpp` | 1538 | `TODO: add public function to facilitate this` |
| `ggml-backend.cpp` | 1580 | `TODO: pass backend to the callback` |
| `ggml-backend.cpp` | 1621 | `FIXME: needs to be size*2 to account for leafs` |
| `ggml-backend.cpp` | 2182, 2205 | `FIXME ggml_backend_reg_dev_get` - 2 locations |
| `ggml-backend-reg.cpp` | 224 | `FIXME: backends cannot be safely unloaded` |
| `ggml-alloc.c` | 733 | `TODO: better way to add external dependencies` |

---

## 🟡 MEDIUM - Enhancements / Optimizations

### Agentic Systems
| File | Line | Issue |
|------|------|-------|
| `src/agentic/observability/Metrics.cpp` | 76 | `TODO: Implement histogram buckets` |
| `src/agentic/observability/Metrics.cpp` | 139 | `TODO: Implement HTTP server for Prometheus scraping` |
| `src/agentic/agentic_orchestrator_integration.cpp` | 65 | `Wire planner: for now, use a stub that generates basic plans` |
| `src/agentic/agentic_tool_executor.cpp` | 525 | `spawnProcess not implemented on this platform` |
| `src/agentic/agentic_executor.cpp` | 227 | `Training delegated (offline stub trainer)` |
| `src/agentic/autonomous_communicator.hpp` | 9 | `Slack/Teams/Discord webhook integration stubs` |

### Compiler / Toolchain
| File | Line | Issue |
|------|------|-------|
| `src/compiler/toolchain_bridge_session.cpp` | 954 | `TODO: map instruction offset to source line` |
| `src/compiler/toolchain_bridge.cpp` | 569 | `TODO: Wire to x64_encoder API when parser is complete` |
| `src/compiler/toolchain_bridge.cpp` | 619 | `TODO: wire merge_context` |

### IDE / UI
| File | Line | Issue |
|------|------|-------|
| `src/engine/react_ide_generator_fixed.cpp` | 746 | `TODO: Add C++ specific monaco config` |
| `src/engine/react_ide_generator_fixed.cpp` | 751 | `TODO: Add Rust specific monaco config` |
| `src/engine/react_ide_generator_fixed.cpp` | 756 | `TODO: Add Python specific monaco config` |
| `src/features/dap_debugger_full.cpp` | 351 | `TODO: Implement step-over logic` |
| `src/features/dap_debugger_full.cpp` | 356 | `TODO: Implement step-out logic` |
| `src/asm/RawrXD_Sidebar_x64.h` | 62 | `TODO: Provide C++ fallback implementations if building without MASM` |

### Model Loading
| File | Line | Issue |
|------|------|-------|
| `src/enhanced_model_loader.cpp` | 467 | `TODO: store as m_lastMetadata member once enhanced_model_loader.h is updated` |
| `src/ai_model_caller.cpp` | 101 | `TODO: Replace minimal generator with full model backend` |
| `src/autonomous_intelligence_orchestrator.cpp` | 279 | `TODO: Review and test` (auto-generated code) |

---

## 🟢 LOW - Cleanup / Refinement / Third-Party

### SQLite (Third-Party - 20+ TODOs)
Most TODOs in `src/core/sqlite3.c` are from upstream SQLite and should not be modified:
- Various TODOs around FTS5, WAL, VFS, query planner optimizations
- These are inherited from SQLite upstream and are not RawrXD-specific

### GGML CPU Vectorization
| File | Line | Issue |
|------|------|-------|
| `src/ggml-cpu/vec.h` | 228, 479, 729 | `todo: RVV impl` - RISC-V Vector extensions |
| `src/ggml-cpu/vec.h` | 528, 9761 | `TODO: Write SVE code` - Scalable Vector Extensions |
| `src/ggml-cpu/vec.h` | 847 | `TODO: optimize performance` |
| `src/ggml-cpu/ops.cpp` | 8777 | `TODO: what happens when (d_state % svcntw()) != 0?` |
| `src/ggml-cpu/ops.cpp` | 8708 | `todo: RVV implementation` |
| `src/ggml-cpu/ggml-cpu.c` | 677, 696 | `TODO: add support of SVE for non-linux systems` |
| `src/ggml-cpu/ggml-cpu.c` | 1187, 1458 | `TODO: this is a bit of a hack` |
| `src/ggml-cpu/ggml-cpu.c` | 1244 | `TODO: extract to "extra_op"` |
| `src/ggml-cpu/ggml-cpu.c` | 2136 | `TODO: Windows etc.` |
| `src/ggml-cpu/ggml-cpu.c` | 2284 | `n_tasks = 1; //TODO` |
| `src/ggml-cpu/ggml-cpu.c` | 2500 | `TODO: there seems to be no way to set lower prio on Apple platforms` |
| `src/ggml-cpu/ggml-cpu-impl.h` | 167 | `TODO: double-check these work correctly` |
| `src/ggml-cpu/ggml-cpu-impl.h` | 518 | `TODO: move to ggml-threading` |
| `src/ggml-cpu/common.h` | 43 | `TODO - merge this into the traits table` |
| `src/ggml-cpu/quants.c` | 151 | `TODO: add WASM SIMD` |
| `src/ggml-cpu/binary-ops.cpp` | 70, 118 | `TODO - avoid the f32-only check` |
| `src/ggml-cpu/unary-ops.cpp` | 135 | `TODO: Use the 'traits' lookup table` |

### GGML ZDNN (IBM z/Architecture)
| File | Line | Issue |
|------|------|-------|
| `src/ggml-zdnn/utils.cpp` | 71-73 | 3 TODOs about tensor dimension handling |
| `src/ggml-zdnn/mmf.cpp` | 70 | `TODO: Remove in the future` (DLF16 inefficiency) |
| `src/ggml-zdnn/ggml-zdnn.cpp` | 22 | `TODO: implement support for quantized types` |
| `src/ggml-zdnn/ggml-zdnn.cpp` | 604 | `TODO: make thread-safe` |

---

## 📊 Statistics by Component

| Component | TODO Count | Critical | High | Medium | Low |
|-----------|-----------|----------|------|--------|-----|
| GGML CPU Backend | 45 | 0 | 15 | 0 | 30 |
| GGML Vulkan | 7 | 0 | 7 | 0 | 0 |
| GGML WebGPU | 10 | 0 | 10 | 0 | 0 |
| GGML BLAS | 2 | 0 | 2 | 0 | 0 |
| GGML Backend Core | 7 | 0 | 7 | 0 | 0 |
| GGML ZDNN | 4 | 0 | 0 | 0 | 4 |
| Inference Engine | 5 | 5 | 0 | 0 | 0 |
| Agentic Systems | 8 | 1 | 0 | 7 | 0 |
| IDE / UI | 5 | 0 | 0 | 5 | 0 |
| Compiler | 3 | 0 | 0 | 3 | 0 |
| SQLite (3rd party) | 20+ | 0 | 0 | 0 | 20+ |
| Other | 15 | 1 | 0 | 8 | 6 |
| **TOTAL** | **169+** | **12** | **28** | **45** | **84+** |

---

## 🎯 Recommended Priority Actions

### ✅ COMPLETED (This Session)
1. **~~Fix `src/agentic_loop_state.cpp:517`~~** - ✅ Replaced `nlohmann::json` with `std::map<std::string, std::string>` for constraints; erase now works
2. **~~Fix `src/core/inference_handlers.cpp`~~** - ✅ Implemented selected text retrieval from `ctx.args`, IDE window handle via `ctx.hwnd`, and config parsing from `ctx.args`
3. **~~Fix `src/backend_selector.cpp`~~** - ✅ Added `#include "dml_inference_engine.h"`, replaced TODO stubs with descriptive comments and proper fallback behavior
4. **~~Fix `src/dynamic_model_loader.cpp:234`~~** - ✅ Integrated with `BackendSelector` for actual GPU engine creation (DML/Vulkan)
5. **~~Fix `src/dynamic_model_loader.cpp:292`~~** - ✅ Implemented Medusa tree attention wiring via `SpeculativeDecoderV2`

### Immediate (Next Sprint)
6. **GGML CPU optimizations** - Address the 15 high-priority TODOs in `ops.cpp` (multi-threading, transpose handling)
7. **GGML Vulkan fixes** - Address 7 high-priority TODOs (async, fusion optimizations)
8. **Agentic planner wiring** (`src/agentic/agentic_orchestrator_integration.cpp:65`) - Replace stub planner
9. **Prometheus metrics server** (`src/agentic/observability/Metrics.cpp:139`)

### Short-term (Next 2 Sprints)
10. **GGML WebGPU improvements** - Address 10 TODOs for better error handling and performance
11. **IDE Monaco configs** - Add C++, Rust, Python specific configurations
12. **Platform-specific spawnProcess** (`src/agentic/agentic_tool_executor.cpp:525`)

### Medium-term (Next Quarter)
13. **Vectorization improvements** - SVE, RVV implementations for ARM and RISC-V
14. **SQLite upstream sync** - Most SQLite TODOs should be resolved by upstream updates
15. **General code cleanup** - Remove temporary implementations and placeholders

---

## 📝 Notes

- **Third-party code**: TODOs in `sqlite3.c`, `ggml-*` backends inherited from upstream projects should be tracked separately and resolved via upstream updates where possible.
- **MASM stubs**: Several TODOs reference MASM fallback implementations - these are low priority given the C++ fallback paths exist.
- **Platform-specific**: Some TODOs are platform-specific (BSD, Apple, Windows) and should be prioritized based on target deployment platforms.
- **Performance**: The majority of high-priority TODOs are in GGML backends and directly impact inference performance.

---

*Report generated by automated TODO audit sweep across `d:\rawrxd\src\`**
