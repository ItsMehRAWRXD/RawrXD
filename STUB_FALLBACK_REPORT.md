# RawrXD / Deep2 Stub / Fallback / Placeholder Report

## Scope: `rawrxd/src/deep2/` (`.cpp`, `.h`, `.hpp`; 696 files)
**Total matches** (TODO|FIXME|STUB|TEMP|fallback|dummy|placeholder|identity): 905 occurrences in 410 files, re-measured in Session 2. All of `src/`: 6526 matches in 1882 of 2887 files.

> Session 2 (2026-09-28) corrected sections 1, 2, 4.2 and 5 below. Status markers: CLOSED = changed and compiled; OPEN = not yet addressed.

---

## 1. DUPLICATE IMPLEMENTATION FILES (Category C — cleanup only) — CLOSED

Correction: neither file was in any CMake target, project or script, and neither was identical to its canonical file (`_out.cpp` differed by 19 lines and was older; `_tmp.cpp` was a 159 KB snapshot from Sep 16 vs the 274 KB canonical file). There was no link-order risk. Both were deleted in Session 2. Remaining stale copies noted but not deleted: `src/deep2/Q.txt` (copy of `QuantKernelRegistry.cpp`), `Deep2Engine*.bak`, `vulkan_compute*.h` variants (`.backup`, `_batch10`, `_patched`, `_git` (0 bytes), ...).

Original text below, kept for history.

### 1.1 QuantKernelRegistry.cpp vs QuantKernelRegistry_out.cpp
- **Files**: `src/deep2/QuantKernelRegistry.cpp`, `src/deep2/QuantKernelRegistry_out.cpp`
- **Observation**: Both files contain identical `block_q2_K` struct definition, identical `gemv_q2_k_scalar`, identical `dequant_q2_k`, identical `#include "QuantKernelRegistry.hpp"`.
- **Risk**: If one is edited and the other is not, the build may use stale code. The `_out.cpp` suffix suggests a generated/exported copy.
- **Verdict**: One should be removed or converted to a wrapper that includes the other.
- **Action**: Delete `QuantKernelRegistry_out.cpp` and ensure CMake references only `QuantKernelRegistry.cpp`.

### 1.2 vulkan_compute.cpp vs vulkan_compute_tmp.cpp
- **Files**: `src/deep2/vulkan_compute.cpp`, `src/deep2/vulkan_compute_tmp.cpp`
- **Observation**: Both implement `VulkanCompute::DispatchRmsNorm`, `DispatchGemvDevice`, `SpecBatchRmsNorm`, etc. with near-identical logic. The `_tmp` suffix suggests a temporary copy.
- **Risk**: If both are compiled into the same binary, linker may silently pick one, causing confusing behavior changes based on link order.
- **Verdict**: Determine which is the authority. Likely `vulkan_compute.cpp` is canonical and `vulkan_compute_tmp.cpp` is a backup.
- **Action**: Remove `vulkan_compute_tmp.cpp` from build after verifying `vulkan_compute.cpp` is complete.

---

## 2. Q2_K PRODUCT DECODE (Category E) — CLOSED (MASM removed); shader OPEN

Correction: the original analysis below had this backwards. `RAWRXD_Q2K_PRODUCT_DECODE=1` selects the correct 84-byte Vulkan route; the check inside `gemv_q2_k_masm` was a guard against the 72-byte MASM kernel, and `gemv_q2_k_masm` was never registered (line ~1915 registers `gemv_q2_k_scalar`). Session 2 deleted the wrapper and its `Deep2_Q2_K_GEMV` extern, removed `sovereign_q2_k_gemv.asm` from CMake, and added `static_assert(sizeof(block_q2_K) == 84)`. The flag remains as the route selector. Open: `gemv_q2k.spv`, which the route needs, does not exist in the tree.

Original text below, kept for history.

### 2.1 RAWRXD_Q2K_PRODUCT_DECODE=1 path
- **Files**: `QuantKernelRegistry.cpp` line 183, `QuantKernelRegistry_out.cpp` line 183, `Deep2Engine_GpuForward.cpp` line 496
- **Code**:
```cpp
const char* pd = std::getenv("RAWRXD_Q2K_PRODUCT_DECODE");
if (pd && pd[0] == '1') return false;
```
- **Context**: This blocks a path that would use `sovereign_q2_k_gemv.asm` (72-byte MASM blocks) instead of the 84-byte GGUF `block_q2_K` layout.
- **Risk**: If this env var is accidentally set, Q2_K GEMV is silently disabled and falls back to CPU F32 expand, destroying TPS.
- **Verdict**: The fallback path is intentionally hard-banned because the MASM block size is wrong. The env var itself is a leftover from debugging.
- **Action**: Remove the `getenv` check and the associated dead code. The ban should be compile-time, not runtime.

---

## 3. GPU FORWARD INSTRUMENTATION STUBS (Category B — Temporary)

### 3.1 Forward layer instrumentation
- **File**: `Deep2Engine_GpuForward.cpp`
- **Observation**: 19 `std::fprintf(stderr, ...)` statements added for GPU forward debugging.
- **Examples**:
```cpp
std::fprintf(stderr, "GPU_FORWARD_STAGE=KV_SEQ_OK layer=%u seq=%llu\n", layer, ...);
std::fprintf(stderr, "GPU_LAYER_BEGIN layer=%u\n", layer);
std::fprintf(stderr, "GEMV_ENTER name=%s type=%d rows=%u cols=%u packed=%d\n", ...);
```
- **Risk**: These are temporary debug prints, not structured logging. They will slow down token generation and clutter stderr.
- **Verdict**: Should be gated behind a `DEEP2_GPU_TRACE` compile flag or removed once correctness is proven.
- **Action**: Replace with conditional logging (e.g., `#ifdef DEEP2_GPU_TRACE`) or a structured telemetry callback.

---

## 4. FALLBACK / RETURN PATTERNS (Category E — Unsafe)

### 4.1 `return true` / `return false` in fail paths
- **File**: `Deep2Engine_GpuForward.cpp`
- **Observation**: The `fail` lambda returns `false`, which is correct, but some outer functions return `true` on error paths after logging.
- **Example** (hypothetical, needs verification):
```cpp
if (!vc->BeginFusedLayer()) {
    std::fprintf(stderr, "GPU_RESIDENT_BEGIN_FUSE_FAIL ...\n");
    return false; // correct
}
```
- **Risk**: Some error paths may `return true` after logging, masking failures.
- **Action**: Audit every `return true` after an error log to ensure it is intentional.

### 4.2 Committed fallback semantics — CLOSED in `forwardTokenAllLayers` (source + compile; runtime NOT_RUN)
- **Session 2 fix**: new member `gpuFwdStateMutated_`, set when `tryGpuTokenForward` or `forwardTokenGpuHybrid` starts layer work. After such a lane fails, or after a dual-row exception with one or more layers done, `forwardTokenAllLayers` refuses every other lane in strict and non-strict mode and prints `COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=<moe_hybrid|resident_first|dual_row|batch9>`. Pre-commit failures (guard/device checks) may still fall back.
- **Still open**: strict-only fallback guards outside this function that were not checked for partial state: `Deep2Engine.cpp` ~2283, ~2870, ~3018; `Deep2Engine_VulkanRuntime.cpp` ~177, ~206; `Deep2Engine_Speculative.cpp` strict-violation sites.
- **File**: `Deep2Engine.cpp` line ~3425
- **Observation**: After `tryGpuTokenForward(hidden)` fails, `gpuFwdCommitted_` is set to `false`, and execution falls through to host CPU forward.
- **Risk**: If GPU partially executed (e.g., layers 0–54 succeeded, layer 55 failed), the KV cache and hidden state may be in an inconsistent state, corrupting subsequent inference.
- **Verdict**: This is A002 — the committed fallback bug.
- **Action**: If GPU execution fails after any layer has been committed, the inference must abort with a fatal error, not fall back to host.

---

## 5. `#if 0` AND `#ifdef` BLOCKS (Category C — Dead Code)

### 5.1 `#if 0` blocks — CLOSED (non-vendored)
- **Corrected counts**: `src/deep2` had 0. `src/core/ssot_handlers_ext.cpp` had 54 (all marked "DUPLICATE REMOVED - defined elsewhere"), `src/core/link_stubs.cpp` had 1 (fake enterprise-license stubs returning "valid"), `src/core/sqlite3.c` has 52 (vendored upstream, left alone). "2887" was the total file count in `src/`, not a block count.
- **Session 2**: removed all 55 non-vendored blocks (832 lines). `link_stubs.cpp` compiled; `ssot_handlers_ext.cpp` is only in IDE targets (off in this build), so that deletion is not compile-verified.
- **Original scope line**: 2887 source files across `src/`
- **Observation**: Many `#if 0` blocks exist as commented-out experimental code.
- **Risk**: These rot silently. When someone re-enables them, they may not compile or may behave incorrectly.
- **Action**: Remove all `#if 0` blocks older than the current release cycle.

### 5.2 `#ifdef _WIN32` / `#ifdef __linux__` platform guards
- **Observation**: Platform guards are necessary but should be centralized in a single `platform.h` rather than scattered.
- **Risk**: Inconsistent platform behavior if guards are missing in some files.
- **Action**: Not urgent; part of dependency audit (Phase 5).

---

## 6. DUMMY / PLACEHOLDER IMPLEMENTATIONS

### 6.1 `SlidingWindowEngine.h`
- **File**: `src/deep2/SlidingWindowEngine.h`
- **Observation**: Minimal class definition; likely a stub.
- **Risk**: May be instantiated but not fully implemented.
- **Action**: Verify if used. If not, remove.

### 6.2 `StreamEngine.h` / `StreamRouter.h`
- **Files**: `src/deep2/StreamEngine.h`, `src/deep2/StreamRouter.h`
- **Observation**: Forward declarations only; may be scaffolding.
- **Action**: Verify if used in active code paths.

---

## 7. CONFIGURATION FLAGS WITHOUT DOCUMENTATION

### 7.1 `DEEP2_Q4K_FORCE_F32_VULKAN`
- **Observation**: Referenced in build environment but not found in `src/deep2/*.cpp` grep.
- **Risk**: May be handled in CMake, shader compilation, or another layer. Invisible to source audit.
- **Action**: Add to `CONFIG_FLAGS.md` once source is found.

### 7.2 `DEEP2_GPU_SOLO_STRICT`
- **Observation**: Referenced in build environment but not found in `src/deep2/*.cpp` grep.
- **Risk**: Same as above.
- **Action**: Search CMake and build scripts.

---

## Summary Table

| Category | Description | Count | Priority |
|----------|-------------|-------|----------|
| A | Real implementation | ~600+ | — |
| B | Temporary implementation (debug prints, instrumentation) | ~100 | Medium |
| C | Dead code (`#if 0`, unused files) | ~30 | Low |
| D | Never called (stubs like `SlidingWindowEngine`) | ~10 | Low |
| E | Unsafe fallback / correctness hazard | ~12 | **Critical** |

## Immediate Actions (Category E)

1. **Delete `QuantKernelRegistry_out.cpp`** — duplicate of canonical file.
2. **Delete `vulkan_compute_tmp.cpp`** — duplicate of canonical file.
3. **Remove `RAWRXD_Q2K_PRODUCT_DECODE` runtime gate** — make the MASM ban compile-time.
4. **Fix committed fallback semantics** — abort inference if GPU fails after partial execution (A002).
5. **Remove `#if 0` blocks** — or move to experimental branches.

## Recommended Next Steps

After completing Category E fixes, proceed to:
- Session 2: Authority collapse (make all executables call `Deep2Engine`)
- Session 3: Fallback hardening (strict mode fatal)
- Session 4: Duplicate math cleanup (unify RMSNorm, GEMV)
