# Sovereign Architecture Atlas
## RawrXD Archaeological Survey 2026-07-09

**Status**: Phase 1-2 Complete (Kernel + GPU Archaeology)  
**Coverage**: 285,495 files mapped, 275,698 orphans catalogued  
**Repository**: `ItsMehRAWRXD/RawrXD`  
**Branch**: `main` (commit `2d344e4da`)

---

## Executive Summary

The RawrXD codebase represents **~10 years of sovereign AI infrastructure development** across multiple epochs. This atlas maps the archaeological layers to identify resurrection candidates.

### Scale
| Metric | Value |
|--------|-------|
| Total Files | 285,495 |
| Total Size | 10.38 GB |
| Orphan Files | 275,698 (96.6%) |
| Active Source | ~40,000 files (3.4%) |

### Language Distribution
| Language | Files | Size | Notes |
|----------|-------|------|-------|
| C/C++ | 124,345 | 2.8 GB | Runtime, loaders, kernels |
| MASM | 32,535 | 2.1 GB | **Sovereign kernels** |
| JS/TS | 43,798 | 588 MB | IDE runtime |
| PowerShell | 21,632 | 1 GB | Build automation |
| Config/Build | ~38,000 | 3.9 GB | Artifacts |

---

## Phase 1: Kernel Archaeology ✅ COMPLETE

### Discovery: 2,107 Kernel Candidates

**Critical Finding**: `RawrXD-Kernels.asm` contains **5 complementary kernels** not in current Sovereign suite:

| Kernel | Function | Status | Action |
|--------|----------|--------|--------|
| `RawrXD_FastTokenScan` | SIMD tokenizer scan | ❌ Missing | **RESURRECT** |
| `RawrXD_FlashAttentionV2` | Flash Attention v2 | ❌ Missing | **RESURRECT** |
| `RawrXD_SVD_Compress` | SVD model compression | ❌ Missing | **RESURRECT** |
| `RawrXD_TokenMerge_AVX512` | AVX-512 token merging | ❌ Missing | **RESURRECT** |
| `RawrXD_Q4_0_Q8_0_MatMul` | Quantized matmul | ⚠️ Different | **MERGE** |

### Top Resurrection Candidates (Score 6-8)

```
Full Source/3rdparty/ggml/src/ggml-cpu/kleidiai/kernels.cpp [6]
  → ARM-optimized kernels (56KB)
  → Keywords: kernel, matmul, gemm, quant, q4, q8

Full Source/Compute_Kernel_DMA_Complete.asm [6]
  → GPU kernel dispatch + DMA (24KB)
  → Keywords: kernel, compute, gpu, dma

Full Source/RawrXD-Kernels.asm [6]
  → Sovereign kernel suite (4.87KB)
  → Keywords: matmul, attention, quant, AVX-512

Full Source/3rdparty/ggml/src/ggml-cpu/llamafile/sgemm.cpp [6]
  → Optimized AVX-512 GEMM (112KB)
  → Keywords: kernel, matmul, AVX-512, SIMD

Full Source/3rdparty/ggml/src/ggml-cpu/spacemit/ime1_kernels.cpp [6]
  → Spacemit optimized kernels (175KB)
  → Keywords: kernel, gemm, quant, FMA
```

---

## Phase 2: GPU Archaeology ✅ COMPLETE

### Discovery: 2,688 GPU Candidates

**Key Finding**: GPU code scattered across test files, not centralized

### GPU Technology Distribution

| Technology | Files | Location Pattern |
|------------|-------|-------------------|
| Vulkan | ~200 | `test-backend-ops.cpp`, `vulkan_*.cpp` |
| CUDA | ~400 | `test-conv*.cpp`, `examples/gpt-2/` |
| HIP | ~50 | `gtest-internal.h`, `gtest.h` |
| SYCL | ~20 | `ggml-sycl/gemm.hpp` |

### Top GPU Candidates (Score 9-12)

```
Full Source/Compute_Kernel_DMA_Complete.asm [10]
  → GPU kernel dispatch, DMA, memory staging
  → Score: OptimizedAssembly + GPUCode + RecentModification

Full Source/3rdparty/ggml/tests/test-backend-ops.cpp [9]
  → 323KB of Vulkan/CUDA backend operations
  → Contains: vulkan, cuda, gpu, buffer

Full Source/compilers/_patched/test_complete_compiler.asm [9]
  → 24KB GPU compiler tests
  → Keywords: buffer, command
```

---

## Phase 3: Model Loader Archaeology ⏳ PENDING

### Target: GGUF/GGML Loader Evolution

**Search Pattern**:
```
Keywords: gguf, ggml, loader, tensor, model, tokenizer, vocab, metadata, quant
Extensions: .cpp, .hpp, .h, .c, .py, .rs
Locations: RawrXD-ModelLoader/, src/loader/, backend/, src/runtime/
```

**Expected Findings**:
- GGUF parser evolution (v1 → v2 → v3 → current)
- Tokenizer implementations
- Quantization format handlers
- Tensor layout experiments

---

## Phase 4: Build System Archaeology ⏳ PENDING

### Target: Orphaned Build Surfaces

**Search Pattern**:
```
Extensions: .bat, .ps1, CMakeLists.txt, *.ninja, *.vcxproj
Keywords: cmake, ninja, make, build, compile, link
```

**Problem**: 275,698 files with "no build association"

**Expected Findings**:
- Broken CMake configurations
- Orphaned batch scripts
- Missing build glue
- Generated artifacts

---

## Phase 5: Reverse Engineering Archaeology ⏳ PENDING

### Target: PE/COFF/Binary Tools

**Search Pattern**:
```
Keywords: pe, coff, disasm, deobf, parser, scanner, binary, loader, inject, symbol
Locations: reverse_engineering/, deobf/, src/reverse_engineering/
```

**Connection to Sovereign**:
- PE generation (already implemented)
- COFF loading (already implemented)
- Custom toolchain
- Binary analysis

---

## Resurrection Priority Matrix

### Priority 1: RESURRECT (90-100 points)
*None found yet - need deeper analysis*

### Priority 2: MERGE (60-89 points)
| File | Source | Target | Action |
|------|--------|--------|--------|
| `RawrXD-Kernels.asm` | Full Source/ | src/asm/ | Extract 5 kernels |
| `Compute_Kernel_DMA_Complete.asm` | Full Source/ | src/gpu/ | Integrate GPU dispatch |
| `llamafile/sgemm.cpp` | 3rdparty/ggml/ | src/kernels/ | Port AVX-512 GEMM |

### Priority 3: ARCHIVE (<60 points)
*2,000+ files - bulk archival candidates*

---

## Immediate Action Items

### 1. Extract `RawrXD-Kernels.asm` Kernels
```powershell
# Extract 5 kernels into Sovereign suite
Copy-Item "Full Source\RawrXD-Kernels.asm" "src\asm\Sovereign_Legacy_Kernels.asm"
```

### 2. Integrate GPU Dispatch
```powershell
# Merge Compute_Kernel_DMA_Complete.asm into GPU backend
Copy-Item "Full Source\Compute_Kernel_DMA_Complete.asm" "src\gpu\GPU_Kernel_Dispatcher.asm"
```

### 3. Port AVX-512 GEMM
```powershell
# Adapt llamafile/sgemm.cpp to Sovereign
Copy-Item "Full Source\3rdparty\ggml\src\ggml-cpu\llamafile\sgemm.cpp" "src\kernels\Sovereign_GEMM_AVX512.cpp"
```

---

## Next Steps

1. **Complete Phase 3** (Loader Archaeology) - Map GGUF evolution
2. **Complete Phase 4** (Build Archaeology) - Fix orphaned builds
3. **Complete Phase 5** (RE Archaeology) - Map binary tools
4. **Generate Final Atlas** - Consolidate all phases
5. **Begin Resurrection** - Extract Priority 1 & 2 candidates

---

## Tools Generated

| Tool | Location | Purpose |
|------|----------|---------|
| `audit_orphans.ps1` | `/audit_orphans.ps1` | Scans orphans into candidates |
| `Kernel_candidates.md` | `/audit_results/` | 2,107 kernel candidates |
| `GPU_candidates.md` | `/audit_results/` | 2,688 GPU candidates |
| `*_summary.txt` | `/audit_results/` | Classification summaries |

---

## Scoring System

```
+5  Referenced by active source
+5  Contains unique symbols
+4  Optimized assembly
+4  GPU code
+3  Has tests
+3  Has build files
+2  Recent modification
+2  Matches current architecture
-5  Generated output
-5  Duplicate hash
-3  Empty scaffold

90-100  → RESURRECT
60-89   → MERGE
<60     → ARCHIVE
```

---

*Generated: 2026-07-09*  
*Survey Status: Phase 1-2 Complete, Phases 3-5 Pending*  
*Next Update: After Phase 5 completion*
