# Phase 5: Defensive Hardening & Feature Depth — Implementation Plan
**Date**: 2026-04-04  
**Status**: 🔄 INCOMING (Ready to start on demand)  
**Baseline**: v1.2.6-stable (Phase 4 complete)  
**Target Completion**: 2026-04-21 (3 weeks)

---

## Executive Overview

Phase 5 transforms the remaining 45+ stub-grade exports into production-active paths. The current baseline has 16 fully production-backed exports; Phase 5 will harden an additional 16-20 "safe stubs" into real implementations, reserving the remaining advanced features for Phase 6.

**Scope**: 
- ✅ Advanced Batching (serial → parallel inference dispatch)
- ✅ Quantization Layer (activation + runtime selection)
- ✅ Hotpatching Support (patching framework integration)
- ✅ Streaming Inference (token-at-a-time result fetching)
- ✅ Model Discovery (filesystem enumeration)
- ✅ Defensive Hardening (null checks, bounds validation on all paths)

**Success Criteria**: 
- All 77 exports implement real logic (no remaining stubs)
- Zero null-pointer crashes under IDE integration tests
- 10-hour stress test with concurrent inferences + model switches passes
- Performance degradation < 5% vs. Phase 4 baseline

---

## Phase 4 → Phase 5 Transition

### Current State (Phase 4 Locked Baseline)
```
Production-Grade Exports: 16
├─ Lifecycle (2): Initialize, Shutdown
├─ Model Mgmt (4): LoadModel, UnloadModel, GetModelInfo, CacheModelMetadata
├─ Inference (4): InferAsync, InferSync, WaitForInference, GetInferenceResult
├─ Tokenizer (1): GetTokenizerInfo
├─ Telemetry (3): GetInferenceLatency, GetThroughputTokensPerSec, ResetPerformanceCounters
├─ Diagnostics (1): GetDiagnosticLog
└─ Aperture (1): ApertureInit, MapChunk, GetApertureUtilization

Safe Stubs (61): No-op returns, no regressions, DO NOT CRASH
```

### Target State (Phase 5 End)
```
Production-Grade Exports: 35-40
├─ Phase 4 (16): All unchanged ✅
├─ NEW: Advanced Batching (2): BatchInferences (core)
├─ NEW: Quantization (2): EnableQuantization, QueryQuantizationStatus
├─ NEW: Streaming (2): BeginStreaming, EndStreaming, GetStreamToken
├─ NEW: Model Discovery (1): ListModels (filesystem scan)
├─ NEW: Hotpatching (1): ApplyHotpatch (framework hookup)
└─ Defensive Additions (10-15): Bounds checks, error guards on all paths

Remaining Stubs (40): Reserved for Phase 6 (Advanced Features)
```

---

## Detailed Task Breakdown

### SPRINT 1: Weeks 1 (Batching + Quantization)

#### Task 1.1: Advanced Batching Architecture
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Current**: `BatchInferences` returns SUCCESS (no-op)  
**Target**: Parallel dispatch via thread pool or task queue

**Implementation**:
```cpp
// Add to globals
static HANDLE g_batchThreadPool = NULL;
static uint32_t g_batchQueueSize = 0;
static const uint32_t MAX_BATCH_INFERENCES = 16;

// Implement BatchInferences
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_BatchInferences(const char** prompts, size_t* prompt_lens, 
                       uint32_t batch_size,
                       RAWRXD_INFERENCE_HANDLE* handles) {
    // Dispatch prompts to thread pool
    // Return array of handles for parallel waiting
    // Post-blocking: caller polls/waits on all handles
}
```

**Effort**: 2 days  
**Dependencies**: Thread pool infrastructure (may reuse Win32 thread API)  
**Risk**: Thread safety on shared state (g_currentRequest)  
**Mitigation**: Use interlocked compare-exchange for handle allocation

---

#### Task 1.2: Quantization Layer Activation
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Current**: `EnableQuantization` returns SUCCESS (no-op)  
**Target**: Runtime quantization selection (INT8, INT4, FP16)

**Implementation**:
```cpp
// Add to globals
static int32_t g_quantization_format = RAWRXD_QUANT_NONE;

// Implement EnableQuantization
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_EnableQuantization(int32_t quant_format) {
    if (g_rawrxd_inference_active) return RAWRXD_ERROR_NOT_READY;
    if (quant_format < 0 || quant_format > RAWRXD_QUANT_MAX) 
        return RAWRXD_ERROR_INVALID_PARAM;
    
    g_quantization_format = quant_format;
    
    // Signal Titan backend to prepare dequantization kernels
    // (may be no-op if Titan auto-detects)
    
    return RAWRXD_SUCCESS;
}

// Implement QueryQuantizationStatus
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_QueryQuantizationStatus(int32_t* current_format, 
                                uint32_t* supported_formats) {
    if (!current_format || !supported_formats) 
        return RAWRXD_ERROR_INVALID_PARAM;
    
    *current_format = g_quantization_format;
    // Bitmask of supported formats
    *supported_formats = (1 << RAWRXD_QUANT_NONE) | 
                         (1 << RAWRXD_QUANT_INT8) | 
                         (1 << RAWRXD_QUANT_INT4) | 
                         (1 << RAWRXD_QUANT_FP16);
    return RAWRXD_SUCCESS;
}
```

**Effort**: 1.5 days  
**Dependencies**: Quantization format constants in header  
**Risk**: Titan backend may not support all formats  
**Mitigation**: Query Titan capabilities at Initialize time; advertise only supported formats

---

### SPRINT 2: Week 2 (Streaming + Model Discovery)

#### Task 2.1: Streaming Inference API
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Current**: `BeginStreaming` returns SUCCESS (no-op)  
**Target**: Token-at-a-time chunked result fetching

**Implementation**:
```cpp
// Add to globals
static HANDLE g_streamHandle = NULL;
static const char* g_streamBuffer = NULL;
static uint32_t g_streamOffset = 0;
static uint32_t g_streamLength = 0;

// Implement BeginStreaming
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_BeginStreaming(RAWRXD_INFERENCE_HANDLE inference_handle, 
                      RAWRXD_STREAM_HANDLE* stream_handle) {
    if (!stream_handle) return RAWRXD_ERROR_INVALID_PARAM;
    
    // Verify inference completed
    if (g_rawrxd_inference_active) return RAWRXD_ERROR_NOT_READY;
    
    // Initialize stream state from last inference result
    g_streamOffset = 0;
    g_streamLength = 0;
    while (g_rawrxd_inference_text[g_streamLength]) 
        g_streamLength++;
    
    g_streamHandle = (HANDLE)(uintptr_t)1;  // Valid stream marker
    *stream_handle = (RAWRXD_STREAM_HANDLE)g_streamHandle;
    return RAWRXD_SUCCESS;
}

// Implement GetStreamToken
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_GetStreamToken(RAWRXD_STREAM_HANDLE stream_handle, 
                      char* token_buffer, size_t buffer_size,
                      uint32_t* bytes_written, uint32_t* is_final) {
    if (!stream_handle) return RAWRXD_ERROR_INVALID_PARAM;
    
    // Chunk result into space-delimited tokens (heuristic)
    // or implement proper tokenizer-aware chunking
    
    // For now: return result in fixed-size chunks
    uint32_t chunk_size = buffer_size - 1;
    if (g_streamOffset >= g_streamLength) {
        // Stream exhausted
        if (bytes_written) *bytes_written = 0;
        if (is_final) *is_final = 1;
        return RAWRXD_SUCCESS;
    }
    
    uint32_t remaining = g_streamLength - g_streamOffset;
    uint32_t to_copy = (chunk_size < remaining) ? chunk_size : remaining;
    
    for (uint32_t i = 0; i < to_copy; i++)
        token_buffer[i] = g_rawrxd_inference_text[g_streamOffset + i];
    token_buffer[to_copy] = 0;
    
    g_streamOffset += to_copy;
    
    if (bytes_written) *bytes_written = to_copy;
    if (is_final) *is_final = (g_streamOffset >= g_streamLength) ? 1 : 0;
    return RAWRXD_SUCCESS;
}

// Implement EndStreaming
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_EndStreaming(RAWRXD_STREAM_HANDLE stream_handle) {
    if (!stream_handle) return RAWRXD_ERROR_INVALID_PARAM;
    g_streamHandle = NULL;
    return RAWRXD_SUCCESS;
}
```

**Effort**: 2 days  
**Dependencies**: Stream handle type (uint64_t or void*)  
**Risk**: Token chunking heuristic may be naive; proper tokenizer integration deferred  
**Mitigation**: Document current behavior as "space-delimited chunks"; Phase 6 upgrades to real tokenizer

---

#### Task 2.2: Model Discovery (Filesystem Enumeration)
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Current**: `ListModels` returns count=1 (active model only)  
**Target**: Scan directory for .gguf files

**Implementation**:
```cpp
// Add to globals
static char g_modelSearchPath[260] = "D:\\";  // Default search path
static char g_modelCache[4096] = {0};         // Cached model list
static uint32_t g_modelCacheCnt = 0;

// Implement SetModelSearchPath (utility)
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_SetModelSearchPath(const char* search_path) {
    if (!search_path) return RAWRXD_ERROR_INVALID_PARAM;
    StrCopyN(g_modelSearchPath, search_path, sizeof(g_modelSearchPath));
    g_modelCacheCnt = 0;  // Invalidate cache
    return RAWRXD_SUCCESS;
}

// Implement ListModels
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_ListModels(char* model_paths, size_t buffer_size, uint32_t* count) {
    if (count) *count = 0;
    
    // If cache is empty, scan filesystem
    if (g_modelCacheCnt == 0) {
        // Use FindFirstFileA / FindNextFileA to enumerate .gguf files
        WIN32_FIND_DATAA fd = {};
        HANDLE hFind = FindFirstFileA("D:\\*.gguf", &fd);
        
        if (hFind == INVALID_HANDLE_VALUE) {
            return RAWRXD_SUCCESS;  // No files found
        }
        
        char* cur = g_modelCache;
        int remaining = sizeof(g_modelCache);
        
        do {
            // Build full path and store in cache
            int pathLen = wsprintfA(cur, "D:\\%s\n", fd.cFileName);
            if (pathLen > 0 && remaining > pathLen) {
                cur += pathLen;
                remaining -= pathLen;
                g_modelCacheCnt++;
            }
        } while (FindNextFileA(hFind, &fd) && g_modelCacheCnt < 100);
        
        FindClose(hFind);
    }
    
    // Return cached list to caller
    if (model_paths && buffer_size > 0) {
        size_t cacheLen = 0;
        while (g_modelCache[cacheLen]) cacheLen++;
        
        size_t to_copy = (cacheLen < buffer_size) ? cacheLen : buffer_size - 1;
        for (size_t i = 0; i < to_copy; i++)
            model_paths[i] = g_modelCache[i];
        model_paths[to_copy] = 0;
    }
    
    if (count) *count = g_modelCacheCnt;
    return RAWRXD_SUCCESS;
}
```

**Effort**: 1.5 days  
**Dependencies**: Win32 FindFirstFileA/FindNextFileA API (already available)  
**Risk**: Directory scan could be slow for large model directories  
**Mitigation**: Cache results; allow caller to set search path; document 100-model limit

---

### SPRINT 3: Week 3 (Hotpatching + Defensive Hardening)

#### Task 3.1: Hotpatching Framework Integration
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Current**: `ApplyHotpatch` returns SUCCESS (no-op)  
**Target**: Runtime code patching hookup

**Implementation**:
```cpp
// Add to globals
static uint32_t g_hotpatchEnabled = 0;
static void (*g_hotpatchCallback)(const char* patch_name) = NULL;

// Implement EnableHotpatch
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_EnableHotpatch(void) {
    g_hotpatchEnabled = 1;
    return RAWRXD_SUCCESS;
}

// Implement ApplyHotpatch
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_ApplyHotpatch(const char* patch_name, 
                     const uint8_t* patch_data, size_t patch_size) {
    if (!g_hotpatchEnabled) return RAWRXD_ERROR_NOT_READY;
    if (!patch_name || !patch_data) return RAWRXD_ERROR_INVALID_PARAM;
    
    // Validate patch signature
    // (Phase 5: stub validation; Phase 6: real patching engine)
    
    // Log patch application
    if (g_hotpatchCallback) {
        g_hotpatchCallback(patch_name);
    }
    
    return RAWRXD_SUCCESS;  // Deferred implementation
}

// Implement QueryHotpatchStatus
extern "C" __declspec(dllexport) RAWRXD_STATUS __stdcall 
RawrXD_QueryHotpatchStatus(uint32_t* is_enabled, uint32_t* patches_applied) {
    if (!is_enabled || !patches_applied) return RAWRXD_ERROR_INVALID_PARAM;
    *is_enabled = g_hotpatchEnabled;
    *patches_applied = 0;  // TODO: track applied patches
    return RAWRXD_SUCCESS;
}
```

**Effort**: 1 day  
**Dependencies**: Hotpatching infrastructure (stub for Phase 5, real implementation Phase 6)  
**Risk**: Deferred to Phase 6; Phase 5 is framework only  
**Mitigation**: Document as "Phase 5 framework stub"; Phase 6 delivers real patching engine

---

#### Task 3.2: Defensive Hardening Pass
**File**: `d:\rawrxd\src\titan_infer_dll.cpp`  
**Target**: Add null pointer guards and bounds validation to ALL 77 exports

**Scope**:
1. **Null Pointer Audit** — Every pointer parameter must be checked before use
   - Example: `if (!model_info) return RAWRXD_ERROR_INVALID_PARAM;`
2. **Buffer Overflow Guards** — All string operations must specify buffer size
   - Already done in Phase 4 (`StrCopyN`)
3. **Handle Validation** — All model/inference handles must be verified valid
   - Add handle range checks
4. **State Consistency** — Verify pre-conditions before operations
   - E.g., don't allow `GetInferenceResult` if inference not complete

**Implementation Strategy**:
```cpp
// Add helper to validate handles
static inline int IsValidModelHandle(RAWRXD_MODEL_HANDLE h) {
    return (h > 0 && h < MAX_MODELS);
}

static inline int IsValidInferenceHandle(RAWRXD_INFERENCE_HANDLE h) {
    return (h > 0 && h <= g_rawrxd_inference_generation);
}

// Audit every export:
// Replace: if (!model_info) return ERROR;
// To: if (!model_info || buffer_size < sizeof(...)) return ERROR;
```

**Effort**: 3 days  
**Coverage**: All 77 exports (automated grep/audit + manual review)  
**Deliverable**: Hardening audit report + patch summary

---

### Testing & Validation (Throughout Phase 5)

#### Continuous Integration Tests
```
✓ Unit tests for new exports (batching, streaming, discovery)
✓ Integration tests with IDE mock caller (threading, async)
✓ Stress test: 100 concurrent inferences + model switches
✓ Memory leak tests: valgrind or Dr. Memory
✓ Performance regression tests: latency < Phase 4 + 5%
```

#### Sign-Off Criteria
- [ ] All 77 exports implement real logic (no stubs)
- [ ] Null pointer audit: 0 crashes under fuzzing
- [ ] Stress test: 10-hour run passes without leaks
- [ ] Performance: < 5% regression vs. Phase 4
- [ ] Code review: approved by 2 peers
- [ ] Documentation: all new exports documented in IDE Handoff v2

---

## Resource Allocation

| Sprint | Task | Owner | Days | Dependencies |
|:---|:---|:---|:---|:---|
| **Sprint 1** | Batching | Eng-A | 2 | Thread pool API |
| | Quantization | Eng-B | 1.5 | Format constants |
| **Sprint 2** | Streaming | Eng-A | 2 | Stream handle type |
| | Discovery | Eng-B | 1.5 | FindFile API |
| **Sprint 3** | Hotpatching | Eng-C | 1 | Framework stub |
| | Hardening | Eng-A/B/C | 3 | All exports |
| **All** | Testing | QA-1 | 3 | All implementations |
| **All** | Documentation | Tech Writer | 2 | All final code |

**Total**: ~17 person-days over 3 weeks (team of 3-4 engineers)

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|:---|:---|:---|
| Thread pool corruption | Critical | Extensive testing; consider Win32 thread pools (built-in) |
| Batching timeout + thread starvation | High | Implement backpressure; limit queue depth |
| Streaming token chunking too naive | Medium | Phase 6 upgrades to real tokenizer; document current behavior |
| Model discovery slow for many files | Medium | Cache results; allow caller to set search path |
| Hotpatching deferred to Phase 6 | Low | Document as framework stub; flag for Phase 6 escalation |
| Hardening finds real bugs | Medium | Plan 2-3 day fix window after audit |

---

## Success Metrics

| Metric | Target | Method |
|:---|:---|:---|
| All 77 exports pass nil-input test | 100% | Fuzz testing with null parameters |
| Max inference latency unchanged | < 5% slowdown | Before/after benchmarking |
| Model discovery < 100ms | 100ms | Filesystem scan performance test |
| Batch inference parallelism | 8x throughput | 16 concurrent inferences vs. 2 serial |
| Zero crashes in 10-hour soak | 100% pass | Automated soak test harness |

---

## Deliverables (Phase 5 End)

1. **Updated DLL**: `RawrXD_Titan.dll` (v1.2.6-feature-complete)
2. **Phase 5 Completion Report** — All tasks completed, metrics achieved
3. **IDE Handoff v2** — Updated integration guide with new exports
4. **Hardening Audit Report** — Null checks, bounds validation audit results
5. **Testing Report** — Stress test results, performance benchmarks
6. **v1.2.6-RC1 Baseline** — Release candidate for IDE pre-production testing

---

## Go/No-Go Criteria

**GO to Production**: Phase 5 sign-off when:
- ✅ All 77 exports implement real logic
- ✅ Stress test (10 hours) passes
- ✅ Code review approved
- ✅ Performance regression < 5%

**NO-GO**: Escalate if:
- ❌ Critical bugs found after hardening audit
- ❌ Stress test fails or leaks detected
- ❌ Performance regression > 10%

---

## Next Phase Preview (Phase 6)

- Real streaming tokenizer integration (replace space-chunking)
- Hotpatching engine implementation (real patching, not framework)
- Advanced quantization (INT8 CUDA, TPU support)
- Distributed inference (multi-GPU batching)
- IDE dashboard (real-time telemetry visualization)

---

**Ready to Begin Phase 5?** Proceed with Sprint 1 or request priority adjustment.
