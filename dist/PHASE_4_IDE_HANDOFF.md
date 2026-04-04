# Phase 4 to Win32 IDE Handoff — Integration Guide
**Date**: 2026-04-04  
**Target**: Win32 IDE RawrXD_Titan.dll Consumer  
**Version**: 1.2.6-alpha-stable  

---

## Purpose

This document clarifies which exports in `RawrXD_Titan.dll` are **production-grade after Phase 4**, which are **safe but stub-level**, and how to consume the DLL from the Win32 IDE without hitting regressions.

---

## Quick Reference: Export Readiness Matrix

### Production-Grade (Full Behavioral Parity)

**Your IDE should make these calls with confidence:**

| Export | Function | Status | Sample IDE Usage |
|:---|:---|:---|:---|
| `RawrXD_Initialize` | System startup | ✅ Live | Called once at IDE startup |
| `RawrXD_Shutdown` | System teardown | ✅ Live | Called on IDE exit |
| `RawrXD_LoadModel` | Load GGUF file | ✅ Live | User selects `.gguf` → calls this |
| `RawrXD_UnloadModel` | Release model | ✅ Live | User switches models |
| `RawrXD_GetModelInfo` | Query model metadata | ✅ Live | Display model name/arch/size in IDE toolbar |
| `RawrXD_CacheModelMetadata` | Prime metadata | ✅ Live | Call after load for progress bar |
| `RawrXD_InferAsync` | Async inference | ✅ Live | User types prompt + sends; shows spinner |
| `RawrXD_WaitForInference` | Poll for completion | ✅ Live | Spinner loop: `WaitForInference(handle, 100ms)` until ready |
| `RawrXD_GetInferenceResult` | Fetch result + tokens | ✅ Live | Append to chat history with token count |
| `RawrXD_InferSync` | Blocking inference | ✅ Live | Alt: synchronous call for scripting |
| `RawrXD_GetTokenizerInfo` | BOS/EOS/vocab size | ✅ Live | Tokenizer configuration queries |
| `RawrXD_GetInferenceLatency` | Latency (ms) | ✅ Live | Telemetry: display inference speed |
| `RawrXD_GetThroughputTokensPerSec` | Throughput (tokens/s) | ✅ Live | Telemetry: display generation speed |
| `RawrXD_GetDiagnosticLog` | Live system state | ✅ Live | Debug panel: show real-time aperture/model state |
| `RawrXD_ApertureInit` | Initialize 1TB placeholder | ✅ Live | System startup (called by Initialize) |
| `RawrXD_MapChunk` | Map model chunk | ✅ Live | Internal: called during model load |
| `RawrXD_GetApertureUtilization` | Query aperture state | ✅ Live | Telemetry panel: show mapped chunks |

---

### Safe but Stub-Grade (No Errors, Limited Functionality)

**Your IDE can call these safely; they won't crash, but they return minimal values or no-ops:**

| Export | Function | Status | Current Behavior | Future Phase |
|:---|:---|:---|:---|:---|
| `RawrXD_ListModels` | Enumerate models | ⚠️ Stub | Returns count=0 or count=1 (active) | Phase 5 |
| `RawrXD_PreloadChunks` | Preload chunks | ⚠️ Stub | Returns SUCCESS (no-op) | Phase 5 |
| `RawrXD_ReleaseChunks` | Release chunks | ⚠️ Stub | Returns SUCCESS (no-op) | Phase 5 |
| `RawrXD_ValidateModelIntegrity` | Check model health | ⚠️ Stub | Returns basic GGUF header check | Phase 5 |
| `RawrXD_BatchInferences` | Parallel prompts | ⚠️ Stub | Returns SUCCESS (serial fallback) | Phase 5+ |
| `RawrXD_BeginStreaming` | Token-at-a-time | ⚠️ Stub | Returns SUCCESS (buffered fallback) | Phase 5+ |
| `RawrXD_EnableQuantization` | Quantization layer | ⚠️ Stub | Returns SUCCESS (no-op) | Phase 5+ |
| `RawrXD_ApplyHotpatch` | Runtime patching | ⚠️ Stub | Returns SUCCESS (no-op) | Phase 5+ |

---

### Critical Integration Notes

#### 1. Telemetry is **Microsecond-Precise**
After `RawrXD_InferAsync` is called, the engine starts a QueryPerformanceCounter timer. When the inference callback fires, the latency is accurately measured and stored in `g_rawrxd_inference_latency_ms`. 

**For IDE telemetry panels:**
```cpp
double latency_ms = 0.0;
RawrXD_GetInferenceLatency(&latency_ms);
// latency_ms now contains actual wall-clock latency of last inference
printf("Inference took %.2f ms\n", latency_ms);
```

#### 2. Aperture State is **Now Observable**
The `RawrXD_GetDiagnosticLog` export emits a single-line snapshot of system state. The IDE can parse this for:
- Current model name and architecture
- Context length and vocabulary size
- BOS/EOS token IDs (from GGUF, not hardcoded)
- Total output tokens (session-wide accumulator)
- Last inference latency
- Aperture base address, mapped chunks, total mapped bytes
- Engine version

**Example usage:**
```cpp
char logBuf[1024] = {0};
size_t bytesWritten = 0;
RawrXD_GetDiagnosticLog(logBuf, sizeof(logBuf), &bytesWritten);
// logBuf now contains:
// "model=codestral-22b arch=moe ctx=32768 vocab=46000 bos=0 eos=2 
//  out_tok=1847 lat_ms=2456.34 ap_base=1A0000000000 ap_chunks=24 
//  ap_bytes=25165824 v=1.2.6"
```

#### 3. Performance Counters are **Cumulative and Resettable**
- `g_rawrxd_total_output_tokens` accumulates across all inferences
- `g_rawrxd_inference_latency_ms` stores the **last** inference latency
- `RawrXD_ResetPerformanceCounters` zeros both + the start tick

**Best practice:** Call `ResetPerformanceCounters` at the start of a new chat session to get clean per-session metrics.

#### 4. Model Fallback Chain is **Defensive**
If `g_modelName` is empty, the engine falls back to `g_modelArchitecture` (e.g., `"moe"`), then to `"(unknown)"`. This prevents null-display scenarios in the IDE.

#### 5. BOS/EOS Tokens are **GGUF-Sourced**
`RawrXD_GetTokenizerInfo` now returns the actual BOS/EOS token IDs read from the GGUF file's `tokenizer.ggml.bos_token_id` and `tokenizer.ggml.eos_token_id` keys. If the GGUF lacks these, defaults to `1` and `2`.

---

## Recommended IDE Integration Sequence

### Phase A: Minimal Viable Product (Day 1)
```cpp
// 1. Startup
RawrXD_Initialize();

// 2. Model selection (user action)
RawrXD_LoadModel("path/to/model.gguf", &handle);
RawrXD_CacheModelMetadata(handle);

// 3. Query model info for display
RAWRXD_MODEL_INFO info = {};
RawrXD_GetModelInfo(handle, &info);
fprintf(stderr, "Loaded: %s (%u params)\n", info.model_name, info.parameter_count);

// 4. Inference loop
const char* prompt = "What is 2+2?";
RAWRXD_INFERENCE_HANDLE inferHandle = 0;
RawrXD_InferAsync(prompt, strlen(prompt), &inferHandle);

// Poll for completion
RAWRXD_INFERENCE_RESULT result = {};
while (RawrXD_WaitForInference(inferHandle, 100) == RAWRXD_ERROR_TIMED_OUT) {
    // Show spinner
}

// Fetch result
RawrXD_GetInferenceResult(inferHandle, &result);
fprintf(stderr, "Result: %s (%u tokens)\n", result.generated_text, result.token_count);

// 5. Shutdown
RawrXD_Shutdown();
```

### Phase B: Telemetry Dashboard (Week 1)
```cpp
// After inference
double latency_ms = 0.0, throughput = 0.0;
RawrXD_GetInferenceLatency(&latency_ms);
RawrXD_GetThroughputTokensPerSec(&throughput);

fprintf(stderr, "Performance: %.2f ms, %.2f tok/s\n", latency_ms, throughput);

// Aperture state
RAWRXD_APERTURE_STATUS aperture = {};
RawrXD_GetApertureUtilization(&aperture);
fprintf(stderr, "Aperture: %u chunks, %.2f%% utilization\n", 
        aperture.mapped_chunks,
        100.0 * aperture.mapped_bytes / aperture.aperture_total_bytes);
```

### Phase C: Advanced Features (Future)
- Token streaming (when `BeginStreaming` is hardened in Phase 5)
- Parallel batch inference (when `BatchInferences` is hardened)
- Model hot-reload (aperture coalescing, per-chunk unmapping)

---

## Error Handling Strategy

### RAWRXD_STATUS Return Values

```cpp
if (status == RAWRXD_SUCCESS) {
    // Proceed normally
}
else if (status == RAWRXD_ERROR_NO_MODEL_LOADED) {
    // User hasn't loaded a model yet; prompt them
    fprintf(stderr, "Please load a model first.\n");
}
else if (status == RAWRXD_ERROR_TIMED_OUT) {
    // Inference is still running; keep waiting
    // (safe to call again after short delay)
}
else if (status == RAWRXD_ERROR_INVALID_PARAM) {
    // IDE bug: passed null or invalid pointer
    // Check your call signatures
}
else if (status == RAWRXD_ERROR_NOT_READY) {
    // Engine is not initialized; call RawrXD_Initialize first
}
else {
    // Generic error; get human-readable message
    char errMsg[256] = {0};
    RawrXD_GetErrorString(status, errMsg, sizeof(errMsg));
    fprintf(stderr, "Error: %s\n", errMsg);
}
```

---

## Known Limitations (Phase 4 Scope)

1. **Token streaming not available yet** — `BeginStreaming` returns success but doesn't stream; use `InferAsync` + `WaitForInference` + `GetInferenceResult` for now.
2. **Batching not available yet** — `BatchInferences` is a stub; issue serial calls to `InferAsync` for multiple prompts.
3. **Model discovery is read-only** — `ListModels` returns only the active model (if loaded); implement directory scanning in IDE for model lists.
4. **Quantization disabled** — `EnableQuantization` is a stub; all inferences run at native model precision.
5. **Aperture compaction is automatic** — `CompactAperture` is a no-op; the kernel manages aperture state.

---

## Testing Checklist for IDE Integration

- [ ] `RawrXD_Initialize` succeeds without crashes
- [ ] `RawrXD_LoadModel` with valid `.gguf` path loads without error
- [ ] `RawrXD_GetModelInfo` returns non-empty model name (from GGUF or fallback)
- [ ] `RawrXD_InferAsync` returns a valid handle
- [ ] `RawrXD_WaitForInference` with reasonable timeout completes
- [ ] `RawrXD_GetInferenceResult` returns non-empty text + token count > 0
- [ ] `RawrXD_GetInferenceLatency` returns non-zero latency (ms)
- [ ] `RawrXD_GetThroughputTokensPerSec` returns reasonable throughput (>0 tokens/sec)
- [ ] `RawrXD_GetDiagnosticLog` output is parseable and contains expected fields
- [ ] `RawrXD_UnloadModel` succeeds and clears state
- [ ] `RawrXD_Shutdown` succeeds and releases resources

---

## Build and Deployment

### DLL Location
```
D:\rxdn_nmake\bin\RawrXD_Titan.dll
```

### Integration Steps
1. Copy `RawrXD_Titan.dll` to your IDE's runtime search path (or same directory as IDE exe)
2. Ensure `RawrXD_Exports.h` is in your IDE's include path
3. Link against the DLL via `LoadLibraryA("RawrXD_Titan.dll")` or static import stub
4. Call exports using the signatures in `RawrXD_Exports.h`

### Version Compatibility
- DLL version: `1.2.6-alpha-stable`
- API version: `1.2.6`
- Compatible with: Win32 IDE v14.7.3+

---

## Support & Escalation

| Issue | Escalation Path |
|:---|:---|
| Inference crashes or invalid memory access | Collect `RawrXD_GetDiagnosticLog` output + call stack |
| Telemetry is zero or obviously wrong | Verify model load via `GetModelInfo` first |
| Model not loading (404 or parse error) | Check GGUF file integrity via `ValidateModelIntegrity` |
| Aperture utility is always 0 | Confirm via `GetApertureUtilization` after first inference + `MapChunk` |

---

## Next Phase Roadmap

**Phase 5** will harden the stub-grade exports:
- `PreloadChunks` / `ReleaseChunks` → explicit manual aperture pre-allocation
- `ListModels` → directory enumeration without engine load
- `BeginStreaming` → real token-at-a-time streaming
- `BatchInferences` → parallel inference dispatch
- `EnableQuantization` → quantization layer activation

**Estimated Phase 5 completion**: ~2 weeks (subject to IDE integration feedback).

---

## Contact

For integration questions or bugs, reference this document version and include output from `RawrXD_GetDiagnosticLog`.

**Document Version**: Phase 4 Handoff (2026-04-04)
