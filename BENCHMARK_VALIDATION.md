# RawrXD IDE - Benchmark Validation Framework

## Overview
This document defines the validation criteria and expected telemetry output for the RawrXD IDE's GhostText inference pipeline.

## Architecture

```
Keystroke
   |
   v
GhostText debounce (200ms)
   |
   v
Context extraction (<5ms)
   |
   v
SovereignBridge_Deep2 (<1ms dispatch)
   |
   v
Deep2 runtime dispatch
   |
   v
Q4_K_M kernels (AVX2/AVX512)
   |
   v
Token generation
   |
   v
Ghost text render (<16ms)
```

## Expected Debug Output

### 1. Startup - Runtime Identity Stamp
```
[SovereignBridge] Initialization complete
[SovereignBridge] Status: Ready (Deep2)
[SovereignBridge] [KernelRegistry]
  q4_k_m_dequant : AVX512
  q4_k_m_matmul  : AVX2
  rope           : AVX2
  rmsnorm        : AVX2
  Backend        : Deep2
  Quant          : Q4_K_M
[SovereignBridge] [SovereignRuntime]
  Model: llama-3.2-8b-Q4_K_M.gguf
  Quant: Q4_K_M
  Layers: 33
  Kernel: Sovereign_Q4KM_AVX512
  Device: Ryzen CPU
  Context: 8192
  MaxTokens: 64
  Temperature: 0.70
```

### 2. Healthy Request Lifecycle
```
[GhostText] Debounce timer reset
[Telemetry] Keystroke: version=42
[GhostText] Context snapshot captured
[Telemetry] Context extraction: 2.34 ms
[SovereignBridge] Request 42 queued (context=512 bytes)
[SovereignBridge] Token generation started
[SovereignBridge] Inference complete: version=42, tokens=12, latency=45.2ms, tps=265.5
[Telemetry] Completion: version=42, latency=45.2ms, tps=265.5, confidence=0.87
[GhostText] Suggestion ready (confidence=0.87)
```

### 3. Stale Request (Cancellation)
```
[SovereignBridge] Request 42 cancelled (new request 43)
[SovereignBridge] Request 43 queued (context=520 bytes)
[SovereignBridge] Inference complete: version=43, tokens=8, latency=38.1ms, tps=210.0
[GhostText] Stale completion discarded
```

### 4. Benchmark Summary (Ctrl+B)
```
[SovereignBridge] [BenchmarkSummary]
  Model: llama-3.2-8b-Q4_K_M.gguf
  Quantization: Q4_K_M
  Backend: Deep2
  Kernel: Sovereign_Q4KM_AVX512
  TotalRequests: 47
  TotalTokens: 523
  AvgLatencyMs: 42.15
  AvgTokensPerRequest: 11.1
  Hardware: Ryzen CPU
  ContextLength: 8192
  MaxTokens: 64
  Temperature: 0.70
[SovereignBridge] [EndBenchmarkSummary]
```

## Performance Targets

| Metric | Target | Validation |
|--------|--------|------------|
| Context extraction | <5 ms | `[Telemetry] Context extraction: X.XX ms` |
| Backend dispatch | <1 ms | Included in extraction time |
| First token latency | <100 ms | `Inference complete: latency=Xms` |
| Streaming TPS | >50 tok/s | `tps=X.X` in completion log |
| Render update | <16 ms | Ghost text visible immediately |

## Test Protocol

### Test 1: Kernel Dispatch Verification
**Action**: Launch IDE and check debug output  
**Expected**: `[SovereignBridge] Status: Ready (Deep2)`  
**Failure**: Fallback to stub mode

### Test 2: Context Extraction Timing
**Action**: Type single character  
**Expected**: `[Telemetry] Context extraction: X.XX ms` where X < 5  
**Failure**: >5ms indicates buffer copy inefficiency

### Test 3: Debounce Timer
**Action**: Type rapidly for 3 seconds  
**Expected**: Multiple `[GhostText] Debounce timer reset` messages  
**Failure**: Timer not resetting or firing prematurely

### Test 4: Request Queue
**Action**: Type, pause 200ms, wait for completion  
**Expected**: `Request {v} queued` followed by `Inference complete`  
**Failure**: Request not reaching bridge

### Test 5: Cancellation
**Action**: Type "std::", wait for ghost text, immediately type "vec"  
**Expected**: `Request {v} cancelled` and new request queued  
**Failure**: Stale completion appearing

### Test 6: Stale Check
**Action**: Trigger completion, type during inference  
**Expected**: `Stale completion discarded`  
**Failure**: Old completion rendering

### Test 7: Performance Baseline
**Action**: Run 50 completions, press Ctrl+B  
**Expected**: `AvgLatencyMs: <100`, `AvgTokensPerRequest: >5`  
**Failure**: Latency >100ms or TPS <50

## Reproducible Benchmark

To generate a reproducible benchmark report:

1. **Environment**
   - Model: llama-3.2-8b-Q4_K_M.gguf
   - Hardware: Ryzen CPU (AVX2/AVX512)
   - Context: 8192 tokens
   - Max generation: 64 tokens

2. **Procedure**
   - Launch IDE
   - Type 50 different code prompts
   - Vary typing speed (normal vs rapid)
   - Press Ctrl+B to output summary

3. **Metrics Captured**
   - Total requests
   - Total tokens generated
   - Average latency per request
   - Average tokens per request
   - Cancellation rate
   - Stale completion rate

4. **Evidence Package**
   - Debug log with all `[SovereignBridge]` traces
   - Benchmark summary output
   - Screenshot of ghost text rendering

## Success Criteria

| Checkpoint | Required | Evidence |
|------------|----------|----------|
| Deep2 backend active | ✅ | `[SovereignBridge] Status: Ready (Deep2)` |
| Q4_K_M kernels loaded | ✅ | `[KernelRegistry]` shows Q4_K_M |
| Context extraction <5ms | ✅ | Telemetry log |
| First token <100ms | ✅ | `Inference complete: latency=Xms` |
| TPS >50 | ✅ | `tps=X.X` in completion |
| Cancellation working | ✅ | `Request X cancelled` in log |
| Stale check working | ✅ | `Stale completion discarded` in log |
| Benchmark reproducible | ✅ | Ctrl+B summary output |

## Notes

- All times are measured in milliseconds
- TPS = tokens per second
- Latency includes context extraction + inference
- Stale completions are silently discarded (not errors)
- Benchmark summary provides evidence for performance claims
