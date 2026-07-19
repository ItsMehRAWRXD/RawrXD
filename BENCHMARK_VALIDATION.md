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

### 1. Startup - Runtime Identity Stamp (LIVE from actual state)
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
  Model: llama-3.2-8b-Q4_K_M.gguf          <- LIVE from loaded GGUF
  ModelFile: D:\models\llama-3.2-8b-Q4_K_M.gguf
  Quant: Q4_K_M                             <- Detected from filename
  Layers: 33                                <- Parsed from model
  Context: 8192                             <- Parsed from model
  Kernel: Sovereign_Q4KM_AVX512             <- Selected by ISA
  Backend: Deep2
  MaxTokens: 64
  Temperature: 0.70
[SovereignBridge] [HardwareFingerprint]       <- LIVE from CPUID/registry
  CPU: AMD Ryzen 9 7950X 16-Core Processor
  Cores: 16
  Threads: 32
  AVX2: YES
  AVX512: YES
  FMA: YES
  TotalRAM: 131072 MB
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

### 4. Benchmark Summary (Ctrl+B) - LIVE from runtime state
```
[SovereignBridge] [BenchmarkSummary]
  Model: llama-3.2-8b-Q4_K_M.gguf           <- LIVE from g_runtime.modelName
  Quantization: Q4_K_M                       <- LIVE from g_runtime.quantization
  Backend: Deep2                             <- LIVE from g_runtime.backendName
  Kernel: Sovereign_Q4KM_AVX512              <- LIVE from g_runtime.kernelName
  TotalRequests: 47
  TotalTokens: 523
  AvgLatencyMs: 42.15
  AvgTokensPerRequest: 11.1
  CPU: AMD Ryzen 9 7950X 16-Core Processor   <- LIVE from registry
  Cores: 16                                  <- LIVE from SYSTEM_INFO
  Threads: 32
  AVX2: YES                                  <- LIVE from Deep2_HasAVX2()
  AVX512: YES                                <- LIVE from Deep2_HasAVX512()
  TotalRAM: 131072 MB                        <- LIVE from GlobalMemoryStatusEx
[SovereignBridge] [Memory]                   <- LIVE from GetProcessMemoryInfo
  ModelMB: 5120
  PeakWorkingSetMB: 6120
  CurrentWorkingSetMB: 5847
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

### Cold vs Warm Benchmarks

| Phase | Description | Target |
|-------|-------------|--------|
| **Cold Start** | First inference after model load | <500ms first token |
| **Warm** | Subsequent completions | <100ms first token |

**Cold Start Sequence:**
```
[SovereignBridge] Loading model: D:\models\llama-3.2-8b-Q4_K_M.gguf
[SovereignBridge] Model loaded: llama-3.2-8b-Q4_K_M.gguf
[SovereignBridge] Quantization: Q4_K_M
[SovereignBridge] Layers: 33
[SovereignBridge] [Memory] ModelMB: 5120
[SovereignBridge] First request (cold): latency=450ms
[SovereignBridge] Second request (warm): latency=42ms
```

### Procedure

1. **Environment**
   - Model: llama-3.2-8b-Q4_K_M.gguf (or actual loaded model)
   - Hardware: Detected at runtime from CPUID/registry
   - Context: From GGUF metadata
   - Max generation: 64 tokens

2. **Cold Start Test**
   - Launch IDE
   - Load model via `SovereignBridge_LoadModel()`
   - Type first prompt
   - Measure: Model load time + first token latency

3. **Warm Test**
   - Type 50 different code prompts
   - Vary typing speed (normal vs rapid)
   - Press Ctrl+B to output summary

4. **Metrics Captured (LIVE)**
   - Model name from GGUF filename
   - Quantization from filename pattern
   - Layers/context from model metadata
   - CPU from registry
   - RAM from GlobalMemoryStatusEx
   - Working set from GetProcessMemoryInfo
   - Total requests/tokens
   - Average latency per request
   - Cancellation rate
   - Stale completion rate

5. **Evidence Package**
   - Debug log with `[SovereignRuntime]` identity stamp
   - `[HardwareFingerprint]` from live detection
   - `[Memory]` telemetry from process info
   - `[BenchmarkSummary]` with all live metrics

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

---

# RawrXD Debugger Stress Test Validation Report

**Test Date:** 2026-07-19  
**Test Duration:** 30 seconds  
**Test Executable:** D:\rawrxd\build\tests\stress_target.exe

## Summary

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Max LastAge | 32ms | 100ms | PASS |
| Max MaxAge | 75ms | 500ms | PASS |
| Arena Growth | 2.1% | 50% | PASS |
| Avg Drop Rate | 96.8% | N/A | INFO |

## Detailed Metrics

### Event Throughput
- **Submission Rate:** 8333.33 events/sec
- **Render Rate:** 266.67 events/sec
- **Sample Count:** 100

### Latency Analysis
- **Max LastAge:** 32ms
- **Max MaxAge:** 75ms
- **Target LastAge:** < 100ms

### Memory Stability
- **Final Arena:** 5.24 MB
- **Arena Growth:** 2.1%
- **Target Growth:** < 50%

## Interpretation

### Sequence Gaps
High sequence gaps indicate the UI is consuming current state rather than stale history. This is **healthy behavior** when combined with low state age.

### Event Drops
Dropped events indicate coalescing is active. This is **expected** during high-frequency debugging to prevent UI starvation.

### State Age
- **LastAge < 100ms**: UI is responsive
- **MaxAge < 500ms**: No significant lag spikes

### Arena Growth
- **Growth < 50%**: Memory stable
- **Growth > 50%**: Potential leak or unbounded buffer

## Raw Telemetry Samples

```
[DebugTelemetry] Submitted: 250 | Rendered: 8 | Gaps: 242 | Dropped: 242 | Total: 250 | LastAge: 12ms | MaxAge: 45ms | Arena: 5242880
[DebugTelemetry] Submitted: 500 | Rendered: 16 | Gaps: 484 | Dropped: 484 | Total: 500 | LastAge: 15ms | MaxAge: 48ms | Arena: 5243904
[DebugTelemetry] Submitted: 750 | Rendered: 24 | Gaps: 726 | Dropped: 726 | Total: 750 | LastAge: 18ms | MaxAge: 52ms | Arena: 5244928
[DebugTelemetry] Submitted: 1000 | Rendered: 32 | Gaps: 968 | Dropped: 968 | Total: 1000 | LastAge: 22ms | MaxAge: 58ms | Arena: 5245952
[DebugTelemetry] Submitted: 1250 | Rendered: 40 | Gaps: 1210 | Dropped: 1210 | Total: 1250 | LastAge: 25ms | MaxAge: 62ms | Arena: 5246976
[DebugTelemetry] Submitted: 1500 | Rendered: 48 | Gaps: 1452 | Dropped: 1452 | Total: 1500 | LastAge: 28ms | MaxAge: 68ms | Arena: 5248000
[DebugTelemetry] Submitted: 1750 | Rendered: 56 | Gaps: 1694 | Dropped: 1694 | Total: 1750 | LastAge: 30ms | MaxAge: 72ms | Arena: 5249024
[DebugTelemetry] Submitted: 2000 | Rendered: 64 | Gaps: 1936 | Dropped: 1936 | Total: 2000 | LastAge: 32ms | MaxAge: 75ms | Arena: 5250048
[DebugTelemetry] Submitted: 2250 | Rendered: 72 | Gaps: 2178 | Dropped: 2178 | Total: 2250 | LastAge: 31ms | MaxAge: 75ms | Arena: 5251072
[DebugTelemetry] Submitted: 2500 | Rendered: 80 | Gaps: 2420 | Dropped: 2420 | Total: 2500 | LastAge: 29ms | MaxAge: 75ms | Arena: 5252096
```

## Validation Notes

This is a **synthetic baseline** generated for demonstration. In production:

1. Run `ValidateStress.ps1` with actual IDE attached to stress_target.exe
2. Capture real DebugTelemetry output via DebugView or IDE logging
3. Compare against thresholds to validate performance

## Next Steps

- [ ] Run full validation with live IDE
- [ ] Capture stress_memory.exe telemetry
- [ ] Profile arena usage during memory window refresh
- [ ] Compare shared memory vs process bridge for debugger events

---

*Generated by ValidateStress.ps1 - RawrXD Debugger Telemetry System*
