# RawrXD N-EVM Validation Pipeline

## Overview

This document describes the empirical validation process for the RawrXD Neural Execution Virtual Machine (N-EVM). The runtime is **feature-complete** but requires validation before being considered production-ready.

## Validation Stages

The validation pipeline runs in 8 stages, each building on the previous:

### Stage 0: Logit Validation (Gate)
**File:** `nevm_logit_validation.exe`

**Purpose:** Numerical correctness gate - if this fails, skip all throughput benchmarks.

**Process:**
```
Model loads
    ↓
Kernel validation
    ↓
Transformer validation
    ↓
Logit validation ← YOU ARE HERE
    ↓
Determinism validation
    ↓
Performance profiling
    ↓
A/B testing
```

**Usage:**
```batch
:: Generate reference from llama.cpp (manual step)
llama-cli -m model.gguf -p "Hello world" -n 10 --logits-file ref_logits.bin

:: Generate NEVM logits and compare
nevm_logit_validation.exe model.gguf -r ref_logits.bin -n 10
```

**Metrics:**
- Max absolute error
- Mean absolute error
- Cosine similarity
- KL divergence
- **Top-1 agreement**: % of tokens where top prediction matches
- **Top-5 agreement**: % of tokens where correct prediction is in top 5

**Success Criteria:**
- Max abs error < 0.01
- Mean abs error < 0.001
- Cosine similarity > 0.999
- Top-1 agreement > 99%

---

### Stage 1: Kernel Validation
**File:** `nevm_kernel_validation.exe`

Validates numerical correctness and throughput of all kernel primitives.

**Tests:**
- Q4 Dequantization numerical correctness
- Q8 Dequantization numerical correctness
- Matrix Multiplication (Q4 × Q8 → FP32)
- SoftMax numerical correctness
- RoPE (Rotary Position Embedding)
- SwiGLU activation
- Layer Normalization
- Throughput benchmark (GOP/s)

**Success Criteria:**
- All numerical tests pass within tolerance
- Throughput meets minimum thresholds

---

### Stage 2: Transformer Block Validation
**File:** `nevm_transformer_validation.exe`

Validates one complete transformer layer against reference FP32 implementation.

**Tests:**
- Single layer forward pass at seq_len = 1, 8, 32, 128
- Numerical comparison with reference implementation
- Output similarity within tolerance

**Success Criteria:**
- Max error < 0.01 (1% tolerance)
- Output preserves expected statistical properties

---

### Stage 3: Determinism Validation (NEW)
**File:** `nevm_determinism_validation.exe`

Verifies reproducible outputs across multiple runs.

**Usage:**
```batch
nevm_determinism_validation.exe model.gguf -r 5 -n 32
```

**Metrics:**
- Identical runs: X/5
- Agreement rate: X%
- Token-level agreement per position
- First divergence position

**Success Criteria:**
- 100% agreement across all runs (with fixed seed)
- No divergence in first N tokens

---

### Stage 4: Short Inference Test
**File:** `nevm_benchmark_runner.exe -n 32`

Validates 32-128 token generation for basic functionality.

**Metrics Collected:**
- Prefill tokens/sec
- Decode tokens/sec
- Time to first token
- Basic memory usage

**Success Criteria:**
- Completes without crash
- Produces valid output
- Memory usage within expected bounds

---

### Stage 5: Long Decode Benchmark
**File:** `nevm_benchmark_runner.exe -n 1024`

Full benchmark with comprehensive metrics collection.

**Metrics Collected:**

#### Throughput
| Metric | Description |
|--------|-------------|
| prefill_tokens_per_sec | Prompt processing speed |
| decode_tokens_per_sec | Autoregressive generation speed |
| overall_tokens_per_sec | Combined throughput |

#### Latency
| Metric | Description |
|--------|-------------|
| time_to_first_token_ms | Time until first output token |
| mean_inter_token_latency_ms | Average time between tokens |
| p50_inter_token_latency_ms | Median inter-token latency |
| p99_inter_token_latency_ms | 99th percentile latency |
| max_inter_token_latency_ms | Worst-case latency |
| stddev_inter_token_latency_ms | Latency variance |

#### Memory
| Metric | Description |
|--------|-------------|
| peak_vram_bytes | Maximum GPU memory used |
| peak_ram_bytes | Maximum system RAM used |
| avg_working_set_bytes | Average memory footprint |
| memory_efficiency_tokens_per_gb | Throughput per GB of memory |

#### MMU Performance
| Metric | Description |
|--------|-------------|
| mmu_lookup_time_ns | Average translation time |
| mmu_hit_rate | TLB hit percentage |
| mmu_hits | Number of TLB hits |
| mmu_misses | Number of TLB misses |

**Target:** <2-5% of decode time

#### Kernel Performance
| Metric | Description |
|--------|-------------|
| kernel_dispatch_count | Total kernel launches |
| avg_kernel_dispatch_time_ns | Average dispatch overhead |
| kernel_call_counts | Breakdown by kernel type |

#### Precision
| Metric | Description |
|--------|-------------|
| precision_transitions | Number of precision switches |
| precision_distribution | Breakdown by precision mode |
| avg_effective_bits | Average bits per parameter |

**Target:** Lower VRAM/RAM at similar output quality

#### Residency
| Metric | Description |
|--------|-------------|
| residency_transitions | Number of state changes |
| residency_distribution | Time in each state |

#### Prefetch
| Metric | Description |
|--------|-------------|
| prefetch_hit_rate | Prefetch success percentage |
| prefetch_hits | Successful prefetches |
| prefetch_misses | Failed prefetches |

**Target:** High hit rate, low stall time

#### Pipeline
| Metric | Description |
|--------|-------------|
| pipeline_stall_percentage | Time spent stalled |
| stall_cycles | Number of stall cycles |
| total_cycles | Total execution cycles |

---

## Stage 6: Stress Testing (NEW)
**File:** `nevm_stress_test.exe`

Extended runtime validation with continuous invariant checking.

**Invariants Monitored:**
- No NaN in outputs
- No Inf in outputs
- No memory leaks (RSS stability)
- No invalid page ownership
- No stale execution plans
- Stable throughput (within variance threshold)
- Stable RSS (within growth threshold)
- Valid KV cache

**Usage:**
```batch
nevm_stress_test.exe model.gguf -i 100 -t 32 --stop-on-error
```

**Output:**
```
Progress: [####################] 100/100 (38.5 tok/s)

============================================================================
Stress Test Results
============================================================================

Iterations completed: 100
Total tokens generated: 3200
Invariant violations: 0

✓ All invariants maintained throughout stress test
```

---

## Subsystem Profiling (NEW)

**File:** `nevm_subsystem_profiler.exe`

Breaks down decode time by component to identify bottlenecks.

**Component Breakdown:**
| Component | Target |
|-------------|--------|
| MMU Lookup | <2-5% of decode time |
| Residency Manager | <1% of decode time |
| Precision Controller | <1% of decode time |
| Kernel Dispatch | <0.5% of decode time |
| Kernel Execution | ~90% of decode time |
| Sampling | <5% of decode time |

**Usage:**
```batch
nevm_subsystem_profiler.exe model.gguf -n 128
```

---

## Performance Budget Analysis (NEW)
**File:** `nevm_performance_budget.exe`

Breaks down time per token by component for optimization targeting.

**Usage:**
```batch
nevm_performance_budget.exe model.gguf -n 128
```

**Output:**
```
============================================================================
Performance Budget (per token)
============================================================================

Component       Time (ns)   %         Calls       Time/Call   Bottleneck
--------------------------------------------------------------------------------
MatMul          82345.2     82.0%     128         82345.20    ***
Attention       9023.4      9.0%      128         9023.40
Sampling        3008.5      3.0%      128         3008.50
Dispatch        2005.6      2.0%      128         2005.60
Residency       1002.8      1.0%      128         1002.80
Scheduler       301.0       0.3%      128         301.00
Other           301.0       0.7%      128         301.00
--------------------------------------------------------------------------------
TOTAL           100387.5    100.0%

Optimization Recommendations:
-----------------------------
Primary bottleneck: MatMul (82.0%)
  → Consider: Larger tile sizes, better kernel selection
```

---

## A/B Testing (NEW)

**File:** `nevm_ab_testing.exe`

Compares configurations to isolate feature contributions.

**Configurations Tested:**
1. Baseline
2. + Kernel Registry
3. + MMU
4. + Adaptive Precision
5. + Residency
6. Full NEVM

**Usage:**
```batch
nevm_ab_testing.exe model.gguf -n 128 -o ab_results.json
```

**Output:**
```
Configuration              Tok/s       Memory(MB)  TTFT(ms)    P99(ms)     Status
------------------------------------------------------------------------------------------
Baseline                   25.50       14336.0     850.00      45.20       PASS
+ Kernel Registry          28.20       14336.0     820.00      41.50       PASS
+ MMU                      27.80       12288.0     835.00      42.10       PASS
+ Adaptive Precision       32.40       10240.0     780.00      35.80       PASS
+ Residency                35.10       10240.0     750.00      32.40       PASS
Full NEVM                  38.50       9216.0      720.00      28.90       PASS

Improvement (Full NEVM vs Baseline):
  Throughput: 1.51x
  Memory:     35.8% reduction
```

---

## Performance Toggle (NEW)

**File:** `nevm_toggle.exe`

Interactive tool to switch between performance profiles.

**Profiles:**
- **Maximum Throughput**: Q4 adaptive, aggressive prefetch, 95% memory
- **Balanced**: Q4 adaptive, moderate prefetch, 75% memory
- **Minimum Memory**: Binary/Q2, conservative prefetch, 50% memory

**Usage:**
```batch
:: Set specific mode
nevm_toggle.exe throughput
nevm_toggle.exe balanced
nevm_toggle.exe memory

:: Interactive demo
nevm_toggle.exe demo
```

---

## Running Validation

### Quick Validation
```batch
run_validation_suite.bat path\to\model.gguf
```

This runs all 4 stages in sequence. If any stage fails, the pipeline stops.

### Individual Stages
```batch
:: Stage 0: Logit validation (NEW)
nevm_logit_validation.exe model.gguf -g -o nevm_logits.bin

:: Stage 1: Kernels
nevm_kernel_validation.exe

:: Stage 2: Transformer
nevm_transformer_validation.exe

:: Stage 3: Short inference
nevm_benchmark_runner.exe model.gguf -n 32 -w 5

:: Stage 4: Long benchmark
nevm_benchmark_runner.exe model.gguf -n 1024 -w 10 -o results.json
```

### With Tracing
```batch
nevm_benchmark_runner.exe model.gguf -n 128 -t -o results.json
```

Enables trace recording for detailed analysis.

### Cold Cache Run
```batch
nevm_benchmark_runner.exe model.gguf -n 128 -c
```

Clears caches before running to measure cold-start performance.

---

## Comparison with llama.cpp

To make meaningful comparisons:

1. **Use identical model** (same GGUF file)
2. **Use identical prompt** (same text, same tokenization)
3. **Use identical settings** (temperature, top_k, etc.)
4. **Use identical hardware** (same CPU affinity, thread count)
5. **Run both warm and cold** (cache effects matter)

### llama.cpp baseline command:
```bash
llama-cli -m model.gguf -p "Hello world" -n 128 --temp 0.8
```

### N-EVM equivalent:
```batch
nevm_benchmark_runner.exe model.gguf -p "Hello world" -n 128 -t 0.8
```

---

## Success Metrics Summary

| Question | Success Metric |
|----------|----------------|
| Does the MMU add measurable overhead? | <2-5% of decode time |
| Does adaptive precision reduce resident memory? | Lower VRAM/RAM at similar quality |
| Does the scheduler hide migration latency? | High prefetch hit rate, low stall % |
| Does the kernel registry select appropriate kernels? | Correct dispatch, expected ISA |
| Does the runtime improve end-to-end inference? | Higher tok/s or lower memory |

---

## Trace and Replay

The trace system records detailed execution:

```json
{
  "token": 153,
  "layer": 18,
  "block": 4412,
  "precision": "Q4",
  "residency": "VRAM",
  "kernel": "AVX512",
  "dispatch_ns": 37
}
```

This enables:
- Performance regression reproduction
- Precision controller tuning
- Bottleneck identification
- Policy comparison (change only one variable)

---

## Production Readiness Checklist

### Correctness Gates (Must Pass)
- [ ] Stage 0: Logit validation passes (Top-1 > 99%)
- [ ] Stage 1: Kernel validation passes
- [ ] Stage 2: Transformer validation passes
- [ ] Stage 3: Determinism validation (0 divergence across 10 runs)
- [ ] No NaN/Inf in 1000+ tokens
- [ ] Top-5 agreement > 99.9%

### Stability Gates (Must Pass)
- [ ] Stage 4: Short inference completes
- [ ] Stage 5: Long benchmark completes
- [ ] Stage 6: Stress test passes (100+ iterations)
- [ ] RSS growth < 10% over stress test
- [ ] Throughput variance < 5% (p95/p99)
- [ ] No page fault spikes
- [ ] KV cache remains valid

### Performance Gates (Must Pass)
- [ ] MMU overhead < 5%
- [ ] Prefetch hit rate > 80%
- [ ] Numerical output matches reference within tolerance
- [ ] Memory usage lower than baseline
- [ ] Throughput higher than baseline
- [ ] Cold-cache performance acceptable
- [ ] A/B tests show feature contributions
- [ ] Subsystem profiling identifies bottlenecks
- [ ] Prefill and decode profiles measured separately
- [ ] MatMul % drops appropriately in decode (40-60%)

### Edge Case Safeguards (See TECHNICAL_EDGE_CASES.md)
- [ ] FMA disabled for determinism-critical paths
- [ ] Tree-based reduction for parallel sums
- [ ] Execution plan freshness checks
- [ ] Memory transfer vs compute profiling

**Note:** The runtime is **feature-complete** but not **production-ready** until all validation stages pass.

---

## Technical Edge Cases

See `TECHNICAL_EDGE_CASES.md` for detailed discussion of:
- Parallel reduction drift
- FMA/AVX precision divergence
- KV cache page fragmentation
- Execution plan freshness
- OS-level virtual memory overhead
- Prefill vs decode profile differences

---

## Results Location

All results are saved to `D:\RawrXD\benchmark_results\` with timestamp:

- `kernel_validation_YYYYMMDD_HHMMSS.log`
- `transformer_validation_YYYYMMDD_HHMMSS.log`
- `short_inference_YYYYMMDD_HHMMSS.json`
- `long_decode_YYYYMMDD_HHMMSS.json`
- `ab_test_YYYYMMDD_HHMMSS.json`
- `subsystem_profile_YYYYMMDD_HHMMSS.json`

---

## Next Steps After Validation

1. **If all stages pass:** Runtime is production-ready
2. **If stages fail:** Debug specific component
3. **Compare with llama.cpp:** Document performance delta
4. **Tune precision controller:** Use trace data to optimize
5. **Profile hotspots:** Identify remaining bottlenecks
6. **A/B test features:** Isolate contribution of each subsystem
