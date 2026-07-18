# Gate D: Performance Validation Methodology

**Version:** 1.0  
**Date:** 2026-07-17  
**Status:** Draft - Pending Review  
**Applies To:** VAL-005, VAL-009, VAL-011

---

## 1. Purpose

This document defines the reproducible benchmark protocol for RawrXD performance validation. Following this methodology ensures performance claims are:

- **Measurable**: Quantified with appropriate metrics
- **Reproducible**: Same hardware/software produces same results
- **Comparable**: Baselines enable regression detection
- **Defensible**: Methodology is documented and reviewable

---

## 2. Scope

### In Scope
- Kernel-level benchmarks (SiLU, RMSNorm, Softmax, Attention)
- GPU inference throughput (KV cache, token generation)
- End-to-end inference latency (TTFT, TPS, total time)

### Out of Scope
- Model accuracy (covered by Gate C)
- Build performance (covered by Gate A)
- Memory usage (separate profiling gate)

---

## 3. Hardware Requirements

### Minimum Disclosure

| Component | Required Info | Example |
|-----------|---------------|---------|
| CPU | Model, cores, base/boost clock | AMD Ryzen 7950X, 16C/32T, 4.5/5.7 GHz |
| GPU | Model, VRAM, architecture | AMD RX 7800 XT, 16GB, RDNA3 |
| GPU Driver | Version, date | Adrenalin 24.5.1, 2024-05-15 |
| RAM | Capacity, speed, channels | 32GB DDR5-6000, dual channel |
| Storage | Type, speed | NVMe Gen4, 7000 MB/s read |
| OS | Version, build | Windows 11 Pro 23H2, 22631.3737 |

### Environment Control
- Close background applications
- Disable power saving modes
- Set GPU to performance mode
- Record ambient temperature (affects throttling)

---

## 4. Software Requirements

### Build Configuration

| Parameter | Required Value | Rationale |
|-----------|----------------|-----------|
| Build Type | Release | Debug builds have different performance |
| Optimizations | /O2 /Ob2 | Standard release optimization |
| CRT | Static (/MT) | Consistent runtime behavior |
| Architecture | x64 | Target platform |
| C++ Standard | C++20 | Current project standard |
| SIMD | AVX2 minimum, AVX-512 if available | Feature detection at runtime |

### Version Pinning

```json
{
  "compiler": "MSVC 14.51.36231",
  "cmake": "3.20+",
  "ninja": "1.11+",
  "windows_sdk": "10.0.22621.0",
  "vulkan_sdk": "1.4.328.1"
}
```

---

## 5. Benchmark Protocol

### 5.1 Warmup Phase

**Purpose:** Stabilize CPU/GPU frequencies, cache states

```
Warmup Iterations: 10
Warmup Duration: Minimum 5 seconds
Discard Results: Yes
```

### 5.2 Measurement Phase

**Purpose:** Collect statistically significant samples

```
Measurement Iterations: 100 (minimum)
Outlier Handling: Discard top/bottom 5% (winsorization)
Reporting: Mean, median, stddev, min, max
```

### 5.3 Cooldown Phase

**Purpose:** Prevent thermal throttling between runs

```
Inter-run Delay: 1 second
Thermal Throttling Check: Monitor GPU/CPU temps
Abort Threshold: >85°C sustained
```

---

## 6. Metrics Definition

### 6.1 Kernel Benchmarks (VAL-009)

| Metric | Unit | Calculation | Acceptance |
|--------|------|-------------|------------|
| Cycles | count | RDTSC delta | Raw measurement |
| Time | ms | cycles / frequency | Raw measurement |
| Cycles/Byte | ratio | cycles / bytes_processed | Lower is better |
| Bandwidth | GB/s | bytes_processed / time | Higher is better |
| Speedup | ratio | scalar_cycles / optimized_cycles | >1.0x expected |
| Max Error | float | max(abs(reference - actual)) | <1e-5 for FP32 |

### 6.2 GPU Inference (VAL-005)

| Metric | Unit | Calculation | Acceptance |
|--------|------|-------------|------------|
| TTFT | ms | Time to first token | <100ms for 4K context |
| TPS | tokens/sec | tokens_generated / generation_time | >50 TPS target |
| Throughput | GB/s | KV_cache_size / transfer_time | Hardware dependent |
| GPU Util | % | GPU active time / total time | >80% expected |

### 6.3 End-to-End (Future)

| Metric | Unit | Calculation | Acceptance |
|--------|------|-------------|------------|
| Total Time | s | end_time - start_time | Use case dependent |
| Tokens/Sec | t/s | total_tokens / total_time | >30 TPS for chat |
| Memory | MB | peak_working_set | <16GB for 7B model |

---

## 7. Statistical Methods

### 7.1 Sample Size

Minimum 100 iterations for kernel benchmarks.  
Minimum 10 runs for end-to-end benchmarks.

### 7.2 Confidence Intervals

Report 95% confidence interval for mean:

```
CI = mean ± (t_critical * stddev / sqrt(n))
```

Where t_critical for 95% CI with n>30 is approximately 1.96.

### 7.3 Variance Reporting

| Statistic | Purpose |
|-----------|---------|
| Mean | Central tendency |
| Median | Robust to outliers |
| StdDev | Spread of measurements |
| CoV (stddev/mean) | Relative variability |
| Min/Max | Range of observed values |

---

## 8. Baseline Management

### 8.1 Baseline Creation

1. Run full benchmark suite on reference hardware
2. Record all metrics with confidence intervals
3. Store in `evidence/gate_d/baselines/`
4. Tag with date and hardware fingerprint

### 8.2 Regression Detection

```
Regression Threshold: >5% degradation from baseline
Significance Test: Two-tailed t-test, p<0.05
Action: Block merge if regression detected
```

### 8.3 Baseline Update

Baselines updated only for:
- Hardware generation changes
- Intentional algorithm changes with documented tradeoffs
- Compiler upgrades with proven performance improvements

---

## 9. Artifact Generation

### 9.1 Required Artifacts

```
evidence/gate_d/
├── benchmark_manifest.json      # Run configuration
├── hardware.json                # System information
├── results.json                 # Raw measurements
├── summary.txt                  # Human-readable summary
└── methodology.md             # This document
```

### 9.2 Binary Verification

```json
{
  "binary": "RawrXD-Benchmark.exe",
  "sha256": "F0E9FAD17D3EC6BEE457682211FA94F40B2017620EB3C9D561F9430C3F392...",
  "build_timestamp": "2026-07-17T12:57:00Z",
  "git_commit": "<commit_hash>"
}
```

---

## 10. Acceptance Criteria

### 10.1 Gate D Completion

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Benchmark protocol documented | ⬜ | This document |
| Hardware disclosure complete | ⬜ | hardware.json |
| Binary hash recorded | ⬜ | benchmark_manifest.json |
| Baseline established | ⬜ | baselines/ directory |
| Statistical validation | ⬜ | results.json with CI |
| Reproducibility verified | ⬜ | Second run matches |

### 10.2 Current Status

**Gate D: Performance** - ⚠️ PARTIAL

- ✅ Build: VAL-011 Flash Attention builds
- ✅ Runtime: VAL-009 Telemetry executes
- ⬜ Methodology: This document (draft)
- ⬜ Baseline: Not yet established
- ⬜ Reproducibility: Single run only

---

## 11. Known Limitations

1. **Single Hardware Configuration**: Current validation only on RX 7800 XT
2. **Single Run**: No statistical variance captured yet
3. **No Warmup Protocol**: Thermal throttling not controlled
4. **C++20 vs C++23**: Some features unavailable

---

## 12. References

- VAL-005: GPU Benchmark
- VAL-009: Telemetry Validation
- VAL-011: Flash Attention Kernel
- VALIDATION_INDEX.md: Master validation record

---

## 13. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-07-17 | Validation Team | Initial draft |

---

*This methodology is a living document. Update as requirements evolve.*
