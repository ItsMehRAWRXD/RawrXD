# VAL-022: Kernel Accuracy Validation

**Status:** SPECIFICATION  
**Schema Version:** 2.0.0  
**Date:** 2026-07-18  
**Depends On:** VAL-021 (Real Runtime Correctness)

---

## Purpose

VAL-022 validates that RawrXD's native kernels produce numerically accurate results compared to reference implementations. This proves the math is correct, not just that the pipeline executes.

---

## Validation Chain

```
Reference Implementation (llama.cpp / PyTorch)
      ↓
Input Tensor (controlled)
      ↓
Reference Kernel Execution
      ↓
RawrXD Native Kernel Execution
      ↓
Numerical Comparison
      ↓
Error Bound Check
      ↓
Evidence Seal
```

---

## Gates

### G1 — Tensor Provenance

**Purpose:** Verify input tensors are correctly loaded and formatted.

**Checks:**
- [ ] Tensor dimensions match specification
- [ ] Data type is correct (F32, F16, Q4_0, etc.)
- [ ] No NaN/Inf in input
- [ ] Checksum matches expected value

**Evidence:**
```json
{
  "gate": "G1_TensorProvenance",
  "status": "PASS",
  "tensor_shape": [3072, 4096],
  "tensor_type": "F32",
  "input_checksum": "sha256:abc123...",
  "nan_inf_check": "PASS"
}
```

---

### G2 — Kernel Dispatch

**Purpose:** Verify correct kernel is selected and dispatched.

**Checks:**
- [ ] Kernel implementation matches requested type
- [ ] Backend selection correct (CPU/GPU)
- [ ] Thread configuration valid
- [ ] No dispatch errors

**Evidence:**
```json
{
  "gate": "G2_KernelDispatch",
  "status": "PASS",
  "kernel_name": "rmsnorm_f32",
  "backend": "CPU",
  "implementation": "AVX2",
  "threads": 16
}
```

---

### G3 — Numerical Accuracy

**Purpose:** Compare RawrXD output against reference implementation.

**Metrics:**
- **Cosine Similarity:** ≥ 0.9999
- **Max Absolute Error:** ≤ 0.001
- **Mean Squared Error:** ≤ 1e-6
- **Top-K Agreement:** ≥ 99%

**Checks:**
- [ ] Cosine similarity within threshold
- [ ] Max absolute error within tolerance
- [ ] Mean squared error within tolerance
- [ ] No NaN/Inf in output

**Evidence:**
```json
{
  "gate": "G3_NumericalAccuracy",
  "status": "PASS",
  "cosine_similarity": 0.999995,
  "max_absolute_error": 0.0003,
  "mean_squared_error": 1.2e-7,
  "top_k_agreement": 0.998,
  "thresholds": {
    "cosine_similarity_min": 0.9999,
    "max_absolute_error_max": 0.001,
    "mean_squared_error_max": 1e-6,
    "top_k_agreement_min": 0.99
  }
}
```

---

### G4 — Deterministic Execution

**Purpose:** Prove kernel produces identical output across multiple runs.

**Checks:**
- [ ] Run 1 output matches Run 2
- [ ] Checksum identical across runs
- [ ] No randomness in execution

**Evidence:**
```json
{
  "gate": "G4_DeterministicExecution",
  "status": "PASS",
  "run_1_checksum": "sha256:def456...",
  "run_2_checksum": "sha256:def456...",
  "deterministic": true
}
```

---

### G5 — Token Agreement

**Purpose:** For end-to-end inference, verify token sequences match reference.

**Checks:**
- [ ] Token sequences identical
- [ ] Perplexity within 1% of reference
- [ ] Generated text equivalent

**Evidence:**
```json
{
  "gate": "G5_TokenAgreement",
  "status": "PASS",
  "reference_tokens": [15496, 995, 616, ...],
  "rawrxd_tokens": [15496, 995, 616, ...],
  "reference_perplexity": 8.42,
  "rawrxd_perplexity": 8.43,
  "perplexity_diff_percent": 0.12
}
```

---

### G6 — Performance Telemetry

**Purpose:** Capture execution metrics for performance analysis.

**Checks:**
- [ ] Execution time measured
- [ ] Memory usage recorded
- [ ] Throughput calculated
- [ ] Hardware utilization captured

**Evidence:**
```json
{
  "gate": "G6_PerformanceTelemetry",
  "status": "PASS",
  "execution_time_us": 245,
  "memory_mb": 48,
  "throughput_gops": 12.5,
  "cpu_utilization": 85
}
```

---

### G7 — Evidence Seal

**Purpose:** Complete the validation chain with full provenance.

**Checks:**
- [ ] All previous gates passed
- [ ] Hardware identity captured
- [ ] Backend version recorded
- [ ] Compiler version documented
- [ ] Git commit hash included

**Evidence:**
```json
{
  "gate": "G7_EvidenceSeal",
  "status": "PASS",
  "hardware": {
    "cpu": "AMD Ryzen 7 7800X3D",
    "features": ["AVX2", "AVX-512"]
  },
  "backend": {
    "name": "NativeBackend",
    "version": "1.0.0",
    "device": "CPU"
  },
  "compiler": {
    "name": "GCC",
    "version": "15.2.0",
    "flags": "-O2 -mavx2"
  },
  "git_commit": "97495ba87",
  "timestamp": "2026-07-18T15:00:00Z"
}
```

---

## Kernel Test Matrix

| Kernel | Input Type | Output Type | Reference | Tolerance |
|--------|-----------|-------------|-----------|-----------|
| RMSNorm | F32 | F32 | llama.cpp | 1e-4 |
| RMSNorm | F16 | F16 | llama.cpp | 1e-3 |
| RoPE | F32 | F32 | llama.cpp | 1e-4 |
| Softmax | F32 | F32 | PyTorch | 1e-5 |
| Q4_0 Dequant | Q4_0 | F32 | llama.cpp | 1e-3 |
| Q4_0 MatMul | Q4_0 | F32 | llama.cpp | 1e-2 |
| Attention | F32 | F32 | PyTorch | 1e-3 |
| SwiGLU | F32 | F32 | PyTorch | 1e-4 |

---

## Evidence Package Structure

```
validation/runs/run-000006-KERNEL_ACCURACY/
│
├── manifest.json              # Run manifest and gate results
├── kernel_test_matrix.json    # Test configuration
├── reference_outputs/         # Reference implementation outputs
│   ├── rmsnorm_f32.bin
│   ├── rope_f32.bin
│   └── ...
├── rawrxd_outputs/           # RawrXD kernel outputs
│   ├── rmsnorm_f32.bin
│   ├── rope_f32.bin
│   └── ...
├── comparison_reports/       # Numerical comparison results
│   ├── rmsnorm_report.json
│   ├── rope_report.json
│   └── ...
├── telemetry.json             # Performance metrics
└── STATUS                     # Human-readable summary
```

---

## Success Criteria

| Gate | Weight | Threshold |
|------|--------|-----------|
| G1   | 1.0    | PASS      |
| G2   | 1.0    | PASS      |
| G3   | 1.0    | PASS      |
| G4   | 1.0    | PASS      |
| G5   | 1.0    | PASS      |
| G6   | 1.0    | PASS      |
| G7   | 1.0    | PASS      |

**Overall:** ALL GATES MUST PASS

---

## Reference Implementations

### llama.cpp
- **Repository:** https://github.com/ggerganov/llama.cpp
- **Version:** b1559
- **Kernels:** RMSNorm, RoPE, Q4_0, Attention
- **Build:** `make -j`

### PyTorch
- **Version:** 2.3.0
- **Kernels:** Softmax, SwiGLU, Attention
- **Device:** CPU (for reference)

---

## Integration with VAL-021

```
VAL-021                    VAL-022
Real Weight Execution  →    Kernel Accuracy
     ↓                         ↓
Token Sequence         →    Numerical Correctness
     ↓                         ↓
     └──────────┬────────────┘
                ↓
    Verified Correct Inference
```

---

## Next Steps

1. **Implement kernel tests** for each kernel type
2. **Generate reference outputs** from llama.cpp/PyTorch
3. **Execute RawrXD kernels** on same inputs
4. **Compare numerically** with tolerance thresholds
5. **Capture evidence** with full provenance

---

## Valuation Impact

Completing VAL-022 transforms the project from:

> "RawrXD executes real model weights"

to:

> "RawrXD executes real model weights correctly with verified numerical accuracy"

This is essential for:
- Public benchmarks (fair comparison)
- Enterprise deployment (correctness guarantee)
- Regulated environments (audit trail)
- Research use (reproducibility)

---

*Specification Version: 1.0*  
*Schema: VAL-022-v1.0*  
*Target Implementation: 2026-07-19*
