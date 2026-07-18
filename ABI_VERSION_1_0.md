# RawrXD ABI Version 1.0 (Frozen)

**Status:** FROZEN  
**Date:** 2026-07-17  
**Version:** 1.0.0  
**Schema:** VALIDATION_SCHEMA_VERSION = 1

---

## Versioning Policy

Once frozen, ABI changes require version increments:

| Change Type | Version Impact | Example |
|-------------|---------------|---------|
| Bug fix (no interface change) | Patch | 1.0.0 → 1.0.1 |
| New function (backward compatible) | Minor | 1.0.0 → 1.1.0 |
| Breaking change | Major | 1.0.0 → 2.0.0 |

---

## Kernel Interface (KERNEL_INTERFACE_VERSION = 1)

### RMSNorm

```c
// Function signature (frozen)
void rmsnorm_avx2_f32(
    const float* input,   // rcx - aligned or unaligned input
    float* output,          // rdx - output buffer
    size_t n,               // r8  - element count
    float epsilon           // xmm3 - small constant (typically 1e-6)
);
```

**Behavior:**
- Computes: `output[i] = input[i] / sqrt(mean(input²) + epsilon)`
- Supports n < 8 (tail handling)
- No alignment requirement on input/output
- Thread-safe

**Performance Target:** ≥3x speedup over scalar
**Accuracy Target:** max_error < 1e-5

---

### Softmax

```c
// Function signature (frozen)
void softmax_avx2_f32(
    const float* input,   // rcx - input array
    float* output,        // rdx - output buffer
    size_t n              // r8  - element count
);
```

**Behavior:**
- Computes: `softmax(x_i) = exp(x_i - max) / sum(exp(x - max))`
- Output sums to 1.0 (within floating-point tolerance)
- Supports n < 8 (tail handling)
- No alignment requirement
- Thread-safe

**Performance Target:** ≥2x speedup over scalar
**Accuracy Target:** max_error < 1e-3, sum ∈ [0.99999, 1.00001]

---

## ExecutionResult Schema (VALIDATION_SCHEMA_VERSION = 1)

```json
{
  "schema_version": 1,
  "timestamp": "ISO8601",
  "validation_id": "VAL-XXX",
  "test_name": "string",
  "status": "PASS|FAIL|SKIP",
  "metrics": {
    "speedup": "float (optional)",
    "max_error": "float (optional)",
    "iterations": "int (optional)"
  },
  "artifacts": [
    {
      "path": "string",
      "sha256": "string",
      "size": "int"
    }
  ]
}
```

---

## Validation ID Format

```
VAL-{XXX}
```

Where XXX is a sequential number:
- VAL-001 to VAL-099: Core infrastructure
- VAL-100 to VAL-199: Kernel validation
- VAL-200 to VAL-299: Integration validation
- VAL-300+: Reserved for future use

---

## Gate Status Values

| Status | Meaning |
|--------|---------|
| PASS | All criteria met |
| FAIL | One or more criteria failed |
| PARTIAL | Some criteria met, known gaps |
| NOT_STARTED | No work begun |
| IN_PROGRESS | Work underway |

---

## Hardware Capability Detection

Runtime must detect and report:

```c
typedef struct {
    uint32_t abi_version;           // Must be 1
    uint32_t kernel_interface_version;  // Must be 1
    
    // CPU capabilities
    bool has_avx2;
    bool has_avx512;
    bool has_fma;
    
    // GPU capabilities (optional)
    bool has_gpu;
    uint32_t gpu_vendor;  // 0=none, 1=AMD, 2=NVIDIA, 3=Intel
    
    // Memory
    size_t system_memory_mb;
    size_t gpu_memory_mb;
} RawrXD_CapabilityReport;
```

---

## Breaking Changes Log

| Version | Date | Change | Migration |
|---------|------|--------|-----------|
| 1.0.0 | 2026-07-17 | Initial freeze | N/A |

---

**Next Review:** 2026-08-17 or upon major feature completion
