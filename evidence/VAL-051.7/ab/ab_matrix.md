# VAL-051.7 — Gate 17: Residency A/B Matrix

## Document Identity
- **Gate:** 17
- **Version:** 1.0
- **Date:** 2026-08-22

---

## OFF Configuration

```
residency = OFF
mapping = baseline (full mmap, no eviction)
model = Codestral-22B-Q4_K_M.gguf
prompt = "Hello"
seed = fixed
sampler = greedy
token count = 15
build = RelWithDebInfo
```

## ON Configuration

```
residency = ON
mapping = bounded window + LRU eviction
maxResidentBytes = 512MB
model = Codestral-22B-Q4_K_M.gguf
prompt = "Hello"
seed = fixed
sampler = greedy
token count = 15
build = RelWithDebInfo
```

## Comparison Dimensions

| Dimension | OFF | ON | Tolerance |
|-----------|-----|----|-----------|
| Token IDs | captured | captured | **exact** |
| Token count | captured | captured | **exact** |
| Position sequence | captured | captured | **exact** |
| Hidden states | captured | captured | **1e-6 relative** |
| Logits | captured | captured | **1e-4 relative** |
| Attention metrics | captured | captured | **1e-4 relative** |
| FFN metrics | captured | captured | **1e-4 relative** |
| NaN/Inf count | captured | captured | **exact (0)** |
| Map count | N/A | measured | N/A |
| Remap count | 0 | measured | N/A |
| Eviction count | 0 | measured | N/A |
| Peak resident bytes | ~35GB | <=512MB | N/A |
| Latency | measured | measured | **±20%** |

## Numerical Equivalence Tolerances

Per-quantity tolerances instead of one global tolerance:

| Quantity | Tolerance | Rationale |
|----------|-----------|-----------|
| Token IDs | Exact | Discrete, must match |
| Position | Exact | Discrete, must match |
| Hidden state (per-element) | 1e-6 relative | FP32 accumulation |
| Logits (per-element) | 1e-4 relative | Dequantization variance |
| Attention scores | 1e-4 relative | Softmax numerical sensitivity |
| FFN activations | 1e-4 relative | SwiGLU nonlinearity |
| KV cache values | 1e-6 relative | Cumulative accumulation |

## Implementation

See `VAL0517BaselineFixture.hpp/cpp` for automated A/B comparator.
