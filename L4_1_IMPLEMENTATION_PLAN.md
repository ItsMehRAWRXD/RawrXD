# RawrXD L4.1 Implementation Plan
**Checkpoint Sequence:** L4.1.0 → L4.1.1 → L4.1.2 → L4.1.3  
**Principle:** Correctness before optimization

---

## Current State

```
Sovereign Runtime Validation State

Documentation:
  ✅ Frozen baseline defined
  ✅ Audit boundary defined
  ✅ Runtime ladder defined
  ✅ L4.1 execution contract defined
  ✅ Navigation/index layer defined

Runtime:
  ✅ Agentic orchestration (L3)
  ✅ GGUF ingestion (L4.0)
  ⏳ First neural operation (L4.1)
  ❌ Transformer execution (L4.2)
  ❌ Generation pipeline (L4.3-L5)
```

---

## L4.1 Scope Constraint

**Single-purpose proof:**

```
GGUF
 |
 | locate token_embd.weight
 |
 | decode one row
 |
 | return embedding vector
 |
 | compare against reference
```

**Explicitly NOT in scope:**
- ❌ Batching
- ❌ GPU path
- ❌ Optimization
- ❌ Multi-token sequences
- ❌ Transformer layers

---

## Checkpoint Sequence

### L4.1.0 — Tensor Discovery

**Goal:** Verify runtime can locate `token_embd.weight`

**Required Output:**
```
Tensor: token_embd.weight
  name: token_embd.weight
  dimensions: [3072, 32064]
  quantization: Q4_0
  file_offset: 0xXXXXXX
  byte_size: XXXXXX
```

**Pass Criteria:**
- [ ] Tensor found in GGUF
- [ ] Metadata matches expected
- [ ] Offset calculated correctly
- [ ] Size matches file layout

---

### L4.1.1 — Single Row Decode

**Goal:** Implement `EmbeddingLookup(token_id)`

**Interface:**
```cpp
std::vector<float> EmbeddingLookup(uint32_t token_id);
```

**Input:**
```
uint32 token_id (e.g., 15043)
```

**Output:**
```
float[embedding_dim] (e.g., 3072 values)
```

**Implementation Notes:**
- No batching
- CPU path only
- Direct GGML tensor access
- Q4_0 dequantization

**Pass Criteria:**
- [ ] Function returns vector of correct size
- [ ] All values finite (no NaN/Inf)
- [ ] Values in reasonable range (-1.0 to 1.0)

---

### L4.1.2 — Reference Validation

**Goal:** Compare against llama.cpp reference

**Machine-Readable Output:**
```json
{
  "model": "phi3-mini-Q4_0.gguf",
  "tensor": "token_embd.weight",
  "token_id": 15043,
  "token_text": "Hello",
  "dimensions": 3072,
  "cosine_similarity": 0.9999,
  "max_absolute_error": 0.0008,
  "mean_absolute_error": 0.00005,
  "reference_implementation": "llama.cpp",
  "result": "PASS"
}
```

**Pass Criteria:**
- [ ] cosine_similarity >= 0.999
- [ ] max_absolute_error < 0.001
- [ ] mean_absolute_error < 0.0001
- [ ] All 3072 values finite

---

### L4.1.3 — Performance Baseline

**Goal:** Measure only after correctness proven

**Metrics:**
```
lookups/sec:        X.XX
memory_touched:     XX MB
decode_latency:       XX µs
cache_behavior:       L3 hit rate XX%
```

**Why last:** Prevents optimizing an incorrect kernel

**Pass Criteria:**
- [ ] Baseline established
- [ ] No regressions from reference
- [ ] Memory bounds verified

---

## Implementation Traps to Avoid

| Trap | Prevention |
|------|------------|
| Optimizing before correctness | Strict checkpoint sequence |
| Batching complexity | Single token only |
| GPU path divergence | CPU path first |
| Reference mismatch ignored | Hard numerical thresholds |
| Scope creep | Explicit "NOT in scope" list |

---

## Evidence Artifacts per Checkpoint

### L4.1.0
```
L4_1_0_TENSOR_DISCOVERY.md
├── Tensor metadata
├── Offset calculation
└── GGUF layout verification
```

### L4.1.1
```
L4_1_1_ROW_DECODE.md
├── Function signature
├── Output vector sample
└── Finite value verification
```

### L4.1.2
```
L4_1_2_REFERENCE_VALIDATION.md
├── JSON comparison output
├── Numerical metrics
└── Pass/fail determination
```

### L4.1.3
```
L4_1_3_PERFORMANCE_BASELINE.md
├── Throughput metrics
├── Memory profile
└── Cache behavior
```

---

## Transition to L4.2

**After L4.1.3 passes:**

```
L4.1 ✅ First neural operation validated
  ↓
L4.2 ⏳ Transformer execution
  ├── RMSNorm
  ├── QKV projection
  ├── RoPE
  ├── Attention
  ├── KV cache
  └── FFN
```

**L4.2 will reuse:**
- Tensor discovery (L4.1.0 pattern)
- Row decode (L4.1.1 pattern)
- Reference validation (L4.1.2 pattern)

---

## Summary

**The remaining work is no longer architectural discovery.**

The architecture boundary is documented. The next milestone is a **numerical proof** that the runtime can transform stored model data into valid neural state.

**Checkpoint L4.1.0 begins when you signal.**

---

*This plan prevents the common trap of optimizing an incorrect kernel by enforcing correctness before performance measurement.*
