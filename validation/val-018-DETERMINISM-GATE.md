# VAL-018.DETERMINISM: Determinism Validation Gate

**Version:** 1.0  
**Date:** 2026-07-17  
**Status:** Framework Defined, Not Yet Executed

---

## Purpose

Before claiming correctness or compatibility, prove that RawrXD native inference produces **deterministic output** for identical inputs across multiple runs.

This gate is especially critical for:
- **GPU inference** (atomic operations, reduction ordering)
- **Parallel kernels** (thread scheduling)
- **Fast math modes** (compiler optimizations)
- **Driver differences** (vendor-specific behavior)

---

## Determinism Requirements

### For CPU Inference

| Aspect | Requirement | Verification |
|--------|-------------|------------|
| **Threading** | Same thread count | `OMP_NUM_THREADS` fixed |
| **Memory layout** | Same allocation pattern | Address space consistent |
| **Instruction order** | Same execution path | No race conditions |

### For GPU Inference

| Aspect | Requirement | Verification |
|--------|-------------|------------|
| **Atomic operations** | Deterministic reduction | Sum/reduce order fixed |
| **Kernel launch** | Same thread blocks | Block size constant |
| **Memory coalescing** | Same access pattern | Stride consistent |
| **Fast math** | Disabled or consistent | Compiler flags fixed |

---

## Test Protocol

### Test 1: Tokenizer Determinism

**Input:**
```
Prompt: "The quick brown fox jumps over the lazy dog."
Tokenizer: test_tokenizer.json
```

**Procedure:**
1. Run tokenizer 10 times
2. Record token IDs each run
3. Compute checksum for each run

**Pass Criteria:**
- All 10 runs produce identical token IDs
- All 10 checksums match
- No variation across runs

**Evidence:**
```json
{
  "test": "tokenizer_determinism",
  "runs": 10,
  "all_identical": true,
  "checksum": "10414629015055014369",
  "variance": 0
}
```

---

### Test 2: Embedding Lookup Determinism

**Input:**
```
Token IDs: [1, 464, 2068, 7586, ...]
Model: BigDaddyG-Q2_K-CHEETAH.gguf
```

**Procedure:**
1. Load GGUF embedding tensor
2. Lookup embeddings for token IDs
3. Run 10 times
4. Record embedding vectors

**Pass Criteria:**
- All 10 runs produce identical embeddings
- Bit-exact match (not just within tolerance)

**Evidence:**
```json
{
  "test": "embedding_determinism",
  "runs": 10,
  "all_identical": true,
  "embedding_checksum": "abc123...",
  "variance": 0
}
```

---

### Test 3: RMSNorm Determinism

**Input:**
```
Input tensor: [1, 4096] float32
Weight tensor: [4096] float32
```

**Procedure:**
1. Run RMSNorm kernel 100 times
2. Record output each time
3. Compute checksum for each run

**Pass Criteria:**
- All 100 runs produce bit-exact output
- Checksums identical across all runs

**Evidence:**
```json
{
  "test": "rmsnorm_determinism",
  "runs": 100,
  "all_identical": true,
  "output_checksum": "def456...",
  "variance": 0
}
```

---

### Test 4: Attention Determinism (Critical)

**Input:**
```
Q: [32, 128, 128] float32
K: [32, 128, 128] float32
V: [32, 128, 128] float32
```

**Procedure:**
1. Run attention kernel 100 times
2. Record attention weights and output
3. Compute checksums

**Pass Criteria:**
- All 100 runs produce identical attention weights
- All 100 runs produce identical output
- No variation from parallel reduction

**Evidence:**
```json
{
  "test": "attention_determinism",
  "runs": 100,
  "all_identical": true,
  "attention_weights_checksum": "ghi789...",
  "output_checksum": "jkl012...",
  "variance": 0
}
```

**Note:** Attention is the most likely source of non-determinism due to:
- Softmax reduction across keys
- Parallel attention head computation
- Floating-point accumulation order

---

### Test 5: Full Forward Pass Determinism

**Input:**
```
Prompt: "Hello, world!"
Model: BigDaddyG-Q2_K-CHEETAH.gguf
Seed: 42
```

**Procedure:**
1. Run complete forward pass (tokenizer → embedding → transformer → logits)
2. Run 10 times with identical inputs
3. Record logits for final token position

**Pass Criteria:**
- All 10 runs produce identical logits
- Logit checksums match exactly

**Evidence:**
```json
{
  "test": "full_forward_determinism",
  "runs": 10,
  "all_identical": true,
  "logits_checksum": "mno345...",
  "variance": 0
}
```

---

## Sources of Non-Determinism

### Compiler/Build Level

| Source | Mitigation |
|--------|------------|
| `/fp:fast` (MSVC) | Use `/fp:precise` |
| `-ffast-math` (GCC) | Disable fast math |
| Auto-vectorization | Fixed SIMD width |
| Link-time optimization | Consistent LTO settings |

### Runtime Level

| Source | Mitigation |
|--------|------------|
| Thread scheduling | Fixed thread pool size |
| Memory allocation | Pre-allocated buffers |
| Random number generation | Fixed seed |
| GPU kernel launch | Fixed block/grid size |

### Algorithm Level

| Source | Mitigation |
|--------|------------|
| Parallel reduction | Tree reduction or sequential fallback |
| Atomic operations | Use deterministic algorithms |
| Sorting | Stable sort algorithms |
| Sampling | Fixed seed for sampling |

---

## Validation Harness

```cpp
// Determinism test harness
class DeterminismValidator {
public:
    template<typename Func>
    DeterminismResult Validate(const std::string& test_name, 
                                int num_runs,
                                Func&& operation) {
        std::vector<uint64_t> checksums;
        
        for(int i = 0; i < num_runs; i++) {
            auto output = operation();
            auto checksum = ComputeChecksum(output);
            checksums.push_back(checksum);
        }
        
        // Check all identical
        bool all_identical = std::all_of(
            checksums.begin(), checksums.end(),
            [&](uint64_t c) { return c == checksums[0]; }
        );
        
        return {
            .test_name = test_name,
            .runs = num_runs,
            .all_identical = all_identical,
            .checksum = checksums[0],
            .variance = ComputeVariance(checksums)
        };
    }
};
```

---

## Acceptance Criteria

### PASS if:
- ✅ All 5 determinism tests pass
- ✅ No variance across runs for any test
- ✅ Bit-exact output for all operations
- ✅ Evidence JSON written with `"determinism_verified": true`

### FAIL if:
- ❌ Any test shows variance across runs
- ❌ Checksums differ between runs
- ❌ Non-determinism detected in any layer

---

## Relationship to Other Gates

```
VAL-018.2 (GGUF Loader)      ──┐
VAL-018.3 (Tokenizer)          │
VAL-018.4 (Embedding)          │
...                           ├──► VAL-018.DETERMINISM ──► VAL-019 (Correctness)
VAL-018.10 (Transformer)     │
VAL-018.11 (Inference)       ──┘
```

**Determinism gate must pass before VAL-019 correctness validation.**

Correctness validation requires comparing against reference outputs. If RawrXD output varies between runs, the comparison is meaningless.

---

## Evidence Package

```
validation/val-018-determinism/
├── execution/
│   ├── tokenizer_determinism.json
│   ├── embedding_determinism.json
│   ├── rmsnorm_determinism.json
│   ├── attention_determinism.json
│   └── full_forward_determinism.json
├── result/
│   └── completion.json
└── summary.md
```

---

## Current Status

| Test | Status | Notes |
|------|--------|-------|
| Tokenizer | ⬜ Not run | VAL-018.3 complete, determinism not verified |
| Embedding | ⬜ Not run | VAL-018.4 pending |
| RMSNorm | ⬜ Not run | VAL-018.5 pending |
| Attention | ⬜ Not run | VAL-018.8 pending |
| Full Forward | ⬜ Not run | VAL-018.11 pending |

**Overall: 0 of 5 determinism tests complete**

---

## Next Steps

1. **After VAL-018.4 (Embedding):** Run embedding determinism test
2. **After VAL-018.5 (RMSNorm):** Run RMSNorm determinism test
3. **After VAL-018.8 (Attention):** Run attention determinism test (critical)
4. **After VAL-018.11 (Inference):** Run full forward pass determinism test
5. **Before VAL-019:** All determinism tests must pass

---

## Conclusion

Determinism is a prerequisite for correctness validation. This gate ensures that RawrXD produces stable, reproducible output before attempting to validate against reference implementations.

**Claim:** "RawrXD native inference is deterministic"  
**Status:** ⬜ Not yet evidenced  
**Blocker for:** VAL-019 correctness validation
