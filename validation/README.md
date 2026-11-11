# RawrXD Validation Suite

## Overview

This directory contains validation frameworks to prove RawrXD produces **correct** output, not just *running* output.

## Validation Philosophy

**Goal:** Bit-exact or numerically equivalent output to llama.cpp reference implementation.

**Acceptance Criteria:**
- Max absolute error: ≤ 1e-5
- Max relative error: ≤ 1e-4
- Deterministic output at temperature=0
- Coherent text generation

---

## Validation Frameworks

### 1. Golden Model Regression (`golden_model_test.py`)

Tests end-to-end inference against known-good outputs.

**What it tests:**
- Token generation matches expected sequence
- Logits hash matches reference
- Determinism (same input → same output)
- Perplexity on test corpus

**Usage:**
```bash
python validation/golden_model_test.py
```

**Requirements:**
- Reference model outputs from llama.cpp
- Golden prompt database

---

### 2. Layer-by-Layer Validation (`layer_by_layer_test.cpp`)

Tests each transformer component individually.

**What it tests:**
- Embedding layer accuracy
- RMSNorm numerical correctness
- QKV projection + RoPE angles
- Attention scores and softmax
- FFN (SwiGLU) computation
- Output projection logits

**Usage:**
```bash
# Build test
g++ -o layer_test validation/layer_by_layer_test.cpp -I./include

# Run tests
./layer_test
```

**Output:**
```
[TEST] Embedding Layer
  Max abs error: 0.00000123 (limit: 0.00001000)
  Max rel error: 0.00004567 (limit: 0.00010000)
  Result: PASS

[TEST] RMSNorm
  ...

SUMMARY
  [PASS] Embedding
  [PASS] RMSNorm
  [FAIL] Attention
  ...
```

---

### 3. Reference Data Generator (`generate_reference_data.py`)

Creates synthetic reference data for testing.

**What it generates:**
- Embedding reference outputs
- RMSNorm reference data
- RoPE angle tables
- Attention reference matrices
- Quantization/dequantization pairs

**Usage:**
```bash
python validation/generate_reference_data.py
```

**Output:** `validation/reference_data/` directory with `.bin` files

**Note:** These are synthetic data. For true validation, replace with actual llama.cpp outputs.

---

## Validation Checklist

### Phase 1: Kernel Validation ✅
- [x] Q4_0 dequantization bit-exact
- [ ] Q2_K validation
- [ ] Q4_K validation
- [ ] Q5_K validation
- [ ] Q8_0 validation

### Phase 2: Layer Validation
- [ ] Embedding layer
- [ ] RMSNorm
- [ ] RoPE angles
- [ ] Attention scores
- [ ] FFN forward pass
- [ ] Output projection

### Phase 3: Integration Validation
- [ ] Full forward pass
- [ ] KV cache correctness
- [ ] Token sampling
- [ ] Long context (4K+)
- [ ] Multi-token generation

### Phase 4: Quality Validation
- [ ] Perplexity benchmarks
- [ ] Human-evaluated coherence
- [ ] Determinism tests
- [ ] Golden prompt regression

---

## Creating Reference Data from llama.cpp

To generate true reference data:

1. **Modify llama.cpp** to dump layer outputs:
```cpp
// In llama.cpp, add after each layer:
dump_tensor("embedding_out.bin", embedding_output);
dump_tensor("rmsnorm_out.bin", rmsnorm_output);
// etc.
```

2. **Run llama.cpp** on test prompts:
```bash
./llama-cli -m model.gguf -p "The capital of France is" -n 1 --temp 0
```

3. **Copy outputs** to `validation/reference_data/`

4. **Run RawrXD tests** and compare

---

## CI Integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: Layer Validation
  run: |
    ./build/layer_by_layer_test
    
- name: Golden Model Regression
  run: |
    python validation/golden_model_test.py
    
- name: Numerical Accuracy
  run: |
    python validation/check_numerical_accuracy.py
```

---

## Debugging Failed Tests

### High Error in Specific Layer

1. Check weight loading (byte alignment, quantization)
2. Verify kernel dispatch (AVX-512 vs AVX2 vs scalar)
3. Compare intermediate values step-by-step
4. Check for off-by-one errors in loops

### Non-Deterministic Output

1. Verify temperature=0 in sampling
2. Check for uninitialized memory
3. Ensure fixed random seed
4. Validate thread synchronization

### Perplexity Too High

1. Check all layer outputs cumulatively
2. Verify vocabulary mapping
3. Validate tokenizer output
4. Compare logit distributions

---

## Success Criteria

**RawrXD is validated when:**

1. ✅ All layer tests pass (error < 1e-5)
2. ✅ Golden prompts produce expected tokens
3. ✅ Temperature=0 is deterministic across 1000 runs
4. ✅ Perplexity within 5% of llama.cpp on WikiText-2
5. ✅ Human evaluation: 90%+ responses are coherent

---

## Current Status

| Component | Status | Evidence |
|-----------|--------|----------|
| Q4_0 Kernel | ✅ Validated | Bit-exact tests pass |
| Other Kernels | ❌ Unknown | Not tested |
| Embedding | ❌ Unknown | Not tested |
| RMSNorm | ❌ Unknown | Not tested |
| RoPE | ❌ Unknown | Not tested |
| Attention | ❌ Unknown | Not tested |
| Full Forward | ❌ Unknown | Not tested |

**Next Priority:** Generate reference data from llama.cpp and run layer tests.

---

## References

- llama.cpp: https://github.com/ggerganov/llama.cpp
- Transformer Math: https://arxiv.org/abs/1706.03762
- RoPE: https://arxiv.org/abs/2104.09864

---

*Validation is the difference between "it runs" and "it runs correctly."*
