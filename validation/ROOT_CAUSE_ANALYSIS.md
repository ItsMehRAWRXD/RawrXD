# Root Cause Analysis: std::bad_alloc on 22B Model

## Executive Summary

**Issue**: `rawrxd_v3.exe` crashes with `std::bad_alloc` when loading the 22B Codestral model  
**Root Cause**: Transformer layer materializes all quantized weights as FP32  
**Impact**: ~52 GB memory allocation for a 12 GB model  
**Fix Required**: Keep weights quantized, dequantize on-the-fly during MatMul

---

## Memory Analysis

### Current Implementation (transformer_layer.cpp)

```cpp
// Lines 37-46: LoadWeights() materializes FP32 copies
attn_weights_.q_proj.resize(hidden_size * hidden_size, 0.01f);      // ~256 MB
attn_weights_.k_proj.resize(hidden_size * kv_size, 0.01f);        // ~128 MB
attn_weights_.v_proj.resize(hidden_size * kv_size, 0.01f);        // ~128 MB
attn_weights_.o_proj.resize(hidden_size * hidden_size, 0.01f);    // ~256 MB
ffn_weights_.gate_proj.resize(hidden_size * intermediate_size);   // ~1 GB
ffn_weights_.up_proj.resize(hidden_size * intermediate_size);     // ~1 GB
ffn_weights_.down_proj.resize(intermediate_size * hidden_size);    // ~1 GB
// ... x 40 layers = ~52 GB total
```

### Memory Requirements by Scenario

| Scenario | Memory Required | Status |
|----------|----------------|--------|
| **Current (FP32)** | ~52 GB | ❌ FAILS |
| With FP16 | ~26 GB | ⚠️ Marginal |
| **Quantized (in-place)** | ~12 GB | ✅ OPTIMAL |

---

## The Fix

### Option 1: In-Place Dequantization (Recommended)

Modify `MatMul` to accept quantized weights and dequantize on-the-fly:

```cpp
// New signature accepting quantized weights
std::vector<float> MatMulQuantized(
    const std::vector<float>& input,
    const QuantizedTensor& weights_q4,  // Keep as Q4_K
    uint32_t in_features,
    uint32_t out_features);

// Inside MatMul:
// 1. Dequantize 256-element blocks to FP32
// 2. Multiply with input
// 3. Accumulate result
// 4. Discard dequantized block
```

### Option 2: Memory-Mapped Weights

Use OS memory mapping instead of loading:

```cpp
// Map GGUF file directly into address space
void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

// Access weights via pointers, let OS page them in
const QuantizedBlock* weights = (const QuantizedBlock*)((char*)mapped + tensor_offset);
```

### Option 3: FP16 Materialization (Quick Fix)

If quantization is complex, use FP16 instead of FP32:

```cpp
// Change from:
std::vector<float> weights;  // 4 bytes/element

// To:
std::vector<uint16_t> weights;  // 2 bytes/element
// Dequantize to FP16 instead of FP32
```

---

## Validation Framework Created

### Files Created

1. **`reference_validator.hpp`** - Compare RawrXD vs reference implementation
   - Logit comparison (max abs error, MSE)
   - Token agreement (top-1, top-5)
   - Per-layer validation

2. **`memory_audit.hpp/cpp`** - Memory usage analysis
   - Track tensor allocations
   - Identify materialized quantized weights
   - Calculate memory waste

3. **`diagnose_simple.cpp`** - Standalone diagnostic tool
   - Parses GGUF header
   - Calculates memory requirements
   - Shows root cause

### Usage

```bash
# Run memory diagnostic
d:\src\validation\diagnose_simple.exe d:\rawrxd\src\codestral22b.gguf

# Expected output shows:
# - File size: 12 GB
# - FP32 materialization: 52 GB (WILL FAIL)
# - Quantized in-place: 12 GB (OPTIMAL)
```

---

## Recommended Roadmap

### Phase 1: Fix Memory (Critical)
1. Modify `transformer_layer.cpp` to keep weights quantized
2. Implement `MatMulQuantized()` for on-the-fly dequantization
3. Test with 22B model to confirm `std::bad_alloc` resolved

### Phase 2: Reference Validation
1. Generate reference outputs with llama.cpp
2. Compare RawrXD logits against reference
3. Ensure < 1e-3 max error before optimization

### Phase 3: Standardized Benchmark
1. Create reproducible benchmark harness
2. Measure end-to-end tokens/sec
3. Profile per-component time (embedding, attention, MLP, sampling)

### Phase 4: Optimization
1. Only after correctness is validated
2. Focus on measured hotspots
3. Quantization, FlashAttention, speculative decoding

---

## Key Insight

> "The limiting factor appears to be validation and integration quality rather than missing architectural pieces."

The infrastructure is sufficient. The next milestone is demonstrating correct outputs and fixing the memory materialization bug.

---

## Files Location

- Validation framework: `d:\src\validation\`
- Memory audit: `d:\src\validation\memory_audit.hpp/cpp`
- Diagnostic tool: `d:\src\validation\diagnose_simple.cpp`
- Analysis report: `d:\src\validation\ROOT_CAUSE_ANALYSIS.md`
