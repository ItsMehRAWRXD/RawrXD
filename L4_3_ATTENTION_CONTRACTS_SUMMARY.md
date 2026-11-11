# RawrXD L4.3 Attention Contracts Summary

## Overview

L4.3 establishes **memory and state contracts** for attention kernels. This freezes the ABI boundary between model graph and kernel implementations before any optimized kernels are written.

## Architecture

```
Model Graph
    |
    v
Tensor / State Contracts  ← L4.3 (this layer)
    |
    v
Attention Kernel Implementations
    |
    v
Backend (CPU / AVX / GPU / future accelerators)
```

## Key Principle

> Without frozen contracts, optimized kernels tend to become ABI-breaking implementations.

## Components

### 1. TensorView ABI

```cpp
struct TensorView {
    float* data;
    
    // Dimensions
    uint32_t rows;
    uint32_t cols;
    uint32_t depth;
    
    // Strides (in elements, not bytes)
    uint32_t row_stride;
    uint32_t col_stride;
    uint32_t depth_stride;
    
    // Metadata
    uint32_t total_elements;
    bool is_contiguous;
    
    // Validation
    bool IsValid() const;
    bool MatchesShape(uint32_t expected_rows, uint32_t expected_cols) const;
    
    // Access
    float& at(uint32_t row, uint32_t col);
    float& at3(uint32_t d, uint32_t row, uint32_t col);
};
```

**Invariants:**
- `data != nullptr`
- Strides explicitly defined
- No hidden contiguous assumptions
- Supports GGUF mapped tensors, arena allocations, KV cache slices

### 2. AttentionConfig Descriptor

```cpp
struct AttentionConfig {
    uint32_t num_heads;         // Number of query heads
    uint32_t num_kv_heads;      // For GQA: num_kv_heads <= num_heads
    uint32_t head_dim;
    uint32_t context_length;
    
    float rope_theta;
    float scale;                // Typically 1/sqrt(head_dim)
    
    bool causal;
    bool use_rope;
    
    // Validation
    bool IsValid() const;
    bool IsGQA() const { return num_kv_heads < num_heads; }
    bool IsMHA() const { return num_kv_heads == num_heads; }
    bool IsMQA() const { return num_kv_heads == 1; }
    
    uint32_t GetQueryHeadsPerKV() const {
        return num_heads / num_kv_heads;
    }
};
```

**Supports:**
- Llama-family GQA
- MHA (Multi-Head Attention)
- MQA (Multi-Query Attention)
- RoPE variants
- Future sliding window attention

### 3. KVCache ABI

```cpp
struct KVCache {
    float* key_cache;           // [max_position, num_kv_heads, head_dim]
    float* value_cache;         // [max_position, num_kv_heads, head_dim]
    
    uint32_t max_position;
    uint32_t current_position;
    
    // Strides for indexing
    uint32_t pos_stride;
    uint32_t head_stride;
    uint32_t dim_stride;
    
    // Operations
    bool Initialize(float* k_buffer, float* v_buffer,
                    uint32_t max_pos, uint32_t num_kv_heads, uint32_t head_dim);
    
    float* GetKey(uint32_t pos, uint32_t head);
    float* GetValue(uint32_t pos, uint32_t head);
    
    bool Append(const float* new_key, const float* new_value,
                uint32_t num_kv_heads, uint32_t head_dim);
    void Reset();
    
    bool IsValid() const;
    bool HasCapacity() const;
};
```

**Design:**
- Cache is an owned state object
- Attention kernels consume the cache, do not own it
- Supports RAM, mmap, GPU memory backends

### 4. Attention Invocation Contract

```cpp
struct AttentionInputs {
    TensorView query;           // [num_heads, head_dim]
    TensorView key;             // [num_kv_heads, head_dim]
    TensorView value;           // [num_kv_heads, head_dim]
    
    KVCache* kv_cache;          // nullptr = use provided K,V
    
    uint32_t seq_position;      // Current sequence position
    uint32_t seq_length;        // Total sequence length
};

struct AttentionOutputs {
    TensorView output;          // [num_heads, head_dim]
    float* attention_weights;   // Optional
    bool kv_cache_updated;
};

// Kernel entry point - deterministic and stateless
bool ExecuteAttentionReference(
    const AttentionConfig& config,
    const AttentionInputs& inputs,
    AttentionOutputs& outputs
);
```

**Constraints:**
- Does not allocate memory
- Does not load models
- Does not parse GGUF
- Does not mutate global state

### 5. Validation Layer

```cpp
struct ValidationResult {
    bool passed;
    float cosine_similarity;
    float max_absolute_error;
    float rmse;
    std::vector<std::string> errors;
    
    bool IsPassing(float cosine_threshold = 0.999f,
                   float max_error_threshold = 0.01f) const;
};

class AttentionValidator {
public:
    static ValidationResult Validate(
        const AttentionConfig& config,
        const AttentionInputs& inputs,
        const AttentionOutputs& outputs,
        const AttentionOutputs& reference_outputs
    );
    
    static float ComputeCosineSimilarity(const TensorView& a, const TensorView& b);
    static float ComputeMaxError(const TensorView& a, const TensorView& b);
    static float ComputeRMSE(const TensorView& a, const TensorView& b);
};
```

## Files Created/Updated

| File | Purpose |
|------|---------|
| `kernels/attention_contracts.h` | Contract definitions (TensorView, AttentionConfig, KVCache, Validation) |
| `kernels/attention_reference.cpp` | Reference attention implementation |
| `tests/attention_contract_test.cpp` | 24 test cases |

## Test Coverage

### TensorView Tests (5)
- CreateContiguous
- CreateContiguous3D
- Invalid detection
- Shape matching
- Element access

### AttentionConfig Tests (6)
- Valid config
- Invalid (zero heads)
- GQA validation
- Uneven GQA rejection
- Scale computation
- Query heads per KV

### KVCache Tests (6)
- Initialize
- Null buffer rejection
- Get key/value
- Append
- Reset
- Capacity checking

### AttentionInputs Tests (2)
- Valid inputs
- Invalid shape rejection

### ValidationResult Tests (3)
- Passing criteria
- Failing criteria
- Error addition

### Integration Tests (3)
- Full Llama-style config
- KVCache with config
- Attention chain validation

## L4.3 Gate Criteria

Before writing SIMD/GPU attention:

| Gate | Status |
|------|--------|
| ✅ TensorView frozen | Complete |
| ✅ KVCache ABI frozen | Complete |
| ✅ AttentionConfig frozen | Complete |
| ✅ Reference attention passes | Complete |
| ✅ Randomized shape tests | Complete |
| ⏳ GGUF metadata mapping | Pending |

## Reference Implementation

```cpp
// Reference scaled dot-product attention
static void ReferenceAttentionSingleHead(
    const float* query,
    const float* keys,
    const float* values,
    float* output,
    uint32_t seq_len,
    uint32_t head_dim,
    float scale,
    bool causal
) {
    // 1. Compute attention scores: Q @ K^T
    for (uint32_t pos = 0; pos < seq_len; ++pos) {
        scores[pos] = DotProduct(query, keys + pos * head_dim, head_dim) * scale;
    }
    
    // 2. Softmax
    Softmax(scores, seq_len);
    
    // 3. Weighted sum: scores @ V
    for (uint32_t d = 0; d < head_dim; ++d) {
        output[d] = 0;
        for (uint32_t pos = 0; pos < seq_len; ++pos) {
            output[d] += scores[pos] * values[pos * head_dim + d];
        }
    }
}
```

## Validation Strategy

```cpp
// Reference → Optimized comparison
ReferenceAttention(...)
    |
    v
OptimizedAttention(...)
    |
    v
Compare(cosine >= 0.999, RMSE <= 0.01)
```

## Next Steps: L4.3.x Optimized Kernels

With contracts frozen, optimized kernels become replaceable:

```cpp
attention_reference()
    |
    +-- attention_avx2()
    |
    +-- attention_avx512()
    |
    +-- attention_cuda()
    |
    +-- attention_vulkan()
```

All implementations consume the same contracts and validate against the same reference.

## Build Commands

```bash
# Compile reference implementation
g++ -std=c++17 -O2 -mavx2 -mfma \
    -I. kernels/attention_reference.cpp \
    -c -o attention_reference.o

# Compile tests
g++ -std=c++17 -O2 -mavx2 -mfma \
    -I. tests/attention_contract_test.cpp \
    attention_reference.o \
    -o attention_contract_test.exe

# Run tests
./attention_contract_test.exe
```

## Status

- ✅ Contracts defined
- ✅ Reference implementation complete
- ✅ Validation layer complete
- ✅ 24 test cases
- ⏳ Optimized kernels ready to proceed

## Architectural Significance

L4.3 transforms the execution layer from "validated math library" into a **transformer execution engine** with clear contracts:

```
L4.2.2: Kernel Registry + Primitives
    ↓
L4.3: Attention Contracts
    ↓
    ├── TensorView ABI
    ├── AttentionConfig
    ├── KVCache ABI
    └── Reference Implementation
    ↓
L4.3.x: Optimized Kernels
    ↓
L4.4: Full Transformer Block
```

The key success condition:

> Given a known tensor input and known weights, produce the same attention output as the reference implementation.

Once this contract is locked, AVX/GPU/fused optimization work becomes safe and replaceable.
