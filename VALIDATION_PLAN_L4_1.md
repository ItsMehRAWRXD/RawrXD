# RawrXD L4.1 Milestone: First Real GGML Execution

**Date:** 2026-07-09  
**Current:** L3 (contract boundary proven)  
**Target:** L4.1 (first real GGML compute)

---

## What L4.1 Means

**Not:** Full Phi-3 generation  
**Yes:** First actual GGML tensor operation

The L4.1 milestone proves the GGML runtime is connected, not just the contract.

---

## L4.1 Acceptance Test

```cpp
TEST(L4_1, EmbeddingLookup) {
    auto engine = std::make_unique<GGMLAgenticEngine>();
    
    // Initialize GGML context
    ASSERT_TRUE(engine->Initialize());
    
    // Load Phi-3-mini GGUF
    ASSERT_TRUE(engine->LoadModel("phi-3-mini-q8_0.gguf"));
    
    // Tokenize "Hello"
    auto tokens = engine->Tokenize("Hello");
    ASSERT_EQ(tokens.size(), 1);  // Single token
    int tokenId = tokens[0];
    
    // L4.1: Perform actual embedding lookup
    auto embedding = engine->GetEmbedding(tokenId);
    
    // Verify we got real data
    ASSERT_EQ(embedding.size(), 3072);  // Phi-3 hidden size
    ASSERT_NE(embedding[0], 0.0f);     // Non-zero (dequantized)
    
    // Report checksum for validation
    float checksum = 0.0f;
    for (float v : embedding) checksum += v;
    std::cout << "Token " << tokenId << " embedding checksum: " << checksum;
}
```

**Success Criteria:**
- [ ] GGUF file is opened and parsed
- [ ] Tensor offsets are correct
- [ ] Q8_0 quantization is decoded
- [ ] Embedding lookup returns 3072 floats
- [ ] Values are non-zero (dequantization worked)
- [ ] Checksum is deterministic

---

## Why Embedding Lookup First?

| Layer | Complexity | Dependencies |
|-------|------------|--------------|
| **Embedding lookup** | Low | Just token ID → tensor slice |
| RMSNorm | Medium | Requires embedding output |
| QKV projection | High | Requires weights, matmul |
| Attention | Higher | Requires QKV, position encodings |
| FFN | High | Requires gate/up/down projections |
| Output projection | High | Requires full transformer stack |
| Sampling | Medium | Requires logits |

Embedding lookup is the **minimal viable GGML operation** that proves:
1. GGUF tensor layout is understood
2. Quantization format (Q8_0) is decoded correctly
3. Memory mapping works
4. The backend is no longer a stub

---

## Implementation Plan

### Step 1: GGUF Tensor Access

```cpp
// In GGMLAgenticEngine::Impl
bool LoadGGUFTensors(const std::string& path) {
    // Open GGUF file
    // Parse header
    // Verify tensor info exists
    // Map tensor data
    // Specifically: "token_embd.weight"
}
```

### Step 2: Q8_0 Dequantization

```cpp
std::vector<float> DequantizeQ8_0(
    const void* quantizedData,
    size_t numElements
) {
    // Q8_0 format: int8 values + float32 scale per block
    // Block size: 32 elements
    // Dequantize to float32
}
```

### Step 3: Embedding Lookup

```cpp
std::vector<float> GetEmbedding(int tokenId) {
    // Verify tokenId < vocab_size
    // Calculate offset: tokenId * hidden_size * sizeof(float)
    // Return dequantized embedding vector
}
```

### Step 4: Validation

```cpp
// Verify against reference
// Option A: Compare with llama.cpp output
// Option B: Compare with Python transformers
// Option C: Verify checksum is stable across runs
```

---

## Current vs Target

### Current (L3 - Contract)

```cpp
std::string Generate(const std::vector<int>& tokens, size_t maxTokens) {
    (void)tokens;
    // Stub: No actual computation
    return "Paris";  // Deterministic fake
}
```

### Target (L4.1 - First Compute)

```cpp
std::vector<float> GetEmbedding(int tokenId) {
    // Real GGML operation:
    // 1. Look up tensor "token_embd.weight"
    // 2. Dequantize Q8_0 block
    // 3. Return embedding vector
    
    const auto& tensor = m_tensors["token_embd.weight"];
    size_t offset = tokenId * tensor.hidden_size;
    return DequantizeQ8_0(tensor.data + offset, tensor.hidden_size);
}
```

---

## Blockers

| Blocker | Status | Resolution |
|---------|--------|------------|
| GGML headers | Need to include | Add to CMake/includes |
| GGUF loader | Exists | Reuse existing loader |
| Q8_0 dequant | Need implementation | Reference: llama.cpp |
| Test model | Need phi-3-mini-q8_0.gguf | Download from HF |

---

## Evidence Required

```
[L4.1] EmbeddingLookup... 
  Loading phi-3-mini-q8_0.gguf... OK
  Tokenizing "Hello"... token_id=15043
  Looking up embedding... 
  Dequantizing Q8_0... 
  Embedding size: 3072
  First 5 values: [0.0123, -0.0456, 0.0789, ...]
  Checksum: 1234.5678
✓ PASS
```

---

## After L4.1

| Milestone | Description |
|-----------|-------------|
| L4.2 | RMSNorm layer |
| L4.3 | QKV projection |
| L4.4 | Attention mechanism |
| L4.5 | FFN (SwiGLU) |
| L4.6 | Output projection + sampling |
| **L4** | **Full single-token generation** |

---

## Summary

**Current:** Contract boundary proven (L3)  
**Next:** First real GGML operation (L4.1)  
**Target:** Embedding lookup from Phi-3-mini  
**Goal:** Prove GGML runtime is connected and functional

The architecture is ready. The remaining work is pure inference runtime engineering.
