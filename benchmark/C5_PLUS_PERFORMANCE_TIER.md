# C5+ Performance Tier: 100+ tok/s Roadmap

**Goal**: Stack multiplicative gains to reach 100+ tok/s  
**Base**: C4 locked at 31.5 tok/s  
**Strategy**: Quantization → AVX-512 → Speculative Decoding

## Gain Stack

```
C4 Baseline:        31.5 tok/s
├── C5a Q4_0:       ×1.5  (cache efficiency)     = 47 tok/s
├── C5b K-Quant:    ×1.2  (quality preservation)  = 56 tok/s  
├── C5c AVX-512:    ×2.0  (dequant speed)        = 113 tok/s
└── C5d Speculative: ×1.5  (token acceptance)     = 170 tok/s
```

**Target: 100-170 tok/s** (conservative: 100, optimistic: 170)

---

## C5a: Q4_0 Quantization

### Memory Impact
- **FP32**: 4 bytes/weight
- **Q4_0**: 0.5 bytes/weight (8:1 compression)
- **Result**: 4× cache capacity, fewer misses

### Implementation
```cpp
// Block: 32 weights → 18 bytes (scale + 16 nibbles)
struct Q4_0Block {
    uint16_t scale_f16;    // 2 bytes
    uint8_t quants[16];    // 16 bytes (32 nibbles)
};  // Total: 18 bytes vs 128 bytes FP32

// Dequantize on-the-fly during matmul
__m256 DequantizeAndLoad(const Q4_0Block* block, int idx);
```

### Expected Gain
- **Memory**: 4× reduction
- **Cache**: 2-3× hit rate improvement
- **Speed**: 1.5× end-to-end (conservative)

---

## C5b: K-Quant (Q4_K)

### Quality Preservation
- **Q4_0**: Uniform quantization (some quality loss)
- **Q4_K**: Non-uniform, per-block optimization
- **Result**: FP16-level quality at Q4_0 size

### Implementation
```cpp
// Q4_K: Smaller blocks, better scale distribution
struct Q4_KBlock {
    uint16_t scale_f16;
    uint16_t min_f16;      // Additional min value
    uint8_t quants[16];    // Same 32 nibbles
};  // Slightly larger, much better quality
```

---

## C5c: AVX-512 Dequantization

### Speedup
- **Scalar**: 1× baseline
- **AVX2**: 4× (256-bit vectors)
- **AVX-512**: 8× (512-bit vectors)

### Implementation
```cpp
// AVX-512 dequant: 16 weights at once
__m512 DequantizeAVX512(const Q4_0Block* block) {
    __m512 scale = _mm512_set1_ps(F16ToF32(block->scale_f16));
    __m512i quants = LoadNibbles(block->quants);  // Custom load
    return _mm512_mul_ps(scale, _mm512_cvtepi32_ps(quants));
}
```

### Expected Gain
- **Dequant**: 8× faster
- **Matmul**: 2-4× faster (memory bound)
- **End-to-end**: 2× speedup

---

## C5d: Speculative Decoding

### Token Acceptance
- **Draft model**: Small (200M params), fast
- **Target model**: Full model, accurate
- **Acceptance**: 2-3 tokens per forward pass

### Implementation
```cpp
// Draft generates K tokens
std::vector<int> draft_tokens = DraftModel.Generate(prompt, K);

// Target verifies all K in parallel
std::vector<float> logits = TargetModel.Forward(prompt + draft_tokens);

// Accept tokens up to first mismatch
int accepted = VerifyTokens(logits, draft_tokens);
```

### Expected Gain
- **Tokens/pass**: 2-3×
- **Speedup**: 1.5-2× (with 70% acceptance)

---

## Implementation Order

```
Week 1: C5a + C5b (Quantization)
        - Q4_0 kernel
        - Q4_K kernel
        - Integration with C4 baseline
        
Week 2: C5c (AVX-512)
        - Dequant kernels
        - Matmul integration
        - Validation vs FP32
        
Week 3: C5d (Speculative)
        - Draft model loading
        - Acceptance logic
        - End-to-end integration
        
Week 4: Validation + Polish
        - Correctness tests
        - Performance tuning
        - Production integration
```

---

## Success Criteria

| Milestone | Target | Validation |
|-----------|--------|------------|
| C5a Q4_0 | 45+ tok/s | Benchmark vs C4 |
| C5c AVX-512 | 90+ tok/s | Benchmark vs C5a |
| C5d Speculative | 120+ tok/s | Real generation |
| **C5+ Total** | **100+ tok/s** | Sustained 1min run |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Quantization quality loss | Q4_K fallback, per-layer sensitivity analysis |
| AVX-512 not available | AVX2 fallback, dynamic dispatch |
| Speculative acceptance low | Adaptive K, temperature tuning |
| Memory bandwidth bound | Profile first, optimize bottlenecks |

---

**Next Step**: Implement C5a Q4_0 quantization kernel
