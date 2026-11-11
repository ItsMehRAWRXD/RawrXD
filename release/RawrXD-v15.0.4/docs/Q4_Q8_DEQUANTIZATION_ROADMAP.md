# Q4/Q8 Dequantization Kernel Roadmap

**Status:** 🚀 Ready for Development  
**Priority:** P0 (Memory Bandwidth Optimization)  
**Estimated Impact:** 2-5x end-to-end inference speedup  
**Target:** RawrXD Phase7b

---

## Executive Summary

The SiLU and Softmax kernels are now production-ready with 50-88x compute speedup. The next bottleneck is **memory bandwidth** - specifically weight dequantization from Q4/Q8 compressed formats.

This roadmap defines high-performance assembly kernels for on-the-fly dequantization, eliminating the memory bandwidth wall in transformer inference.

---

## The Problem: Memory Bandwidth Wall

### Current State
- **Compute:** SiLU/Softmax are now lightning-fast (6-19 µs)
- **Memory:** Weights spend ~70% of inference time being fetched from DRAM
- **Dequantization:** Current C++ implementation is scalar and slow

### Why Q4/Q8 Matters
| Format | Bits/Weight | Relative Size | Use Case |
|--------|-------------|---------------|----------|
| FP32 | 32 | 100% | Training |
| FP16 | 16 | 50% | Inference |
| Q8_0 | 8 | 25% | Quality inference |
| Q4_0 | 4 | 12.5% | Fast inference |
| Q4_K | 4 | 12.5% | Balanced quality |

**Insight:** Dequantization must happen **on-the-fly** during matrix multiplication to avoid materializing full FP16/FP32 tensors in memory.

---

## Architecture: Fused Dequantization-MatMul

### Concept
Instead of:
```
1. Load Q4 weights → 2. Dequant to FP16 → 3. MatMul
```

We do:
```
1. Load Q4 weights → 2. Dequant+MatMul in registers (fused)
```

### Memory Layout Requirements

#### Q4_0 Block Format (GGUF)
```
struct block_q4_0 {
    float   scale;        // 4 bytes (shared for 32 weights)
    uint8_t qs[16];       // 16 bytes (32 nibbles, packed)
}; // 20 bytes total = 4.375 bits/weight
```

#### Q8_0 Block Format (GGUF)
```
struct block_q8_0 {
    float   scale;        // 4 bytes (shared for 32 weights)
    int8_t  qs[32];       // 32 bytes (32 int8 values)
}; // 36 bytes total = 9 bits/weight
```

### Dequantization Formula

```
// Q4_0: 4-bit unsigned, stored as nibbles
weight[i] = (qs[i/2] >> (4*(i&1)) & 0xF) * scale - 8*scale

// Q8_0: 8-bit signed
weight[i] = qs[i] * scale
```

---

## Kernel Specifications

### Kernel 1: Q4_0 Dequantization (AVX2)

**Purpose:** Dequantize Q4_0 blocks to FP32 for matrix multiplication

**Signature:**
```asm
; Parameters:
;   RCX = const block_q4_0* blocks (32-byte aligned)
;   RDX = float* output (32-byte aligned)
;   R8  = size_t num_blocks
; Returns: RAX = 0 on success

MASM_Dequant_Q4_0_AVX2 PROC
```

**Implementation Strategy:**
1. Load 2x blocks (64 weights) per iteration
2. Unpack nibbles using `vpshufb` + lookup table
3. Convert to FP32 using `vcvtdq2ps`
4. Apply scale and bias
5. Store 64 floats

**Performance Target:**
- Throughput: ~1 cycle per weight
- Block processing: ~32 cycles per 32-weight block
- Memory bandwidth: Saturate DDR4-3200 (~50 GB/s)

### Kernel 2: Q8_0 Dequantization (AVX2)

**Purpose:** Dequantize Q8_0 blocks to FP32

**Signature:**
```asm
MASM_Dequant_Q8_0_AVX2 PROC
```

**Implementation Strategy:**
1. Load scale (broadcast to YMM)
2. Load 32 int8 values (256 bits)
3. Sign-extend to int32 using `vpmovsxbw` + `vpmovsxwd`
4. Convert to FP32 using `vcvtdq2ps`
5. Multiply by scale
6. Store 32 floats

**Performance Target:**
- Simpler than Q4 (no nibble unpacking)
- Throughput: ~0.5 cycles per weight

### Kernel 3: Fused Dequant-MatMul (AVX-512)

**Purpose:** Fused dequantization + partial matrix multiplication

**Signature:**
```asm
MASM_Fused_Dequant_MatMul_Q4_AVX512 PROC
```

**Implementation Strategy:**
1. Load activation vector (16 FP32 values in ZMM)
2. For each Q4 block:
   - Dequantize 32 weights to ZMM registers
   - Compute 16 partial dot products using `vfmadd231ps`
   - Accumulate results
3. Return 16 output values

**Performance Target:**
- Eliminate separate dequantization pass
- 2-3x faster than separate kernels
- Requires careful register management (32 ZMM registers available)

---

## Implementation Phases

### Phase 1: Q4_0 Dequantization Kernel (Week 1)
- [ ] Define exact GGUF block layout
- [ ] Implement nibble unpacking (AVX2)
- [ ] Add scale/bias application
- [ ] Write comprehensive tests
- [ ] Benchmark vs scalar implementation

### Phase 2: Q8_0 Dequantization Kernel (Week 1-2)
- [ ] Implement sign-extension (AVX2)
- [ ] Optimize scale broadcast
- [ ] Add tests and benchmarks
- [ ] Compare quality vs Q4_0

### Phase 3: Fused Dequant-MatMul (Week 2-3)
- [ ] Design register allocation strategy
- [ ] Implement AVX-512 version
- [ ] Handle edge cases (partial blocks)
- [ ] Integration with existing MatMul kernels

### Phase 4: Integration & Optimization (Week 3-4)
- [ ] Hook into inference pipeline
- [ ] Add runtime format detection
- [ ] Optimize for different matrix sizes
- [ ] End-to-end benchmarks

---

## Technical Details

### Nibble Unpacking (Q4_0)

The tricky part of Q4_0 is extracting 4-bit values from packed bytes:

```asm
; Input: YMM0 = 32 bytes (64 nibbles packed)
; Output: YMM1-YMM4 = 64 floats (dequantized)

; Step 1: Split into low/high nibbles
vpsrlw  ymm1, ymm0, 4          ; Shift right to get high nibbles
vpand   ymm0, ymm0, ymm_mask   ; Mask low nibbles
vpand   ymm1, ymm1, ymm_mask   ; Mask high nibbles

; Step 2: Interleave to get sequential values
vpackuswb ymm2, ymm0, ymm1     ; Pack to bytes
vpermq    ymm2, ymm2, 0xD8     ; Permute for correct order

; Step 3: Convert to FP32
vpmovzxbd ymm3, xmm2            ; Zero-extend first 4 values
vcvtdq2ps ymm3, ymm3            ; Convert to FP32
; ... repeat for all 64 values
```

### Sign Extension (Q8_0)

```asm
; Input: YMM0 = 32 int8 values
; Output: YMM1 = 32 FP32 values

vpmovsxbw ymm1, xmm0            ; Sign-extend to 16-bit
vextracti128 xmm2, ymm0, 1      ; Get high half
vpmovsxbw ymm2, xmm2            ; Sign-extend high half

; Now have 32 int16 values in ymm1 and ymm2
; Need to extend to int32...
```

---

## ABI Compliance

Following the SiLU/Softmax pattern:

```asm
MASM_Dequant_Q4_0_AVX2 PROC
    ; Save non-volatile registers
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    ; ... implementation ...
    
    ; Restore and return
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
MASM_Dequant_Q4_0_AVX2 ENDP
```

---

## Testing Strategy

### Unit Tests
1. **Correctness:** Dequantize known values, compare to reference
2. **Alignment:** Test with various alignments (should handle 32-byte)
3. **Edge Cases:** Test partial blocks, empty inputs
4. **Error Handling:** Null pointers, misaligned data

### Benchmarks
1. **Throughput:** GB/s dequantization rate
2. **Latency:** Cycles per block
3. **Comparison:** vs scalar C++ implementation
4. **End-to-end:** Full model inference with new kernels

### Validation
```cpp
// Reference implementation (scalar)
void Dequant_Q4_0_Reference(const block_q4_0* blocks, 
                               float* output, 
                               size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = blocks[b].scale;
        for (int i = 0; i < 32; i++) {
            uint8_t byte = blocks[b].qs[i/2];
            uint8_t nibble = (byte >> (4*(i&1))) & 0xF;
            output[b*32 + i] = (nibble - 8) * scale;
        }
    }
}
```

---

## Expected Performance

### Q4_0 Dequantization
| Metric | Scalar C++ | AVX2 Assembly | Speedup |
|--------|------------|---------------|---------|
| Throughput | ~2 GB/s | ~40 GB/s | **20x** |
| Latency | ~100 cycles/block | ~5 cycles/block | **20x** |

### End-to-End Impact
| Model Size | Current (FP16) | With Q4+Dequant | Improvement |
|------------|----------------|-----------------|-------------|
| 7B | 6 GB | 1.5 GB | **4x smaller** |
| 13B | 12 GB | 3 GB | **4x smaller** |
| 70B | 65 GB | 16 GB | **4x smaller** |

**Inference Speed:** 2-5x faster (memory bandwidth limited)

---

## Dependencies

- **GGUF Loader:** Must provide aligned block pointers
- **Memory Pool:** Need aligned allocation for output buffers
- **MatMul Kernels:** Integration point for fused kernel
- **ABI Layer:** Reuse existing assertion framework

---

## Success Criteria

- [ ] Q4_0 kernel achieves >20x speedup over scalar
- [ ] Q8_0 kernel achieves >15x speedup over scalar
- [ ] Fused kernel achieves >2x speedup over separate ops
- [ ] All tests passing (correctness, alignment, edge cases)
- [ ] End-to-end inference shows measurable improvement
- [ ] ABI compliance verified (no register corruption)

---

## Resources

### Reference Implementations
- `llama.cpp` q4_0 dequantization (ggml-quants.c)
- `ggml` Q4_0 CUDA kernels (ggml-cuda.cu)
- Intel AVX2 intrinsics guide

### Documentation
- GGUF format specification
- AVX2/AVX-512 instruction reference
- RawrXD ABI compliance notes (ABI_COMPLIANCE_NOTES.md)

---

## Next Steps

1. **Immediate:** Review and approve this roadmap
2. **Day 1-2:** Implement Q4_0 nibble unpacking
3. **Day 3-4:** Add scale/bias, write tests
4. **Day 5:** Benchmark and optimize
5. **Week 2:** Q8_0 implementation
6. **Week 3:** Fused kernel development
7. **Week 4:** Integration and validation

---

**Ready to begin Phase 1?** The foundation is set with ABI-compliant kernels. Let's break the memory bandwidth wall.

---

*Document Version: 1.0*  
*Author: RawrXD Kernel Team*  
*Date: 2026-07-07*
