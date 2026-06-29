/**
 * @file aperture_register_map.md
 * @brief AVX-512 ZMM Register Allocation Strategy
 * @version 1.0.0
 * 
 * Defines the register allocation for Aperture Q4_0 dequantization kernel.
 * Optimized for zero spills and maximum throughput.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

# Aperture AVX-512 Register Map

## Overview

This document defines the ZMM register allocation for the Q4_0 dequantization kernel.
The goal is to minimize register spills and maximize instruction-level parallelism.

## Architecture

- **Target**: Intel/AMD x86-64 with AVX-512F/BW/DQ
- **Register File**: 32 ZMM registers (ZMM0-ZMM31)
- **Mask Registers**: 8 mask registers (K0-K7)
- **Cache Line**: 64 bytes

## Register Allocation

### Input/Output Registers

| Register | Purpose | Persistence |
|----------|---------|-------------|
| RCX | Source pointer (Q4_0 blocks) | Call-preserved |
| RDX | Destination pointer (float32) | Call-preserved |
| R8 | Number of blocks | Call-preserved |
| R12 | Saved source pointer | Callee-saved |
| R13 | Saved destination pointer | Callee-saved |
| R14 | Block counter | Callee-saved |
| R15 | Loop counter | Callee-saved |

### ZMM Register Map

#### Constant Registers (Setup Once)

| ZMM | Purpose | Initialization |
|-----|---------|----------------|
| ZMM14 | Subtract 8 constant | `vpbroadcastd zmm14, [eight]` |
| ZMM15 | Nibble mask (0x0F) | `vpbroadcastq zmm15, 0x0F0F...` |

#### Working Registers (Per Block)

| ZMM | Purpose | Lifetime |
|-----|---------|----------|
| ZMM0 | Scale (broadcasted float32) | Block |
| ZMM1 | Packed weights (16 bytes) | Block |
| ZMM2 | Unpacked low nibbles | Block |
| ZMM3 | Unpacked high nibbles | Block |
| ZMM4 | Low nibbles as int32 | Block |
| ZMM5 | High nibbles as int32 | Block |
| ZMM16 | Output: First 16 floats | Block |
| ZMM17 | Output: Last 16 floats | Block |

#### Available for Future Use

| ZMM | Status | Notes |
|-----|--------|-------|
| ZMM6-ZMM13 | Free | Can be used for 4-block unroll |
| ZMM18-ZMM23 | Free | Can be used for 4-block unroll |
| ZMM24-ZMM31 | Free | Reserved for output staging |

## 4-Block Unroll Strategy

To achieve maximum throughput, we process 4 blocks (128 weights) simultaneously:

```
Block 0: ZMM0 (scale), ZMM1 (weights) -> ZMM16, ZMM17 (output)
Block 1: ZMM2 (scale), ZMM3 (weights) -> ZMM18, ZMM19 (output)
Block 2: ZMM4 (scale), ZMM5 (weights) -> ZMM20, ZMM21 (output)
Block 3: ZMM6 (scale), ZMM7 (weights) -> ZMM22, ZMM23 (output)
```

This allows interleaved execution and hides latency.

## Instruction Flow

### Per Block (32 weights)

```asm
; 1. Load scale (float16) and broadcast
movzx   eax, WORD PTR [src]
call    float16_to_float32_sse      ; ~10 cycles
vbroadcastss zmm0, xmm0             ; 1 cycle

; 2. Load packed weights
vmovdqu64 xmm1, XMMWORD PTR [src+2] ; 1 cycle

; 3. Unpack nibbles
vpmovzxbw ymm1, xmm1                ; 1 cycle
vpandd  zmm2, zmm1, zmm15           ; 1 cycle (low)
vpsrlw  zmm3, zmm1, 4               ; 1 cycle
vpandd  zmm3, zmm3, zmm15           ; 1 cycle (high)

; 4. Convert to int32
vpmovzxwd zmm4, ymm2                ; 1 cycle
vpmovzxwd zmm5, ymm3                ; 1 cycle

; 5. Subtract 8
vpsubd  zmm4, zmm4, zmm14           ; 1 cycle
vpsubd  zmm5, zmm5, zmm14           ; 1 cycle

; 6. Convert to float
vcvtdq2ps zmm4, zmm4                ; 3 cycles
vcvtdq2ps zmm5, zmm5                ; 3 cycles

; 7. Multiply by scale
vmulps  zmm4, zmm4, zmm0            ; 3 cycles
vmulps  zmm5, zmm5, zmm0            ; 3 cycles

; 8. Store results
vmovaps [dst], zmm4                 ; 1 cycle
vmovaps [dst+64], zmm5              ; 1 cycle
```

**Total latency per block**: ~15-20 cycles
**Throughput**: 32 weights / 20 cycles = 1.6 weights/cycle
**With 4-block unroll**: ~6.4 weights/cycle (theoretical)

## Memory Layout

### Input (Q4_0 Block)

```
Offset  Size    Description
0       2       Scale (float16)
2       16      Weights (32 nibbles packed)
18      -       Total block size
```

### Output (Dequantized)

```
Offset  Size    Description
0       128     32 floats (32 * 4 bytes)
```

## Optimization Notes

### 1. Scale Conversion

Float16 to float32 conversion is expensive (~10 cycles).
Strategy: Process 4 blocks to amortize conversion cost.

### 2. Memory Bandwidth

- Input: 18 bytes/block
- Output: 128 bytes/block
- Ratio: 1:7 (compute-bound, not memory-bound)

### 3. Cache Efficiency

- Input fits in L1 (18 bytes * 4 = 72 bytes)
- Output streaming to L2/L3
- No cache thrashing

### 4. Branch Prediction

- Main loop is branchless
- Remainder handling (0-3 blocks) is predictable

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Throughput | 50-100 GB/s | TBD |
| Latency | <1 cycle/weight | TBD |
| Spills | 0 | ✓ |
| Branches | Minimal | ✓ |

## Future Optimizations

1. **VPMADDUBSW**: Use multiply-add for faster conversion
2. **Gather**: Use vgatherdps for irregular access patterns
3. **Prefetch**: Add prefetchnta for streaming stores
4. **FMA**: Use vfmadd for scale multiplication

## Validation

To verify register allocation:

```bash
# Compile with register allocation dump
ml64.exe /c /Zi /Faaperture_q4_0_avx512.asm

# Check for spills in assembly output
grep -i "mov.*rsp" aperture_q4_0_avx512.asm  # Should be empty
```

## References

- Intel 64 and IA-32 Architectures Optimization Reference Manual
- AMD64 Architecture Programmer's Manual
- AVX-512 Instruction Set Architecture
