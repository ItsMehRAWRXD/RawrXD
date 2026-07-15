# GFX1101 (RDNA3) Opcode Reference

## Real Instruction Encodings for RX 7800 XT

Based on AMD RDNA3 ISA Document 57019

---

## VOP3P Instructions (Matrix Operations)

### v_wmma_f16_16x16x16_f16
**Description**: Matrix multiply-accumulate FP16 16x16x16 tiles  
**Encoding**: `0xD5CC` prefix + operands  
**Format**: `v_wmma_f16_16x16x16_f16 vdst, vsrc0, vsrc1, vsrc2`  
**Bytes**: `CC 00 vdst D5 | vsrc0 vsrc1 vsrc2 00`

```
DWORD0: CC 00 VDST D5
DWORD1: SRC0 SRC1 SRC2 00
```

### v_wmma_f32_16x16x16_f16
**Description**: Matrix multiply-accumulate FP32 result, FP16 inputs  
**Encoding**: `0xD5CD` prefix  
**Bytes**: `CD 00 vdst D5 | vsrc0 vsrc1 vsrc2 00`

### v_wmma_i32_16x16x16_iu8
**Description**: Integer matrix multiply for quantized ops  
**Encoding**: `0xD5D0` prefix  
**Bytes**: `D0 00 vdst D5 | vsrc0 vsrc1 vsrc2 00`

---

## SMEM Instructions (Scalar Memory)

### s_load_dwordx4
**Description**: Load 128 bits from scalar memory  
**Encoding**: SMEM format  
**Bytes**: `offset_lo offset_hi 03 00 | sdst sbase 00 00`

### s_load_dwordx8
**Description**: Load 256 bits from scalar memory  
**Encoding**: SMEM format  
**Bytes**: `offset_lo offset_hi 04 00 | sdst sbase 00 00`

---

## MUBUF Instructions (Buffer Operations)

### buffer_load_dword
**Description**: Load dword from buffer  
**Encoding**: MUBUF format  
**Bytes**: `00 00 vdst 18 | vaddr 00 srd E0`

### buffer_load_dwordx4
**Description**: Load 128 bits from buffer  
**Encoding**: MUBUF format  
**Bytes**: `00 00 vdst 1C | vaddr 00 srd E0`

### buffer_store_dword
**Description**: Store dword to buffer  
**Encoding**: MUBUF format  
**Bytes**: `00 00 vdata 58 | vaddr 00 srd E0`

---

## SOPP Instructions (Scalar Control Flow)

### s_barrier
**Description**: Wait for all waves in workgroup  
**Encoding**: SOPP  
**Bytes**: `FF 0F 00 BF` (with SIMM16=0x0FFF)

### s_waitcnt
**Description**: Wait for memory operations  
**Encoding**: SOPP  
**Format**: `s_waitcnt vmcnt(n) & lgkmcnt(m)`  
**Bytes**: `((lgkmcnt << 4) | vmcnt) 0F 00 BF`

Examples:
- `s_waitcnt vmcnt(0)`: `0F 0F 00 BF`
- `s_waitcnt lgkmcnt(0)`: `F0 0F 00 BF`
- `s_waitcnt vmcnt(0) & lgkmcnt(0)`: `FF 0F 00 BF`

### s_branch
**Description**: Unconditional branch  
**Encoding**: SOPP  
**Bytes**: `offset_lo offset_hi 00 BF`

### s_cbranch_scc0
**Description**: Branch if SCC=0  
**Encoding**: SOPP  
**Bytes**: `offset_lo offset_hi 04 BF`

### s_cbranch_scc1
**Description**: Branch if SCC=1  
**Encoding**: SOPP  
**Bytes**: `offset_lo offset_hi 05 BF`

### s_endpgm
**Description**: End of program  
**Encoding**: SOPP  
**Bytes**: `00 00 9C BF`

---

## VOP1 Instructions (Vector Unary)

### v_mov_b32
**Description**: Move 32-bit value  
**Encoding**: VOP1  
**Bytes**: `src 00 dst 7E`

### v_cvt_f32_u32
**Description**: Convert unsigned int to float  
**Encoding**: VOP1  
**Bytes**: `src 00 dst 7E 0A 00 00 00`

### v_cvt_f16_f32
**Description**: Convert float to half-float  
**Encoding**: VOP1  
**Bytes**: `src 00 dst 7E 0A 00 00 00`

---

## VOP2 Instructions (Vector Binary)

### v_add_u32
**Description**: Add unsigned 32-bit  
**Encoding**: VOP2  
**Bytes**: `src1 00 dst 4F | src0 00 00 00`

### v_add_f16
**Description**: Add half-float  
**Encoding**: VOP2  
**Bytes**: `src1 00 dst 13 | src0 00 00 00`

### v_mul_f16
**Description**: Multiply half-float  
**Encoding**: VOP2  
**Bytes**: `src1 00 dst 10 | src0 00 00 00`

### v_and_b32
**Description**: Bitwise AND  
**Encoding**: VOP2  
**Bytes**: `src1 00 dst 12 | src0 00 00 00`

### v_lshlrev_b32
**Description**: Logical shift left (reverse)  
**Encoding**: VOP2  
**Bytes**: `src1 00 dst 2A | ssrc0 00 00 00`

---

## VOP3A Instructions (Vector Ternary)

### v_mbcnt_lo_u32_b32
**Description**: Masked bit count low  
**Encoding**: VOP3A  
**Bytes**: `CB 00 dst D5 | src 00 ssrc 00`

### v_mbcnt_hi_u32_b32
**Description**: Masked bit count high  
**Encoding**: VOP3A  
**Bytes**: `CC 00 dst D5 | src 00 ssrc 00`

### v_dot2_f32_f16
**Description**: 2-way dot product FP16->FP32  
**Encoding**: VOP3A  
**Bytes**: `C1 00 dst D5 | src0 src1 src2 00`

### v_fma_f32
**Description**: Fused multiply-add FP32  
**Encoding**: VOP3A  
**Bytes**: `C0 00 dst D5 | src0 src1 src2 00`

---

## Scalar ALU Instructions

### s_mov_b32
**Description**: Move scalar 32-bit  
**Encoding**: SOP1  
**Bytes**: `src 00 00 BE | dst 00 00 00`

### s_add_u32
**Description**: Add unsigned 32-bit scalar  
**Encoding**: SOP2  
**Bytes**: `src1 00 src0 80 | dst 00 00 00`

### s_cmp_lt_u32
**Description**: Compare unsigned less than  
**Encoding**: SOPC  
**Bytes**: `src1 00 src0 BF | 02 00 00 80`

---

## Kernel Binary Format

### AMD GPU Magic Number
```
64 86 01 00 00 00 00 00  ; Magic: 0x016864
01 10 00 00 00 00 00 00  ; gfx1101 target
00 00 00 00 00 00 00 00  ; Version
```

### Kernel Code Header (64 bytes)
```
00 01 00 00 00 00 00 00  ; Code size (256 bytes)
00 00 00 00 00 00 00 00  ; Reserved
00 00 00 00 00 00 00 00  ; Reserved
00 00 00 00 00 00 00 00  ; Reserved
```

---

## Usage Example

```asm
; Load kernel arguments
s_load_dwordx4 s0, s4, 0      ; Load first 4 args
s_waitcnt lgkmcnt(0)           ; Wait for load

; Calculate thread ID
v_mbcnt_lo_u32_b32 v0, 0, 0
v_mbcnt_hi_u32_b32 v0, 0, v0

; WMMA matrix multiply
v_wmma_f16_16x16x16_f16 v0, v16, v32, v0

; Store result
buffer_store_dword v0, v1, s8
s_waitcnt vmcnt(0)

; End kernel
s_endpgm
```

---

## Notes

1. **Little-endian encoding**: All multi-byte values are little-endian
2. **Register numbering**: V0-V255 for vectors, S0-S103 for scalars
3. **Wavefront size**: 64 threads on gfx1101
4. **WMMA tile size**: 16x16x16 for FP16 operations
5. **LDS size**: 128KB per CU on RX 7800 XT

## References

- AMD RDNA3 ISA Document 57019
- AMD GPUOpen documentation
- ROCm compiler output analysis
