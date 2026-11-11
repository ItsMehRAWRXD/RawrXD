;=============================================================================
; Fix #4: Fused Q4_0 MatMul Kernel
; RawrXD IDE - AVX-512 Assembly Implementation
;=============================================================================
; Target: 650 TPS (1.2-1.3x gain over 540 TPS)
; Strategy: Fused dequantize + FMA with zero memory spill
;
; Register Allocation (Strict):
;   ZMM0-ZMM7:   Accumulators (C matrix dot products)
;   ZMM8-ZMM15:  Scale factor broadcast registers
;   ZMM16-ZMM23: Weight loading and unpacking
;   ZMM24-ZMM31: Activation vectors
;=============================================================================

        .code
        OPTION AVXENCODING:AVX512

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
Q4_0_BLOCK_SIZE EQU 32          ; 32 elements per quantization block
Q4_0_NIBBLES_PER_BYTE EQU 2     ; 2 nibbles per byte
BITS_PER_NIBBLE EQU 4

;-----------------------------------------------------------------------------
; Structure: Q4_0Block
;   scale:  float (4 bytes) - block scale factor
;   data:   byte[16] (16 bytes) - 32 packed 4-bit weights
;   Total:  20 bytes per block
;-----------------------------------------------------------------------------
Q4_0_SCALE_OFFSET EQU 0
Q4_0_DATA_OFFSET EQU 4
Q4_0_BLOCK_BYTES EQU 20

;-----------------------------------------------------------------------------
; Macro: FusedDequantizeFMA
;   Fuses 4-bit weight dequantization with FMA in single pipeline
;   Inputs:
;     weight_reg: ZMM register containing packed 4-bit weights
;     scale_reg:  ZMM register containing broadcasted scale
;     accum_reg:  ZMM accumulator for dot product
;     act_reg:    ZMM register containing activation vector
;   Clobbers: weight_reg (unpacked to float), temporary registers
;-----------------------------------------------------------------------------
FusedDequantizeFMA MACRO weight_reg, scale_reg, accum_reg, act_reg, temp_reg1, temp_reg2
        ; Step 1: Extract low nibbles (bits 0-3)
        ; weight_reg = packed bytes, each containing 2 nibbles
        ; temp_reg1 = low nibbles (0-15)
        vpandd          temp_reg1, weight_reg, [low_nibble_mask]
        
        ; Step 2: Extract high nibbles (bits 4-7)  
        ; temp_reg2 = high nibbles (0-15), shifted right
        vpsrld          temp_reg2, weight_reg, BITS_PER_NIBBLE
        vpandd          temp_reg2, temp_reg2, [low_nibble_mask]
        
        ; Step 3: Interleave to get full 32-element block
        ; Use vpmovzxbd to zero-extend bytes to 32-bit integers
        ; Then convert to float and scale
        
        ; Process first 16 elements (low nibbles)
        vpmovzxbd       weight_reg, xmm temp_reg1      ; Zero-extend to 32-bit
        vcvtdq2ps       weight_reg, weight_reg         ; Convert to float
        vmulps          weight_reg, weight_reg, scale_reg  ; Dequantize
        vfmadd231ps     accum_reg, weight_reg, act_reg   ; Fused FMA
        
        ; Process second 16 elements (high nibbles)  
        vpmovzxbd       weight_reg, xmm temp_reg2
        vcvtdq2ps       weight_reg, weight_reg
        vmulps          weight_reg, weight_reg, scale_reg
        vfmadd231ps     accum_reg, weight_reg, act_reg
ENDM

;-----------------------------------------------------------------------------
; Function: RawrXD_FusedQ4_0_MatMul_AVX512
;   C = A * B where B is Q4_0 quantized
;   A: M x K matrix (float32, activation)
;   B: K x N matrix (Q4_0 quantized, weights)
;   C: M x N matrix (float32, output)
;
;   Windows x64 ABI:
;     RCX = A matrix pointer
;     RDX = B matrix pointer (Q4_0 blocks)
;     R8  = C matrix pointer
;     R9  = M (rows of A)
;     [RSP+40] = K (cols of A / rows of B)
;     [RSP+48] = N (cols of B / cols of C)
;     [RSP+56] = lda (leading dimension of A)
;     [RSP+64] = ldc (leading dimension of C)
;-----------------------------------------------------------------------------
RawrXD_FusedQ4_0_MatMul_AVX512 PROC FRAME
        ; Save non-volatile registers
        push            rbp
        .pushreg        rbp
        mov             rbp, rsp
        push            rbx
        .pushreg        rbx
        push            rsi
        .pushreg        rsi
        push            rdi
        .pushreg        rdi
        push            r12
        .pushreg        r12
        push            r13
        .pushreg        r13
        push            r14
        .pushreg        r14
        push            r15
        .pushreg        r15
        .endprolog

        ; Load parameters
        mov             r10, rcx                ; A matrix
        mov             r11, rdx                ; B matrix (Q4_0)
        mov             r12, r8                 ; C matrix
        mov             r13, r9                 ; M
        mov             r14, [rbp+48]           ; K
        mov             r15, [rbp+56]           ; N
        mov             rbx, [rbp+64]           ; lda
        mov             rsi, [rbp+72]           ; ldc

        ; Calculate number of Q4_0 blocks per row
        ; blocks_per_row = K / Q4_0_BLOCK_SIZE
        mov             rax, r14
        xor             rdx, rdx
        mov             rcx, Q4_0_BLOCK_SIZE
        div             rcx
        mov             rdi, rax                ; rdi = blocks_per_row

        ; Outer loop: iterate over M rows
        xor             r8, r8                  ; m = 0
row_loop:
        cmp             r8, r13
        jge             row_done

        ; Inner loop: iterate over N columns
        xor             r9, r9                  ; n = 0
col_loop:
        cmp             r9, r15
        jge             col_done

        ; Initialize 8 accumulators (ZMM0-ZMM7) to zero
        ; Each accumulator handles 16 output elements (512 bits / 32 bits)
        vxorps          zmm0, zmm0, zmm0
        vxorps          zmm1, zmm1, zmm1
        vxorps          zmm2, zmm2, zmm2
        vxorps          zmm3, zmm3, zmm3
        vxorps          zmm4, zmm4, zmm4
        vxorps          zmm5, zmm5, zmm5
        vxorps          zmm6, zmm6, zmm6
        vxorps          zmm7, zmm7, zmm7

        ; Block loop: iterate over K in Q4_0_BLOCK_SIZE chunks
        xor             rax, rax                ; block_idx = 0
block_loop:
        cmp             rax, rdi
        jge             block_done

        ; Load scale factor for this block
        ; Scale is at beginning of each Q4_0 block
        mov             rcx, rax
        imul            rcx, Q4_0_BLOCK_BYTES   ; Offset to block
        add             rcx, r11                ; B matrix base
        vbroadcastss    zmm8, dword ptr [rcx]   ; Broadcast scale to ZMM8

        ; Load 32 packed 4-bit weights (16 bytes)
        vmovdqu64       zmm16, zmmword ptr [rcx+Q4_0_DATA_OFFSET]

        ; Load activation vector (32 floats = 128 bytes)
        ; A row offset: m * lda + block_idx * Q4_0_BLOCK_SIZE
        mov             rdx, r8
        imul            rdx, rbx                ; m * lda
        mov             rcx, rax
        imul            rcx, Q4_0_BLOCK_SIZE  ; block_idx * 32
        add             rdx, rcx
        lea             rdx, [r10+rdx*4]        ; A + offset (float32)
        
        vmovups         zmm24, zmmword ptr [rdx]      ; First 16 floats
        vmovups         zmm25, zmmword ptr [rdx+64]    ; Second 16 floats

        ; Fused dequantize + FMA for first 16 activations
        ; Extract and process low nibbles
        vpandd          zmm17, zmm16, [low_nibble_mask]
        vpmovzxbd       zmm18, xmm17            ; Zero-extend to 32-bit
        vcvtdq2ps       zmm18, zmm18            ; Convert to float
        vmulps          zmm18, zmm18, zmm8      ; Dequantize
        vfmadd231ps     zmm0, zmm18, zmm24      ; FMA into accumulator

        ; Extract and process high nibbles
        vpsrld          zmm17, zmm16, BITS_PER_NIBBLE
        vpandd          zmm17, zmm17, [low_nibble_mask]
        vpmovzxbd       zmm18, xmm17
        vcvtdq2ps       zmm18, zmm18
        vmulps          zmm18, zmm18, zmm8
        vfmadd231ps     zmm1, zmm18, zmm25      ; Second half

        ; Interleaved integer/float for pipeline efficiency
        ; Preload next block's scale while FMA retires
        inc             rax
        cmp             rax, rdi
        jge             skip_preload
        mov             rcx, rax
        imul            rcx, Q4_0_BLOCK_BYTES
        add             rcx, r11
        vbroadcastss    zmm9, dword ptr [rcx]   ; Preload next scale
skip_preload:

        jmp             block_loop
block_done:

        ; Store results to C matrix
        ; C offset: m * ldc + n
        mov             rdx, r8
        imul            rdx, rsi                ; m * ldc
        add             rdx, r9                   ; + n
        lea             rdx, [r12+rdx*4]        ; C + offset

        vmovups         zmmword ptr [rdx], zmm0
        vmovups         zmmword ptr [rdx+64], zmm1
        vmovups         zmmword ptr [rdx+128], zmm2
        vmovups         zmmword ptr [rdx+192], zmm3
        vmovups         zmmword ptr [rdx+256], zmm4
        vmovups         zmmword ptr [rdx+320], zmm5
        vmovups         zmmword ptr [rdx+384], zmm6
        vmovups         zmmword ptr [rdx+448], zmm7

        add             r9, 128                 ; n += 128 (8 ZMM registers * 16 floats)
        jmp             col_loop
col_done:

        inc             r8                      ; m++
        jmp             row_loop
row_done:

        ; Restore non-volatile registers
        vzeroupper
        pop             r15
        pop             r14
        pop             r13
        pop             r12
        pop             rdi
        pop             rsi
        pop             rbx
        pop             rbp
        ret
RawrXD_FusedQ4_0_MatMul_AVX512 ENDP

;-----------------------------------------------------------------------------
; Data Section: Constants
;-----------------------------------------------------------------------------
        .data
        ALIGN 64
low_nibble_mask:
        DD 16 DUP (0x0F)        ; 16 dwords of 0x0F for nibble masking

        END
