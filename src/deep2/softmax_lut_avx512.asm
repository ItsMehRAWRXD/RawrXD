; ============================================================================
; softmax_lut_avx512.asm - AVX-512 Softmax with fast exp approximation
;
; Simplified vectorized approach: no scalar loop, all vector ops.
; Uses 2^(x*log2(e)) with truncation for integer part.
;
; ABI (Windows x64):
;   rcx = input scores (float*)
;   rdx = output probabilities (float*)
;   r8  = exp_lut (float*, 256 entries - unused in simplified version)
;   r9  = n (size_t, must be 16)
;
; Copyright (c) 2026 RawrXD Sovereign Runtime
; ============================================================================

.code

SoftmaxLUT_AVX512 PROC public

    push rbx
    sub  rsp, 32

    ; --- Step 1: Load 16 floats ---
    vmovups zmm0, [rcx]               ; zmm0 = input scores

    ; --- Step 2: Find max ---
    vextractf32x8 ymm1, zmm0, 1
    vmaxps  ymm2, ymm1, ymm0
    vextractf32x4 xmm3, ymm2, 1
    vmaxps  xmm4, xmm2, xmm3          ; xmm4 = max across all 8 lanes of ymm2
    vshufps xmm5, xmm4, xmm4, 4Eh
    vmaxps  xmm5, xmm5, xmm4
    vshufps xmm6, xmm5, xmm5, 0B1h
    vmaxps  xmm6, xmm6, xmm5
    vbroadcastss zmm10, xmm6          ; zmm10 = max

    ; --- Step 3: Subtract max ---
    vsubps  zmm11, zmm0, zmm10        ; zmm11 = scores - max

    ; --- Step 4: Fast exp via 2^(x * log2(e)) ---
    mov  eax, 3FB8AA3Bh               ; log2(e)
    vmovd xmm1, eax
    vbroadcastss zmm12, xmm1
    vmulps  zmm13, zmm11, zmm12       ; x * log2(e)

    ; Floor via cvtps2dq + cvtdq2ps
    vcvtps2dq zmm14, zmm13            ; int32
    vcvtdq2ps zmm14, zmm14            ; back to float (truncated)
    vsubps   zmm15, zmm13, zmm14      ; fractional part

    ; 2^frac ≈ 1 + f * ln2 (vectorized)
    mov  eax, 3F317218h               ; ln2
    vmovd xmm1, eax
    vbroadcastss zmm16, xmm1
    vmulps  zmm17, zmm15, zmm16       ; f * ln2
    mov  eax, 3F800000h               ; 1.0
    vmovd xmm1, eax
    vbroadcastss zmm18, xmm1
    vaddps  zmm19, zmm18, zmm17       ; 1 + f*ln2

    ; 2^int: for each lane, extract int, add 127, shift left 23
    ; zmm14 has the integer parts as floats
    ; Store to stack, process as integers
    sub  rsp, 64
    vmovups [rsp], zmm14
    vcvtps2dq ymm1, ymmword ptr [rsp]      ; lower 8 ints
    vcvtps2dq ymm2, ymmword ptr [rsp+32]   ; upper 8 ints

    ; Add 127 to each
    mov  eax, 127
    vmovd xmm3, eax
    vbroadcastss ymm4, xmm3
    vpaddd  ymm1, ymm1, ymm4
    vpaddd  ymm2, ymm2, ymm4

    ; Shift left 23 (pslld)
    vpslld  ymm1, ymm1, 23
    vpslld  ymm2, ymm2, 23

    ; Store int values, load as floats (reinterpret bits)
    vmovups ymmword ptr [rsp], ymm1
    vmovups ymmword ptr [rsp+32], ymm2
    vmovups zmm20, [rsp]              ; zmm20 = 2^int (reinterpreted bits)

    ; exp = 2^int * 2^frac
    vmulps  zmm21, zmm20, zmm19       ; zmm21 = exp(scores)

    ; --- Step 5: Sum reduction ---
    vextractf32x8 ymm22, zmm21, 1
    vaddps  ymm23, ymm22, ymm21       ; combine halves (low + high)
    vextractf32x4 xmm24, ymm23, 1
    vaddps  xmm25, xmm24, xmm23       ; combine quarters (low + high)
    vshufps xmm26, xmm25, xmm25, 4Eh
    vaddps  xmm26, xmm26, xmm25
    vshufps xmm27, xmm26, xmm26, 0B1h
    vaddss  xmm28, xmm27, xmm26       ; xmm28 = sum

    ; --- Step 6: Reciprocal ---
    mov  eax, 3F800000h               ; 1.0
    vmovd xmm29, eax
    vdivss xmm30, xmm29, xmm28        ; 1/sum

    ; --- Step 7: Normalize ---
    vbroadcastss zmm31, xmm30
    vmulps  zmm0, zmm21, zmm31        ; softmax = exp / sum

    ; --- Store ---
    vmovups [rdx], zmm0

    add  rsp, 64
    add  rsp, 32
    pop  rbx
    vzeroupper
    ret

SoftmaxLUT_AVX512 ENDP

end