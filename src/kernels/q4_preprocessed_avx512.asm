;=============================================================================
; Q4_0 Preprocessed Weight AVX-512 Kernel
; Fast dot product using byte-planar weights
;
; Input: Preprocessed block (128 bytes):
;   [0:15]  Q4BlockHeader (16 bytes)
;   [16:19] scale (fp32)
;   [20:83] 64 unpacked int8 weights (-8 to +7)
;   [84:127] padding
;
; Process: 64 weights in 4 chunks of 16
;   Load 16 int8 weights
;   Sign-extend to int32
;   Convert to float
;   Multiply by scale
;   FMA with 16 activations
;=============================================================================

include rawrxd_win64.inc

.data
align 8
    sz_q4_start db "[Q4] Preprocessed dot start", 0

.code

;-----------------------------------------------------------------------------
; q4_preprocessed_dot_avx512_asm
; Input:  rcx = PreprocessedQ4Block* (128 bytes, aligned)
;         rdx = activations* (64 x fp32, aligned)
; Output: xmm0 = dot product (fp32)
;-----------------------------------------------------------------------------
PUBLIC q4_preprocessed_dot_avx512_asm
q4_preprocessed_dot_avx512_asm PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    .endprolog

    mov rbx, rcx                        ; block ptr
    mov r12, rdx                        ; activations ptr

    ; Load scale (fp32, already converted during preprocessing)
    ; Header is 16 bytes, scale is at offset 16
    vbroadcastss zmm7, DWORD PTR [rbx + 16]  ; zmm7 = scale (all 16 lanes)

    ; Initialize accumulator
    vpxord zmm0, zmm0, zmm0              ; zmm0 = accumulator

    ; === Pass 1: Weights 0-15 ===
    ; Weights start at offset 20 (header 16 + scale 4)
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 20]   ; sign-extend 16 int8 -> int32
    vcvtdq2ps zmm1, zmm1                 ; int32 -> fp32
    vmulps zmm1, zmm1, zmm7              ; * scale

    ; Load 16 activations
    vmovaps zmm2, ZMMWORD PTR [r12]      ; activations[0:15]

    ; FMA: acc += weight * activation
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 2: Weights 16-31 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 36]  ; weights[16:31] (offset 20 + 16)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 64]    ; activations[16:31]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 3: Weights 32-47 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 52]  ; weights[32:47] (offset 20 + 32)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 128]   ; activations[32:47]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 4: Weights 48-63 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 68]  ; weights[48:63] (offset 20 + 48)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 192]   ; activations[48:63]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Horizontal sum of zmm0 ===
    ; zmm0 has 16 partial sums
    ; Reduce to single float in xmm0

    ; Extract high 8 floats and add to low 8
    vextractf64x4 ymm1, zmm0, 1         ; high 8 floats
    vaddps ymm0, ymm0, ymm1             ; 8 floats

    ; Extract high 4 floats and add to low 4
    vextractf128 xmm1, ymm0, 1          ; high 4 floats
    vaddps xmm0, xmm0, xmm1             ; 4 floats

    ; Horizontal add within xmm0
    vshufps xmm1, xmm0, xmm0, 04Eh      ; [2,3,0,1]
    vaddps xmm0, xmm0, xmm1             ; [0+2, 1+3, ...]

    vshufps xmm1, xmm0, xmm0, 0B1h      ; [1,0,3,2]
    vaddss xmm0, xmm0, xmm1             ; final sum in xmm0[0]

    pop r12
    pop rbx
    ret

q4_preprocessed_dot_avx512_asm ENDP

END
