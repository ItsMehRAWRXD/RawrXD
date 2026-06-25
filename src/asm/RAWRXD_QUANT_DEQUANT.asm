;==============================================================================
; RAWRXD_QUANT_DEQUANT.asm
; LANE B: NATIVE SUB-PRECISION QUANTIZATION ENGINES
; Vectorized INT8 -> FP32 dequantization with AVX-512 / AVX2 dispatch
; Zero-CRT, compact, no scaffolding.
;==============================================================================
OPTION CASEMAP:NONE

.CODE

;------------------------------------------------------------------------------
; Quant_Dequant_INT8_AVX512(
;     pSrc:rcx, pDst:rdx, n:r8d, pParams:r9
; )
; Dequantizes n int8 values to float32 using AVX-512.
; pParams points to: { float scale; int32_t zero_point; }
; Processes 16 int8 -> 16 float per iteration (64 bytes output).
; Clobbers: zmm0-zmm3, rax, r10, r11
;------------------------------------------------------------------------------
Quant_Dequant_INT8_AVX512 PROC
    test rcx, rcx
    jz @@done
    test rdx, rdx
    jz @@done
    test r8d, r8d
    jz @@done
    test r9, r9
    jz @@done

    ; Load scale and zero_point from params struct
    vbroadcastss zmm3, dword ptr [r9]        ; scale broadcast to all lanes
    vpbroadcastd zmm2, dword ptr [r9+4]      ; zero_point broadcast to all lanes

    mov r10d, r8d
    shr r10d, 4              ; n / 16 (main loop count)
    jz @@tail

@@loop16:
    ; Load 16 int8 values (16 bytes) into xmm0
    vmovdqu xmm0, xmmword ptr [rcx]
    ; Sign-extend int8 -> int32 across 512 bits (4 per 128-bit lane * 4 lanes)
    vpmovsxbd zmm1, xmm0
    ; Subtract zero_point
    vpsubd zmm1, zmm1, zmm2
    ; Convert int32 -> float32
    vcvtdq2ps zmm0, zmm1
    ; Multiply by scale
    vmulps zmm0, zmm0, zmm3
    ; Store 16 floats (64 bytes)
    vmovups zmmword ptr [rdx], zmm0

    add rcx, 16
    add rdx, 64
    dec r10d
    jnz @@loop16

@@tail:
    ; Handle remaining elements (0-15) with scalar fallback
    mov r10d, r8d
    and r10d, 15             ; n % 16
    jz @@done

    ; Load scale and zp into GPRs for scalar path
    movss xmm3, dword ptr [r9]
    mov r11d, dword ptr [r9+4]

@@tail_loop:
    movsx eax, byte ptr [rcx]    ; int8 -> int32
    sub eax, r11d                ; subtract zero_point
    cvtsi2ss xmm0, eax           ; int32 -> float
    mulss xmm0, xmm3             ; * scale
    movss dword ptr [rdx], xmm0
    inc rcx
    add rdx, 4
    dec r10d
    jnz @@tail_loop

@@done:
    vzeroupper
    ret
Quant_Dequant_INT8_AVX512 ENDP

;------------------------------------------------------------------------------
; Quant_Dequant_INT8_AVX2(
;     pSrc:rcx, pDst:rdx, n:r8d, pParams:r9
; )
; Dequantizes n int8 values to float32 using AVX2.
; pParams points to: { float scale; int32_t zero_point; }
; Processes 8 int8 -> 8 float per iteration (32 bytes output).
; Clobbers: ymm0-ymm3, rax, r10, r11
;------------------------------------------------------------------------------
Quant_Dequant_INT8_AVX2 PROC
    test rcx, rcx
    jz @@done
    test rdx, rdx
    jz @@done
    test r8d, r8d
    jz @@done
    test r9, r9
    jz @@done

    ; Load scale and zero_point from params struct
    vbroadcastss ymm3, dword ptr [r9]        ; scale broadcast
    vpbroadcastd ymm2, dword ptr [r9+4]      ; zero_point broadcast

    mov r10d, r8d
    shr r10d, 3              ; n / 8 (main loop count)
    jz @@tail

@@loop8:
    ; Load 8 int8 values (8 bytes) into xmm0
    vmovq xmm0, qword ptr [rcx]
    ; Sign-extend int8 -> int32 across 256 bits (4 per 128-bit lane * 2 lanes)
    vpmovsxbd ymm1, xmm0
    ; Subtract zero_point
    vpsubd ymm1, ymm1, ymm2
    ; Convert int32 -> float32
    vcvtdq2ps ymm0, ymm1
    ; Multiply by scale
    vmulps ymm0, ymm0, ymm3
    ; Store 8 floats (32 bytes)
    vmovups ymmword ptr [rdx], ymm0

    add rcx, 8
    add rdx, 32
    dec r10d
    jnz @@loop8

@@tail:
    ; Handle remaining elements (0-7) with scalar fallback
    mov r10d, r8d
    and r10d, 7              ; n % 8
    jz @@done

    ; Load scale and zp into GPRs for scalar path
    movss xmm3, dword ptr [r9]
    mov r11d, dword ptr [r9+4]

@@tail_loop:
    movsx eax, byte ptr [rcx]
    sub eax, r11d
    cvtsi2ss xmm0, eax
    mulss xmm0, xmm3
    movss dword ptr [rdx], xmm0
    inc rcx
    add rdx, 4
    dec r10d
    jnz @@tail_loop

@@done:
    vzeroupper
    ret
Quant_Dequant_INT8_AVX2 ENDP

END
