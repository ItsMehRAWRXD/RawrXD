; Titan_RMS_Norm.asm
; High-Frequency Vectorized RMSNorm Compute Engine
; FIXED: vrsqrtss 2-operand SSE syntax -> 3-operand AVX syntax
; Constraint: Under 99 Lines, Zero Dependencies

.CODE
ALIGN 16
PUBLIC Titan_RMS_Norm_AVX2
; RCX = float* target_vector     (8 elements, 32-byte aligned)
; RDX = const float* gamma_gain  (8 elements, 32-byte aligned)
; XMM2 = float epsilon            (x64 calling convention)
Titan_RMS_Norm_AVX2 PROC
    push rbp
    mov rbp, rsp
    test rcx, 1Fh
    jnz Alignment_Fault
    test rdx, 1Fh
    jnz Alignment_Fault
    vmovaps ymm0, ymmword ptr [rcx]
    vmovaps ymm1, ymmword ptr [rdx]
    vmulps ymm3, ymm0, ymm0
    vperm2f128 ymm4, ymm3, ymm3, 1
    vaddps ymm5, ymm3, ymm4
    vshufps ymm4, ymm5, ymm5, 4Eh
    vaddps ymm5, ymm5, ymm4
    vshufps ymm4, ymm5, ymm5, 11h
    vaddps ymm5, ymm5, ymm4
    mov eax, 041000000h
    movd xmm4, eax
    divss xmm5, xmm4
    addss xmm5, xmm2
    ; FIXED: explicit 3-operand AVX encoding
    vrsqrtss xmm5, xmm5, xmm5
    vbroadcastss ymm5, xmm5
    vmulps ymm0, ymm0, ymm5
    vmulps ymm0, ymm0, ymm1
    vmovaps ymmword ptr [rcx], ymm0
    vzeroupper
    mov eax, 1
    pop rbp
    ret
Alignment_Fault:
    xor eax, eax
    pop rbp
    ret
Titan_RMS_Norm_AVX2 ENDP
END
