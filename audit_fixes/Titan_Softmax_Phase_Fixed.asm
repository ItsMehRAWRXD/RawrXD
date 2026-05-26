; Titan_Softmax_Phase.asm
; Ultra-High-Frequency In-Place 8-Channel Vector Softmax Engine
; FIXED: Replaced divergent 3rd-order Taylor with Schraudolph bit-hack fast_exp2
; Valid because x <= 0 after max-subtraction, and e^x = 2^(x/ln2)
; Constraint: Under 99 Lines, Zero Dependencies

.DATA
ALIGN 32
ExpMagic     REAL4 12102203.0, 12102203.0, 12102203.0, 12102203.0, 12102203.0, 12102203.0, 12102203.0, 12102203.0
ExpOffset    REAL4 1065353216.0, 1065353216.0, 1065353216.0, 1065353216.0, 1065353216.0, 1065353216.0, 1065353216.0, 1065353216.0
Ln2Inv       REAL4 1.442695041, 1.442695041, 1.442695041, 1.442695041, 1.442695041, 1.442695041, 1.442695041, 1.442695041

.CODE
ALIGN 16
PUBLIC Titan_Vector_Softmax_AVX2
; RCX = float* target_vector (8 contiguous elements, 32-byte aligned)
Titan_Vector_Softmax_AVX2 PROC
    push rbp
    mov rbp, rsp
    test rcx, 1Fh
    jnz Execution_Fault
    vmovaps ymm0, ymmword ptr [rcx]
    ; Horizontal max reduction
    vperm2f128 ymm1, ymm0, ymm0, 1
    vmaxps ymm2, ymm0, ymm1
    vshufps ymm1, ymm2, ymm2, 4Eh
    vmaxps ymm2, ymm2, ymm1
    vshufps ymm1, ymm2, ymm2, 11h
    vmaxps ymm1, ymm2, ymm1
    vsubps ymm0, ymm0, ymm1
    ; Fast e^x via bit-hack: e^x = 2^(x/ln2)
    vmovaps ymm2, ymmword ptr [Ln2Inv]
    vmulps ymm0, ymm0, ymm2
    vmovaps ymm2, ymmword ptr [ExpMagic]
    vmovaps ymm3, ymmword ptr [ExpOffset]
    vfmadd231ps ymm3, ymm0, ymm2
    vcvttps2dq ymm3, ymm3
    vcvtdq2ps ymm0, ymm3
    ; Horizontal sum
    vperm2f128 ymm3, ymm0, ymm0, 1
    vaddps ymm4, ymm0, ymm3
    vshufps ymm3, ymm4, ymm4, 4Eh
    vaddps ymm4, ymm4, ymm3
    vshufps ymm3, ymm4, ymm4, 11h
    vaddps ymm4, ymm4, ymm3
    ; Divide
    vdivps ymm0, ymm0, ymm4
    vmovaps ymmword ptr [rcx], ymm0
    vzeroupper
    mov eax, 1
    pop rbp
    ret
Execution_Fault:
    xor eax, eax
    pop rbp
    ret
Titan_Vector_Softmax_AVX2 ENDP
END
