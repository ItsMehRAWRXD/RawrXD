; Titan_GEMV_FMA_Core.asm
; High-Frequency AVX2 Fused Multiply-Add (FMA3) Compute Engine
; FIXED: Added horizontal reduction tree to produce scalar dot product
; Constraint: Under 99 Lines, Zero Dependencies

.CODE
ALIGN 16
PUBLIC Titan_GEMV_Interleaved_AVX2
; RCX = const float* interleaved_weights (32-byte aligned)
; RDX = const float* input_vector        (32-byte aligned)
; R8  = float* output_scalar             (Single float destination)
; R9  = size_t vector_dimension          (K, multiple of 8)
Titan_GEMV_Interleaved_AVX2 PROC
    push rbp
    mov rbp, rsp
    test rcx, 1Fh
    jnz Alignment_Fault
    test rdx, 1Fh
    jnz Alignment_Fault
    vxorps ymm0, ymm0, ymm0
    xor rax, rax
    shl r9, 2
Compute_Stride_Loop:
    vmovaps ymm1, ymmword ptr [rdx + rax]
    vmovaps ymm2, ymmword ptr [rcx + rax]
    vfmadd231ps ymm0, ymm1, ymm2
    add rax, 32
    cmp rax, r9
    jb Compute_Stride_Loop
    ; Horizontal reduction: 8 lanes -> 1 scalar
    vperm2f128 ymm1, ymm0, ymm0, 1
    vaddps ymm0, ymm0, ymm1
    vshufps ymm1, ymm0, ymm0, 4Eh
    vaddps ymm0, ymm0, ymm1
    vshufps ymm1, ymm0, ymm0, 11h
    vaddps ymm0, ymm0, ymm1
    vmovss dword ptr [r8], xmm0
    vzeroupper
    mov eax, 1
    pop rbp
    ret
Alignment_Fault:
    xor eax, eax
    pop rbp
    ret
Titan_GEMV_Interleaved_AVX2 ENDP
END
