; Titan_Vector_Hadamard_Bias.asm
; High-Frequency Fused Elementwise Multiplication and Add Engine
; FIXED: vfmadd213ps -> vfmadd231ps for correct dest += a * b
; Constraint: Under 99 Lines, Zero Dependencies

.CODE
ALIGN 16
PUBLIC Titan_Vector_Merge_AVX2
; RCX = float* vector_a_dest (Primary vector accumulator, 32-byte aligned)
; RDX = const float* vector_b    (Secondary factor matrix input, 32-byte aligned)
; R8  = const float* bias_vector (Bias baseline configuration array, 32-byte aligned)
; R9  = size_t element_count     (Dimension tracking parameter, multiple of 8)
Titan_Vector_Merge_AVX2 PROC
    push rbp
    mov rbp, rsp
    test rcx, 1Fh
    jnz Pipeline_Fault
    test rdx, 1Fh
    jnz Pipeline_Fault
    test r8, 1Fh
    jnz Pipeline_Fault
    xor rax, rax
    shl r9, 2
Merge_Loop:
    vmovaps ymm0, ymmword ptr [rcx + rax]
    vmovaps ymm1, ymmword ptr [rdx + rax]
    vmovaps ymm2, ymmword ptr [r8 + rax]
    ; FIXED: ymm2 = (ymm0 * ymm1) + ymm2  -> dest = (dest * src) + bias
    vfmadd231ps ymm2, ymm0, ymm1
    vmovaps ymmword ptr [rcx + rax], ymm2
    add rax, 32
    cmp rax, r9
    jb Merge_Loop
    vzeroupper
    mov eax, 1
    pop rbp
    ret
Pipeline_Fault:
    xor eax, eax
    pop rbp
    ret
Titan_Vector_Merge_AVX2 ENDP
END
