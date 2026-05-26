; Titan_Vector_Scale_Add.asm
; NEW KERNEL: Fused Scale-Multiply-Add-Accumulate
; Computes: dest[i] += (src[i] * scale) + bias[i]
; 5th arg (scale) passed in XMM0 per Windows x64 float register rule
; Constraint: Under 99 Lines, Zero Dependencies

.CODE
ALIGN 16
PUBLIC Titan_Vector_Scale_Add_AVX2
; RCX = float* dest (32-byte aligned)
; RDX = const float* src (32-byte aligned)
; R8  = const float* bias (32-byte aligned)
; R9  = size_t count (multiple of 8)
; XMM0 = float scale
Titan_Vector_Scale_Add_AVX2 PROC
    push rbp
    mov rbp, rsp
    test rcx, 1Fh
    jnz Fault
    test rdx, 1Fh
    jnz Fault
    test r8, 1Fh
    jnz Fault
    vbroadcastss ymm4, xmm0
    xor rax, rax
    shl r9, 2
Loop:
    vmovaps ymm0, ymmword ptr [rdx + rax]
    vmovaps ymm1, ymmword ptr [r8 + rax]
    vmovaps ymm2, ymmword ptr [rcx + rax]
    vfmadd231ps ymm1, ymm0, ymm4
    vaddps ymm2, ymm2, ymm1
    vmovaps ymmword ptr [rcx + rax], ymm2
    add rax, 32
    cmp rax, r9
    jb Loop
    vzeroupper
    mov eax, 1
    pop rbp
    ret
Fault:
    xor eax, eax
    pop rbp
    ret
Titan_Vector_Scale_Add_AVX2 ENDP
END
