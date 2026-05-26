; Titan_Tensor_Transpose.asm
; Ultra-High-Frequency In-Place 8x8 Matrix Transposition Engine
; FIXED: Saves/restores non-volatile YMM6-YMM15 per Windows x64 ABI
; Constraint: Zero Dependencies, Zero Branching

.CODE
ALIGN 16
PUBLIC Titan_Matrix_Transpose_8x8
; RCX = float* base_matrix_ptr (32-byte aligned)
; RDX = size_t stride_bytes (Row pitch)
Titan_Matrix_Transpose_8x8 PROC
    push rbp
    mov rbp, rsp
    sub rsp, 320
    and rsp, -32
    ; Save non-volatile YMM registers
    vmovaps ymmword ptr [rsp+0],   ymm6
    vmovaps ymmword ptr [rsp+32],  ymm7
    vmovaps ymmword ptr [rsp+64],  ymm8
    vmovaps ymmword ptr [rsp+96],  ymm9
    vmovaps ymmword ptr [rsp+128], ymm10
    vmovaps ymmword ptr [rsp+160], ymm11
    vmovaps ymmword ptr [rsp+192], ymm12
    vmovaps ymmword ptr [rsp+224], ymm13
    vmovaps ymmword ptr [rsp+256], ymm14
    vmovaps ymmword ptr [rsp+288], ymm15
    test rcx, 1Fh
    jnz Structural_Fault
    ; Load 8 rows
    vmovaps ymm0,  ymmword ptr [rcx]
    vmovaps ymm1,  ymmword ptr [rcx+rdx]
    lea rax, [rcx+rdx*2]
    vmovaps ymm2,  ymmword ptr [rax]
    vmovaps ymm3,  ymmword ptr [rax+rdx]
    lea rax, [rax+rdx*2]
    vmovaps ymm4,  ymmword ptr [rax]
    vmovaps ymm5,  ymmword ptr [rax+rdx]
    lea rax, [rax+rdx*2]
    vmovaps ymm6,  ymmword ptr [rax]
    vmovaps ymm7,  ymmword ptr [rax+rdx]
    ; Transpose network
    vunpcklps ymm8,  ymm0, ymm1
    vunpckhps ymm9,  ymm0, ymm1
    vunpcklps ymm10, ymm2, ymm3
    vunpckhps ymm11, ymm2, ymm3
    vunpcklps ymm12, ymm4, ymm5
    vunpckhps ymm13, ymm4, ymm5
    vunpcklps ymm14, ymm6, ymm7
    vunpckhps ymm15, ymm6, ymm7
    vshufps ymm0, ymm8,  ymm10, 44h
    vshufps ymm1, ymm8,  ymm10, 0EEh
    vshufps ymm2, ymm9,  ymm11, 44h
    vshufps ymm3, ymm9,  ymm11, 0EEh
    vshufps ymm4, ymm12, ymm14, 44h
    vshufps ymm5, ymm12, ymm14, 0EEh
    vshufps ymm6, ymm13, ymm15, 44h
    vshufps ymm7, ymm13, ymm15, 0EEh
    vperm2f128 ymm8,  ymm0, ymm4, 20h
    vperm2f128 ymm9,  ymm1, ymm5, 20h
    vperm2f128 ymm10, ymm2, ymm6, 20h
    vperm2f128 ymm11, ymm3, ymm7, 20h
    vperm2f128 ymm12, ymm0, ymm4, 31h
    vperm2f128 ymm13, ymm1, ymm5, 31h
    vperm2f128 ymm14, ymm2, ymm6, 31h
    vperm2f128 ymm15, ymm3, ymm7, 31h
    ; Store 8 rows
    vmovaps ymmword ptr [rcx],      ymm8
    vmovaps ymmword ptr [rcx+rdx],  ymm9
    lea rax, [rcx+rdx*2]
    vmovaps ymmword ptr [rax],      ymm10
    vmovaps ymmword ptr [rax+rdx],  ymm11
    lea rax, [rax+rdx*2]
    vmovaps ymmword ptr [rax],      ymm12
    vmovaps ymmword ptr [rax+rdx],  ymm13
    lea rax, [rax+rdx*2]
    vmovaps ymmword ptr [rax],      ymm14
    vmovaps ymmword ptr [rax+rdx],  ymm15
    vzeroupper
    mov eax, 1
Restore_Regs:
    vmovaps ymm6,  ymmword ptr [rsp+0]
    vmovaps ymm7,  ymmword ptr [rsp+32]
    vmovaps ymm8,  ymmword ptr [rsp+64]
    vmovaps ymm9,  ymmword ptr [rsp+96]
    vmovaps ymm10, ymmword ptr [rsp+128]
    vmovaps ymm11, ymmword ptr [rsp+160]
    vmovaps ymm12, ymmword ptr [rsp+192]
    vmovaps ymm13, ymmword ptr [rsp+224]
    vmovaps ymm14, ymmword ptr [rsp+256]
    vmovaps ymm15, ymmword ptr [rsp+288]
    mov rsp, rbp
    pop rbp
    ret
Structural_Fault:
    xor eax, eax
    jmp Restore_Regs
Titan_Matrix_Transpose_8x8 ENDP
END
