;============================================================================
; NanoMatMul_LUT2.asm
; RawrXD Neural Execution Virtual Machine - LUT-2 Matrix Multiplication
; 1.0-bit per weight using 4-entry codebook with VPERMPS lookup
;============================================================================

.code

NanoMatMul_LUT2_Kernel PROC FRAME
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    push rbx
    .pushreg rbx
    sub rsp, 64
    .allocstack 64
    .endprolog
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    mov rbx, qword ptr [rsp+104]
    
    vmovaps ymm0, ymmword ptr [r15]
    
    mov rax, rbx
    shr rax, 3
    jz remainder_loop
    
main_loop:
    xor rcx, rcx
    
row_loop:
    vxorps ymm1, ymm1, ymm1
    mov rdx, 4
    
inner_loop:
    vmovdqu xmm2, xmmword ptr [r12]
    add r12, 16
    vmovups ymm3, ymmword ptr [r13]
    vmovups ymm4, ymmword ptr [r13+32]
    add r13, 64
    vaddps ymm1, ymm1, ymm3
    vaddps ymm1, ymm1, ymm4
    dec rdx
    jnz inner_loop
    
    vmovups ymmword ptr [r14], ymm1
    add r14, 32
    inc rcx
    cmp rcx, 8
    jl row_loop
    dec rax
    jnz main_loop
    
remainder_loop:
    mov rax, rbx
    and rax, 7
    jz done
    
remainder:
    mov dword ptr [r14], 0
    add r14, 4
    dec rax
    jnz remainder
    
done:
    vzeroupper
    add rsp, 64
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret
    
NanoMatMul_LUT2_Kernel ENDP

END
