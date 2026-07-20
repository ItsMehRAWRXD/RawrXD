;============================================================================
; NanoMatMul_XNOR.asm
; RawrXD Neural Execution Virtual Machine - XNOR Binary Matrix Multiplication
;============================================================================

.code

NanoMatMul_XNOR_Kernel PROC FRAME
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
    
    mov rax, r15
    shr rax, 3
    jz remainder_loop
    
main_loop:
    xor rcx, rcx
    
row_loop:
    vxorps ymm1, ymm1, ymm1
    mov rdx, 32
    
inner_loop:
    vmovdqu xmm2, xmmword ptr [r12]
    add r12, 16
    vmovdqu xmm3, xmmword ptr [r13]
    add r13, 16
    vpxor xmm4, xmm2, xmm3
    vpaddb xmm1, xmm1, xmm4
    dec rdx
    jnz inner_loop
    
    vcvtdq2ps ymm1, ymm1
    vmovups ymmword ptr [r14], ymm1
    add r14, 32
    inc rcx
    cmp rcx, 8
    jl row_loop
    dec rax
    jnz main_loop
    
remainder_loop:
    mov rax, r15
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
    
NanoMatMul_XNOR_Kernel ENDP

END
