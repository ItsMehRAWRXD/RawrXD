;============================================================================
; Q4_Dequantize.asm
; RawrXD Neural Execution Virtual Machine - Q4 Dequantization Kernel
;============================================================================

.code

Q4_Dequantize_Kernel PROC FRAME
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    
    vbroadcastss ymm0, xmm2
    vbroadcastss ymm1, xmm3
    
    mov rax, r14
    shr rax, 4
    jz remainder_loop
    
main_loop:
    vmovdqu xmm2, xmmword ptr [r12]
    add r12, 16
    
    vpand xmm3, xmm2, xmmword ptr [nibble_mask]
    vpsrlw xmm4, xmm2, 4
    vpand xmm4, xmm4, xmmword ptr [nibble_mask]
    
    vpmovzxbw ymm3, xmm3
    vpmovzxbw ymm4, xmm4
    
    vcvtdq2ps ymm3, ymm3
    vcvtdq2ps ymm4, ymm4
    
    vsubps ymm3, ymm3, ymm1
    vsubps ymm4, ymm4, ymm1
    
    vmulps ymm3, ymm3, ymm0
    vmulps ymm4, ymm4, ymm0
    
    vmovups ymmword ptr [r13], ymm3
    add r13, 32
    vmovups ymmword ptr [r13], ymm4
    add r13, 32
    
    dec rax
    jnz main_loop
    
remainder_loop:
    mov rax, r14
    and rax, 15
    jz done
    
remainder:
    movzx edx, byte ptr [r12]
    mov ecx, edx
    and ecx, 0Fh
    shr edx, 4
    
    vcvtsi2ss xmm5, xmm5, ecx
    vsubss xmm5, xmm5, xmm3
    vmulss xmm5, xmm5, xmm2
    vmovss dword ptr [r13], xmm5
    add r13, 4
    
    vcvtsi2ss xmm5, xmm5, edx
    vsubss xmm5, xmm5, xmm3
    vmulss xmm5, xmm5, xmm2
    vmovss dword ptr [r13], xmm5
    add r13, 4
    
    inc r12
    sub rax, 2
    ja remainder
    
done:
    vzeroupper
    add rsp, 32
    pop r14
    pop r13
    pop r12
    ret
    
Q4_Dequantize_Kernel ENDP

.data
align 16
nibble_mask db 16 dup(0Fh)

END
