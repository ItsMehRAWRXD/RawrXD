;============================================================================
; Q8_Dequantize.asm
; RawrXD Neural Execution Virtual Machine - Q8 Dequantization Kernel
;============================================================================

.code

Q8_Dequantize_Kernel PROC FRAME
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
    
    mov rax, r14
    shr rax, 5
    jz remainder_loop
    
main_loop:
    vpmovzxbw ymm1, xmmword ptr [r12]
    add r12, 16
    vpmovzxbw ymm2, xmmword ptr [r12]
    add r12, 16
    
    vpmovzxwd ymm3, xmm1
    vextracti128 xmm1, ymm1, 1
    vpmovzxwd ymm4, xmm1
    
    vpmovzxwd ymm5, xmm2
    vextracti128 xmm2, ymm2, 1
    vpmovzxwd ymm6, xmm2
    
    vcvtdq2ps ymm3, ymm3
    vcvtdq2ps ymm4, ymm4
    vcvtdq2ps ymm5, ymm5
    vcvtdq2ps ymm6, ymm6
    
    vmulps ymm3, ymm3, ymm0
    vmulps ymm4, ymm4, ymm0
    vmulps ymm5, ymm5, ymm0
    vmulps ymm6, ymm6, ymm0
    
    vmovups ymmword ptr [r13], ymm3
    add r13, 32
    vmovups ymmword ptr [r13], ymm4
    add r13, 32
    vmovups ymmword ptr [r13], ymm5
    add r13, 32
    vmovups ymmword ptr [r13], ymm6
    add r13, 32
    
    dec rax
    jnz main_loop
    
remainder_loop:
    mov rax, r14
    and rax, 31
    jz done
    
remainder:
    movzx edx, byte ptr [r12]
    inc r12
    vcvtsi2ss xmm1, xmm1, edx
    vmulss xmm1, xmm1, xmm2
    vmovss dword ptr [r13], xmm1
    add r13, 4
    dec rax
    jnz remainder
    
done:
    vzeroupper
    add rsp, 32
    pop r14
    pop r13
    pop r12
    ret
    
Q8_Dequantize_Kernel ENDP

END
