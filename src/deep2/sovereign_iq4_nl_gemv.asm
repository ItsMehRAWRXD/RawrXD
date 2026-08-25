; ============================================================================
; sovereign_iq4_nl_gemv.asm - IQ4_NL GEMV Kernel (AVX2)
; 4-bit improved quantization, non-linear
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_IQ4_NL_GEMV PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h
    .endprolog

    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    mov r12d, r9d
    mov r13d, dword ptr [rsp+60h]

    xor r14, r14

BlockLoop:
    cmp r14, r12
    jae Done

    movzx eax, word ptr [rbx]
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16
    add rbx, 2

    ; 32 4-bit weights = 16 bytes
    xor r15, r15

QuantLoop:
    cmp r15, 16
    jae NextBlock

    mov al, byte ptr [rbx + r15]
    
    ; Low nibble
    mov cl, al
    and cl, 0Fh
    ; IQ4_NL non-linear lookup table
    lea r10, [NL_Table]
    movzx ecx, cl
    movss xmm1, dword ptr [r10 + rcx*4]
    vmulss xmm1, xmm1, xmm0

    mov r10d, r14d
    imul r10d, 32
    add r10d, r15d
    shl r10d, 1
    shl r10d, 2
    add r10, rsi
    vmovss xmm3, dword ptr [r10]
    vfmaddss xmm2, xmm1, xmm3, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    ; High nibble
    mov cl, al
    shr cl, 4
    lea r10, [NL_Table]
    movzx ecx, cl
    movss xmm1, dword ptr [r10 + rcx*4]
    vmulss xmm1, xmm1, xmm0

    add r10d, r15d
    shl r10d, 1
    shl r10d, 2
    add r10, rsi
    vmovss xmm3, dword ptr [r10]
    vfmaddss xmm2, xmm1, xmm3, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    inc r15
    jmp QuantLoop

NextBlock:
    add rbx, 16
    inc r14
    jmp BlockLoop

Done:
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

    .data
NL_Table dd -7.0, -6.0, -5.0, -4.0, -3.0, -2.0, -1.0, 0.0
         dd  1.0,  2.0,  3.0,  4.0,  5.0,  6.0,  7.0,  8.0
    .code

Deep2_IQ4_NL_GEMV ENDP

END
