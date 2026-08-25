; ============================================================================
; sovereign_iq2_xxs_gemv.asm - IQ2_XXS GEMV Kernel (AVX2)
; 2-bit improved quantization: extremely compact
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_IQ2_XXS_GEMV PROC FRAME
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

    ; IQ2_XXS: 1 scale per 32 weights, 2-bit values packed
    movzx eax, word ptr [rbx]       ; FP16 scale
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16

    add rbx, 2

    ; 32 2-bit weights = 8 bytes
    xor r15, r15
QuantLoop:
    cmp r15, 8
    jae NextBlock

    mov al, byte ptr [rbx + r15]
    
    ; Unpack 4x 2-bit values
    xor r9d, r9d
InnerLoop:
    cmp r9d, 4
    jae NextByte

    mov cl, al
    and cl, 3
    sub cl, 2
    vcvtsi2ss xmm1, xmm1, ecx
    vmulss xmm1, xmm1, xmm0

    mov r10d, r14d
    imul r10d, 32
    add r10d, r15d
    shl r10d, 2
    add r10d, r9d
    shl r10d, 2
    add r10, rsi

    vmovss xmm3, dword ptr [r10]
    vfmaddss xmm2, xmm1, xmm3, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    shr eax, 2
    inc r9d
    jmp InnerLoop

NextByte:
    inc r15
    jmp QuantLoop

NextBlock:
    add rbx, 8
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

Deep2_IQ2_XXS_GEMV ENDP

END
