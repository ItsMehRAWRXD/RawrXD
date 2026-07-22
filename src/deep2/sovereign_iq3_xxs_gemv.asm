; ============================================================================
; sovereign_iq3_xxs_gemv.asm - IQ3_XXS GEMV Kernel (AVX2)
; 3-bit improved quantization
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_IQ3_XXS_GEMV PROC FRAME
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

    ; 32 3-bit weights = 12 bytes
    xor r15, r15
    xor r10, r10

QuantLoop:
    cmp r15, 12
    jae NextBlock

    ; Load 3 bytes = 8x 3-bit values
    mov eax, dword ptr [rbx + r15]
    
    xor r9d, r9d
InnerLoop:
    cmp r9d, 8
    jae NextByte

    mov ecx, eax
    and ecx, 7
    sub ecx, 4
    vcvtsi2ss xmm1, xmm1, ecx
    vmulss xmm1, xmm1, xmm0

    mov r11d, r14d
    imul r11d, 32
    add r11d, r10d
    shl r11d, 2
    add r11, rsi

    vfmaddss xmm2, xmm1, dword ptr [r11], dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    shr eax, 3
    inc r9d
    inc r10d
    jmp InnerLoop

NextByte:
    add r15, 3
    jmp QuantLoop

NextBlock:
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

Deep2_IQ3_XXS_GEMV ENDP

END
