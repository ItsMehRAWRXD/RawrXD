; ============================================================================
; sovereign_q4_1_gemv.asm - Q4_1 GEMV Kernel (AVX2)
; 4-bit block quantization with FP16 scale and FP16 min
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_Q4_1_GEMV PROC FRAME
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

    ; Q4_1: FP16 scale + FP16 min + 16 bytes quants = 20 bytes per block
    movzx eax, word ptr [rbx]       ; scale
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16

    movzx eax, word ptr [rbx + 2]   ; min
    movd xmm1, eax
    punpcklwd xmm1, xmm1
    pslld xmm1, 16

    add rbx, 4

    xor r15, r15
QuantLoop:
    cmp r15, 16
    jae NextBlock

    mov al, byte ptr [rbx + r15]

    ; Low nibble
    mov cl, al
    and cl, 0Fh
    vcvtsi2ss xmm2, xmm2, ecx
    vmulss xmm2, xmm2, xmm0
    vaddss xmm2, xmm2, xmm1

    mov r10d, r14d
    imul r10d, 32
    add r10d, r15d
    shl r10d, 1
    shl r10d, 2
    add r10, rsi
    vmovss xmm4, dword ptr [r10]
    vfmaddss xmm3, xmm2, xmm4, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm3

    ; High nibble
    mov cl, al
    shr cl, 4
    vcvtsi2ss xmm2, xmm2, ecx
    vmulss xmm2, xmm2, xmm0
    vaddss xmm2, xmm2, xmm1

    add r10, 4
    vmovss xmm4, dword ptr [r10]
    vfmaddss xmm3, xmm2, xmm4, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm3

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

Deep2_Q4_1_GEMV ENDP

END
