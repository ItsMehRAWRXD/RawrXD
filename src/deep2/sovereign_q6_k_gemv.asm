; ============================================================================
; sovereign_q6_k_gemv.asm - Q6_K GEMV Kernel (AVX2)
; 6-bit k-quant: 256 weights per super-block
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_Q6_K_GEMV PROC FRAME
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

    ; Q6_K: 16 FP16 scales + 192 bytes quants (6 bits * 256 / 8) = 224 bytes
    xor r15, r15

ScaleLoop:
    cmp r15, 16
    jae ProcessQuants

    movzx eax, word ptr [rbx + r15*2]
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16

    mov r8d, r15d
    shl r8d, 4
    add r8d, r14d
    imul r8d, 256

    ; Load 3 bytes for 4 weights (6 bits each = 24 bits = 3 bytes)
    mov eax, dword ptr [rbx + 32 + r15*3]  ; 3 bytes + 1 extra

    xor r9d, r9d
UnpackLoop:
    cmp r9d, 4
    jae NextScale

    mov ecx, eax
    and ecx, 3Fh        ; 6 bits
    sub ecx, 32         ; center
    vcvtsi2ss xmm1, xmm1, ecx
    vmulss xmm1, xmm1, xmm0

    mov r10d, r8d
    add r10d, r9d
    shl r10d, 2
    add r10, rsi
    vfmaddss xmm2, xmm1, dword ptr [r10], dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    shr eax, 6
    inc r9d
    jmp UnpackLoop

NextScale:
    inc r15
    jmp ScaleLoop

ProcessQuants:
    add rbx, 224
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

Deep2_Q6_K_GEMV ENDP

END
