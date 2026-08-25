; ============================================================================
; sovereign_q2_k_gemv.asm - Q2_K GEMV Kernel (AVX2)
; 2-bit k-quant: super-block of 256 weights, grouped scales
; ============================================================================

OPTION CASEMAP:NONE

.CODE

; void Deep2_Q2_K_GEMV(const void* weights, const float* input, float* output, uint32_t numBlocks, uint32_t outputDim)
Deep2_Q2_K_GEMV PROC FRAME
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

    ; Q2_K block: 72 bytes per super-block of 256 weights
    ; 16 scales (FP16) + 64 bytes quants (4 bits per weight, packed)
    
    ; Process 16 scale values
    xor r15, r15

ScaleLoop:
    cmp r15, 16
    jae ProcessQuants

    movzx eax, word ptr [rbx + r15*2]
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16

    ; Dequantize 16 weights per scale group
    mov r8d, r15d
    shl r8d, 4          ; 16 weights per group
    add r8d, r14d
    imul r8d, 256       ; super-block offset

    ; Load 4 bytes of packed 2-bit weights (16 weights * 2 bits = 32 bits = 4 bytes)
    mov eax, dword ptr [rbx + 32 + r15*4]

    ; Unpack 2-bit values
    xor r9d, r9d
UnpackLoop:
    cmp r9d, 16
    jae NextScale

    mov ecx, eax
    and ecx, 3
    sub ecx, 2          ; center: -2 to +1
    vcvtsi2ss xmm1, xmm1, ecx
    vmulss xmm1, xmm1, xmm0

    ; Accumulate
    mov r10d, r8d
    add r10d, r9d
    shl r10d, 2
    add r10, rsi
    vmovss xmm3, dword ptr [r10]
    vfmaddss xmm2, xmm1, xmm3, dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    shr eax, 2
    inc r9d
    jmp UnpackLoop

NextScale:
    inc r15
    jmp ScaleLoop

ProcessQuants:
    add rbx, 72
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

Deep2_Q2_K_GEMV ENDP

END
