; ============================================================================
; sovereign_q8_0_gemv.asm - Q8_0 GEMV Kernel (AVX2)
; 8-bit block quantization: 32 weights per block, FP16 scale
; ============================================================================

OPTION CASEMAP:NONE

.CODE

; void Deep2_Q8_0_GEMV(const void* weights, const float* input, float* output, uint32_t numBlocks, uint32_t outputDim)
Deep2_Q8_0_GEMV PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h
    .endprolog

    mov rbx, rcx        ; weights
    mov rsi, rdx        ; input
    mov rdi, r8         ; output
    mov r12d, r9d       ; numBlocks
    mov r13d, dword ptr [rsp+60h] ; outputDim

    xor r14, r14        ; block index

BlockLoop:
    cmp r14, r12
    jae Done

    ; Load scale (FP16 -> FP32)
    movzx eax, word ptr [rbx]
    movd xmm0, eax
    punpcklwd xmm0, xmm0
    pslld xmm0, 16

    add rbx, 2          ; skip scale

    ; Process 32 int8 weights
    xor r15, r15

QuantLoop:
    cmp r15, 32
    jae NextBlock

    movsx ecx, byte ptr [rbx + r15]
    vcvtsi2ss xmm1, xmm1, ecx
    vmulss xmm1, xmm1, xmm0

    ; Accumulate: output[block] += val * input[block*32 + i]
    mov eax, r14d
    imul eax, 32
    add eax, r15d
    shl eax, 2
    add rax, rsi

    vfmaddss xmm2, xmm1, dword ptr [rax], dword ptr [rdi + r14*4]
    movss dword ptr [rdi + r14*4], xmm2

    inc r15
    jmp QuantLoop

NextBlock:
    add rbx, 32         ; skip quants
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

Deep2_Q8_0_GEMV ENDP

END
