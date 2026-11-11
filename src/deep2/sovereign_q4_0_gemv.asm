; ============================================================================
; sovereign_q4_0_gemv.asm - Q4_0 GEMV Kernel (AVX2)
; 4-bit block quantization: 32 weights per block, FP16 scale
; ============================================================================

OPTION CASEMAP:NONE

.CODE

; void Deep2_Q4_0_GEMV(const void* weights, const float* input, float* output, uint32_t numBlocks, uint32_t outputDim)
; RCX = weights, RDX = input, R8 = output, R9D = numBlocks, [RSP+40] = outputDim
Deep2_Q4_0_GEMV PROC FRAME
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
    ; FP16 to FP32 conversion
    punpcklwd xmm0, xmm0
    pslld xmm0, 16
    ; xmm0 now has FP32 scale

    add rbx, 2          ; skip scale

    ; Process 32 quants (16 bytes of 4-bit)
    xor r15, r15        ; sub-block index

QuantLoop:
    cmp r15, 16
    jae NextBlock

    mov al, byte ptr [rbx + r15]
    
    ; Low nibble
    mov cl, al
    and cl, 0Fh
    sub cl, 8           ; center
    vcvtsi2ss xmm1, xmm1, ecx
    
    ; High nibble
    mov cl, al
    shr cl, 4
    sub cl, 8
    vcvtsi2ss xmm2, xmm2, ecx

    ; Dequantize: val * scale
    vmulss xmm1, xmm1, xmm0
    vmulss xmm2, xmm2, xmm0

    ; Accumulate: output[i] += val * input[j]
    mov eax, r14d
    imul eax, 32
    add eax, r15d
    shl eax, 1          ; *2 for two nibbles
    mov ecx, eax
    shl ecx, 2          ; *4 for float offset
    add rcx, rsi        ; input + offset

    movss xmm3, dword ptr [rdi + r14*4]
    vfmaddss xmm3, xmm1, dword ptr [rcx], xmm3
    movss dword ptr [rdi + r14*4], xmm3

    add ecx, 4
    vfmaddss xmm3, xmm2, dword ptr [rcx], xmm3
    movss dword ptr [rdi + r14*4], xmm3

    inc r15
    jmp QuantLoop

NextBlock:
    add rbx, 16         ; skip quants
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

Deep2_Q4_0_GEMV ENDP

END
