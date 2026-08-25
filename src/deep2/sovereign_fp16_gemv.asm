; ============================================================================
; sovereign_fp16_gemv.asm - FP16 GEMV Kernel (AVX2)
; Half-precision float matrix-vector multiply
; ============================================================================

OPTION CASEMAP:NONE

.CODE

Deep2_FP16_GEMV PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h
    .endprolog

    mov rbx, rcx        ; weights (FP16)
    mov rsi, rdx        ; input (FP32)
    mov rdi, r8         ; output (FP32)
    mov r12d, r9d       ; rows
    mov r13d, dword ptr [rsp+60h] ; cols

    xor r14, r14

RowLoop:
    cmp r14, r12
    jae Done

    xor r15, r15
    vxorps ymm0, ymm0, ymm0

ColLoop:
    cmp r15, r13
    jae StoreResult

    ; Load FP16 weight, convert to FP32
    mov r11d, r14d
    add r11d, r15d
    movzx eax, word ptr [rbx + r11*2]
    movd xmm1, eax
    punpcklwd xmm1, xmm1
    pslld xmm1, 16

    ; Load FP32 input
    vmovss xmm2, dword ptr [rsi + r15*4]

    ; Multiply and accumulate
    vfmaddss xmm0, xmm1, xmm2, xmm0

    inc r15
    jmp ColLoop

StoreResult:
    vmovss dword ptr [rdi + r14*4], xmm0
    inc r14
    jmp RowLoop

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

Deep2_FP16_GEMV ENDP

END
