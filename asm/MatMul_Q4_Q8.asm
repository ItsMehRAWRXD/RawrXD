; ============================================================================
; MatMul_Q4_Q8.asm - Real Q4_0 x Q8_0 Matrix Multiplication
; ============================================================================

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
ALIGN 16

; Constants
low_nibble_mask BYTE 32 DUP(0Fh)
high_nibble_mask BYTE 32 DUP(0F0h)
sign_extend_4bit WORD 16 DUP(0FFF8h)

; Scale factors
scale_q4 REAL4 0.0078125, 0.0078125, 0.0078125, 0.0078125
scale_q8 REAL4 0.00390625, 0.00390625, 0.00390625, 0.00390625

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code
ALIGN 16

; ============================================================================
; MatMul_Q4_Q8 - Real quantized matrix multiplication
; ============================================================================
MatMul_Q4_Q8 PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 192
    .allocstack 192
    .endprolog
    
    mov rbp, rsp
    
    ; Save parameters
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    
    ; Load n, k from stack
    mov rax, QWORD PTR [rbp+216]
    mov QWORD PTR [rbp+64], rax
    mov rax, QWORD PTR [rbp+224]
    mov QWORD PTR [rbp+72], rax
    
    ; Validate
    cmp QWORD PTR [rbp+64], 0
    je @@error
    cmp QWORD PTR [rbp+72], 0
    je @@error
    
    ; Calculate blocks per k dimension
    mov rax, QWORD PTR [rbp+72]
    add rax, 31
    shr rax, 5
    mov QWORD PTR [rbp+80], rax
    
    ; Initialize row loop: i = 0
    xor rax, rax
    mov QWORD PTR [rbp+88], rax
    
@@row_loop:
    mov rax, QWORD PTR [rbp+88]
    cmp rax, r15
    jge @@success
    
    ; Initialize column loop: j = 0
    xor rbx, rbx
    mov QWORD PTR [rbp+96], rbx
    
@@col_loop:
    mov rbx, QWORD PTR [rbp+96]
    cmp rbx, QWORD PTR [rbp+64]
    jge @@next_row
    
    ; Compute C[i,j]
    vxorps ymm0, ymm0, ymm0
    
    ; Inner loop over k blocks
    xor rcx, rcx
    mov QWORD PTR [rbp+104], rcx
    
@@block_loop:
    mov rcx, QWORD PTR [rbp+104]
    cmp rcx, QWORD PTR [rbp+80]
    jge @@store_result
    
    ; Load Q4_0 block for A[i, kb]
    mov rdi, QWORD PTR [rbp+88]
    imul rdi, QWORD PTR [rbp+80]
    add rdi, QWORD PTR [rbp+104]
    imul rdi, 18
    
    mov rsi, r12
    add rsi, rdi
    
    ; Load 16 bytes (32 nibbles) of weights
    vmovdqu xmm1, XMMWORD PTR [rsi + 2]
    
    ; Unpack nibbles to bytes
    vpand xmm2, xmm1, XMMWORD PTR [low_nibble_mask]
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [low_nibble_mask]
    
    ; Interleave to get 32 bytes
    vpunpcklbw xmm4, xmm2, xmm3
    vpunpckhbw xmm5, xmm2, xmm3
    
    ; Convert to 16-bit integers
    vpmovzxbw ymm4, xmm4
    vpmovzxbw ymm5, xmm5
    
    vpsubw ymm4, ymm4, YMMWORD PTR [sign_extend_4bit]
    vpsubw ymm5, ymm5, YMMWORD PTR [sign_extend_4bit]
    
    ; Load Q8_0 block for B[kb, j]
    mov rdi, QWORD PTR [rbp+104]
    imul rdi, QWORD PTR [rbp+64]
    add rdi, QWORD PTR [rbp+96]
    imul rdi, 34
    
    mov rsi, r13
    add rsi, rdi
    
    ; Load 32 bytes of Q8 weights
    vmovdqu ymm6, YMMWORD PTR [rsi + 2]
    
    ; Convert to 16-bit
    vpmovzxbw ymm7, xmm6
    vextracti128 xmm6, ymm6, 1
    vpmovzxbw ymm8, xmm6
    
    ; Multiply
    vpmullw ymm9, ymm4, ymm7
    vpmullw ymm10, ymm5, ymm8
    
    ; Horizontal sum
    vphaddw ymm9, ymm9, ymm9
    vphaddw ymm9, ymm9, ymm9
    vphaddw ymm9, ymm9, ymm9
    
    vphaddw ymm10, ymm10, ymm10
    vphaddw ymm10, ymm10, ymm10
    vphaddw ymm10, ymm10, ymm10
    
    ; Extract and accumulate
    vextracti128 xmm11, ymm9, 0
    vextracti128 xmm12, ymm10, 0
    
    vpmovsxwd xmm9, xmm11
    vpmovsxwd xmm10, xmm12
    
    vcvtdq2ps xmm9, xmm9
    vcvtdq2ps xmm10, xmm10
    
    vaddps xmm0, xmm0, xmm9
    vaddps xmm0, xmm0, xmm10
    
    vinsertf128 ymm0, ymm0, xmm0, 0
    
    ; Increment block counter
    inc QWORD PTR [rbp+104]
    jmp @@block_loop
    
@@store_result:
    ; Horizontal sum of accumulator
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Apply scale
    vmulps xmm0, xmm0, XMMWORD PTR [scale_q4]
    
    ; Store result
    mov rsi, r14
    mov rdi, QWORD PTR [rbp+88]
    imul rdi, QWORD PTR [rbp+64]
    add rdi, QWORD PTR [rbp+96]
    shl rdi, 2
    
    vmovss DWORD PTR [rsi + rdi], xmm0
    
    ; Increment column
    inc QWORD PTR [rbp+96]
    jmp @@col_loop
    
@@next_row:
    inc QWORD PTR [rbp+88]
    jmp @@row_loop
    
@@success:
    vzeroupper
    xor rax, rax
    jmp @@cleanup
    
@@error:
    mov rax, -1
    
@@cleanup:
    add rsp, 192
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
MatMul_Q4_Q8 ENDP

; C API Export
PUBLIC matmul_q4_q8
matmul_q4_q8 PROC
    jmp MatMul_Q4_Q8
matmul_q4_q8 ENDP

END
