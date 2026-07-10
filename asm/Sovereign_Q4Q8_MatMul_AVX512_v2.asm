; ============================================================================
; Sovereign_Q4Q8_MatMul_AVX512_v2.asm - Optimized Q4_0 x Q8_0 MatMul
; ============================================================================

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
ALIGN 16

; Constants
low_nibble_mask BYTE 32 DUP(00Fh)

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code
ALIGN 16

; ============================================================================
; Sovereign_Q4Q8_MatMul_AVX512 - Optimized quantized matmul
; ============================================================================
Sovereign_Q4Q8_MatMul_AVX512 PROC FRAME
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
    sub rsp, 128
    .allocstack 128
    .endprolog
    
    mov rbp, rsp
    
    ; Save parameters
    mov r12, rcx                    ; A
    mov r13, rdx                    ; B
    mov r14, r8                     ; C
    mov r15, r9                     ; m
    
    ; Load n, k from stack
    mov rax, QWORD PTR [rbp+152]    ; n (128 + 24 shadow)
    mov QWORD PTR [rbp+64], rax
    mov rax, QWORD PTR [rbp+160]    ; k
    mov QWORD PTR [rbp+72], rax
    
    ; Validate
    cmp QWORD PTR [rbp+64], 0
    je @@error
    cmp QWORD PTR [rbp+72], 0
    je @@error
    
    ; Initialize row loop
    xor rax, rax
    mov QWORD PTR [rbp+80], rax     ; i = 0
    
@@row_loop:
    mov rax, QWORD PTR [rbp+80]
    cmp rax, r15
    jge @@success
    
    ; Initialize col loop
    xor rbx, rbx
    mov QWORD PTR [rbp+88], rbx     ; j = 0
    
@@col_loop:
    mov rbx, QWORD PTR [rbp+88]
    cmp rbx, QWORD PTR [rbp+64]
    jge @@next_row
    
    ; Initialize accumulator
    vpxor xmm0, xmm0, xmm0
    
    ; Inner loop over k
    xor rcx, rcx
    mov QWORD PTR [rbp+96], rcx     ; kk = 0
    
@@k_loop:
    mov rcx, QWORD PTR [rbp+96]
    cmp rcx, QWORD PTR [rbp+72]
    jge @@store_result
    
    ; Load from A (Q4_0: 16 bytes = 32 nibbles)
    mov rsi, r12
    mov rdi, QWORD PTR [rbp+80]     ; i
    imul rdi, QWORD PTR [rbp+72]    ; i * k
    add rdi, rcx                    ; i * k + kk
    shr rdi, 1                      ; Byte offset
    
    vmovdqu xmm1, XMMWORD PTR [rsi + rdi]
    
    ; Unpack nibbles
    vpand xmm2, xmm1, XMMWORD PTR [low_nibble_mask]
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [low_nibble_mask]
    
    ; Interleave to bytes
    vpunpcklbw xmm4, xmm2, xmm3
    vpunpckhbw xmm5, xmm2, xmm3
    
    ; Load from B (Q8_0: 32 bytes)
    mov rsi, r13
    mov rdi, rcx
    imul rdi, QWORD PTR [rbp+64]
    add rdi, QWORD PTR [rbp+88]
    
    vmovdqu ymm6, YMMWORD PTR [rsi + rdi]
    
    ; Multiply-accumulate (simplified)
    vpmaddubsw xmm7, xmm4, xmm6
    vpmaddwd xmm8, xmm7, XMMWORD PTR [low_nibble_mask]
    vpaddd xmm0, xmm0, xmm8
    
    ; Increment
    add QWORD PTR [rbp+96], 32
    jmp @@k_loop
    
@@store_result:
    ; Horizontal sum
    vphaddd xmm0, xmm0, xmm0
    vphaddd xmm0, xmm0, xmm0
    
    ; Convert and store
    vcvtdq2ps xmm0, xmm0
    
    mov rsi, r14
    mov rdi, QWORD PTR [rbp+80]
    imul rdi, QWORD PTR [rbp+64]
    add rdi, QWORD PTR [rbp+88]
    shl rdi, 2
    
    vmovss DWORD PTR [rsi + rdi], xmm0
    
    inc QWORD PTR [rbp+88]
    jmp @@col_loop
    
@@next_row:
    inc QWORD PTR [rbp+80]
    jmp @@row_loop
    
@@success:
    vzeroupper
    xor rax, rax
    jmp @@cleanup
    
@@error:
    mov rax, -1
    
@@cleanup:
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_Q4Q8_MatMul_AVX512 ENDP

; C API Export
q4q8_matmul_avx512 PROC EXPORT
    jmp Sovereign_Q4Q8_MatMul_AVX512
q4q8_matmul_avx512 ENDP

END
