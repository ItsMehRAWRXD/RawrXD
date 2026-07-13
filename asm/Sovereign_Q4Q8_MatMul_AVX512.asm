; ============================================================================
; Sovereign_Q4Q8_MatMul_AVX512.asm - Optimized Q4_0 x Q8_0 Matrix Multiplication
; ============================================================================
; AVX-512 implementation using vpmaddubsw/vpmaddwd for 4-bit x 8-bit multiply
; 
; Q4_0 format: 4-bit weights packed in bytes, with 1 scale per 32 weights
; Q8_0 format: 8-bit weights with 1 scale per 32 weights
; 
; Strategy:
;   - Process 32 elements at a time (1 block)
;   - Use vpmaddubsw for packed multiply: (a*b + c*d) in 16-bit
;   - Use vpmaddwd to accumulate to 32-bit
;   - Apply scales at the end
; ============================================================================

.686p
.xmm
option casemap:none
option frame:auto
option win64:3
option align:64

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
ALIGN 64

; Constants for unpacking
low_nibble_mask  BYTE 64 DUP(0x0F)     ; 64 bytes of 0x0F
high_nibble_shuf BYTE 0,2,4,6,8,10,12,14,1,3,5,7,9,11,13,15
                  BYTE 64 DUP(0)       ; Padding to 64 bytes

; Scale factor for converting int32 to float
scale_factor REAL4 0.0078125, 0.0078125, 0.0078125, 0.0078125  ; 1/128

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code
ALIGN 64

; Public exports for kernel functions
PUBLIC Sovereign_Q4Q8_MatMul_AVX512
PUBLIC q4q8_matmul_avx512

; ============================================================================
; Sovereign_Q4Q8_MatMul_AVX512 - Optimized quantized matmul
; ============================================================================
; Parameters (Microsoft x64):
;   RCX = A (Q4_0 quantized, const void*)
;   RDX = B (Q8_0 quantized, const void*)
;   R8  = C (result, float*)
;   R9  = m (rows in A)
;   [RSP+40] = n (cols in B)
;   [RSP+48] = k (cols in A / rows in B)
;
; Returns: RAX = 0 on success
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
    sub rsp, 256
    .allocstack 256
    .endprolog
    
    mov rbp, rsp
    
    ; Save parameters
    mov r12, rcx                    ; A
    mov r13, rdx                    ; B
    mov r14, r8                     ; C
    mov r15, r9                     ; m
    
    ; Load n, k from stack
    mov rax, QWORD PTR [rbp+280]    ; n
    mov QWORD PTR [rbp+64], rax
    mov rax, QWORD PTR [rbp+288]    ; k
    mov QWORD PTR [rbp+72], rax
    
    ; Validate
    cmp QWORD PTR [rbp+64], 0
    je @@error
    cmp QWORD PTR [rbp+72], 0
    je @@error
    
    ; Initialize row loop: i = 0
    xor rax, rax
    mov QWORD PTR [rbp+80], rax     ; i
    
@@row_loop:
    mov rax, QWORD PTR [rbp+80]
    cmp rax, r15                    ; i < m
    jge @@success
    
    ; Initialize col loop: j = 0
    xor rbx, rbx
    mov QWORD PTR [rbp+88], rbx     ; j
    
@@col_loop:
    mov rbx, QWORD PTR [rbp+88]
    cmp rbx, QWORD PTR [rbp+64]     ; j < n
    jge @@next_row
    
    ; Compute dot product for C[i,j]
    ; Initialize accumulator (zmm0 = 0)
    vpxorq zmm0, zmm0, zmm0
    
    ; Inner loop over k dimension (process 32 at a time)
    xor rcx, rcx
    mov QWORD PTR [rbp+96], rcx     ; kk
    
@@k_loop:
    mov rcx, QWORD PTR [rbp+96]
    cmp rcx, QWORD PTR [rbp+72]     ; kk < k
    jge @@store_result
    
    ; Calculate how many elements to process this iteration
    mov rax, QWORD PTR [rbp+72]
    sub rax, rcx                    ; remaining = k - kk
    cmp rax, 32
    jle @@process_remaining
    mov rax, 32
@@process_remaining:
    mov r11, rax                    ; count
    
    ; Load 32 elements from A (Q4_0 packed: 16 bytes = 32 nibbles)
    mov rsi, r12
    mov rdi, QWORD PTR [rbp+80]     ; i
    imul rdi, QWORD PTR [rbp+72]    ; i * k
    add rdi, rcx                    ; i * k + kk
    shr rdi, 1                      ; Byte offset
    
    ; Load 16 bytes from A
    vmovdqu64 xmm1, XMMWORD PTR [rsi + rdi]
    
    ; Unpack nibbles to bytes using vpmaddubsw trick
    ; First, duplicate and mask
    vpand xmm2, xmm1, XMMWORD PTR [low_nibble_mask]  ; Low nibbles
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [low_nibble_mask]   ; High nibbles
    
    ; Interleave to get 32 bytes
    vpunpcklbw xmm4, xmm2, xmm3
    vpunpckhbw xmm5, xmm2, xmm3
    
    ; Load 32 elements from B (Q8_0: 32 bytes)
    mov rsi, r13
    mov rdi, rcx                    ; kk
    imul rdi, QWORD PTR [rbp+64]  ; kk * n
    add rdi, QWORD PTR [rbp+88]   ; kk * n + j
    
    vmovdqu64 ymm6, YMMWORD PTR [rsi + rdi]
    
    ; Multiply: vpmaddubsw (unsigned * signed -> 16-bit)
    ; xmm4/xmm5 contain unsigned A values (0-15)
    ; ymm6 contains signed B values (-128 to 127)
    vpmaddubsw xmm7, xmm4, xmm6
    vpmaddubsw xmm8, xmm5, xmm6
    
    ; Accumulate to 32-bit
    vpmaddwd xmm9, xmm7, XMMWORD PTR [one_vec]
    vpmaddwd xmm10, xmm8, XMMWORD PTR [one_vec]
    
    vpaddd xmm0, xmm0, xmm9
    vpaddd xmm0, xmm0, xmm10
    
    ; Increment kk by 32
    add QWORD PTR [rbp+96], 32
    jmp @@k_loop
    
@@store_result:
    ; Horizontal sum of xmm0
    vphaddd xmm0, xmm0, xmm0
    vphaddd xmm0, xmm0, xmm0
    
    ; Convert to float and apply scale
    vcvtdq2ps xmm0, xmm0
    vmulps xmm0, xmm0, XMMWORD PTR [scale_factor]
    
    ; Store result
    mov rsi, r14
    mov rdi, QWORD PTR [rbp+80]     ; i
    imul rdi, QWORD PTR [rbp+64]    ; i * n
    add rdi, QWORD PTR [rbp+88]     ; i * n + j
    shl rdi, 2                      ; * 4 bytes
    
    vmovss DWORD PTR [rsi + rdi], xmm0
    
    ; Increment j
    inc QWORD PTR [rbp+88]
    jmp @@col_loop
    
@@next_row:
    inc QWORD PTR [rbp+80]          ; i++
    jmp @@row_loop
    
@@success:
    vzeroupper
    xor rax, rax
    jmp @@cleanup
    
@@error:
    mov rax, -1
    
@@cleanup:
    add rsp, 256
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

; ============================================================================
; C API Export
; ============================================================================
q4q8_matmul_avx512 PROC EXPORT
    jmp Sovereign_Q4Q8_MatMul_AVX512
q4q8_matmul_avx512 ENDP

; ============================================================================
; End of Module
; ============================================================================
END
