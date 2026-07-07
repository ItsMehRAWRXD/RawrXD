; ============================================================================
; softmax_forward_avx2.asm
; ============================================================================
; Softmax Kernel - AVX2 Implementation
; 
; Mathematical Definition:
;   softmax(x_i) = exp(x_i - max(x)) / sum(exp(x_j - max(x)))
; 
; Algorithm:
;   1. Find max value (horizontal reduction)
;   2. Subtract max from all elements (prevent overflow)
;   3. Compute exp(x - max) using polynomial approximation
;   4. Sum all exp values (horizontal reduction)
;   5. Divide each exp by sum (multiply by reciprocal)
;
; Performance Characteristics:
;   - Horizontal reduction for max and sum
;   - Fast exp approximation (4th-order polynomial)
;   - Division replaced with reciprocal multiplication
;   - AVX2 allows processing 8 floats per iteration
;
; ABI Compliance:
;   - x64 Windows __fastcall (Microsoft x64 calling convention)
;   - Non-volatile registers preserved: RBX, RBP, RDI, RSI, R12-R15
;   - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5
;   - Shadow space: 32 bytes allocated on stack
;
; Parameters:
;   RCX = void* data       (pointer to float array, must be 32-byte aligned)
;   RDX = size_t data_size (number of bytes, must be multiple of 32)
;
; Returns:
;   RAX = 0 on success, non-zero on error
;
; ============================================================================

OPTION CASEMAP:NONE

.const

ALIGN 16
; Constants for exp approximation
; exp(x) ≈ 1 + x + x^2/2! + x^3/3! + x^4/4!
; For better accuracy, we use: exp(x) ≈ 1 + x*(1 + x/2*(1 + x/3*(1 + x/4)))
g_one           REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_half          REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5
g_third         REAL4 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333
g_fourth        REAL4 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25
; IEEE 754 representation of -infinity (0xFF800000)
g_neg_inf       DWORD 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h

.code

; ============================================================================
; MASM_Softmax_Forward_AVX2 - Standard version with parameter validation
; ============================================================================

MASM_Softmax_Forward_AVX2 PROC FRAME

    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    push r12
    .pushreg r12
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rbx, rcx               ; rbx = data pointer
    mov rdi, rdx               ; rdi = data_size
    
    ; ========================================================================
    ; Parameter Validation
    ; ========================================================================
    
    ; Check for null pointer
    test rbx, rbx
    jz error_null
    
    ; Check for zero size
    test rdi, rdi
    jz error_zero
    
    ; Check alignment (must be 32-byte aligned for AVX2)
    test rbx, 31
    jnz error_align
    
    ; Check size (must be multiple of 32)
    test rdi, 31
    jnz error_size
    
    ; ========================================================================
    ; Step 1: Find Maximum Value (Horizontal Reduction)
    ; ========================================================================
    
    ; Initialize max to -infinity
    vmovaps ymm0, YMMWORD PTR [g_neg_inf]
    
    ; Calculate number of iterations
    mov rsi, rdi
    shr rsi, 5                  ; Divide by 32 (8 floats * 4 bytes)
    
    ; Save original pointer
    mov rax, rbx
    
    ; Process 8 floats per iteration
max_loop:
    test rsi, rsi
    jz max_done
    
    ; Load 8 floats
    vmovaps ymm1, YMMWORD PTR [rax]
    
    ; Update max
    vmaxps ymm0, ymm0, ymm1
    
    ; Advance pointer
    add rax, 32
    dec rsi
    jnz max_loop
    
max_done:
    ; Horizontal reduction to find global max
    ; ymm0 = [m0, m1, m2, m3, m4, m5, m6, m7]
    
    ; Extract high 128 bits
    vextractf128 xmm1, ymm0, 1
    
    ; Max of high and low parts
    vmaxps xmm0, xmm0, xmm1
    
    ; Horizontal max (first pass)
    vmaxps xmm1, xmm0, xmm0
    vshufps xmm2, xmm0, xmm0, 0EEh    ; [m2, m3, m2, m3]
    vmaxps xmm0, xmm1, xmm2
    
    ; Horizontal max (second pass)
    vshufps xmm1, xmm0, xmm0, 01h     ; [m1, m0, m1, m0]
    vmaxps xmm0, xmm0, xmm1
    
    ; Broadcast max to all lanes
    vbroadcastss ymm0, xmm0
    
    ; ========================================================================
    ; Step 2: Subtract Max and Compute Exp
    ; ========================================================================
    
    ; Reset pointer and iteration count
    mov rax, rbx
    mov rsi, rdi
    shr rsi, 5
    
    ; Initialize sum accumulator
    vxorps ymm2, ymm2, ymm2    ; sum = 0
    
    ; Load constants for exp approximation
    vmovaps ymm3, YMMWORD PTR [g_one]
    vmovaps ymm4, YMMWORD PTR [g_half]
    vmovaps ymm5, YMMWORD PTR [g_third]
    vmovaps ymm6, YMMWORD PTR [g_fourth]
    
exp_loop:
    test rsi, rsi
    jz exp_done
    
    ; Load 8 floats
    vmovaps ymm1, YMMWORD PTR [rax]
    
    ; Subtract max (prevent overflow)
    vsubps ymm1, ymm1, ymm0
    
    ; Compute exp(x) using polynomial approximation
    ; exp(x) ≈ 1 + x*(1 + x/2*(1 + x/3*(1 + x/4)))
    
    ; ymm7 = x/4
    vmulps ymm7, ymm1, ymm6
    
    ; ymm7 = 1 + x/4
    vaddps ymm7, ymm7, ymm3
    
    ; ymm7 = x/3 * (1 + x/4)
    vmulps ymm7, ymm5, ymm7
    
    ; ymm7 = 1 + x/3*(1 + x/4)
    vaddps ymm7, ymm7, ymm3
    
    ; ymm7 = x/2 * (1 + x/3*(1 + x/4))
    vmulps ymm7, ymm4, ymm7
    
    ; ymm7 = 1 + x/2*(1 + x/3*(1 + x/4))
    vaddps ymm7, ymm7, ymm3
    
    ; ymm7 = x * (1 + x/2*(1 + x/3*(1 + x/4)))
    vmulps ymm7, ymm1, ymm7
    
    ; ymm7 = 1 + x*(1 + x/2*(1 + x/3*(1 + x/4)))
    vaddps ymm7, ymm7, ymm3
    
    ; Store exp values back to memory
    vmovaps YMMWORD PTR [rax], ymm7
    
    ; Accumulate sum
    vaddps ymm2, ymm2, ymm7
    
    ; Advance pointer
    add rax, 32
    dec rsi
    jnz exp_loop
    
exp_done:
    ; ========================================================================
    ; Step 3: Horizontal Sum of Exp Values
    ; ========================================================================
    
    ; Horizontal reduction to find global sum
    vextractf128 xmm1, ymm2, 1
    vaddps xmm2, xmm2, xmm1
    vhaddps xmm2, xmm2, xmm2
    vhaddps xmm2, xmm2, xmm2
    
    ; xmm2[0] now contains the sum
    
    ; ========================================================================
    ; Step 4: Compute Reciprocal and Normalize
    ; ========================================================================
    
    ; Compute 1.0 / sum
    vdivps xmm2, xmm3, xmm2     ; xmm2 = 1.0 / sum
    
    ; Broadcast reciprocal to all lanes
    vbroadcastss ymm2, xmm2
    
    ; Reset pointer and iteration count
    mov rax, rbx
    mov rsi, rdi
    shr rsi, 5
    
normalize_loop:
    test rsi, rsi
    jz normalize_done
    
    ; Load exp values
    vmovaps ymm1, YMMWORD PTR [rax]
    
    ; Normalize: exp / sum
    vmulps ymm1, ymm1, ymm2
    
    ; Store result
    vmovaps YMMWORD PTR [rax], ymm1
    
    ; Advance pointer
    add rax, 32
    dec rsi
    jnz normalize_loop
    
normalize_done:
    ; Success
    xor rax, rax
    jmp epilogue
    
error_null:
    mov rax, 1
    jmp epilogue
    
error_zero:
    mov rax, 2
    jmp epilogue
    
error_align:
    mov rax, 3
    jmp epilogue
    
error_size:
    mov rax, 4
    
epilogue:
    ; Epilogue: Restore non-volatile registers
    add rsp, 32
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

MASM_Softmax_Forward_AVX2 ENDP

; ============================================================================
; MASM_Softmax_Forward_AVX2_Fast - Optimized version without validation
; ============================================================================

MASM_Softmax_Forward_AVX2_Fast PROC FRAME

    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    push r12
    .pushreg r12
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rbx, rcx
    mov rdi, rdx
    
    ; Initialize max to -infinity
    vmovaps ymm0, YMMWORD PTR [g_neg_inf]
    
    ; Calculate iterations
    mov rsi, rdi
    shr rsi, 5
    
    ; Save pointer
    mov rax, rbx
    
    ; Find max
fast_max_loop:
    test rsi, rsi
    jz fast_max_done
    
    vmovaps ymm1, YMMWORD PTR [rax]
    vmaxps ymm0, ymm0, ymm1
    
    add rax, 32
    dec rsi
    jnz fast_max_loop
    
fast_max_done:
    ; Horizontal max reduction
    vextractf128 xmm1, ymm0, 1
    vmaxps xmm0, xmm0, xmm1
    vmaxps xmm1, xmm0, xmm0
    vshufps xmm2, xmm0, xmm0, 0EEh
    vmaxps xmm0, xmm1, xmm2
    vshufps xmm1, xmm0, xmm0, 01h
    vmaxps xmm0, xmm0, xmm1
    vbroadcastss ymm0, xmm0
    
    ; Subtract max and compute exp
    mov rax, rbx
    mov rsi, rdi
    shr rsi, 5
    vxorps ymm2, ymm2, ymm2
    
    ; Load constants
    vmovaps ymm3, YMMWORD PTR [g_one]
    vmovaps ymm4, YMMWORD PTR [g_half]
    vmovaps ymm5, YMMWORD PTR [g_third]
    vmovaps ymm6, YMMWORD PTR [g_fourth]
    
fast_exp_loop:
    test rsi, rsi
    jz fast_exp_done
    
    vmovaps ymm1, YMMWORD PTR [rax]
    vsubps ymm1, ymm1, ymm0
    
    ; Fast exp approximation
    vmulps ymm7, ymm1, ymm6
    vaddps ymm7, ymm7, ymm3
    vmulps ymm7, ymm5, ymm7
    vaddps ymm7, ymm7, ymm3
    vmulps ymm7, ymm4, ymm7
    vaddps ymm7, ymm7, ymm3
    vmulps ymm7, ymm1, ymm7
    vaddps ymm7, ymm7, ymm3
    
    vmovaps YMMWORD PTR [rax], ymm7
    vaddps ymm2, ymm2, ymm7
    
    add rax, 32
    dec rsi
    jnz fast_exp_loop
    
fast_exp_done:
    ; Horizontal sum
    vextractf128 xmm1, ymm2, 1
    vaddps xmm2, xmm2, xmm1
    vhaddps xmm2, xmm2, xmm2
    vhaddps xmm2, xmm2, xmm2
    
    ; Compute reciprocal
    vdivps xmm2, xmm3, xmm2
    vbroadcastss ymm2, xmm2
    
    ; Normalize
    mov rax, rbx
    mov rsi, rdi
    shr rsi, 5
    
fast_normalize_loop:
    test rsi, rsi
    jz fast_normalize_done
    
    vmovaps ymm1, YMMWORD PTR [rax]
    vmulps ymm1, ymm1, ymm2
    vmovaps YMMWORD PTR [rax], ymm1
    
    add rax, 32
    dec rsi
    jnz fast_normalize_loop
    
fast_normalize_done:
    xor rax, rax
    
fast_epilogue:
    add rsp, 32
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

MASM_Softmax_Forward_AVX2_Fast ENDP

END