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
;   3. Compute exp(x - max) using FAST_EXP macro (stable approximation)
;   4. Sum all exp values (horizontal reduction)
;   5. Divide each exp by sum (multiply by reciprocal)
;
; Performance Characteristics:
;   - Horizontal reduction for max and sum
;   - Fast exp approximation using Minimax polynomial
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

; Include math approximation macros
INCLUDE math_approx.inc

.const

ALIGN 16
; Constants for exp approximation (now handled by math_approx.inc)
; We only need the IEEE 754 representation of -infinity for max finding
g_neg_inf       DWORD 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h, 0FF800000h

; Math constants for FAST_EXP macro
MATH_CONSTANTS

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
    
exp_loop:
    test rsi, rsi
    jz exp_done
    
    ; Load 8 floats
    vmovaps ymm1, YMMWORD PTR [rax]
    
    ; Subtract max (prevent overflow)
    vsubps ymm1, ymm1, ymm0
    
    ; Compute exp(x - max) using FAST_EXP macro
    ; This uses the stable 2^x approximation via Minimax polynomial
    ; e^(x - max) = 2^((x - max) * log2(e))
    FAST_EXP ymm7, ymm1, ymm8, ymm9, ymm10
    
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
    
    ; Ensure sum is positive (prevent division by zero or negative)
    vmaxps xmm2, xmm2, xmm3    ; sum = max(sum, 1.0)
    
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

END