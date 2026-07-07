; ============================================================================
; silu_activation_avx2.asm - AVX2 (256-bit) Version
; ============================================================================
; SiLU (Sigmoid Linear Unit) Activation Kernel - AVX2 Implementation
; 
; Mathematical Definition:
;   SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
;
; Polynomial Approximation:
;   sigmoid(x) ≈ 0.5 + 0.25*x - 0.020833*x^3 + 0.002604*x^5
;
; Performance Target:
;   - Scalar C++: ~358,638 cycles for 1024 floats
;   - AVX2 Goal: <100,000 cycles (3.5x speedup)
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
; ============================================================================

OPTION CASEMAP:NONE

.const

ALIGN 16
g_silu_one          REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_silu_half         REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5
g_silu_quarter      REAL4 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25
g_silu_neg_020833   REAL4 -0.020833, -0.020833, -0.020833, -0.020833, -0.020833, -0.020833, -0.020833, -0.020833
g_silu_pos_002604   REAL4 0.002604, 0.002604, 0.002604, 0.002604, 0.002604, 0.002604, 0.002604, 0.002604

.code

; ============================================================================
; MASM_Silu_Activation_AVX512 - AVX2 version (processes 8 floats at a time)
; ============================================================================

MASM_Silu_Activation_AVX512 PROC FRAME

    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rax, rcx               ; rax = data pointer
    mov r8, rdx                ; r8 = data_size
    
    ; Check for null pointer
    test rax, rax
    jz error_null
    
    ; Check for zero size
    test r8, r8
    jz error_zero
    
    ; Check alignment (32-byte for AVX2)
    test rax, 31
    jnz error_align
    
    ; Check size (must be multiple of 32)
    test r8, 31
    jnz error_size
    
    ; Load constants (using YMM registers for AVX2)
    vmovaps ymm4, YMMWORD PTR [g_silu_one]
    vmovaps ymm5, YMMWORD PTR [g_silu_half]
    vmovaps ymm6, YMMWORD PTR [g_silu_quarter]
    vmovaps ymm7, YMMWORD PTR [g_silu_neg_020833]
    vmovaps ymm8, YMMWORD PTR [g_silu_pos_002604]
    
    ; Calculate iterations
    mov rcx, r8
    shr rcx, 5                  ; Divide by 32 (8 floats * 4 bytes)
    
    ; Process loop
process_loop:
    test rcx, rcx
    jz done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rax]
    
    ; Compute SiLU(x) = x * sigmoid(x)
    ; sigmoid(x) ≈ 0.5 + 0.25*x - 0.020833*x^3 + 0.002604*x^5
    
    ; ymm1 = x^2
    vmulps ymm1, ymm0, ymm0
    
    ; ymm2 = x^3 = x^2 * x
    vmulps ymm2, ymm1, ymm0
    
    ; ymm3 = x^5 = x^3 * x^2
    vmulps ymm3, ymm2, ymm1
    
    ; ymm1 = 0.25*x
    vmulps ymm1, ymm0, ymm6
    
    ; ymm2 = -0.020833*x^3
    vmulps ymm2, ymm2, ymm7
    
    ; ymm3 = 0.002604*x^5
    vmulps ymm3, ymm3, ymm8
    
    ; sigmoid = 0.5 + ymm1 + ymm2 + ymm3
    vaddps ymm1, ymm5, ymm1
    vaddps ymm1, ymm1, ymm2
    vaddps ymm1, ymm1, ymm3
    
    ; SiLU = x * sigmoid
    vmulps ymm0, ymm0, ymm1
    
    ; Store result
    vmovaps YMMWORD PTR [rax], ymm0
    
    ; Advance pointer
    add rax, 32
    dec rcx
    jnz process_loop
    
done:
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
    add rsp, 32
    pop rbp
    ret

MASM_Silu_Activation_AVX512 ENDP

; ============================================================================
; MASM_Silu_Activation_AVX512_Fast - AVX2 version without validation
; ============================================================================

MASM_Silu_Activation_AVX512_Fast PROC FRAME

    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rax, rcx
    mov r8, rdx
    
    ; Load constants
    vmovaps ymm4, YMMWORD PTR [g_silu_one]
    vmovaps ymm5, YMMWORD PTR [g_silu_half]
    vmovaps ymm6, YMMWORD PTR [g_silu_quarter]
    vmovaps ymm7, YMMWORD PTR [g_silu_neg_020833]
    vmovaps ymm8, YMMWORD PTR [g_silu_pos_002604]
    
    ; Calculate iterations
    mov rcx, r8
    shr rcx, 5
    
    ; Process loop
fast_loop:
    test rcx, rcx
    jz fast_done
    
    vmovaps ymm0, YMMWORD PTR [rax]
    vmulps ymm1, ymm0, ymm0
    vmulps ymm2, ymm1, ymm0
    vmulps ymm3, ymm2, ymm1
    vmulps ymm1, ymm0, ymm6
    vmulps ymm2, ymm2, ymm7
    vmulps ymm3, ymm3, ymm8
    vaddps ymm1, ymm5, ymm1
    vaddps ymm1, ymm1, ymm2
    vaddps ymm1, ymm1, ymm3
    vmulps ymm0, ymm0, ymm1
    vmovaps YMMWORD PTR [rax], ymm0
    
    add rax, 32
    dec rcx
    jnz fast_loop
    
fast_done:
    xor rax, rax
    
fast_epilogue:
    add rsp, 32
    pop rbp
    ret

MASM_Silu_Activation_AVX512_Fast ENDP

; ============================================================================
; MASM_Silu_Activation_AVX512_Bounded - AVX2 version with clamping
; ============================================================================

MASM_Silu_Activation_AVX512_Bounded PROC FRAME

    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rax, rcx
    mov r8, rdx
    
    ; Check for null pointer
    test rax, rax
    jz bounded_error_null
    
    ; Check for zero size
    test r8, r8
    jz bounded_error_zero
    
    ; Check alignment
    test rax, 31
    jnz bounded_error_align
    
    ; Check size
    test r8, 31
    jnz bounded_error_size
    
    ; Load constants
    vmovaps ymm4, YMMWORD PTR [g_silu_one]
    vmovaps ymm5, YMMWORD PTR [g_silu_half]
    vmovaps ymm6, YMMWORD PTR [g_silu_quarter]
    vmovaps ymm7, YMMWORD PTR [g_silu_neg_020833]
    vmovaps ymm8, YMMWORD PTR [g_silu_pos_002604]
    
    ; Calculate iterations
    mov rcx, r8
    shr rcx, 5
    
    ; Process loop
bounded_loop:
    test rcx, rcx
    jz bounded_done
    
    vmovaps ymm0, YMMWORD PTR [rax]
    vmulps ymm1, ymm0, ymm0
    vmulps ymm2, ymm1, ymm0
    vmulps ymm3, ymm2, ymm1
    vmulps ymm1, ymm0, ymm6
    vmulps ymm2, ymm2, ymm7
    vmulps ymm3, ymm3, ymm8
    vaddps ymm1, ymm5, ymm1
    vaddps ymm1, ymm1, ymm2
    vaddps ymm1, ymm1, ymm3
    vmulps ymm0, ymm0, ymm1
    
    ; Clamp to [-10, 10]
    mov eax, 0C1200000h
    vmovd xmm9, eax
    vbroadcastss ymm9, xmm9
    mov eax, 41200000h
    vmovd xmm10, eax
    vbroadcastss ymm10, xmm10
    vmaxps ymm0, ymm0, ymm9
    vminps ymm0, ymm0, ymm10
    
    vmovaps YMMWORD PTR [rax], ymm0
    
    add rax, 32
    dec rcx
    jnz bounded_loop
    
bounded_done:
    xor rax, rax
    jmp bounded_epilogue
    
bounded_error_null:
    mov rax, 1
    jmp bounded_epilogue
    
bounded_error_zero:
    mov rax, 2
    jmp bounded_epilogue
    
bounded_error_align:
    mov rax, 3
    jmp bounded_epilogue
    
bounded_error_size:
    mov rax, 4
    
bounded_epilogue:
    add rsp, 32
    pop rbp
    ret

MASM_Silu_Activation_AVX512_Bounded ENDP

END