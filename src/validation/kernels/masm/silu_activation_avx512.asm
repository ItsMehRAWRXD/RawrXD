; ============================================================================
; silu_activation_avx2.asm - AVX2 (256-bit) Version - FIXED
; ============================================================================
; SiLU (Sigmoid Linear Unit) Activation Kernel - AVX2 Implementation
; 
; Mathematical Definition:
;   SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
;
; Implementation:
;   Uses FAST_EXP2 for accurate sigmoid approximation
;   sigmoid(x) = 1 / (1 + exp(-x))
;   exp(-x) = 2^(-x * log2(e))
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

; Include shared math approximation library
INCLUDE math_approx.inc

.const

; Constants for SiLU computation
ALIGN 16
g_silu_neg_one    REAL4 -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0
g_silu_one       REAL4  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0

.data

; Define constants from math_approx.inc
MATH_CONSTANTS

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
    
    ; Calculate iterations - rcx = data_size / 32
    mov rcx, r8
    shr rcx, 5                  ; Divide by 32 (8 floats * 4 bytes)
    
    ; Early exit if no iterations
    test rcx, rcx
    jz done
    
    ; Process loop
process_loop:
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rax]
    
    ; --- Compute sigmoid(x) = 1 / (1 + exp(-x)) ---
    ; Step 1: Compute -x
    vmulps ymm1, ymm0, YMMWORD PTR [g_silu_neg_one]  ; ymm1 = -x
    
    ; Step 2: Compute exp(-x) using FAST_EXP
    ; FAST_EXP computes e^x, so we pass -x to get e^(-x)
    ; Register allocation:
    ;   ymm1 = -x (input to FAST_EXP)
    ;   ymm2 = temporary for FAST_EXP
    ;   ymm3 = temporary for FAST_EXP
    ;   ymm4 = temporary for FAST_EXP
    FAST_EXP ymm1, ymm1, ymm2, ymm3, ymm4
    
    ; ymm1 now contains exp(-x)
    
    ; Step 3: Compute 1 + exp(-x)
    vaddps ymm1, ymm1, YMMWORD PTR [g_silu_one]  ; ymm1 = 1 + exp(-x)
    
    ; Step 4: Compute sigmoid(x) = 1 / (1 + exp(-x))
    ; Use reciprocal approximation: vrcpps (fast but approximate)
    ; For better accuracy, we use division
    vdivps ymm1, YMMWORD PTR [g_silu_one], ymm1  ; ymm1 = 1 / (1 + exp(-x)) = sigmoid(x)
    
    ; Step 5: Compute SiLU(x) = x * sigmoid(x)
    vmulps ymm0, ymm0, ymm1  ; ymm0 = x * sigmoid(x)
    
    ; Store result
    vmovaps YMMWORD PTR [rax], ymm0
    
    ; Advance pointer and decrement counter
    add rax, 32
    sub rcx, 1
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

END