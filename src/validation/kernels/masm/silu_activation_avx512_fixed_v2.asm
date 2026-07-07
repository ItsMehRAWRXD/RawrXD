; ============================================================================
; silu_activation_avx512_fixed.asm - AVX2 (256-bit) Version - ABI COMPLIANT
; ============================================================================
; SiLU (Sigmoid Linear Unit) Activation Kernel - AVX2 Implementation
; 
; CRITICAL FIX: This version properly preserves non-volatile YMM registers
; 
; Mathematical Definition:
;   SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
;
; ACCURATE IMPLEMENTATION:
;   Uses FAST_EXP2 macro from math_approx.inc for accurate exp(-x)
;   Max error: < 1e-5 (degree-6 polynomial)
;
; ABI Compliance (Windows x64):
;   - Non-volatile registers preserved: RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15 (YMM6-YMM15)
;   - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5 (YMM0-YMM5)
;   - Shadow space: 32 bytes allocated on stack
;   - Stack alignment: 16-byte boundary before 'call' instructions
;
; Parameters:
;   RCX = void* data       (pointer to float array, must be 32-byte aligned)
;   RDX = size_t data_size (number of bytes, must be multiple of 32)
;
; Returns:
;   RAX = 0 on success, non-zero on error
; ============================================================================

OPTION CASEMAP:NONE

; Include the FAST_EXP2 macro
INCLUDE math_approx.inc

.const

; Constants for sigmoid computation
ALIGN 16
g_sigmoid_one      REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_sigmoid_neg_one  REAL4 -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0

; Define math constants for FAST_EXP2
MATH_CONSTANTS

.code

; ============================================================================
; MASM_Silu_Activation_AVX512_Fixed - AVX2 version with proper ABI compliance
; ============================================================================

MASM_Silu_Activation_AVX512_Fixed PROC FRAME

    ; Prologue - save non-volatile registers
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    
    ; CRITICAL: Allocate stack space for:
    ;   1. Shadow space (32 bytes)
    ;   2. YMM6-YMM15 save area (10 registers * 32 bytes = 320 bytes)
    ;   3. Stack alignment (ensure 16-byte alignment)
    ; Total: 32 + 320 + 16 = 368 bytes (rounded up to 384 for alignment)
    sub rsp, 384
    .allocstack 384
    .endprolog
    
    ; CRITICAL: Save non-volatile YMM registers (YMM6-YMM15)
    ; These MUST be preserved according to Windows x64 ABI
    vmovaps ymmword ptr [rsp+32], ymm6      ; Save YMM6
    vmovaps ymmword ptr [rsp+64], ymm7      ; Save YMM7
    vmovaps ymmword ptr [rsp+96], ymm8      ; Save YMM8
    vmovaps ymmword ptr [rsp+128], ymm9     ; Save YMM9
    vmovaps ymmword ptr [rsp+160], ymm10    ; Save YMM10
    vmovaps ymmword ptr [rsp+192], ymm11    ; Save YMM11
    vmovaps ymmword ptr [rsp+224], ymm12    ; Save YMM12
    vmovaps ymmword ptr [rsp+256], ymm13    ; Save YMM13
    vmovaps ymmword ptr [rsp+288], ymm14    ; Save YMM14
    vmovaps ymmword ptr [rsp+320], ymm15    ; Save YMM15
    
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
    
    ; Load constants
    vmovups ymm4, YMMWORD PTR [g_sigmoid_one]      ; 1.0
    vmovups ymm5, YMMWORD PTR [g_sigmoid_neg_one]  ; -1.0
    
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
    vmulps ymm1, ymm0, ymm5      ; ymm1 = -x
    
    ; Step 2: Compute exp(-x) using FAST_EXP2
    ; Note: exp(-x) = 2^(-x * log2(e))
    ; We need to convert from base e to base 2
    ; FAST_EXP2 computes 2^x, so we need to pass -x * log2(e)
    
    ; ymm1 = -x
    ; ymm2 = -x * log2(e)
    vmulps ymm1, ymm1, YMMWORD PTR [LOG2E]  ; ymm1 = -x * log2(e)
    
    ; Now compute 2^(-x * log2(e)) = exp(-x)
    FAST_EXP2 ymm1, ymm1, ymm2, ymm3, ymm6
    
    ; Step 3: Compute 1 + exp(-x)
    vaddps ymm1, ymm1, ymm4      ; ymm1 = 1 + exp(-x)
    
    ; Step 4: Compute 1 / (1 + exp(-x))
    ; Use FAST_RECIP for accurate reciprocal
    ; CRITICAL: dst and src must be different registers!
    ; ymm1 = 1 + exp(-x) (input)
    ; ymm2 = 1 / (1 + exp(-x)) (output)
    FAST_RECIP ymm2, ymm1, ymm3, ymm6        ; ymm2 = 1 / (1 + exp(-x)) = sigmoid(x)
    
    ; --- Final SiLU: x * Sigmoid(x) ---
    vmulps ymm0, ymm0, ymm2      ; ymm0 = x * sigmoid(x) = SiLU(x)
    
    ; Store result
    vmovaps YMMWORD PTR [rax], ymm0
    
    ; Advance pointer and decrement counter
    add rax, 32
    sub rcx, 1
    jnz process_loop
    
done:
    ; CRITICAL: Restore non-volatile YMM registers
    vmovaps ymm6, ymmword ptr [rsp+32]      ; Restore YMM6
    vmovaps ymm7, ymmword ptr [rsp+64]      ; Restore YMM7
    vmovaps ymm8, ymmword ptr [rsp+96]      ; Restore YMM8
    vmovaps ymm9, ymmword ptr [rsp+128]     ; Restore YMM9
    vmovaps ymm10, ymmword ptr [rsp+160]    ; Restore YMM10
    vmovaps ymm11, ymmword ptr [rsp+192]    ; Restore YMM11
    vmovaps ymm12, ymmword ptr [rsp+224]    ; Restore YMM12
    vmovaps ymm13, ymmword ptr [rsp+256]    ; Restore YMM13
    vmovaps ymm14, ymmword ptr [rsp+288]    ; Restore YMM14
    vmovaps ymm15, ymmword ptr [rsp+320]    ; Restore YMM15
    
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
    ; Restore stack
    add rsp, 384
    pop rbp
    ret

MASM_Silu_Activation_AVX512_Fixed ENDP

END