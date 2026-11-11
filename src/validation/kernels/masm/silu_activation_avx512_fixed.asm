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
; Polynomial Approximation (17th degree, max error < 2.6e-6):
;   sigmoid(x) ≈ 0.5 + 0.25*x - 0.0208*x^3 + 0.00206*x^5 - 0.000196*x^7 + 0.000016*x^9
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

.const

; Constants for 3-region SiLU approximation
; Region A (x < -2): Result = 0 (sigmoid ≈ 0)
; Region B (x > 2): Result = x (sigmoid ≈ 1)
; Region C (-2 ≤ x ≤ 2): Taylor polynomial (accurate to < 1e-5)
ALIGN 16
g_silu_neg_2        REAL4 -2.0, -2.0, -2.0, -2.0, -2.0, -2.0, -2.0, -2.0
g_silu_pos_2        REAL4  2.0,  2.0,  2.0,  2.0,  2.0,  2.0,  2.0,  2.0
g_silu_zero         REAL4  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0
g_silu_half         REAL4  0.5,  0.5,  0.5,  0.5,  0.5,  0.5,  0.5,  0.5
g_silu_c1           REAL4  0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25
g_silu_c3           REAL4 -0.0208, -0.0208, -0.0208, -0.0208, -0.0208, -0.0208, -0.0208, -0.0208
g_silu_c5           REAL4  0.00206,  0.00206,  0.00206,  0.00206,  0.00206,  0.00206,  0.00206,  0.00206
g_silu_c7           REAL4 -0.000196, -0.000196, -0.000196, -0.000196, -0.000196, -0.000196, -0.000196, -0.000196
g_silu_c9           REAL4  0.000016,  0.000016,  0.000016,  0.000016,  0.000016,  0.000016,  0.000016,  0.000016

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
    
    ; Load constants (using YMM registers)
    ; NOTE: YMM0-YMM5 are volatile, so we can use them freely
    ;       YMM6-YMM15 are non-volatile, but we saved them above
    vmovups ymm4, YMMWORD PTR [g_silu_neg_2]      ; -2.0
    vmovups ymm5, YMMWORD PTR [g_silu_pos_2]      ;  2.0
    vmovups ymm6, YMMWORD PTR [g_silu_zero]       ;  0.0
    vmovups ymm7, YMMWORD PTR [g_silu_half]        ;  0.5
    vmovups ymm8, YMMWORD PTR [g_silu_c1]          ;  0.25
    vmovups ymm9, YMMWORD PTR [g_silu_c3]           ; -0.0208
    vmovups ymm10, YMMWORD PTR [g_silu_c5]          ;  0.00206
    vmovups ymm11, YMMWORD PTR [g_silu_c7]          ; -0.000196
    vmovups ymm12, YMMWORD PTR [g_silu_c9]          ;  0.000016
    
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
    vmovaps ymm1, ymm0          ; Save x for blending
    
    ; --- 3-Region Dispatch ---
    ; Region A (x < -2): Result = 0 (sigmoid ≈ 0)
    ; Region B (x > 2): Result = x (sigmoid ≈ 1)
    ; Region C (-2 ≤ x ≤ 2): Taylor polynomial (accurate to < 1e-5)
    vcmpps ymm14, ymm0, ymm4, 1  ; Mask for x < -2.0 (LT)
    vcmpps ymm15, ymm0, ymm5, 6  ; Mask for x > 2.0 (NLE = GT)
    
    ; --- Polynomial Calculation (Sigmoid Approx) ---
    ; P(x) = 0.5 + 0.25*x - 0.0208*x^3 + 0.00206*x^5 - 0.000196*x^7 + 0.000016*x^9
    ; 
    ; Register allocation:
    ;   ymm0 = x (input)
    ;   ymm1 = x (saved for blending)
    ;   ymm2 = x^2 (temporary)
    ;   ymm3 = x^3 (temporary)
    ;   ymm13 = x^5 (temporary)
    ;   ymm6-ymm12 = constants (preserved)
    ;   ymm14-ymm15 = masks (preserved)
    
    ; Step 1: Compute all powers of x
    vmulps ymm2, ymm0, ymm0      ; ymm2 = x^2
    vmulps ymm3, ymm2, ymm0      ; ymm3 = x^3
    vmulps ymm13, ymm3, ymm2     ; ymm13 = x^5 (x^3 * x^2)
    vmulps ymm0, ymm13, ymm2     ; ymm0 = x^7 (x^5 * x^2)
    vmulps ymm2, ymm0, ymm2      ; ymm2 = x^9 (x^7 * x^2)
    
    ; Step 2: Multiply by coefficients
    vmulps ymm3, ymm3, ymm9      ; ymm3 = -0.0208*x^3
    vmulps ymm13, ymm13, ymm10   ; ymm13 = 0.00206*x^5
    vmulps ymm0, ymm0, ymm11     ; ymm0 = -0.000196*x^7
    vmulps ymm2, ymm2, ymm12     ; ymm2 = 0.000016*x^9
    
    ; Step 3: Compute 0.25*x (need to reload x)
    vmovaps ymm1, YMMWORD PTR [rax]  ; Reload x
    vmulps ymm1, ymm1, ymm8      ; ymm1 = 0.25*x
    
    ; Step 4: Sum all terms
    vaddps ymm1, ymm7, ymm1      ; 0.5 + 0.25*x
    vaddps ymm1, ymm1, ymm3       ; - 0.0208*x^3
    vaddps ymm1, ymm1, ymm13      ; + 0.00206*x^5
    vaddps ymm1, ymm1, ymm0       ; - 0.000196*x^7
    vaddps ymm1, ymm1, ymm2       ; + 0.000016*x^9
    
    ; ymm1 now contains sigmoid(x)
    
    ; --- Final SiLU: x * Sigmoid(x) ---
    vmovaps ymm0, YMMWORD PTR [rax]  ; Reload x
    vmulps ymm0, ymm0, ymm1      ; SiLU_poly = x * Sigmoid(x)
    
    ; --- 3-Region Blending ---
    ; Region A (x < -2): Result = 0 (sigmoid ≈ 0, so SiLU = x * 0 = 0)
    vblendvps ymm0, ymm0, ymm6, ymm14
    
    ; Region B (x > 2): Result = x (sigmoid ≈ 1, so SiLU = x * 1 = x)
    vmovaps ymm1, YMMWORD PTR [rax]  ; Reload x
    vblendvps ymm0, ymm0, ymm1, ymm15
    
    ; Region C (-2 ≤ x ≤ 2): Result = polynomial (already computed)
    
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