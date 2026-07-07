; ============================================================================
; silu_correct.asm - Corrected SiLU implementation
; ============================================================================
; This version uses the same algorithm as the scalar C++ implementation:
;   SiLU(x) = x / (1 + exp(-x))
; Uses polynomial approximation for exp() that matches scalar version
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
; Constants for exp approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
g_exp_c0    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0      ; 1
g_exp_c1    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0      ; 1 (coefficient of x)
g_exp_c2    REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5      ; 1/2
g_exp_c3    REAL4 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667  ; 1/6
g_exp_c4    REAL4 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667  ; 1/24
g_one       REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_neg_one   REAL4 -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0

.code

; ============================================================================
; MASM_SiLU_Correct - Corrected SiLU using exp approximation
; ============================================================================
; Parameters:
;   RCX = float* data (32-byte aligned)
;   RDX = size_t data_size (in bytes, multiple of 32)
; Returns: RAX = 0 on success
; ============================================================================

MASM_SiLU_Correct PROC FRAME
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
    
    ; Validate inputs
    test rax, rax
    jz error_null
    test r8, r8
    jz error_zero
    test rax, 31
    jz alignment_ok
    mov rax, 3                 ; Error: misaligned
    jmp epilogue
    
alignment_ok:
    test r8, 31
    jz size_ok
    mov rax, 4                 ; Error: invalid size
    jmp epilogue
    
size_ok:
    ; Calculate iterations
    mov rcx, r8
    shr rcx, 5                  ; rcx = data_size / 32 (number of 8-float blocks)
    
    ; Load constants
    vmovaps ymm8, YMMWORD PTR [g_exp_c0]   ; 1.0
    vmovaps ymm9, YMMWORD PTR [g_exp_c1]   ; 1.0
    vmovaps ymm10, YMMWORD PTR [g_exp_c2]  ; 0.5
    vmovaps ymm11, YMMWORD PTR [g_exp_c3]  ; 0.166667
    vmovaps ymm12, YMMWORD PTR [g_exp_c4]  ; 0.041667
    vmovaps ymm13, YMMWORD PTR [g_one]     ; 1.0
    vmovaps ymm14, YMMWORD PTR [g_neg_one] ; -1.0
    
process_loop:
    cmp rcx, 0
    jle done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rax]    ; ymm0 = x
    
    ; Compute -x
    vmulps ymm1, ymm0, ymm14           ; ymm1 = -x
    
    ; Compute exp(-x) using polynomial: 1 + (-x) + (-x)^2/2 + (-x)^3/6 + (-x)^4/24
    ; Let y = -x
    ; exp(y) ≈ 1 + y + y^2/2 + y^3/6 + y^4/24
    
    ; y^2
    vmulps ymm2, ymm1, ymm1            ; ymm2 = y^2
    
    ; y^3 = y^2 * y
    vmulps ymm3, ymm2, ymm1            ; ymm3 = y^3
    
    ; y^4 = y^2 * y^2
    vmulps ymm4, ymm2, ymm2            ; ymm4 = y^4
    
    ; exp(y) = 1 + y + y^2/2 + y^3/6 + y^4/24
    vmulps ymm5, ymm2, ymm10           ; ymm5 = y^2/2
    vmulps ymm6, ymm3, ymm11           ; ymm6 = y^3/6
    vmulps ymm7, ymm4, ymm12           ; ymm7 = y^4/24
    
    vaddps ymm15, ymm8, ymm1           ; ymm15 = 1 + y
    vaddps ymm15, ymm15, ymm5          ; ymm15 += y^2/2
    vaddps ymm15, ymm15, ymm6          ; ymm15 += y^3/6
    vaddps ymm15, ymm15, ymm7          ; ymm15 += y^4/24
    
    ; Now ymm15 = exp(-x)
    ; Compute 1 + exp(-x)
    vaddps ymm15, ymm15, ymm13         ; ymm15 = 1 + exp(-x)
    
    ; Compute x / (1 + exp(-x)) = SiLU(x)
    ; Use reciprocal multiplication: x * (1 / (1 + exp(-x)))
    vdivps ymm15, ymm0, ymm15          ; ymm15 = x / (1 + exp(-x))
    
    ; Store result
    vmovaps YMMWORD PTR [rax], ymm15
    
    ; Advance
    add rax, 32
    dec rcx
    jmp process_loop
    
done:
    xor rax, rax
    jmp epilogue

error_null:
    mov rax, 1
    jmp epilogue

error_zero:
    mov rax, 2
    jmp epilogue

epilogue:
    ; Clear YMM state
    vzeroupper
    
    add rsp, 32
    pop rbp
    ret

MASM_SiLU_Correct ENDP

END
