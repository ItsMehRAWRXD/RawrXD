; ============================================================================
; silu_clamped.asm - SiLU with input clamping for numerical stability
; ============================================================================
; Clamps input to [-4, 4] before polynomial evaluation to prevent
; catastrophic divergence outside the polynomial's valid range.
;
; SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
; Clamp boundaries
g_neg4      REAL4 -4.0, -4.0, -4.0, -4.0, -4.0, -4.0, -4.0, -4.0
g_pos4      REAL4  4.0,  4.0,  4.0,  4.0,  4.0,  4.0,  4.0,  4.0
g_zero      REAL4  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0
g_one       REAL4  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0

; Constants for exp approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
g_exp_c0    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_exp_c1    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
g_exp_c2    REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5
g_exp_c3    REAL4 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667
g_exp_c4    REAL4 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667

.code

; ============================================================================
; MASM_SiLU_Clamped - SiLU with input clamping for numerical stability
; ============================================================================
; Parameters:
;   RCX = float* data (32-byte aligned)
;   RDX = size_t data_size (in bytes, multiple of 32)
; Returns: RAX = 0 on success
; ============================================================================

MASM_SiLU_Clamped PROC FRAME
    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog

    push rbx
    push rsi

    ; Save parameters
    mov rsi, rcx               ; rsi = data pointer
    mov rbx, rdx               ; rbx = data_size
    
    ; Validate inputs
    test rsi, rsi
    jz error_null
    test rbx, rbx
    jz error_zero
    test rsi, 31
    jnz error_align
    test rbx, 31
    jnz error_size

    ; Calculate iterations
    mov rcx, rbx
    shr rcx, 5                  ; rcx = number of 32-byte blocks
    
    ; Load clamp boundaries
    vmovaps ymm15, YMMWORD PTR [g_neg4]    ; ymm15 = -4.0
    vmovaps ymm14, YMMWORD PTR [g_pos4]    ; ymm14 = 4.0
    
    ; Load exp constants
    vmovaps ymm8, YMMWORD PTR [g_exp_c0]   ; 1.0
    vmovaps ymm9, YMMWORD PTR [g_exp_c1]   ; 1.0
    vmovaps ymm10, YMMWORD PTR [g_exp_c2]  ; 0.5
    vmovaps ymm11, YMMWORD PTR [g_exp_c3]  ; 0.166667
    vmovaps ymm12, YMMWORD PTR [g_exp_c4]  ; 0.041667
    vmovaps ymm13, YMMWORD PTR [g_one]     ; 1.0

process_loop:
    cmp rcx, 0
    jle done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rsi]    ; ymm0 = x
    
    ; ============================================================================
    ; CLAMP INPUT to [-4, 4] before polynomial evaluation
    ; This prevents catastrophic divergence outside the polynomial's valid range
    ; ============================================================================
    vmaxps ymm0, ymm0, ymm15           ; ymm0 = max(x, -4.0)
    vminps ymm0, ymm0, ymm14           ; ymm0 = min(ymm0, 4.0)
    ; Now ymm0 is clamped to [-4, 4]
    
    ; Compute -x for exp(-x)
    ; Load zero and subtract x
    vxorps ymm1, ymm1, ymm1            ; ymm1 = 0
    vsubps ymm1, ymm1, ymm0            ; ymm1 = -x
    
    ; Compute exp(-x) using polynomial: 1 + y + y^2/2 + y^3/6 + y^4/24
    ; where y = -x
    
    ; y^2
    vmulps ymm2, ymm1, ymm1            ; ymm2 = y^2
    
    ; y^3 = y^2 * y
    vmulps ymm3, ymm2, ymm1            ; ymm3 = y^3
    
    ; y^4 = y^2 * y^2
    vmulps ymm4, ymm2, ymm2            ; ymm4 = y^4
    
    ; exp(y) = 1 + y + y^2/2 + y^3/6 + y^4/24
    vmulps ymm2, ymm2, ymm10           ; ymm2 = y^2/2
    vmulps ymm3, ymm3, ymm11           ; ymm3 = y^3/6
    vmulps ymm4, ymm4, ymm12           ; ymm4 = y^4/24
    
    vaddps ymm5, ymm8, ymm1            ; ymm5 = 1 + y
    vaddps ymm5, ymm5, ymm2            ; ymm5 += y^2/2
    vaddps ymm5, ymm5, ymm3            ; ymm5 += y^3/6
    vaddps ymm5, ymm5, ymm4            ; ymm5 += y^4/24
    
    ; Now ymm5 = exp(-x)
    ; Compute 1 + exp(-x)
    vaddps ymm6, ymm5, ymm13           ; ymm6 = 1 + exp(-x)
    
    ; Compute x / (1 + exp(-x)) = SiLU(x)
    ; Use reciprocal multiplication for speed
    vrcpps ymm7, ymm6                  ; ymm7 ≈ 1 / (1 + exp(-x))
    vmulps ymm0, ymm0, ymm7            ; ymm0 = x / (1 + exp(-x))
    
    ; Store result
    vmovaps YMMWORD PTR [rsi], ymm0
    
    ; Advance
    add rsi, 32
    dec rcx
    jmp process_loop

done:
    xor rax, rax
    jmp cleanup

error_null:
    mov rax, 1
    jmp cleanup

error_zero:
    mov rax, 2
    jmp cleanup

error_align:
    mov rax, 3
    jmp cleanup

error_size:
    mov rax, 4

cleanup:
    vzeroupper
    pop rsi
    pop rbx
    add rsp, 32
    pop rbp
    ret

MASM_SiLU_Clamped ENDP

END
