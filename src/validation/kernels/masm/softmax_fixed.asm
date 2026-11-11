; ============================================================================
; softmax_fixed.asm - Corrected Softmax implementation
; ============================================================================
; 4-phase architecture:
;   Phase 1: Horizontal Max Reduction (for numerical stability)
;   Phase 2: Exp Approximation (exp(x - max))
;   Phase 3: Horizontal Sum Reduction
;   Phase 4: Normalization (using reciprocal, not division)
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
; Constants for exp approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
g_exp_c0    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0      ; 1
g_exp_c1    REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0      ; 1 (x coefficient)
g_exp_c2    REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5      ; 1/2
g_exp_c3    REAL4 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667, 0.166667  ; 1/6
g_exp_c4    REAL4 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667, 0.041667  ; 1/24
g_neg_inf   REAL4 -1.0E20, -1.0E20, -1.0E20, -1.0E20, -1.0E20, -1.0E20, -1.0E20, -1.0E20
g_one       REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0

.code

; ============================================================================
; MASM_Softmax_Fixed - Corrected Softmax with AVX2
; ============================================================================
; Parameters:
;   RCX = float* data (32-byte aligned, in-place)
;   RDX = size_t data_size (in bytes, multiple of 32)
; Returns: RAX = 0 on success
; ============================================================================

MASM_Softmax_Fixed PROC FRAME
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
    push r12
    push r13
    push r14

    ; Validate parameters
    test rcx, rcx
    jz error_null
    test rdx, rdx
    jz error_zero
    test rcx, 31
    jnz error_align
    test rdx, 31
    jnz error_size

    ; Save parameters
    mov rsi, rcx          ; rsi = data pointer
    mov rbx, rdx          ; rbx = data_size (bytes)
    mov r12, rcx          ; r12 = original data pointer (for phase 2)
    mov r13, rdx          ; r13 = original size
    shr r13, 2            ; r13 = number of floats

    ; Calculate iterations
    mov rcx, rbx
    shr rcx, 5            ; rcx = data_size / 32 (number of 8-float blocks)

    ; ============================================================================
    ; Phase 1: Find Maximum Value (Horizontal Reduction)
    ; ============================================================================
    vmovaps ymm0, YMMWORD PTR [g_neg_inf]  ; ymm0 = max = -inf
    mov rax, rsi          ; rax = data pointer for phase 1
    mov r14, rcx          ; r14 = iteration count

max_loop:
    cmp r14, 0
    jle max_done

    vmovaps ymm1, YMMWORD PTR [rax]        ; ymm1 = 8 floats
    vmaxps ymm0, ymm0, ymm1                ; ymm0 = max(ymm0, ymm1)

    add rax, 32
    dec r14
    jmp max_loop

max_done:
    ; Horizontal reduction of ymm0 to get global max
    ; ymm0 = [m0, m1, m2, m3, m4, m5, m6, m7]
    vextractf128 xmm1, ymm0, 1             ; xmm1 = [m4, m5, m6, m7]
    vmaxps xmm0, xmm0, xmm1                ; xmm0 = [max(m0,m4), max(m1,m5), ...]
    
    vmovshdup xmm1, xmm0                   ; xmm1 = [max(m1,m5), max(m3,m7), ...]
    vmaxps xmm0, xmm0, xmm1                ; xmm0 = [max(m0,m1,m4,m5), ...]
    
    vmovhlps xmm1, xmm1, xmm0              ; xmm1 = [max(m2,m3,m6,m7), ...]
    vmaxps xmm0, xmm0, xmm1                ; xmm0[0] = global max

    ; Broadcast max to all lanes
    vbroadcastss ymm7, xmm0                ; ymm7 = [max, max, max, ...]

    ; ============================================================================
    ; Phase 2: Compute exp(x - max) and accumulate sum
    ; ============================================================================
    mov rax, rsi          ; rax = data pointer
    mov r14, rcx          ; r14 = iteration count
    vxorps ymm6, ymm6, ymm6                ; ymm6 = sum = 0

    ; Load exp constants
    vmovaps ymm8, YMMWORD PTR [g_exp_c0]   ; 1.0
    vmovaps ymm9, YMMWORD PTR [g_exp_c1]   ; 1.0
    vmovaps ymm10, YMMWORD PTR [g_exp_c2]  ; 0.5
    vmovaps ymm11, YMMWORD PTR [g_exp_c3]  ; 0.166667
    vmovaps ymm12, YMMWORD PTR [g_exp_c4]  ; 0.041667

exp_loop:
    cmp r14, 0
    jle exp_done

    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rax]        ; ymm0 = x

    ; Compute x - max
    vsubps ymm0, ymm0, ymm7                ; ymm0 = x - max

    ; Compute exp(x - max) using polynomial approximation
    ; exp(y) ≈ 1 + y + y^2/2 + y^3/6 + y^4/24
    
    ; y^2
    vmulps ymm1, ymm0, ymm0                ; ymm1 = y^2
    
    ; y^3 = y^2 * y
    vmulps ymm2, ymm1, ymm0                ; ymm2 = y^3
    
    ; y^4 = y^2 * y^2
    vmulps ymm3, ymm1, ymm1                ; ymm3 = y^4
    
    ; exp(y) = 1 + y + y^2/2 + y^3/6 + y^4/24
    vmulps ymm1, ymm1, ymm10               ; ymm1 = y^2/2
    vmulps ymm2, ymm2, ymm11               ; ymm2 = y^3/6
    vmulps ymm3, ymm3, ymm12               ; ymm3 = y^4/24
    
    vaddps ymm4, ymm8, ymm0                ; ymm4 = 1 + y
    vaddps ymm4, ymm4, ymm1                ; ymm4 += y^2/2
    vaddps ymm4, ymm4, ymm2                ; ymm4 += y^3/6
    vaddps ymm4, ymm4, ymm3                ; ymm4 += y^4/24
    
    ; Store exp result back
    vmovaps YMMWORD PTR [rax], ymm4
    
    ; Accumulate sum
    vaddps ymm6, ymm6, ymm4                ; ymm6 += exp(x - max)

    add rax, 32
    dec r14
    jmp exp_loop

exp_done:
    ; ============================================================================
    ; Phase 3: Horizontal Sum Reduction
    ; ============================================================================
    ; ymm6 contains partial sums, need to reduce to single value
    vextractf128 xmm1, ymm6, 1             ; xmm1 = high 4 elements
    vaddps xmm0, xmm0, xmm1                ; xmm0 = low + high
    
    vmovshdup xmm1, xmm0                   ; xmm1 = shuffled
    vaddps xmm0, xmm0, xmm1                ; xmm0 = partial sum
    
    vmovhlps xmm1, xmm1, xmm0              ; xmm1 = high half
    vaddps xmm0, xmm0, xmm1                ; xmm0[0] = total sum

    ; Compute reciprocal of sum (1/sum) using approximation
    ; For better precision, we could use Newton-Raphson refinement
    vrcpss xmm0, xmm0, xmm0                ; xmm0 ≈ 1/sum
    
    ; Broadcast reciprocal sum to all lanes
    vbroadcastss ymm5, xmm0                ; ymm5 = [1/sum, 1/sum, ...]

    ; ============================================================================
    ; Phase 4: Normalize (multiply by reciprocal sum)
    ; ============================================================================
    mov rax, rsi          ; rax = data pointer
    mov r14, rcx          ; r14 = iteration count

normalize_loop:
    cmp r14, 0
    jle normalize_done

    vmovaps ymm0, YMMWORD PTR [rax]        ; ymm0 = exp(x - max)
    vmulps ymm0, ymm0, ymm5                ; ymm0 = exp(x - max) / sum
    vmovaps YMMWORD PTR [rax], ymm0        ; store result

    add rax, 32
    dec r14
    jmp normalize_loop

normalize_done:
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
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rbx
    add rsp, 32
    pop rbp
    ret

MASM_Softmax_Fixed ENDP

END
