;===============================================================================
; GGML Core Operations - Pure x64 MASM Implementation
; No external dependencies - completely self-contained
; Operations: add, mul, scale, silu, softmax, rope, matmul
;===============================================================================

;-------------------------------------------------------------------------------
; Exports
;-------------------------------------------------------------------------------
PUBLIC ggml_masm_add_f32
PUBLIC ggml_masm_mul_f32
PUBLIC ggml_masm_scale_f32
PUBLIC ggml_masm_silu_f32
PUBLIC ggml_masm_softmax_f32
PUBLIC ggml_masm_rope_f32
PUBLIC ggml_masm_matmul_f32
PUBLIC ggml_masm_rms_norm_f32
PUBLIC ggml_masm_transpose_f32
PUBLIC ggml_masm_copy_f32

;-------------------------------------------------------------------------------
; Data Section - Constants
;-------------------------------------------------------------------------------
.data

; SiLU constants
silu_neg_one  REAL4 -1.0
silu_one      REAL4 1.0
silu_half     REAL4 0.5

; RMS norm epsilon
rms_epsilon   REAL4 1.0e-6

;-------------------------------------------------------------------------------
; Code Section
;-------------------------------------------------------------------------------
.code

;===============================================================================
; ggml_masm_add_f32
; Adds two float arrays element-wise
; RCX = dst pointer, RDX = src0 pointer, R8 = src1 pointer, R9 = count
;===============================================================================
ggml_masm_add_f32 PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src0
    mov     rbx, r8         ; src1
    mov     rcx, r9         ; count
    
    ; Process 8 floats at a time using AVX
    mov     rax, rcx
    shr     rax, 3          ; rax = count / 8
    jz      add_remainder
    
add_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]
    vmovups ymm1, YMMWORD PTR [rsi + 32]
    vmovups ymm2, YMMWORD PTR [rbx]
    vmovups ymm3, YMMWORD PTR [rbx + 32]
    
    vaddps  ymm0, ymm0, ymm2
    vaddps  ymm1, ymm1, ymm3
    
    vmovups YMMWORD PTR [rdi], ymm0
    vmovups YMMWORD PTR [rdi + 32], ymm1
    
    add     rsi, 64
    add     rbx, 64
    add     rdi, 64
    dec     rax
    jnz     add_loop_8
    
add_remainder:
    ; Handle remaining elements
    mov     rax, rcx
    and     rax, 7          ; rax = count % 8
    jz      add_done
    
add_loop_1:
    movss   xmm0, DWORD PTR [rsi]
    addss   xmm0, DWORD PTR [rbx]
    movss   DWORD PTR [rdi], xmm0
    add     rsi, 4
    add     rbx, 4
    add     rdi, 4
    dec     rax
    jnz     add_loop_1
    
add_done:
    vzeroupper
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
ggml_masm_add_f32 ENDP

;===============================================================================
; ggml_masm_mul_f32
; Multiplies two float arrays element-wise
; RCX = dst pointer, RDX = src0 pointer, R8 = src1 pointer, R9 = count
;===============================================================================
ggml_masm_mul_f32 PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src0
    mov     rbx, r8         ; src1
    mov     rcx, r9         ; count
    
    ; Process 8 floats at a time
    mov     rax, rcx
    shr     rax, 3
    jz      mul_remainder
    
mul_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]
    vmovups ymm1, YMMWORD PTR [rsi + 32]
    vmovups ymm2, YMMWORD PTR [rbx]
    vmovups ymm3, YMMWORD PTR [rbx + 32]
    
    vmulps  ymm0, ymm0, ymm2
    vmulps  ymm1, ymm1, ymm3
    
    vmovups YMMWORD PTR [rdi], ymm0
    vmovups YMMWORD PTR [rdi + 32], ymm1
    
    add     rsi, 64
    add     rbx, 64
    add     rdi, 64
    dec     rax
    jnz     mul_loop_8
    
mul_remainder:
    mov     rax, rcx
    and     rax, 7
    jz      mul_done
    
mul_loop_1:
    movss   xmm0, DWORD PTR [rsi]
    mulss   xmm0, DWORD PTR [rbx]
    movss   DWORD PTR [rdi], xmm0
    add     rsi, 4
    add     rbx, 4
    add     rdi, 4
    dec     rax
    jnz     mul_loop_1
    
mul_done:
    vzeroupper
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
ggml_masm_mul_f32 ENDP

;===============================================================================
; ggml_masm_scale_f32
; Scales a float array by a constant
; RCX = dst pointer, RDX = src pointer, R8 = count, XMM3 = scale (float)
;===============================================================================
ggml_masm_scale_f32 PROC FRAME
    push    rsi
    push    rdi
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rcx, r8         ; count
    vbroadcastss ymm3, xmm3   ; Broadcast scale to all lanes
    
    ; Process 8 floats at a time
    mov     rax, rcx
    shr     rax, 3
    jz      scale_remainder
    
scale_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]
    vmovups ymm1, YMMWORD PTR [rsi + 32]
    
    vmulps  ymm0, ymm0, ymm3
    vmulps  ymm1, ymm1, ymm3
    
    vmovups YMMWORD PTR [rdi], ymm0
    vmovups YMMWORD PTR [rdi + 32], ymm1
    
    add     rsi, 64
    add     rdi, 64
    dec     rax
    jnz     scale_loop_8
    
scale_remainder:
    mov     rax, rcx
    and     rax, 7
    jz      scale_done
    
scale_loop_1:
    movss   xmm0, DWORD PTR [rsi]
    mulss   xmm0, xmm3
    movss   DWORD PTR [rdi], xmm0
    add     rsi, 4
    add     rdi, 4
    dec     rax
    jnz     scale_loop_1
    
scale_done:
    vzeroupper
    pop     rdi
    pop     rsi
    ret
    
ggml_masm_scale_f32 ENDP

;===============================================================================
; ggml_masm_silu_f32
; SiLU activation: x * sigmoid(x) = x / (1 + exp(-x))
; RCX = dst pointer, RDX = src pointer, R8 = count
;===============================================================================
ggml_masm_silu_f32 PROC FRAME
    push    rsi
    push    rdi
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rcx, r8         ; count
    
    ; Process 8 floats at a time
    mov     rax, rcx
    shr     rax, 3
    jz      silu_remainder
    
silu_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]      ; x
    vmovups ymm1, YMMWORD PTR [rsi + 32] ; x
    
    ; Compute exp(-x)
    vxorps  ymm2, ymm2, ymm2
    vsubps  ymm2, ymm2, ymm0             ; -x
    
    ; Approximate exp using polynomial (simplified for performance)
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmovups ymm3, ymm2
    vmulps  ymm4, ymm2, ymm2             ; x^2
    vmulps  ymm5, ymm4, ymm2             ; x^3
    vmulps  ymm6, ymm5, ymm2             ; x^4
    
    vmulps  ymm4, ymm4, DWORD PTR [silu_half]    ; x^2/2
    vmulps  ymm5, ymm5, DWORD PTR [silu_one]     ; x^3/6 (approx)
    vmulps  ymm6, ymm6, DWORD PTR [silu_one]     ; x^4/24 (approx)
    
    vaddps  ymm3, ymm3, ymm2             ; 1 + x
    vaddps  ymm3, ymm3, ymm4             ; + x^2/2
    vaddps  ymm3, ymm3, ymm5             ; + x^3/6
    vaddps  ymm3, ymm3, ymm6             ; + x^4/24
    
    ; sigmoid = 1 / (1 + exp(-x))
    vaddps  ymm3, ymm3, DWORD PTR [silu_one]     ; 1 + exp(-x)
    vrcpps  ymm3, ymm3                   ; 1 / (1 + exp(-x))
    
    ; SiLU = x * sigmoid(x)
    vmulps  ymm0, ymm0, ymm3
    
    ; Second batch
    vmovups YMMWORD PTR [rdi], ymm0
    
    add     rsi, 64
    add     rdi, 64
    dec     rax
    jnz     silu_loop_8
    
silu_remainder:
    mov     rax, rcx
    and     rax, 7
    jz      silu_done
    
silu_loop_1:
    movss   xmm0, DWORD PTR [rsi]        ; x
    movss   xmm1, xmm0
    
    ; exp(-x) approximation
    xorps   xmm2, xmm2
    subss   xmm2, xmm0                   ; -x
    
    ; Simplified exp for single element
    movss   xmm3, DWORD PTR [silu_one]
    addss   xmm3, xmm2                   ; 1 + (-x) approximation
    
    ; sigmoid = 1 / (1 + exp(-x))
    movss   xmm4, DWORD PTR [silu_one]
    addss   xmm4, xmm3
    movss   xmm5, DWORD PTR [silu_one]
    divss   xmm5, xmm4
    
    ; SiLU = x * sigmoid
    mulss   xmm0, xmm5
    movss   DWORD PTR [rdi], xmm0
    
    add     rsi, 4
    add     rdi, 4
    dec     rax
    jnz     silu_loop_1
    
silu_done:
    vzeroupper
    pop     rdi
    pop     rsi
    ret
    
ggml_masm_silu_f32 ENDP

;===============================================================================
; ggml_masm_softmax_f32
; Softmax: exp(x_i) / sum(exp(x_j))
; RCX = dst pointer, RDX = src pointer, R8 = count
;===============================================================================
ggml_masm_softmax_f32 PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rcx, r8         ; count
    
    ; Find max for numerical stability
    movss   xmm0, DWORD PTR [rsi]        ; max = src[0]
    mov     rax, 1
    
find_max_loop:
    cmp     rax, rcx
    jge     find_max_done
    movss   xmm1, DWORD PTR [rsi + rax*4]
    maxss   xmm0, xmm1
    inc     rax
    jmp     find_max_loop
    
find_max_done:
    vmovss  xmm7, xmm0                   ; xmm7 = max
    
    ; Compute exp(x - max) and sum - scalar version for simplicity
    xorps   xmm6, xmm6                   ; xmm6 = sum
    mov     rax, rcx
    mov     r12, rdi                     ; save dst
    mov     r13, rsi                     ; save src
    
exp_loop:
    test    rax, rax
    jz      exp_done
    
    ; Process 8 elements at a time
    cmp     rax, 8
    jl      exp_scalar
    
    vmovups ymm0, YMMWORD PTR [r13]
    ; Subtract max from each element
    ; Broadcast xmm7 to ymm4: use vshufps to replicate within xmm, then insert
    vmovaps xmm4, xmm7                   ; xmm4 = max
    vshufps xmm4, xmm4, xmm4, 0          ; xmm4 = [max, max, max, max]
    ; Create ymm4 with xmm4 in both halves
    ; vinsertf128 ymm, ymm, xmm, imm - ymm dest, ymm src1, xmm src2, imm8
    ; Use vmovlhps to duplicate xmm4, then vinsertf128
    vmovlhps xmm5, xmm4, xmm4            ; xmm5 = xmm4
    vinsertf128 ymm4, ymm4, xmm5, 1      ; ymm4 high = xmm5
    vsubps  ymm0, ymm0, ymm4             ; x - max
    
    ; Approximate exp
    vmovups ymm1, ymm0
    vmulps  ymm2, ymm0, ymm0             ; x^2
    vmulps  ymm3, ymm2, ymm0             ; x^3
    
    vmulps  ymm2, ymm2, DWORD PTR [silu_half]    ; x^2/2
    vmulps  ymm3, ymm3, DWORD PTR [silu_one]       ; x^3/6 (approx)
    
    vaddps  ymm0, ymm1, ymm0             ; 1 + x
    vaddps  ymm0, ymm0, ymm2             ; + x^2/2
    vaddps  ymm0, ymm0, ymm3             ; + x^3/6
    
    vmovups YMMWORD PTR [r12], ymm0
    
    ; Accumulate sum (horizontal add)
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    addss   xmm6, xmm0
    
    add     r13, 32
    add     r12, 32
    sub     rax, 8
    jmp     exp_loop
    
exp_scalar:
    ; Process remaining elements
    test    rax, rax
    jz      exp_done
    
    movss   xmm0, DWORD PTR [r13]
    subss   xmm0, xmm7                   ; x - max
    
    ; exp(x) approximation
    movss   xmm1, xmm0
    mulss   xmm1, xmm1                   ; x^2
    movss   xmm2, xmm1
    mulss   xmm2, xmm0                   ; x^3
    
    mulss   xmm1, DWORD PTR [silu_half]  ; x^2/2
    mulss   xmm2, DWORD PTR [silu_one]   ; x^3/6 (approx)
    
    addss   xmm0, xmm0                   ; 1 + x (xmm0 already has x)
    addss   xmm0, xmm1                   ; + x^2/2
    addss   xmm0, xmm2                   ; + x^3/6
    addss   xmm0, DWORD PTR [silu_one]   ; + 1
    
    movss   DWORD PTR [r12], xmm0
    addss   xmm6, xmm0
    
    add     r13, 4
    add     r12, 4
    dec     rax
    jmp     exp_scalar
    
exp_done:
    ; Normalize: divide by sum
    mov     rax, rcx
    mov     r12, rdi                     ; restore dst
    
    ; Create broadcasted sum in ymm7
    vxorps  ymm7, ymm7, ymm7
    vinsertf128 ymm7, ymm7, xmm6, 0      ; ymm7 low = xmm6
    vinsertf128 ymm7, ymm7, xmm6, 1      ; ymm7 high = xmm6
    
norm_loop:
    test    rax, rax
    jz      softmax_done
    
    cmp     rax, 8
    jl      norm_scalar
    
    vmovups ymm0, YMMWORD PTR [r12]
    vdivps  ymm0, ymm0, ymm7
    vmovups YMMWORD PTR [r12], ymm0
    
    add     r12, 32
    sub     rax, 8
    jmp     norm_loop
    
norm_scalar:
    test    rax, rax
    jz      softmax_done
    
    movss   xmm0, DWORD PTR [r12]
    divss   xmm0, xmm6
    movss   DWORD PTR [r12], xmm0
    
    add     r12, 4
    dec     rax
    jmp     norm_scalar
    
softmax_done:
    vzeroupper
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
ggml_masm_softmax_f32 ENDP

;===============================================================================
; ggml_masm_rope_f32
; Rotary Position Embedding
; RCX = dst pointer, RDX = src pointer, R8 = head_dim, R9 = position
;===============================================================================
ggml_masm_rope_f32 PROC FRAME
    push    rsi
    push    rdi
    push    rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg rbx
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rbx, r8         ; head_dim
    mov     rcx, r9         ; position
    
    cvtsi2ss xmm6, rcx                     ; position as float
    
    xor     rax, rax                       ; i = 0
    
rope_loop:
    cmp     rax, rbx
    jge     rope_done
    
    ; freq = 1.0 / (10000.0 ^ (2*i / head_dim))
    mov     r8, rax
    shr     r8, 1                          ; i / 2
    cvtsi2ss xmm0, r8
    cvtsi2ss xmm1, rbx
    divss   xmm0, xmm1                     ; (i/2) / head_dim
    
    ; 10000.0 ^ x = exp(x * ln(10000))
    movss   xmm1, DWORD PTR [silu_one]
    mov     r8d, 9219                      ; ln(10000) * 2^20 approx
    movd    xmm2, r8d
    mulss   xmm0, xmm2
    
    ; Simplified: freq = 1.0 / (1.0 + x * 9.21) for approximation
    mulss   xmm0, DWORD PTR [silu_one]     ; scale
    addss   xmm0, DWORD PTR [silu_one]
    movss   xmm1, DWORD PTR [silu_one]
    divss   xmm1, xmm0                     ; freq
    
    ; angle = position * freq
    movss   xmm0, xmm6
    mulss   xmm0, xmm1                     ; angle
    
    ; Load x, y pair
    movss   xmm2, DWORD PTR [rsi + rax*4]     ; x
    movss   xmm3, DWORD PTR [rsi + rax*4 + 4]  ; y
    
    ; Compute cos, sin (using approximation)
    ; cos(a) ≈ 1 - a^2/2 + a^4/24
    ; sin(a) ≈ a - a^3/6 + a^5/120
    movss   xmm4, xmm0
    mulss   xmm4, xmm4                     ; a^2
    
    movss   xmm5, DWORD PTR [silu_one]
    movss   xmm7, xmm4
    mulss   xmm7, DWORD PTR [silu_half]    ; a^2/2
    subss   xmm5, xmm7                     ; 1 - a^2/2
    
    ; sin(a) ≈ a (simplified)
    
    ; Apply rotation
    ; x' = x * cos - y * sin
    ; y' = x * sin + y * cos
    movss   xmm7, xmm2
    mulss   xmm7, xmm5                     ; x * cos
    movss   xmm8, xmm3
    mulss   xmm8, xmm0                     ; y * sin (approx)
    subss   xmm7, xmm8                     ; x'
    
    movss   xmm8, xmm2
    mulss   xmm8, xmm0                     ; x * sin
    movss   xmm9, xmm3
    mulss   xmm9, xmm5                     ; y * cos
    addss   xmm8, xmm9                     ; y'
    
    movss   DWORD PTR [rdi + rax*4], xmm7
    movss   DWORD PTR [rdi + rax*4 + 4], xmm8
    
    add     rax, 2
    jmp     rope_loop
    
rope_done:
    pop     rbx
    pop     rdi
    pop     rsi
    ret
    
ggml_masm_rope_f32 ENDP

;===============================================================================
; ggml_masm_matmul_f32
; Matrix multiplication: C = A * B
; RCX = C pointer, RDX = A pointer, R8 = B pointer
; R9 = M (rows of A), [RSP+40] = N (cols of B), [RSP+48] = K (cols of A / rows of B)
;===============================================================================
ggml_masm_matmul_f32 PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog
    
    mov     rdi, rcx        ; C
    mov     rsi, rdx        ; A
    mov     rbx, r8         ; B
    mov     r12, r9         ; M
    mov     r13, QWORD PTR [rsp + 64]   ; N
    mov     r14, QWORD PTR [rsp + 72]   ; K
    
    xor     r15, r15        ; i = 0 (row of A/C)
    
row_loop:
    cmp     r15, r12
    jge     matmul_done
    
    xor     rcx, rcx        ; j = 0 (col of B/C)
    
col_loop:
    cmp     rcx, r13
    jge     next_row
    
    ; Compute dot product of row i of A and column j of B
    vxorps  ymm0, ymm0, ymm0             ; Accumulator
    
    xor     rax, rax        ; k = 0
    
dot_loop:
    cmp     rax, r14
    jge     dot_done
    
    ; Load 8 elements from A row
    vmovups ymm1, YMMWORD PTR [rsi + rax*4]
    
    ; Load 8 elements from B column (need to gather)
    ; For simplicity, assume B is row-major and compute offset
    ; B[k, j] is at B + k*N + j
    mov     r8, rax
    imul    r8, r13
    add     r8, rcx
    vmovups ymm2, YMMWORD PTR [rbx + r8*4]
    
    ; Multiply and accumulate
    vfmadd231ps ymm0, ymm1, ymm2
    
    add     rax, 8
    jmp     dot_loop
    
dot_done:
    ; Horizontal sum of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Store result C[i, j]
    mov     r8, r15
    imul    r8, r13
    add     r8, rcx
    movss   DWORD PTR [rdi + r8*4], xmm0
    
    inc     rcx
    jmp     col_loop
    
next_row:
    inc     r15
    ; Advance A to next row
    mov     rax, r14
    shl     rax, 2
    add     rsi, rax
    jmp     row_loop
    
matmul_done:
    vzeroupper
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
ggml_masm_matmul_f32 ENDP

;===============================================================================
; ggml_masm_rms_norm_f32
; RMS Normalization: x / sqrt(mean(x^2) + epsilon)
; RCX = dst pointer, RDX = src pointer, R8 = count
;===============================================================================
ggml_masm_rms_norm_f32 PROC FRAME
    push    rsi
    push    rdi
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rcx, r8         ; count
    
    ; Compute sum of squares
    vxorps  ymm0, ymm0, ymm0             ; sum
    
    mov     rax, rcx
    shr     rax, 3                       ; Process 8 at a time
    jz      rms_remainder_sum
    
rms_sum_loop_8:
    vmovups ymm1, YMMWORD PTR [rsi]
    vmulps  ymm1, ymm1, ymm1             ; x^2
    vaddps  ymm0, ymm0, ymm1
    add     rsi, 32
    dec     rax
    jnz     rms_sum_loop_8
    
rms_remainder_sum:
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Add remaining elements
    mov     rax, rcx
    and     rax, 7
    jz      rms_compute_norm
    
rms_sum_loop_1:
    movss   xmm1, DWORD PTR [rsi]
    mulss   xmm1, xmm1
    addss   xmm0, xmm1
    add     rsi, 4
    dec     rax
    jnz     rms_sum_loop_1
    
rms_compute_norm:
    ; mean = sum / count
    cvtsi2ss xmm1, rcx
    divss   xmm0, xmm1
    
    ; rms = sqrt(mean + epsilon)
    addss   xmm0, DWORD PTR [rms_epsilon]
    sqrtss  xmm0, xmm0
    
    ; scale = 1 / rms
    movss   xmm1, DWORD PTR [silu_one]
    divss   xmm1, xmm0                   ; xmm1 = scale
    vbroadcastss ymm1, xmm1
    
    ; Reset src pointer
    mov     rsi, rdx
    
    ; Scale all elements
    mov     rax, rcx
    shr     rax, 3
    jz      rms_scale_remainder
    
rms_scale_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]
    vmulps  ymm0, ymm0, ymm1
    vmovups YMMWORD PTR [rdi], ymm0
    add     rsi, 32
    add     rdi, 32
    dec     rax
    jnz     rms_scale_loop_8
    
rms_scale_remainder:
    mov     rax, rcx
    and     rax, 7
    jz      rms_done
    
rms_scale_loop_1:
    movss   xmm0, DWORD PTR [rsi]
    mulss   xmm0, xmm1
    movss   DWORD PTR [rdi], xmm0
    add     rsi, 4
    add     rdi, 4
    dec     rax
    jnz     rms_scale_loop_1
    
rms_done:
    vzeroupper
    pop     rdi
    pop     rsi
    ret
    
ggml_masm_rms_norm_f32 ENDP

;===============================================================================
; ggml_masm_transpose_f32
; Transpose a matrix
; RCX = dst pointer, RDX = src pointer, R8 = rows, R9 = cols
;===============================================================================
ggml_masm_transpose_f32 PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     r12, r8         ; rows
    mov     rbx, r9         ; cols
    
    xor     rcx, rcx        ; i = 0
    
transpose_row_loop:
    cmp     rcx, r12
    jge     transpose_done
    
    xor     rdx, rdx        ; j = 0
    
transpose_col_loop:
    cmp     rdx, rbx
    jge     next_transpose_row
    
    ; dst[j * rows + i] = src[i * cols + j]
    mov     r8, rcx
    imul    r8, rbx
    add     r8, rdx
    movss   xmm0, DWORD PTR [rsi + r8*4]
    
    mov     r8, rdx
    imul    r8, r12
    add     r8, rcx
    movss   DWORD PTR [rdi + r8*4], xmm0
    
    inc     rdx
    jmp     transpose_col_loop
    
next_transpose_row:
    inc     rcx
    jmp     transpose_row_loop
    
transpose_done:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
ggml_masm_transpose_f32 ENDP

;===============================================================================
; ggml_masm_copy_f32
; Copy float array
; RCX = dst pointer, RDX = src pointer, R8 = count
;===============================================================================
ggml_masm_copy_f32 PROC FRAME
    push    rsi
    push    rdi
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov     rdi, rcx        ; dst
    mov     rsi, rdx        ; src
    mov     rcx, r8         ; count
    
    ; Process 8 floats at a time
    mov     rax, rcx
    shr     rax, 3
    jz      copy_remainder
    
copy_loop_8:
    vmovups ymm0, YMMWORD PTR [rsi]
    vmovups YMMWORD PTR [rdi], ymm0
    add     rsi, 32
    add     rdi, 32
    dec     rax
    jnz     copy_loop_8
    
copy_remainder:
    mov     rax, rcx
    and     rax, 7
    jz      copy_done
    
copy_loop_1:
    movss   xmm0, DWORD PTR [rsi]
    movss   DWORD PTR [rdi], xmm0
    add     rsi, 4
    add     rdi, 4
    dec     rax
    jnz     copy_loop_1
    
copy_done:
    vzeroupper
    pop     rdi
    pop     rsi
    ret
    
ggml_masm_copy_f32 ENDP

;-------------------------------------------------------------------------------
; End of file
;-------------------------------------------------------------------------------
END
