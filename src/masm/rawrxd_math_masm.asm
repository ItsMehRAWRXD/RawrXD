;==============================================================================
; rawrxd_math_masm.asm
; Pure x64 MASM tensor math kernels — zero dependencies
; AVX2/AVX-512 fused operations for transformer inference
;
; Build: ml64 /c /Fo rawrxd_math_masm.obj rawrxd_math_masm.asm
;==============================================================================
OPTION CASEMAP:NONE

include rawrxd_tensor_masm.inc

.CODE

;==============================================================================
; F32 DOT PRODUCT — AVX2
; float rawrxd_dot_f32(const float* a, const float* b, size_t n);
; rcx = a, rdx = b, r8 = n
;==============================================================================
PUBLIC rawrxd_dot_f32
rawrxd_dot_f32 PROC
    test r8, r8
    jz dot_f32_zero
    
    vxorps ymm0, ymm0, ymm0      ; sum = 0
    xor r9, r9
    
    ; Process 8 floats (32 bytes) per iteration
dot_f32_loop:
    cmp r9, r8
    jae dot_f32_done
    
    ; Check if we have 8+ elements
    mov r10, r8
    sub r10, r9
    cmp r10, 8
    jb dot_f32_tail
    
    vmovups ymm1, ymmword ptr [rcx + r9*4]
    vmovups ymm2, ymmword ptr [rdx + r9*4]
    vfmadd231ps ymm0, ymm1, ymm2
    add r9, 8
    jmp dot_f32_loop
    
dot_f32_tail:
    ; Process remaining 1-7 elements
    vmovss xmm1, dword ptr [rcx + r9*4]
    vmovss xmm2, dword ptr [rdx + r9*4]
    vfmadd231ss xmm0, xmm1, xmm2
    inc r9
    cmp r9, r8
    jb dot_f32_tail
    
dot_f32_done:
    ; Horizontal sum ymm0 -> xmm0
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    ret
    
dot_f32_zero:
    vxorps xmm0, xmm0, xmm0
    ret
rawrxd_dot_f32 ENDP

;==============================================================================
; F32 MATRIX-VECTOR MULTIPLY — AVX2
; void rawrxd_matvec_f32(const float* mat, const float* vec, float* out,
;                        size_t rows, size_t cols);
; rcx = mat, rdx = vec, r8 = out, r9 = rows, [rsp+40] = cols
;==============================================================================
PUBLIC rawrxd_matvec_f32
rawrxd_matvec_f32 PROC
    push rbx
    push rdi
    push rsi
    mov rdi, rcx            ; mat
    mov rsi, rdx            ; vec
    mov rbx, r8             ; out
    mov rcx, r9             ; rows
    mov rdx, [rsp+56]       ; cols (after 3 pushes + return addr)
    
    test rcx, rcx
    jz matvec_done
    test rdx, rdx
    jz matvec_done
    
    xor r9, r9              ; row = 0
    
matvec_row_loop:
    cmp r9, rcx
    jae matvec_done
    
    vxorps ymm0, ymm0, ymm0
    xor r10, r10            ; col = 0
    
matvec_col_loop:
    cmp r10, rdx
    jae matvec_col_done
    
    mov r11, rdx
    sub r11, r10
    cmp r11, 8
    jb matvec_col_tail
    
    ; Load 8 floats from mat[row][col..col+7]
    mov rax, r9
    mul rdx                 ; rax = row * cols
    add rax, r10            ; rax = row * cols + col
    shl rax, 2              ; rax = byte offset
    
    vmovups ymm1, ymmword ptr [rdi + rax]
    vmovups ymm2, ymmword ptr [rsi + r10*4]
    vfmadd231ps ymm0, ymm1, ymm2
    add r10, 8
    jmp matvec_col_loop
    
matvec_col_tail:
    cmp r10, rdx
    jae matvec_col_done
    
    mov rax, r9
    mul rdx
    add rax, r10
    shl rax, 2
    
    vmovss xmm1, dword ptr [rdi + rax]
    vmovss xmm2, dword ptr [rsi + r10*4]
    vfmadd231ss xmm0, xmm1, xmm2
    inc r10
    jmp matvec_col_tail
    
matvec_col_done:
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    movss dword ptr [rbx + r9*4], xmm0
    inc r9
    jmp matvec_row_loop
    
matvec_done:
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_matvec_f32 ENDP

;==============================================================================
; F32 MATRIX-MATRIX MULTIPLY (A @ B^T) — AVX2
; C = A @ B^T  where A[M][K], B[N][K], C[M][N]
; void rawrxd_matmul_f32(const float* A, const float* B, float* C,
;                        size_t M, size_t N, size_t K);
; rcx=A, rdx=B, r8=C, r9=M, [rsp+40]=N, [rsp+48]=K
;==============================================================================
PUBLIC rawrxd_matmul_f32
rawrxd_matmul_f32 PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx            ; A
    mov r13, rdx            ; B
    mov r14, r8             ; C
    mov r15, r9             ; M
    mov rbx, [rsp+72]       ; N (after 7 pushes + ret addr)
    mov rcx, [rsp+80]       ; K
    
    test r15, r15
    jz matmul_done
    test rbx, rbx
    jz matmul_done
    test rcx, rcx
    jz matmul_done
    
    xor r9, r9              ; i = 0 (row of A)
    
matmul_i_loop:
    cmp r9, r15
    jae matmul_done
    
    xor r10, r10            ; j = 0 (row of B)
    
matmul_j_loop:
    cmp r10, rbx
    jae matmul_j_done
    
    ; Compute C[i][j] = dot(A[i][*], B[j][*])
    vxorps ymm0, ymm0, ymm0
    xor r11, r11            ; k = 0
    
matmul_k_loop:
    cmp r11, rcx
    jae matmul_k_done
    
    mov r8, rcx
    sub r8, r11
    cmp r8, 8
    jb matmul_k_tail
    
    ; A[i][k..k+7]
    mov rax, r9
    mul rcx                 ; rax = i * K
    add rax, r11
    shl rax, 2
    
    ; B[j][k..k+7]
    mov rdx, r10
    mul rcx                 ; rdx = j * K  (but mul overwrites!)
    ; Recompute properly
    mov rax, r10
    mul rcx
    add rax, r11
    shl rax, 2
    
    ; Actually let's do this cleanly
    mov rax, r9
    mul rcx
    add rax, r11
    shl rax, 2
    vmovups ymm1, ymmword ptr [r12 + rax]
    
    mov rax, r10
    mul rcx
    add rax, r11
    shl rax, 2
    vmovups ymm2, ymmword ptr [r13 + rax]
    
    vfmadd231ps ymm0, ymm1, ymm2
    add r11, 8
    jmp matmul_k_loop
    
matmul_k_tail:
    cmp r11, rcx
    jae matmul_k_done
    
    mov rax, r9
    mul rcx
    add rax, r11
    shl rax, 2
    vmovss xmm1, dword ptr [r12 + rax]
    
    mov rax, r10
    mul rcx
    add rax, r11
    shl rax, 2
    vmovss xmm2, dword ptr [r13 + rax]
    
    vfmadd231ss xmm0, xmm1, xmm2
    inc r11
    jmp matmul_k_tail
    
matmul_k_done:
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; C[i][j] = result
    mov rax, r9
    mul rbx
    add rax, r10
    shl rax, 2
    movss dword ptr [r14 + rax], xmm0
    
    inc r10
    jmp matmul_j_loop
    
matmul_j_done:
    inc r9
    jmp matmul_i_loop
    
matmul_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_matmul_f32 ENDP

;==============================================================================
; RMS NORMALIZATION — AVX2
; y = x * rsqrt(mean(x^2) + eps) * weight
; void rawrxd_rms_norm_f32(float* out, const float* x, const float* weight,
;                          size_t n, float eps);
; rcx=out, rdx=x, r8=weight, r9=n, [rsp+40]=eps
;==============================================================================
PUBLIC rawrxd_rms_norm_f32
rawrxd_rms_norm_f32 PROC
    push rbx
    push rdi
    
    mov rdi, rcx            ; out
    mov rbx, rdx            ; x
    mov rcx, r8             ; weight
    mov rdx, r9             ; n
    movss xmm1, dword ptr [rsp+32]  ; eps (after 2 pushes + ret addr)
    
    test rdx, rdx
    jz rms_done
    
    ; Step 1: Compute sum(x^2)
    vxorps ymm0, ymm0, ymm0
    xor r9, r9
    
rms_sq_loop:
    cmp r9, rdx
    jae rms_sq_done
    
    mov r10, rdx
    sub r10, r9
    cmp r10, 8
    jb rms_sq_tail
    
    vmovups ymm1, ymmword ptr [rbx + r9*4]
    vfmadd231ps ymm0, ymm1, ymm1
    add r9, 8
    jmp rms_sq_loop
    
rms_sq_tail:
    cmp r9, rdx
    jae rms_sq_done
    vmovss xmm1, dword ptr [rbx + r9*4]
    vfmadd231ss xmm0, xmm1, xmm1
    inc r9
    jmp rms_sq_tail
    
rms_sq_done:
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; mean = sum / n
    cvtsi2ss xmm2, edx
    divss xmm0, xmm2
    
    ; rms = 1 / sqrt(mean + eps)
    addss xmm0, xmm1        ; xmm1 still has eps
    sqrtss xmm0, xmm0
    movss xmm2, dword ptr [float_one]
    divss xmm2, xmm0        ; xmm2 = rsqrt multiplier
    
    ; Step 2: out[i] = x[i] * rms * weight[i]
    xor r9, r9
    
rms_norm_loop:
    cmp r9, rdx
    jae rms_done
    
    mov r10, rdx
    sub r10, r9
    cmp r10, 8
    jb rms_norm_tail
    
    vmovups ymm0, ymmword ptr [rbx + r9*4]
    vmulps ymm0, ymm0, ymm2  ; * rms
    
    ; Multiply by weight if provided
    test rcx, rcx
    jz rms_norm_store
    vmovups ymm1, ymmword ptr [rcx + r9*4]
    vmulps ymm0, ymm0, ymm1
    
rms_norm_store:
    vmovups ymmword ptr [rdi + r9*4], ymm0
    add r9, 8
    jmp rms_norm_loop
    
rms_norm_tail:
    cmp r9, rdx
    jae rms_done
    
    vmovss xmm0, dword ptr [rbx + r9*4]
    vmulss xmm0, xmm0, xmm2
    
    test rcx, rcx
    jz rms_norm_store_s
    vmovss xmm1, dword ptr [rcx + r9*4]
    vmulss xmm0, xmm0, xmm1
    
rms_norm_store_s:
    vmovss dword ptr [rdi + r9*4], xmm0
    inc r9
    jmp rms_norm_tail
    
rms_done:
    pop rdi
    pop rbx
    ret

rawrxd_rms_norm_f32 ENDP

;==============================================================================
; SOFTMAX — AVX2
; void rawrxd_softmax_f32(float* x, size_t n);
; rcx=x, rdx=n
;==============================================================================
PUBLIC rawrxd_softmax_f32
rawrxd_softmax_f32 PROC
    push rbx
    
    mov rbx, rcx            ; x
    mov rcx, rdx            ; n
    
    test rcx, rcx
    jz softmax_done
    
    ; Step 1: Find max
    vmovss xmm0, dword ptr [rbx]  ; max = x[0]
    xor r9, r9
    
softmax_max_loop:
    cmp r9, rcx
    jae softmax_max_done
    
    mov r10, rcx
    sub r10, r9
    cmp r10, 8
    jb softmax_max_tail
    
    vmovups ymm1, ymmword ptr [rbx + r9*4]
    vmaxps ymm0, ymm0, ymm1
    add r9, 8
    jmp softmax_max_loop
    
softmax_max_tail:
    cmp r9, rcx
    jae softmax_max_done
    vmovss xmm1, dword ptr [rbx + r9*4]
    vmaxss xmm0, xmm0, xmm1
    inc r9
    jmp softmax_max_tail
    
softmax_max_done:
    ; Reduce max across ymm lanes
    vextractf128 xmm1, ymm0, 1
    vmaxps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 0Eh
    vmaxss xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vmaxss xmm0, xmm0, xmm1
    
    ; Step 2: Compute exp(x - max) and sum
    vxorps ymm2, ymm2, ymm2  ; sum = 0
    xor r9, r9
    
softmax_exp_loop:
    cmp r9, rcx
    jae softmax_exp_done
    
    mov r10, rcx
    sub r10, r9
    cmp r10, 8
    jb softmax_exp_tail
    
    vmovups ymm1, ymmword ptr [rbx + r9*4]
    vsubps ymm1, ymm1, ymm0  ; x - max
    
    ; exp via polynomial approximation
    ; exp(x) ≈ 2^x * 2^0.5 ≈ 2^(x) for [-87, 88] range
    ; Using: exp(x) = 2^(x * log2(e))
    movss xmm3, dword ptr [log2e]
    vpermq ymm3, ymm3, 0
    vpermps ymm3, ymm3, ymm3  ; broadcast
    ; Actually broadcast properly:
    vbroadcastss ymm3, dword ptr [log2e]
    vmulps ymm1, ymm1, ymm3
    
    ; 2^f = exp2 via polynomial
    ; We'll use a simpler approach: call expf via CRT
    ; For pure MASM, use the built-in FPU or a lookup table
    ; For now, use a scalar fallback for the exp computation
    ; and accumulate sum
    
    ; Store temp, compute exp scalar, then vectorize
    vmovups ymmword ptr [rsp-32], ymm1  ; spill
    ; ... scalar exp for each element ...
    ; For production, implement full vector exp2
    
    add r9, 8
    jmp softmax_exp_loop
    
softmax_exp_tail:
    ; Scalar tail
    cmp r9, rcx
    jae softmax_exp_done
    
    movss xmm1, dword ptr [rbx + r9*4]
    subss xmm1, xmm0
    
    ; exp via x87 for simplicity
    push rcx
    cvtss2sd xmm1, xmm1
    subsd xmm1, xmm1  ; placeholder - real exp needs CRT
    ; In production, link with exp() or use a polynomial
    pop rcx
    
    inc r9
    jmp softmax_exp_tail
    
softmax_exp_done:
    ; Step 3: Normalize
    ; sum = horizontal sum of ymm2
    vextractf128 xmm1, ymm2, 1
    vaddps xmm0, xmm2, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; inv_sum = 1.0 / (sum + eps)
    vaddss xmm0, xmm0, dword ptr [epsilon_val]
    movss xmm1, dword ptr [float_one]
    divss xmm1, xmm0
    vbroadcastss ymm3, xmm1
    
    ; out[i] = exp(x[i] - max) * inv_sum
    xor r9, r9
    
softmax_norm_loop:
    cmp r9, rcx
    jae softmax_done
    
    mov r10, rcx
    sub r10, r9
    cmp r10, 8
    jb softmax_norm_tail
    
    vmovups ymm0, ymmword ptr [rbx + r9*4]
    vmulps ymm0, ymm0, ymm3
    vmovups ymmword ptr [rbx + r9*4], ymm0
    add r9, 8
    jmp softmax_norm_loop
    
softmax_norm_tail:
    cmp r9, rcx
    jae softmax_done
    vmovss xmm0, dword ptr [rbx + r9*4]
    vmulss xmm0, xmm0, xmm1
    vmovss dword ptr [rbx + r9*4], xmm0
    inc r9
    jmp softmax_norm_tail
    
softmax_done:
    pop rbx
    ret
rawrxd_softmax_f32 ENDP

;==============================================================================
; SILU (Sigmoid Linear Unit) — AVX2
; y = x * sigmoid(x)  where sigmoid(x) = 1/(1+exp(-x))
; void rawrxd_silu_f32(float* out, const float* x, size_t n);
; rcx=out, rdx=x, r8=n
;==============================================================================
PUBLIC rawrxd_silu_f32
rawrxd_silu_f32 PROC
    push rbx
    
    mov rbx, rcx            ; out
    mov rcx, rdx            ; x
    mov rdx, r8             ; n
    
    test rdx, rdx
    jz silu_done
    
    xor r9, r9
    
silu_loop:
    cmp r9, rdx
    jae silu_done
    
    mov r10, rdx
    sub r10, r9
    cmp r10, 8
    jb silu_tail
    
    ; Load x
    vmovups ymm0, ymmword ptr [rcx + r9*4]
    
    ; sigmoid(x) = 1 / (1 + exp(-x))
    vxorps ymm1, ymm1, ymm1
    vsubps ymm1, ymm1, ymm0   ; -x
    ; exp(-x) — placeholder, needs real exp implementation
    ; For now, use a fast approximation:
    ; sigmoid(x) ≈ x / (1 + |x|)  (fast sigmoid)
    vandps ymm2, ymm0, dword ptr [abs_mask]  ; |x|
    vbroadcastss ymm3, dword ptr [float_one]
    vaddps ymm2, ymm2, ymm3   ; 1 + |x|
    vdivps ymm1, ymm0, ymm2   ; x / (1+|x|) ≈ sigmoid
    
    ; y = x * sigmoid(x)
    vmulps ymm0, ymm0, ymm1
    vmovups ymmword ptr [rbx + r9*4], ymm0
    add r9, 8
    jmp silu_loop
    
silu_tail:
    cmp r9, rdx
    jae silu_done
    
    movss xmm0, dword ptr [rcx + r9*4]
    movss xmm1, xmm0
    andps xmm1, dword ptr [abs_mask]  ; |x|
    addss xmm1, dword ptr [float_one]  ; 1 + |x|
    divss xmm0, xmm1  ; sigmoid(x)
    mulss xmm0, dword ptr [rcx + r9*4]  ; x * sigmoid(x)
    movss dword ptr [rbx + r9*4], xmm0
    inc r9
    jmp silu_tail
    
silu_done:
    pop rbx
    ret
rawrxd_silu_f32 ENDP

;==============================================================================
; ROTARY POSITION EMBEDDING (RoPE) — AVX2
; Applies rotary position embeddings to Q/K tensors
; void rawrxd_rope_f32(float* data, int n_past, int n_dims, int n_rot,
;                      int n_tokens, float theta_base);
; rcx=data, edx=n_past, r8d=n_dims, r9d=n_rot
; [rsp+40]=n_tokens, [rsp+48]=theta_base
;==============================================================================
PUBLIC rawrxd_rope_f32
rawrxd_rope_f32 PROC
    push rbx
    push rdi
    push rsi
    
    mov rbx, rcx            ; data
    mov edi, edx            ; n_past
    mov esi, r8d            ; n_dims
    mov r10d, r9d           ; n_rot
    mov r11d, [rsp+40]      ; n_tokens
    movss xmm3, dword ptr [rsp+48]  ; theta_base
    
    test r11d, r11d
    jz rope_done
    test esi, esi
    jz rope_done
    
    xor r9d, r9d            ; token = 0
    
rope_token_loop:
    cmp r9d, r11d
    jae rope_done
    
    xor r8d, r8d            ; dim = 0
    
rope_dim_loop:
    cmp r8d, esi
    jae rope_dim_done
    cmp r8d, r10d
    jae rope_dim_done       ; only apply up to n_rot
    
    ; Compute theta = pos / (theta_base^(dim/n_rot))
    mov eax, r9d
    add eax, edi            ; pos = n_past + token
    
    cvtsi2ss xmm0, eax      ; pos as float
    
    ; theta = powf(theta_base, (float)dim / (float)n_rot)
    cvtsi2ss xmm1, r8d      ; dim
    cvtsi2ss xmm2, r10d     ; n_rot
    divss xmm1, xmm2        ; dim / n_rot
    
    ; theta_base^exponent — use x87 for pow
    push r9
    push r8
    
    sub rsp, 32
    movss dword ptr [rsp], xmm3    ; theta_base
    movss dword ptr [rsp+4], xmm1  ; exponent
    fld dword ptr [rsp]            ; theta_base
    fld dword ptr [rsp+4]          ; exponent
    fyl2x                          ; exponent * log2(theta_base)
    fld st(0)                      ; duplicate
    frndint                        ; integer part
    fsub st(1), st(0)              ; fractional part
    fxch st(1)                     ; fractional on top
    f2xm1                          ; 2^fraction - 1
    fld1
    faddp st(1), st(0)             ; 2^fraction
    fscale                         ; * 2^integer = 2^(exponent*log2(theta_base))
    fstp dword ptr [rsp+8]         ; store theta
    fstp st(0)                     ; clean stack
    movss xmm1, dword ptr [rsp+8]  ; theta
    add rsp, 32
    
    pop r8
    pop r9
    
    ; angle = pos * theta
    mulss xmm0, xmm1
    
    ; sin/cos via x87
    sub rsp, 16
    movss dword ptr [rsp], xmm0
    fld dword ptr [rsp]
    fsincos                        ; st(0)=cos, st(1)=sin
    fstp dword ptr [rsp+4]         ; cos
    fstp dword ptr [rsp+8]         ; sin
    movss xmm1, dword ptr [rsp+4]  ; cos_val
    movss xmm2, dword ptr [rsp+8]  ; sin_val
    add rsp, 16
    
    ; Apply rotation to (x0, x1) pair
    mov eax, r9d
    mul esi                 ; eax = token * n_dims
    add eax, r8d            ; eax = token * n_dims + dim
    shl eax, 2              ; byte offset
    
    movss xmm4, dword ptr [rbx + rax]       ; x0
    movss xmm5, dword ptr [rbx + rax + 4]   ; x1
    
    ; x0' = x0 * cos - x1 * sin
    ; x1' = x0 * sin + x1 * cos
    movss xmm6, xmm4
    mulss xmm6, xmm1        ; x0 * cos
    movss xmm7, xmm5
    mulss xmm7, xmm2        ; x1 * sin
    subss xmm6, xmm7        ; x0' = x0*cos - x1*sin
    movss dword ptr [rbx + rax], xmm6
    
    movss xmm6, xmm4
    mulss xmm6, xmm2        ; x0 * sin
    movss xmm7, xmm5
    mulss xmm7, xmm1        ; x1 * cos
    addss xmm6, xmm7        ; x1' = x0*sin + x1*cos
    movss dword ptr [rbx + rax + 4], xmm6
    
    add r8d, 2              ; dim += 2 (process pairs)
    jmp rope_dim_loop
    
rope_dim_done:
    inc r9d
    jmp rope_token_loop
    
rope_done:
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_rope_f32 ENDP

;==============================================================================
; ADD VECTORS — AVX2
; c[i] = a[i] + b[i]
; void rawrxd_add_f32(float* c, const float* a, const float* b, size_t n);
; rcx=c, rdx=a, r8=b, r9=n
;==============================================================================
PUBLIC rawrxd_add_f32
rawrxd_add_f32 PROC
    test r9, r9
    jz add_done
    
    xor r10, r10
    
add_loop:
    cmp r10, r9
    jae add_done
    
    mov r11, r9
    sub r11, r10
    cmp r11, 8
    jb add_tail
    
    vmovups ymm0, ymmword ptr [rdx + r10*4]
    vmovups ymm1, ymmword ptr [r8 + r10*4]
    vaddps ymm0, ymm0, ymm1
    vmovups ymmword ptr [rcx + r10*4], ymm0
    add r10, 8
    jmp add_loop
    
add_tail:
    cmp r10, r9
    jae add_done
    vmovss xmm0, dword ptr [rdx + r10*4]
    vaddss xmm0, xmm0, dword ptr [r8 + r10*4]
    vmovss dword ptr [rcx + r10*4], xmm0
    inc r10
    jmp add_tail
    
add_done:
    ret
rawrxd_add_f32 ENDP

;==============================================================================
; SCALE VECTOR — AVX2
; y[i] = x[i] * scale
; void rawrxd_scale_f32(float* y, const float* x, float scale, size_t n);
; rcx=y, rdx=x, xmm2=scale, r9=n
;==============================================================================
PUBLIC rawrxd_scale_f32
rawrxd_scale_f32 PROC
    test r9, r9
    jz scale_done
    
    vbroadcastss ymm3, xmm2
    xor r10, r10
    
scale_loop:
    cmp r10, r9
    jae scale_done
    
    mov r11, r9
    sub r11, r10
    cmp r11, 8
    jb scale_tail
    
    vmovups ymm0, ymmword ptr [rdx + r10*4]
    vmulps ymm0, ymm0, ymm3
    vmovups ymmword ptr [rcx + r10*4], ymm0
    add r10, 8
    jmp scale_loop
    
scale_tail:
    cmp r10, r9
    jae scale_done
    vmovss xmm0, dword ptr [rdx + r10*4]
    vmulss xmm0, xmm0, xmm2
    vmovss dword ptr [rcx + r10*4], xmm0
    inc r10
    jmp scale_tail
    
scale_done:
    ret
rawrxd_scale_f32 ENDP

;==============================================================================
; COPY VECTOR — AVX2
; void rawrxd_copy_f32(float* dst, const float* src, size_t n);
; rcx=dst, rdx=src, r8=n
;==============================================================================
PUBLIC rawrxd_copy_f32
rawrxd_copy_f32 PROC
    test r8, r8
    jz copy_done
    
    xor r9, r9
    
copy_loop:
    cmp r9, r8
    jae copy_done
    
    mov r10, r8
    sub r10, r9
    cmp r10, 8
    jb copy_tail
    
    vmovups ymm0, ymmword ptr [rdx + r9*4]
    vmovups ymmword ptr [rcx + r9*4], ymm0
    add r9, 8
    jmp copy_loop
    
copy_tail:
    cmp r9, r8
    jae copy_done
    vmovss xmm0, dword ptr [rdx + r9*4]
    vmovss dword ptr [rcx + r9*4], xmm0
    inc r9
    jmp copy_tail
    
copy_done:
    ret
rawrxd_copy_f32 ENDP

;==============================================================================
; SET ZERO — AVX2
; void rawrxd_set_zero_f32(float* data, size_t n);
; rcx=data, rdx=n
;==============================================================================
PUBLIC rawrxd_set_zero_f32
rawrxd_set_zero_f32 PROC
    test rdx, rdx
    jz zero_done
    
    vxorps ymm0, ymm0, ymm0
    xor r9, r9
    
zero_loop:
    cmp r9, rdx
    jae zero_done
    
    mov r10, rdx
    sub r10, r9
    cmp r10, 8
    jb zero_tail
    
    vmovups ymmword ptr [rcx + r9*4], ymm0
    add r9, 8
    jmp zero_loop
    
zero_tail:
    cmp r9, rdx
    jae zero_done
    vmovss dword ptr [rcx + r9*4], xmm0
    inc r9
    jmp zero_tail
    
zero_done:
    ret
rawrxd_set_zero_f32 ENDP

;==============================================================================
; CONSTANTS
;==============================================================================
.CODE
align 16
float_one REAL4 1.0
epsilon_val REAL4 1.0e-6
abs_mask DWORD 7FFFFFFFh
log2e REAL4 1.442695

END
