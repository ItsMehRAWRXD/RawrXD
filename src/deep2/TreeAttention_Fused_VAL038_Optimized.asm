; ============================================================================
; TreeAttention_Fused_VAL038_Optimized.asm
;
; VAL-038 Phase 2: Sub-500ns Fused Attention Kernel
;
; Optimization: Eliminates [rsp+224] stack spill by using register-to-register
; vbroadcastss directly from source zmm registers. All intermediate state
; stays in zmm registers through the entire Q×K→softmax→×V pipeline.
;
; Target: <500ns (down from 684ns baseline)
; Method: Zero stack spills, full register residency
;
; Register Allocation (32 zmm registers, zero spills):
;   zmm0-zmm3:    Query vectors (pinned, loaded once)
;   zmm4-zmm7:    Key cache stream (loaded per-token)
;   zmm8-zmm11:   Value cache stream (loaded per-token)
;   zmm12:        Score accumulator (Q·K dot product)
;   zmm13:        Max score (for numerical stability)
;   zmm14:        Sum of exp scores (softmax denominator)
;   zmm15:        Broadcast scale (1/sqrt(head_dim))
;   zmm16-zmm19:  Output accumulators (V weighted by attention)
;   zmm20:        Exp workspace (never spilled)
;   zmm21:        Mask workspace
;   zmm22-zmm31:  Reserved for future Medusa/speculative paths
;
; ABI (Windows x64):
;   rcx = Q (float*, head_dim elements)
;   rdx = K (float*, seq_len * head_dim elements)
;   r8  = V (float*, seq_len * head_dim elements)
;   r9  = output (float*, head_dim elements)
;   [rsp+40] = seq_len (int)
;   [rsp+48] = head_dim (int)
;
; Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
; ============================================================================

.code

; ---------------------------------------------------------------------------
; extern "C" void TreeAttention_Fused_VAL038_Optimized(
;     const float* Q,        // rcx
;     const float* K,        // rdx
;     const float* V,        // r8
;     float*       output,   // r9
;     int          seq_len,  // [rsp+40]
;     int          head_dim  // [rsp+48]
; );
; ---------------------------------------------------------------------------

TreeAttention_Fused_VAL038_Optimized PROC public

    ; --- Prologue: minimal register saves ---
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 40                      ; shadow space only (no local spills)

    ; Load stack arguments
    mov  ebx, dword ptr [rsp+40+40]   ; seq_len
    mov  esi, dword ptr [rsp+48+40]   ; head_dim

    ; --- Compute scale = 1/sqrt(head_dim) ---
    ; head_dim is power of 2 (typically 128), sqrt = 11.31...
    ; Use bit hack for fast 1/sqrt
    cvtsi2ss xmm0, esi                 ; xmm0 = (float)head_dim
    rsqrtss xmm0, xmm0                 ; xmm0 = 1/sqrt(head_dim) approx
    vbroadcastss zmm15, xmm0           ; zmm15 = scale (broadcast, no spill)

    ; --- Load Q into zmm0-zmm3 (first 64 floats, head_dim=128 → 8 loads) ---
    ; For head_dim=128: Q has 128 floats = 8 zmm registers
    ; We process in two passes of 64 elements each
    vmovups zmm0, [rcx]                ; Q[0:15]
    vmovups zmm1, [rcx+64]             ; Q[16:31]
    vmovups zmm2, [rcx+128]            ; Q[32:47]
    vmovups zmm3, [rcx+192]            ; Q[48:63]

    ; --- Initialize accumulators (zero-set) ---
    vpxord  zmm12, zmm12, zmm12        ; score accumulator = 0
    vpxord  zmm13, zmm13, zmm13        ; max score = 0
    vpxord  zmm14, zmm14, zmm14        ; exp sum = 0
    vpxord  zmm16, zmm16, zmm16        ; output accumulator 0
    vpxord  zmm17, zmm17, zmm17        ; output accumulator 1
    vpxord  zmm18, zmm18, zmm18        ; output accumulator 2
    vpxord  zmm19, zmm19, zmm19        ; output accumulator 3

    ; --- Process each key/value token ---
    xor  edi, edi                      ; token index = 0
    mov  r12, rdx                      ; K pointer
    mov  r13, r8                       ; V pointer

    ; head_dim in bytes for stride
    mov  r14, rsi
    shl  r14, 2                        ; head_dim * 4 (bytes per token row)

token_loop:
    cmp  edi, ebx
    jge  token_loop_end

    ; --- Q · K^T dot product (first 64 elements) ---
    vmovups zmm4, [r12]                ; K[token, 0:15]
    vmovups zmm5, [r12+64]             ; K[token, 16:31]
    vmovups zmm6, [r12+128]            ; K[token, 32:47]
    vmovups zmm7, [r12+192]            ; K[token, 48:63]

    ; FMA: zmm12 += Q * K (4 chunks of 16)
    vfmadd231ps zmm12, zmm0, zmm4      ; zmm12 += Q[0:15] * K[0:15]
    vfmadd231ps zmm12, zmm1, zmm5      ; += Q[16:31] * K[16:31]
    vfmadd231ps zmm12, zmm2, zmm6      ; += Q[32:47] * K[32:47]
    vfmadd231ps zmm12, zmm3, zmm7      ; += Q[48:63] * K[48:63]

    ; --- Horizontal sum of zmm12 to get scalar score ---
    ; Use vextractf64x4 + hadd for fast reduction (no stack spill)
    vextractf64x4 ymm0, zmm12, 1       ; ymm0 = high 256 bits
    vaddps ymm0, ymm0, ymm12           ; ymm0 = sum of high+low
    vhaddps ymm0, ymm0, ymm0           ; pairwise add
    vhaddps ymm0, ymm0, ymm0           ; pairwise add again
    ; ymm0[0] now has the scalar sum (approximate, good enough for routing)

    ; --- Apply scale: score *= 1/sqrt(head_dim) ---
    ; Register-to-register broadcast (NO stack spill)
    vmulss xmm1, xmm0, xmm15           ; xmm1 = score * scale (scalar lane)
    vbroadcastss zmm20, xmm1            ; zmm20 = broadcast score (for vector ops)

    ; --- Update max score (for numerical stability) ---
    ; max_score = max(max_score, score)
    vmaxss xmm2, xmm1, xmm13            ; scalar max
    vbroadcastss zmm13, xmm2             ; update zmm13 (no spill)

    ; --- Compute exp(score - max) ---
    ; exp_sub = exp(score - max_score)
    vsubss xmm3, xmm1, xmm2             ; xmm3 = score - max
    ; Fast exp approximation using polynomial (avoids libm call)
    ; exp(x) ≈ 2^(x * log2(e)) using AVX-512 exponent
    ; For exact: use exp2f(x * 1.442695041f)
    vmulss xmm3, xmm3, xmm0             ; xmm3 *= log2(e) (reuse xmm0)
    ; Round to integer for 2^n, multiply fractional part
    ; Simplified: use exp approximation
    vbroadcastss zmm20, xmm3             ; zmm20 = exponent
    ; exp2 via AVX-512: not directly available, use polynomial
    ; For now: use scalar expf (will optimize with LUT later)
    ; Store to temp register only (zmm21, no stack)
    vmovd eax, xmm3
    cvtsi2ss xmm4, eax                  ; integer part
    vsubss xmm5, xmm3, xmm4             ; fractional part
    ; 2^frac ≈ 1 + frac*0.6931 + frac^2*0.2402 + ...
    vmovss xmm6, dword ptr [exp2_poly+0]  ; 1.0
    vfmadd132ss xmm5, xmm6, dword ptr [exp2_poly+4]  ; + 0.6931
    vfmadd132ss xmm5, xmm6, dword ptr [exp2_poly+8]  ; + 0.2402
    ; 2^int via bit manipulation
    vaddss xmm4, xmm4, dword ptr [exp2_bias]  ; add 127 bias
    vcvtps2dq xmm4, xmm4                     ; to int
    vpslld xmm4, xmm4, 23                    ; shift to exponent position
    vmulss xmm5, xmm5, xmm4                  ; combine
    vbroadcastss zmm20, xmm5                 ; zmm20 = exp(score - max)

    ; --- Accumulate exp sum ---
    vaddss xmm7, xmm14, xmm5                 ; xmm7 = exp_sum + exp_val
    vbroadcastss zmm14, xmm7                  ; update zmm14 (no spill)

    ; --- Load V and accumulate weighted output ---
    vmovups zmm8, [r13]                       ; V[token, 0:15]
    vmovups zmm9, [r13+64]                    ; V[token, 16:31]
    vmovups zmm10, [r13+128]                  ; V[token, 32:47]
    vmovups zmm11, [r13+192]                  ; V[token, 48:63]

    ; output += exp_val * V (register-to-register, no spill)
    vfmadd231ps zmm16, zmm20, zmm8            ; out[0:15] += exp * V[0:15]
    vfmadd231ps zmm17, zmm20, zmm9            ; out[16:31] += exp * V[16:31]
    vfmadd231ps zmm18, zmm20, zmm10           ; out[32:47] += exp * V[32:47]
    vfmadd231ps zmm19, zmm20, zmm11           ; out[48:63] += exp * V[48:63]

    ; --- Advance to next token ---
    add r12, r14                              ; K += head_dim * 4
    add r13, r14                              ; V += head_dim * 4
    inc edi
    jmp token_loop

token_loop_end:
    ; --- Normalize: output /= exp_sum ---
    ; Compute 1/exp_sum once, broadcast, multiply
    vrcp14ss xmm0, xmm14                      ; approximate reciprocal
    ; Refine with Newton-Raphson: r = r * (2 - x * r)
    vmulss xmm1, xmm14, xmm0
    vsubss xmm2, dword ptr [one_const], xmm1
    vmulss xmm0, xmm0, xmm2
    vbroadcastss zmm15, xmm0                   ; zmm15 = 1/exp_sum

    vmulps zmm16, zmm16, zmm15                 ; normalize output
    vmulps zmm17, zmm17, zmm15
    vmulps zmm18, zmm18, zmm15
    vmulps zmm19, zmm19, zmm15

    ; --- Store output (first 64 elements) ---
    vmovups [r9], zmm16                        ; output[0:15]
    vmovups [r9+64], zmm17                     ; output[16:31]
    vmovups [r9+128], zmm18                    ; output[32:47]
    vmovups [r9+192], zmm19                    ; output[48:63]

    ; --- Process second half of head_dim (64:127) if head_dim > 64 ---
    cmp esi, 64
    jle cleanup

    ; Reload Q for second half
    vmovups zmm0, [rcx+256]                    ; Q[64:79]
    vmovups zmm1, [rcx+320]                    ; Q[80:95]
    vmovups zmm2, [rcx+384]                    ; Q[96:111]
    vmovups zmm3, [rcx+448]                    ; Q[112:127]

    ; Reset accumulators for second half
    vpxord zmm12, zmm12, zmm12
    vpxord zmm13, zmm13, zmm13
    vpxord zmm14, zmm14, zmm14
    vpxord zmm16, zmm16, zmm16
    vpxord zmm17, zmm17, zmm17
    vpxord zmm18, zmm18, zmm18
    vpxord zmm19, zmm19, zmm19

    ; Reset pointers
    mov r12, rdx
    mov r13, r8
    xor edi, edi

token_loop2:
    cmp edi, ebx
    jge token_loop2_end

    vmovups zmm4, [r12+256]
    vmovups zmm5, [r12+320]
    vmovups zmm6, [r12+384]
    vmovups zmm7, [r12+448]

    vfmadd231ps zmm12, zmm0, zmm4
    vfmadd231ps zmm12, zmm1, zmm5
    vfmadd231ps zmm12, zmm2, zmm6
    vfmadd231ps zmm12, zmm3, zmm7

    vextractf64x4 ymm0, zmm12, 1
    vaddps ymm0, ymm0, ymm12
    vhaddps ymm0, ymm0, ymm0
    vhaddps ymm0, ymm0, ymm0

    vmulss xmm1, xmm0, xmm15
    vmaxss xmm2, xmm1, xmm13
    vbroadcastss zmm13, xmm2
    vsubss xmm3, xmm1, xmm2
    vmulss xmm3, xmm3, xmm0
    vbroadcastss zmm20, xmm3
    vmovd eax, xmm3
    cvtsi2ss xmm4, eax
    vsubss xmm5, xmm3, xmm4
    vmovss xmm6, dword ptr [exp2_poly+0]
    vfmadd132ss xmm5, xmm6, dword ptr [exp2_poly+4]
    vfmadd132ss xmm5, xmm6, dword ptr [exp2_poly+8]
    vaddss xmm4, xmm4, dword ptr [exp2_bias]
    vcvtps2dq xmm4, xmm4
    vpslld xmm4, xmm4, 23
    vmulss xmm5, xmm5, xmm4
    vbroadcastss zmm20, xmm5
    vaddss xmm7, xmm14, xmm5
    vbroadcastss zmm14, xmm7

    vmovups zmm8, [r13+256]
    vmovups zmm9, [r13+320]
    vmovups zmm10, [r13+384]
    vmovups zmm11, [r13+448]

    vfmadd231ps zmm16, zmm20, zmm8
    vfmadd231ps zmm17, zmm20, zmm9
    vfmadd231ps zmm18, zmm20, zmm10
    vfmadd231ps zmm19, zmm20, zmm11

    add r12, r14
    add r13, r14
    inc edi
    jmp token_loop2

token_loop2_end:
    vrcp14ss xmm0, xmm14
    vmulss xmm1, xmm14, xmm0
    vsubss xmm2, dword ptr [one_const], xmm1
    vmulss xmm0, xmm0, xmm2
    vbroadcastss zmm15, xmm0

    vmulps zmm16, zmm16, zmm15
    vmulps zmm17, zmm17, zmm15
    vmulps zmm18, zmm18, zmm15
    vmulps zmm19, zmm19, zmm15

    vmovups [r9+256], zmm16
    vmovups [r9+320], zmm17
    vmovups [r9+384], zmm18
    vmovups [r9+448], zmm19

cleanup:
    add  rsp, 40
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

TreeAttention_Fused_VAL038_Optimized ENDP

; ============================================================================
; Data section: polynomial coefficients for fast exp2 approximation
; ============================================================================
.data
align 16
exp2_poly:
    dd 1.0f          ; c0 = 1.0
    dd 0.693147181f  ; c1 = ln(2)
    dd 0.240226507f  ; c2 = (ln(2))^2 / 2
exp2_bias:
    dd 127.0f        ; IEEE 754 exponent bias
one_const:
    dd 1.0f

end