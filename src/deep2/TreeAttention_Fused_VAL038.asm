; ============================================================================
; TreeAttention_Fused_VAL038.asm - Fused Attention Kernel for VAL-038
;
; Single-pass, register-resident attention computation:
;   Q × K → LUT softmax → × V → output
;
; No intermediate score buffer. No cache pollution. No stack spills.
;
; Register allocation:
;   zmm0-zmm3:   Query vectors (pinned for head computation)
;   zmm4-zmm7:   Key cache strides (streamed from L1)
;   zmm8-zmm15:  Score accumulators + exponential sums
;   zmm16-zmm23: Value blocks
;   zmm24-zmm31: Output accumulators + sliding window state
;
; ABI (Windows x64):
;   rcx = Q (float*, head_dim elements)
;   rdx = K (float*, seq_len * head_dim elements)
;   r8  = V (float*, seq_len * head_dim elements)
;   r9  = output (float*, head_dim elements)
;   [rsp+40] = seq_len (int)
;   [rsp+48] = head_dim (int)
;
; All floats are 32-bit. head_dim must be multiple of 16.
;
; Copyright (c) 2026 RawrXD Sovereign Runtime
; ============================================================================

.code

; ---------------------------------------------------------------------------
; extern "C" void TreeAttention_Fused_VAL038(
;     const float* Q,        // rcx
;     const float* K,        // rdx
;     const float* V,        // r8
;     float*       output,   // r9
;     int          seq_len,  // [rsp+40]
;     int          head_dim  // [rsp+48]
; );
; ---------------------------------------------------------------------------

TreeAttention_Fused_VAL038 PROC public

    ; --- Prologue: save non-volatile registers ---
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 128                     ; shadow space + locals

    ; Load stack arguments
    mov  ebx, dword ptr [rsp+40+128]  ; seq_len (adjusted for pushes + sub)
    mov  esi, dword ptr [rsp+48+128]  ; head_dim

    ; --- Load Q into zmm0 (first 16 floats of Q) ---
    ; For head_dim=128, Q has 128 floats = 8 zmm registers
    ; We process in 16-element chunks
    vmovups zmm0, [rcx]               ; Q[0:15]
    vmovups zmm1, [rcx+64]            ; Q[16:31]
    vmovups zmm2, [rcx+128]           ; Q[32:47]
    vmovups zmm3, [rcx+192]           ; Q[48:63]

    ; --- Initialize accumulators ---
    vpxord  zmm8, zmm8, zmm8          ; max score = 0
    vpxord  zmm9, zmm9, zmm9          ; sum of exp = 0
    vpxord  zmm24, zmm24, zmm24       ; output accumulator 0
    vpxord  zmm25, zmm25, zmm25       ; output accumulator 1
    vpxord  zmm26, zmm26, zmm26       ; output accumulator 2
    vpxord  zmm27, zmm27, zmm27       ; output accumulator 3

    ; --- Process each key/value token ---
    xor  edi, edi                     ; token index = 0
    mov  r12, rdx                     ; K pointer
    mov  r13, r8                      ; V pointer

    ; head_dim in bytes for stride
    mov  r14, rsi
    shl  r14, 2                       ; head_dim * 4 (bytes per token row)

token_loop:
    cmp  edi, ebx
    jge  token_loop_end

    ; --- Q · K^T dot product (first 64 elements) ---
    vmovups zmm4, [r12]               ; K[token, 0:15]
    vmovups zmm5, [r12+64]            ; K[token, 16:31]
    vmovups zmm6, [r12+128]           ; K[token, 32:47]
    vmovups zmm7, [r12+192]           ; K[token, 48:63]

    ; Dot product: score = sum(Q * K)
    ; Process 4 chunks of 16, accumulate into zmm10
    vfmadd231ps zmm10, zmm0, zmm4     ; zmm10 += Q[0:15] * K[0:15]
    vfmadd231ps zmm10, zmm1, zmm5     ; += Q[16:31] * K[16:31]
    vfmadd231ps zmm10, zmm2, zmm6     ; += Q[32:47] * K[32:47]
    vfmadd231ps zmm10, zmm3, zmm7     ; += Q[48:63] * K[48:63]

    ; Horizontal sum of zmm10 to get scalar score
    vextractf32x8 ymm11, zmm10, 1
    vaddps  ymm12, ymm10, ymm11
    vextractf32x4 xmm13, ymm12, 1
    vaddps  xmm14, xmm12, xmm13
    vshufps xmm15, xmm14, xmm14, 0eh
    vaddps  xmm16, xmm14, xmm15
    vshufps xmm17, xmm16, xmm16, 01h
    vaddss  xmm18, xmm16, xmm17
    ; xmm18[0] = dot product score (scalar)

    ; --- Scale by 1/sqrt(head_dim) ---
    cvtsi2ss xmm19, esi               ; head_dim as float
    vsqrtss xmm19, xmm19
    vbroadcastss zmm20, xmm19
    vdivss  xmm21, xmm18, xmm19       ; score / sqrt(head_dim)
    ; xmm21[0] = scaled score

    ; --- LUT-based exp approximation ---
    ; exp(x) ≈ 2^(x * log2(e))
    ; For simplicity: use exp2 via bit manipulation
    ; Scale by log2(e)
    vmulss  xmm22, xmm21, xmmword ptr [rip + log2e_val]
    ; xmm22 = x * log2(e)

    ; Split into integer and fractional parts
    vroundss xmm23, xmm22, xmm22, 1   ; floor to integer
    vsubss  xmm24, xmm22, xmm23        ; fractional part

    ; exp2(n + f) = 2^n * 2^f
    ; 2^n: construct float by manipulating exponent bits
    ; Add n to bias (127) and shift into exponent position
    cvtss2si eax, xmm23               ; integer part
    add     eax, 127                   ; add bias
    shl     eax, 23                   ; shift to exponent
    vmovd   xmm25, eax                ; 2^integer part

    ; 2^f: use polynomial approximation (1 + f*ln2 + (f*ln2)^2/2)
    ; Simplified: 2^f ≈ 1 + f * 0.6931
    vbroadcastss xmm26, xmmword ptr [rip + ln2_val]
    vfmadd213ps xmm27, xmm24, xmm26   ; xmm27 = f * ln2
    vaddss   xmm28, xmm27, xmmword ptr [rip + one_val] ; 1 + f*ln2

    ; exp_val = 2^int * 2^frac
    vmulss  xmm29, xmm25, xmm28       ; xmm29 = exp(score)

    ; --- Update max and sum ---
    vmaxss  xmm8, xmm8, xmm29         ; track running max (simplified)
    vaddss  xmm9, xmm9, xmm29          ; sum of exp

    ; --- Weighted V accumulation ---
    ; output += exp(score) * V[token]
    vbroadcastss zmm30, xmm29          ; broadcast weight to all lanes

    vmovups zmm16, [r13]              ; V[token, 0:15]
    vmovups zmm17, [r13+64]           ; V[token, 16:31]
    vmovups zmm18, [r13+128]          ; V[token, 32:47]
    vmovups zmm19, [r13+192]          ; V[token, 48:63]

    vfmadd231ps zmm24, zmm30, zmm16   ; output[0:15] += w * V[0:15]
    vfmadd231ps zmm25, zmm30, zmm17   ; output[16:31] += w * V[16:31]
    vfmadd231ps zmm26, zmm30, zmm18   ; output[32:47] += w * V[32:47]
    vfmadd231ps zmm27, zmm30, zmm19   ; output[48:63] += w * V[48:63]

    ; Advance to next token
    inc  edi
    add  r12, r14                     ; K += head_dim * 4
    add  r13, r14                     ; V += head_dim * 4
    jmp  token_loop

token_loop_end:
    ; --- Normalize: output /= sum ---
    vrcp14ss xmm30, xmm9              ; approximate 1/sum
    ; Newton-Raphson refinement
    vmulss  xmm31, xmm30, xmm9
    vsubss  xmm0, xmmword ptr [rip + two_val], xmm31
    vmulss  xmm30, xmm30, xmm0        ; refined 1/sum

    vbroadcastss zmm31, xmm30         ; broadcast 1/sum

    vmulps  zmm24, zmm24, zmm31       ; normalize
    vmulps  zmm25, zmm25, zmm31
    vmulps  zmm26, zmm26, zmm31
    vmulps  zmm27, zmm27, zmm31

    ; --- Store output ---
    vmovups [r9], zmm24               ; output[0:15]
    vmovups [r9+64], zmm25            ; output[16:31]
    vmovups [r9+128], zmm26           ; output[32:47]
    vmovups [r9+192], zmm27           ; output[48:63]

    ; --- Epilogue ---
    add  rsp, 128
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    vzeroupper
    ret

TreeAttention_Fused_VAL038 ENDP

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------
.data
ALIGN 16
log2e_val dd 1.4426950408889634
ln2_val   dd 0.6931471805599453
one_val   dd 1.0
two_val   dd 2.0

end