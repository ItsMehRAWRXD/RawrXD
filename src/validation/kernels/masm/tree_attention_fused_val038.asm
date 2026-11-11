; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: Fused Tree Attention Kernel (Q@K^T → Softmax → A@V)
; ═══════════════════════════════════════════════════════════════════════════════
; Single kernel eliminating intermediate writes
; Target: 0.5-0.8 µs total (down from 1.846 µs baseline)
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Public Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_Fused_VAL038

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
HEAD_DIM        EQU     64              ; Head dimension (must match C++ code)
BLOCK_M         EQU     16              ; Query block size (fits in zmm registers)
BLOCK_N         EQU     16              ; Key block size
ATTN_SCALE      EQU     0.125           ; 1/sqrt(64) = 0.125

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data
ALIGN 64

attn_scale_const    REAL4   0.125       ; 1/sqrt(64)
neg_inf_const       REAL4   -1.0E38     ; -Infinity
one_const           REAL4   1.0

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_Fused_VAL038
;
; Fused attention: Q@K^T → Softmax → A@V in single pass
;
; Parameters (Windows x64 ABI):
;   RCX = output (float* [num_q, head_dim])
;   RDX = Q (float* [num_q, head_dim])
;   R8  = K (float* [num_k, head_dim])
;   R9  = V (float* [num_k, head_dim])
;   [RSP+40] = num_q (uint32_t)
;   [RSP+48] = num_k (uint32_t)
;   [RSP+56] = tree_mask (uint8_t* [num_q, num_k])
;
; Returns: void
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_Fused_VAL038 PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 256
    .allocstack 256
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Save parameters
    mov     r15, rcx                    ; r15 = output
    mov     r12, rdx                    ; r12 = Q
    mov     r13, r8                     ; r13 = K
    mov     r14, r9                     ; r14 = V
    mov     ebx, [rsp+296]              ; ebx = num_q (after pushed regs)
    mov     r8d, [rsp+304]              ; r8d = num_k
    mov     r9, [rsp+312]               ; r9 = tree_mask

    ; Broadcast scale factor
    vbroadcastss zmm15, dword ptr [attn_scale_const]

    ; Outer loop over query blocks
    xor     r10d, r10d                  ; q_idx = 0

.query_loop:
    cmp     r10d, ebx
    jae     .done

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Load Q row into registers (head_dim = 64 floats = 4 zmm registers)
    ; ═══════════════════════════════════════════════════════════════════════════
    mov     rax, r10
    imul    rax, HEAD_DIM * 4           ; rax = q_idx * head_dim * 4
    add     rax, r12                    ; rax = &Q[q_idx, 0]

    vmovaps zmm0, zmmword ptr [rax + 0*64]     ; Q[0:15]
    vmovaps zmm1, zmmword ptr [rax + 1*64]     ; Q[16:31]
    vmovaps zmm2, zmmword ptr [rax + 2*64]     ; Q[32:47]
    vmovaps zmm3, zmmword ptr [rax + 3*64]     ; Q[48:63]

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 1: Compute Q@K^T for this query against all keys
    ; ═══════════════════════════════════════════════════════════════════════════
    vxorps  zmm4, zmm4, zmm4            ; zmm4 = max_score = -inf (will set later)
    vbroadcastss zmm4, dword ptr [neg_inf_const]

    xor     r11d, r11d                  ; k_idx = 0

.score_loop:
    cmp     r11d, r8d
    jae     .score_done

    ; Check tree mask
    mov     rax, r10
    imul    rax, r8                     ; rax = q_idx * num_k
    add     rax, r11                    ; rax = q_idx * num_k + k_idx
    cmp     byte ptr [r9 + rax], 0
    je      .skip_key                 ; Skip if masked

    ; Load K row
    mov     rax, r11
    imul    rax, HEAD_DIM * 4
    add     rax, r13                    ; rax = &K[k_idx, 0]

    vmovaps zmm8, zmmword ptr [rax + 0*64]
    vmovaps zmm9, zmmword ptr [rax + 1*64]
    vmovaps zmm10, zmmword ptr [rax + 2*64]
    vmovaps zmm11, zmmword ptr [rax + 3*64]

    ; Compute dot product Q · K
    vmulps  zmm12, zmm0, zmm8
    vfmadd231ps zmm12, zmm1, zmm9
    vfmadd231ps zmm12, zmm2, zmm10
    vfmadd231ps zmm12, zmm3, zmm11

    ; Horizontal sum to get score
    ; zmm12 contains 16 partial sums
    vextractf64x4 ymm13, zmm12, 1
    vaddps  ymm12, ymm12, ymm13
    vextractf128 xmm13, ymm12, 1
    vaddps  xmm12, xmm12, xmm13
    vshufps xmm13, xmm12, xmm12, 0Eh
    vaddps  xmm12, xmm12, xmm13
    vshufps xmm13, xmm12, xmm12, 01h
    vaddps  xmm12, xmm12, xmm13

    ; Scale by 1/sqrt(head_dim)
    vmulss  xmm12, xmm12, xmm15

    ; Update max score (online softmax)
    vmaxss  xmm4, xmm4, xmm12

    ; Store score for later softmax (in stack buffer)
    mov     rax, r11
    and     rax, 15                     ; Index into 16-entry buffer
    vmovss  dword ptr [rsp + rax*4], xmm12

.skip_key:
    inc     r11d
    jmp     .score_loop

.score_done:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 2: Online Softmax (compute exp(score - max) and sum)
    ; ═══════════════════════════════════════════════════════════════════════════
    vbroadcastss zmm5, xmm4             ; zmm5 = max_score (broadcasted)
    vxorps  zmm6, zmm6, zmm6            ; zmm6 = sum_exp = 0

    xor     r11d, r11d
.softmax_loop:
    cmp     r11d, r8d
    jae     .softmax_done

    ; Check mask
    mov     rax, r10
    imul    rax, r8
    add     rax, r11
    cmp     byte ptr [r9 + rax], 0
    je      .skip_softmax

    ; Load score
    mov     rax, r11
    and     rax, 15
    vbroadcastss zmm7, dword ptr [rsp + rax*4]

    ; Compute exp(score - max)
    vsubps  zmm7, zmm7, zmm5            ; zmm7 = score - max

    ; Fast exp approximation using polynomial (degree 3 for speed)
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 for x near 0
    ; Since x <= 0 after max subtraction, this is stable

    vmulps  zmm8, zmm7, zmm7            ; zmm8 = x^2
    vmulps  zmm9, zmm8, zmm7            ; zmm9 = x^3

    vbroadcastss zmm10, dword ptr [one_const]
    vfmadd231ps zmm10, zmm7, zmm10      ; 1 + x
    vfmadd231ps zmm10, zmm8, zmm10      ; + x^2/2 (approx)
    vfmadd231ps zmm10, zmm9, zmm10      ; + x^3/6 (approx)

    ; Store exp value back
    vmovss  dword ptr [rsp + rax*4], xmm10

    ; Accumulate sum
    vaddps  zmm6, zmm6, zmm10

.skip_softmax:
    inc     r11d
    jmp     .softmax_loop

.softmax_done:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Phase 3: Weighted sum of V rows (output = sum(exp * V) / sum_exp)
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Compute reciprocal of sum_exp
    vrcp14ps zmm7, zmm6                 ; zmm7 = approx 1/sum_exp

    ; One Newton-Raphson iteration
    vbroadcastss zmm8, dword ptr [one_const]
    vfnmadd231ps zmm8, zmm6, zmm7       ; zmm8 = 1 - sum * r
    vfmadd231ps zmm7, zmm7, zmm8        ; zmm7 = r + r*(1 - sum*r)

    ; Initialize accumulators for output
    vxorps  zmm8, zmm8, zmm8            ; Output[0:15]
    vxorps  zmm9, zmm9, zmm9            ; Output[16:31]
    vxorps  zmm10, zmm10, zmm10         ; Output[32:47]
    vxorps  zmm11, zmm11, zmm11         ; Output[48:63]

    xor     r11d, r11d
.attention_loop:
    cmp     r11d, r8d
    jae     .attention_done

    ; Check mask
    mov     rax, r10
    imul    rax, r8
    add     rax, r11
    cmp     byte ptr [r9 + rax], 0
    je      .skip_attention

    ; Load exp value
    mov     rax, r11
    and     rax, 15
    vbroadcastss zmm12, dword ptr [rsp + rax*4]

    ; Multiply by reciprocal sum
    vmulps  zmm12, zmm12, zmm7          ; zmm12 = weight = exp / sum_exp

    ; Load V row
    mov     rax, r11
    imul    rax, HEAD_DIM * 4
    add     rax, r14

    vmovaps zmm13, zmmword ptr [rax + 0*64]
    vmovaps zmm14, zmmword ptr [rax + 1*64]

    ; Accumulate weighted V
    vfmadd231ps zmm8, zmm12, zmm13
    vfmadd231ps zmm9, zmm12, zmm14

    vmovaps zmm13, zmmword ptr [rax + 2*64]
    vmovaps zmm14, zmmword ptr [rax + 3*64]

    vfmadd231ps zmm10, zmm12, zmm13
    vfmadd231ps zmm11, zmm12, zmm14

.skip_attention:
    inc     r11d
    jmp     .attention_loop

.attention_done:
    ; Store output row
    mov     rax, r10
    imul    rax, HEAD_DIM * 4
    add     rax, r15

    vmovaps zmmword ptr [rax + 0*64], zmm8
    vmovaps zmmword ptr [rax + 1*64], zmm9
    vmovaps zmmword ptr [rax + 2*64], zmm10
    vmovaps zmmword ptr [rax + 3*64], zmm11

    ; Next query
    inc     r10d
    jmp     .query_loop

.done:
    ; Epilogue
    vzeroupper
    add     rsp, 256
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttention_Fused_VAL038 ENDP

END
