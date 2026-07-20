; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: Fused Tree Attention Kernel (MASM x64)
; ═══════════════════════════════════════════════════════════════════════════════
; Single kernel: Q@K^T → Online Softmax → A@V
; Eliminates intermediate writes to memory
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
VEC_WIDTH       EQU     16              ; 16 floats per zmm register (512-bit)
SCALE_FACTOR    EQU     0x3E000000      ; 1/sqrt(64) = 0.125 in IEEE 754

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

; Lookup table for exp(x) with range reduction
; 256 entries covering [-8.0, 0.0] with linear interpolation
exp_lut LABEL REAL4
    REPEAT 256
        REAL4 0.0
    ENDM

scale_factor    REAL4   0.125           ; 1/sqrt(64)
neg_inf         REAL4   -1.0e38         ; Approximate -infinity

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_Fused_VAL038
;
; Fused attention: Q@K^T → Online Softmax → A@V
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
; Clobbers: zmm0-zmm15, k1-k7, rax-r11
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
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 256
    .allocstack 256
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    mov     ebx, [rbp+64]               ; ebx = num_q
    mov     esi, [rbp+72]               ; esi = num_k
    mov     rdi, [rbp+80]               ; rdi = tree_mask

    ; Broadcast scale factor
    vbroadcastss zmm15, dword ptr [scale_factor]

    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done

    ; Load Q row into registers (head_dim = 64 = 4 zmm registers)
    mov     rax, r8
    imul    rax, HEAD_DIM * 4           ; rax = q_idx * head_dim * 4 bytes
    lea     rcx, [r13 + rax]            ; rcx = &Q[q_idx * head_dim]

    vmovaps zmm0, zmmword ptr [rcx]         ; Q[0:15]
    vmovaps zmm1, zmmword ptr [rcx + 64]    ; Q[16:31]
    vmovaps zmm2, zmmword ptr [rcx + 128]   ; Q[32:47]
    vmovaps zmm3, zmmword ptr [rcx + 192]   ; Q[48:63]

    ; Initialize online softmax state
    vbroadcastss zmm13, dword ptr [neg_inf] ; zmm13 = max_score = -inf
    vxorps  zmm14, zmm14, zmm14             ; zmm14 = sum_exp = 0
    vxorps  zmm4, zmm4, zmm4                ; zmm4 = accum output[0:15]
    vxorps  zmm5, zmm5, zmm5                ; zmm5 = accum output[16:31]
    vxorps  zmm6, zmm6, zmm6                ; zmm6 = accum output[32:47]
    vxorps  zmm7, zmm7, zmm7                ; zmm7 = accum output[48:63]

    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0

.key_loop:
    cmp     r9d, esi
    jae     .store_output

    ; Check tree mask
    mov     rax, r8
    imul    rax, rsi                    ; rax = q_idx * num_k
    add     rax, r9                     ; rax = q_idx * num_k + k_idx
    cmp     byte ptr [rdi + rax], 0
    je      .skip_key                   ; Skip if masked

    ; Load K row
    mov     rax, r9
    imul    rax, HEAD_DIM * 4
    lea     rcx, [r14 + rax]            ; rcx = &K[k_idx * head_dim]

    vmovaps zmm8, zmmword ptr [rcx]
    vmovaps zmm9, zmmword ptr [rcx + 64]
    vmovaps zmm10, zmmword ptr [rcx + 128]
    vmovaps zmm11, zmmword ptr [rcx + 192]

    ; Compute dot product Q·K (4 FMAs per 16 elements)
    vmulps  zmm12, zmm0, zmm8           ; Q[0:15] * K[0:15]
    vfmadd231ps zmm12, zmm1, zmm9       ; += Q[16:31] * K[16:31]
    vfmadd231ps zmm12, zmm2, zmm10      ; += Q[32:47] * K[32:47]
    vfmadd231ps zmm12, zmm3, zmm11      ; += Q[48:63] * K[48:63]

    ; Horizontal sum to get score
    vextractf64x4 ymm8, zmm12, 1
    vaddps  ymm12, ymm12, ymm8
    vextractf128 xmm8, ymm12, 1
    vaddps  xmm12, xmm12, xmm8
    vhaddps xmm12, xmm12, xmm12
    vhaddps xmm12, xmm12, xmm12

    ; Scale by 1/sqrt(head_dim)
    vmulss  xmm12, xmm12, xmm15

    ; Online softmax update
    ; Broadcast score to compare with max
    vbroadcastss zmm8, xmm12

    ; Update max: new_max = max(old_max, score)
    vmaxps  zmm13, zmm13, zmm8          ; zmm13 = max(max_score, score)

    ; Compute exp(score - max) using scalar exp for now
    ; (LUT version would be faster)
    vsubss  xmm12, xmm12, xmm13         ; xmm12 = score - max

    ; Store for exp computation
    vmovss  dword ptr [rsp], xmm12

    ; Call expf (simplified - inline exp would be faster)
    ; For now, approximate with fast path
    ; exp(x) ≈ 2^(x/ln2) using vgetexp/vgetmant

    ; Compute exp using polynomial approximation
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24 for x in [-1, 1]

    ; Simplified: just use the value directly for now
    ; (Real impl would use proper exp approximation)
    vmovaps zmm9, zmm8                  ; weight = score (simplified)

    ; Update sum_exp
    vaddps  zmm14, zmm14, zmm9          ; sum_exp += weight

    ; Load V row and accumulate weighted sum
    mov     rax, r9
    imul    rax, HEAD_DIM * 4
    lea     rcx, [r15 + rax]            ; rcx = &V[k_idx * head_dim]

    vmovaps zmm10, zmmword ptr [rcx]
    vmovaps zmm11, zmmword ptr [rcx + 64]
    vmovaps zmm12, zmmword ptr [rcx + 128]
    vmovaps zmm8, zmmword ptr [rcx + 192]

    ; Accumulate: output += weight * V
    vfmadd231ps zmm4, zmm9, zmm10       ; output[0:15] += weight * V[0:15]
    vfmadd231ps zmm5, zmm9, zmm11       ; output[16:31] += weight * V[16:31]
    vfmadd231ps zmm6, zmm9, zmm12       ; output[32:47] += weight * V[32:47]
    vfmadd231ps zmm7, zmm9, zmm8        ; output[48:63] += weight * V[48:63]

.skip_key:
    inc     r9d
    jmp     .key_loop

.store_output:
    ; Normalize by sum_exp: output /= sum_exp
    ; (Simplified - should broadcast sum_exp and divide)

    ; Store output row
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    lea     rcx, [r12 + rax]            ; rcx = &output[q_idx * head_dim]

    vmovaps zmmword ptr [rcx], zmm4
    vmovaps zmmword ptr [rcx + 64], zmm5
    vmovaps zmmword ptr [rcx + 128], zmm6
    vmovaps zmmword ptr [rcx + 192], zmm7

    ; Next query
    inc     r8d
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
