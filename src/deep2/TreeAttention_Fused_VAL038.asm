; ============================================================================
; TreeAttention_Fused_VAL038.asm - Fused Attention Kernel for VAL-038
;
; Single-pass attention: Q.K -> exp -> normalize -> .V -> output
; Register-resident, no intermediate score buffer.
;
; ABI (Windows x64):
;   rcx = Q (float*)
;   rdx = K (float*)
;   r8  = V (float*)
;   r9  = output (float*)
;   [rsp+40] = seq_len (int)
;   [rsp+48] = head_dim (int)
;
; Copyright (c) 2026 RawrXD Sovereign Runtime
; ============================================================================

.code

TreeAttention_Fused_VAL038 PROC public

    ; --- Prologue ---
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32

    ; Stack: 7 pushes (56) + 32 sub = 88 bytes offset for args
    mov  ebx, DWORD PTR [rsp+40+88]   ; seq_len
    mov  esi, DWORD PTR [rsp+48+88]   ; head_dim

    ; --- Load Q into zmm0-zmm3 ---
    vmovups zmm0, [rcx]
    vmovups zmm1, [rcx+64]
    vmovups zmm2, [rcx+128]
    vmovups zmm3, [rcx+192]

    ; --- Reserve score buffer on stack (4 bytes per token, aligned to 8) ---
    mov  eax, ebx
    shl  eax, 2                        ; seq_len * 4
    add  eax, 7
    and  eax, 0FFFFFFF8h               ; round up to 8
    sub  rsp, rax
    mov  r15, rsp                      ; r15 = score buffer base

    ; --- Init accumulators ---
    vxorps  zmm24, zmm24, zmm24        ; weighted V chunk 0
    vxorps  zmm25, zmm25, zmm25        ; weighted V chunk 1
    vxorps  zmm26, zmm26, zmm26        ; weighted V chunk 2
    vxorps  zmm27, zmm27, zmm27        ; weighted V chunk 3
    vxorps  xmm23, xmm23, xmm23        ; exp sum accumulator
    vxorps  xmm22, xmm22, xmm22        ; max score accumulator (for softmax stability)

    ; --- sqrt(head_dim) via integer to float conversion ---
    movd xmm8, esi                    ; xmm8 = (int)head_dim
    cvtdq2ps xmm8, xmm8              ; xmm8 = (float)head_dim
    vsqrtss xmm8, xmm8, xmm8          ; xmm8 = sqrt(head_dim)

    ; --- Token loop setup ---
    xor  edi, edi
    mov  r12, rdx
    mov  r13, r8
    mov  r14, rsi
    shl  r14, 2                        ; head_dim * 4

    ; ============================================================
    ; PASS 1: compute all scaled dot-product scores and find max
    ; ============================================================
score_loop:
    cmp  edi, ebx
    jge  score_loop_end

    ; --- Load K[token] ---
    vmovups zmm4, [r12]
    vmovups zmm5, [r12+64]
    vmovups zmm6, [r12+128]
    vmovups zmm7, [r12+192]

    ; --- Q . K dot product ---
    vmulps  zmm10, zmm0, zmm4
    vmulps  zmm11, zmm1, zmm5
    vmulps  zmm12, zmm2, zmm6
    vmulps  zmm13, zmm3, zmm7

    vaddps  zmm10, zmm10, zmm11
    vaddps  zmm10, zmm10, zmm12
    vaddps  zmm10, zmm10, zmm13

    ; --- Horizontal sum zmm10 -> xmm18 scalar ---
    vextractf32x8 ymm14, zmm10, 1
    vaddps  ymm14, ymm10, ymm14          ; ymm14 = low + high halves
    vextractf32x4 xmm15, ymm14, 1
    vaddps  xmm15, xmm14, xmm15          ; xmm15 = low + high quarters
    vshufps xmm16, xmm15, xmm15, 4Eh     ; 04Eh = 4Eh
    vaddps  xmm16, xmm16, xmm15
    vshufps xmm17, xmm16, xmm16, 0B1h    ; swap pairs
    vaddss  xmm18, xmm16, xmm17

    ; --- Scale: score / sqrt(head_dim) ---
    vdivss  xmm18, xmm18, xmm8

    ; --- Track max score ---
    vmaxss  xmm22, xmm22, xmm18

    ; Store scaled score in buffer
    mov  eax, edi
    shl  eax, 2
    vmovss  DWORD PTR [r15 + rax], xmm18

    ; Next token
    inc  edi
    add  r12, r14
    jmp  score_loop

score_loop_end:
    ; ============================================================
    ; PASS 2: compute exp(score - max) and accumulate weighted V
    ; ============================================================
    ; Reset pointers and counter
    xor  edi, edi
    mov  r12, rdx
    mov  r13, r8

exp_loop:
    cmp  edi, ebx
    jge  exp_loop_end

    ; Retrieve scaled score from buffer
    mov  eax, edi
    shl  eax, 2
    vmovss xmm18, DWORD PTR [r15 + rax]

    ; --- score - max ---
    vsubss  xmm18, xmm18, xmm22

    ; --- Accurate exp(x) via 2^(x*log2(e)) with polynomial 2^frac ---
    ; exp(x) = 2^(x * log2(e))
    mov  eax, 3FB8AA3Bh             ; log2(e) float bits
    vmovd xmm1, eax
    vmulss xmm1, xmm18, xmm1        ; xmm1 = x * log2(e)

    ; Floor to get integer part
    vroundss xmm2, xmm1, xmm1, 9   ; xmm2 = floor
    vsubss  xmm3, xmm1, xmm2        ; xmm3 = fractional part in [0,1)

    ; Clamp fractional part to avoid edge artifacts
    xor    eax, eax
    vmovd  xmm10, eax               ; 0.0
    vmaxss xmm3, xmm3, xmm10
    mov    eax, 3F7FFFFFh           ; 0.99999994
    vmovd  xmm11, eax
    vminss xmm3, xmm3, xmm11

    ; 2^integer: set float exponent bits
    cvtss2si eax, xmm2               ; eax = integer part
    add  eax, 127
    shl  eax, 23
    vmovd xmm4, eax                  ; xmm4 = 2^int

    ; 2^frac polynomial: minimax for 2^f on [0,1)
    ; p(f) = 1 + f*(ln2 + f*(ln2^2/2 + f*(ln2^3/6 + f*ln2^4/24)))
    ; Coefficients:
    ; c0 = 1.0
    ; c1 = ln2          = 0.69314718  (0x3F317218)
    ; c2 = ln2^2/2      = 0.24022650  (0x3E75FDF0)
    ; c3 = ln2^3/6      = 0.05550410  (0x3D635847)
    ; c4 = ln2^4/24     = 0.00961813  (0x3C1D8C19)
    mov  eax, 3C1D8C19h
    vmovd xmm5, eax
    vmulss xmm6, xmm3, xmm5         ; f * c4
    mov  eax, 3D635847h
    vmovd xmm5, eax
    vaddss xmm6, xmm6, xmm5         ; + c3
    vmulss xmm6, xmm6, xmm3         ; * f
    mov  eax, 3E75FDF0h
    vmovd xmm5, eax
    vaddss xmm6, xmm6, xmm5         ; + c2
    vmulss xmm6, xmm6, xmm3         ; * f
    mov  eax, 3F317218h
    vmovd xmm5, eax
    vaddss xmm6, xmm6, xmm5         ; + c1
    vmulss xmm6, xmm6, xmm3         ; * f
    mov  eax, 3F800000h             ; 1.0
    vmovd xmm5, eax
    vaddss xmm6, xmm6, xmm5         ; + c0

    ; exp = 2^int * 2^frac
    vmulss xmm7, xmm4, xmm6         ; xmm7 = exp(score - max)

    ; --- Accumulate weighted V ---
    vbroadcastss zmm30, xmm7

    vmovups zmm16, [r13]
    vmovups zmm17, [r13+64]
    vmovups zmm18, [r13+128]
    vmovups zmm19, [r13+192]

    vfmadd231ps zmm24, zmm30, zmm16
    vfmadd231ps zmm25, zmm30, zmm17
    vfmadd231ps zmm26, zmm30, zmm18
    vfmadd231ps zmm27, zmm30, zmm19

    ; Accumulate exp sum
    vaddss  xmm23, xmm23, xmm7

    ; Next token
    inc  edi
    add  r12, r14
    add  r13, r14
    jmp  exp_loop

exp_loop_end:
    ; --- Broadcast exp sum reciprocal ---
    mov  eax, 3F800000h                  ; 1.0
    vmovd xmm9, eax
    vdivss xmm9, xmm9, xmm23             ; xmm9 = 1.0 / sum_exp
    vbroadcastss zmm31, xmm9

    ; --- Normalize and store output ---
    vmulps  zmm24, zmm24, zmm31
    vmulps  zmm25, zmm25, zmm31
    vmulps  zmm26, zmm26, zmm31
    vmulps  zmm27, zmm27, zmm31

    vmovups [r9], zmm24
    vmovups [r9+64], zmm25
    vmovups [r9+128], zmm26
    vmovups [r9+192], zmm27

    ; --- Epilogue ---
    ; Restore score buffer allocation
    mov  eax, ebx
    shl  eax, 2
    add  eax, 7
    and  eax, 0FFFFFFF8h
    add  rsp, rax
    add  rsp, 32
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

end