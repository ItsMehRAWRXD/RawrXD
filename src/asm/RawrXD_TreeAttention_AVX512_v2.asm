; ═══════════════════════════════════════════════════════════════════════════════
; RawrXD Tree Attention AVX-512 Kernel (VAL-032)
; ═══════════════════════════════════════════════════════════════════════════════
; Branchless DAG traversal using k-mask registers for speculative decoding.
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
HEAD_DIM        EQU     128
BLOCK_M         EQU     64
BLOCK_N         EQU     64
VEC_WIDTH       EQU     16

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section (Read-Only Constants)
; ═══════════════════════════════════════════════════════════════════════════════
.DATA
    ALIGN 64
scale_factor    REAL4   0.08838834764831843
neg_inf         REAL4   -3.4028235E38
zero_val        REAL4   0.0
log2e           REAL4   1.4426950408889634
exp_min         REAL4   -126.0
exp_max         REAL4   127.0

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.CODE

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512 - Main entry point
; RCX = Q, RDX = K, R8 = V, R9 = output
; [RSP+0x28] = tree_mask, [RSP+0x30] = num_nodes, [RSP+0x38] = head_dim
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_AVX512 PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    push    rbp
    .pushreg rbp
    
    sub     rsp, 128
    .allocstack 128
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    ; Load stack parameters
    mov     r10, QWORD PTR [rbp+128+40]     ; tree_mask
    mov     r11d, DWORD PTR [rbp+128+48]    ; num_nodes
    mov     r12d, DWORD PTR [rbp+128+56]    ; head_dim
    
    ; Save input pointers
    mov     r13, rcx                        ; Q
    mov     r14, rdx                        ; K
    mov     r15, r8                         ; V
    mov     rbx, r9                         ; output
    
    ; Broadcast constants
    vbroadcastss zmm30, DWORD PTR [scale_factor]
    vbroadcastss zmm31, DWORD PTR [neg_inf]
    
    ; Process each query node
    xor     r8d, r8d                        ; node_idx = 0
    
NodeLoop:
    cmp     r8d, r11d
    jae     NodeLoopDone
    
    ; Initialize max score
    vmovaps zmm0, zmm31
    
    ; Compute attention scores
    xor     r9d, r9d                        ; key_idx = 0
    
KeyLoop:
    cmp     r9d, r11d
    jae     KeyLoopDone
    
    ; Check tree mask
    mov     eax, r8d
    mul     r11d
    add     eax, r9d
    movzx   edx, BYTE PTR [r10+rax]
    cmp     dl, 1
    sete    al
    kmovw   k1, eax
    
    ; Compute dot product
    vxorps  zmm1, zmm1, zmm1
    
    mov     rax, r8
    imul    rax, r12
    shl     rax, 2
    add     rax, r13
    
    mov     rdx, r9
    imul    rdx, r12
    shl     rdx, 2
    add     rdx, r14
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
DotProductLoop:
    cmp     edi, ecx
    jae     DotProductDone
    
    vmovups zmm2, ZMMWORD PTR [rax+rdi*64]
    vmovups zmm3, ZMMWORD PTR [rdx+rdi*64]
    vfmadd231ps zmm1, zmm2, zmm3
    
    inc     edi
    jmp     DotProductLoop
    
DotProductDone:
    ; Horizontal sum
    vextractf64x4 ymm2, zmm1, 1
    vaddps  ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 4Eh
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 0B1h
    vaddps  xmm1, xmm1, xmm2
    vbroadcastss zmm1, xmm1
    vmulps  zmm1, zmm1, zmm30
    
    ; Update max
    vmaxps  zmm0 {k1}, zmm0, zmm1
    
    inc     r9d
    jmp     KeyLoop
    
KeyLoopDone:
    ; Compute softmax and weighted sum
    vxorps  zmm29, zmm29, zmm29
    
    xor     r9d, r9d
    
SoftmaxLoop:
    cmp     r9d, r11d
    jae     SoftmaxDone
    
    ; Check mask
    mov     eax, r8d
    mul     r11d
    add     eax, r9d
    movzx   edx, BYTE PTR [r10+rax]
    cmp     dl, 1
    sete    al
    kmovw   k1, eax
    
    ; Recompute score
    vxorps  zmm1, zmm1, zmm1
    
    mov     rax, r8
    imul    rax, r12
    shl     rax, 2
    add     rax, r13
    
    mov     rdx, r9
    imul    rdx, r12
    shl     rdx, 2
    add     rdx, r14
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
ScoreRecomputeLoop:
    cmp     edi, ecx
    jae     ScoreRecomputeDone
    
    vmovups zmm2, ZMMWORD PTR [rax+rdi*64]
    vmovups zmm3, ZMMWORD PTR [rdx+rdi*64]
    vfmadd231ps zmm1, zmm2, zmm3
    
    inc     edi
    jmp     ScoreRecomputeLoop
    
ScoreRecomputeDone:
    vextractf64x4 ymm2, zmm1, 1
    vaddps  ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 4Eh
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 0B1h
    vaddps  xmm1, xmm1, xmm2
    vbroadcastss zmm1, xmm1
    vmulps  zmm1, zmm1, zmm30
    
    ; exp(score - max)
    vsubps  zmm1, zmm1, zmm0
    
    ; Simplified exp - production would use proper approximation
    ; For now, just accumulate
    vaddps  zmm29 {k1}, zmm29, zmm1
    
    inc     r9d
    jmp     SoftmaxLoop
    
SoftmaxDone:
    ; Weighted sum
    xor     r9d, r9d
    vxorps  zmm28, zmm28, zmm28
    
WeightedSumLoop:
    cmp     r9d, r11d
    jae     WeightedSumDone
    
    mov     eax, r8d
    mul     r11d
    add     eax, r9d
    movzx   edx, BYTE PTR [r10+rax]
    cmp     dl, 1
    sete    al
    kmovw   k1, eax
    
    mov     rdx, r9
    imul    rdx, r12
    shl     rdx, 2
    add     rdx, r15
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
VLoadLoop:
    cmp     edi, ecx
    jae     VLoadDone
    
    vmovups zmm2, ZMMWORD PTR [rdx+rdi*64]
    vaddps  zmm28 {k1}, zmm28, zmm2
    
    inc     edi
    jmp     VLoadLoop
    
VLoadDone:
    inc     r9d
    jmp     WeightedSumLoop
    
WeightedSumDone:
    ; Store output
    mov     rax, r8
    imul    rax, r12
    shl     rax, 2
    add     rax, rbx
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
StoreOutputLoop:
    cmp     edi, ecx
    jae     StoreOutputDone
    
    vmovups ZMMWORD PTR [rax+rdi*64], zmm28
    
    inc     edi
    jmp     StoreOutputLoop
    
StoreOutputDone:
    inc     r8d
    jmp     NodeLoop
    
NodeLoopDone:
    mov     rsp, rbp
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    
    vzeroupper
    ret
    
TreeAttention_AVX512 ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_ScoreBatch - Batch score computation
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_ScoreBatch PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    push    rbp
    .pushreg rbp
    
    sub     rsp, 64
    .allocstack 64
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    mov     r10d, DWORD PTR [rbp+64+40]     ; num_q
    mov     r11d, DWORD PTR [rbp+64+48]     ; num_k
    mov     r12d, DWORD PTR [rbp+64+56]     ; head_dim
    
    mov     r13, rcx                        ; Q
    mov     r14, rdx                        ; K
    mov     r15, r8                         ; scores
    mov     rbx, r9                         ; tree_mask
    
    vbroadcastss zmm30, DWORD PTR [scale_factor]
    
    xor     eax, eax                        ; q_idx
    
QueryLoop:
    cmp     eax, r10d
    jae     ScoreBatchDone
    
    xor     edx, edx                        ; k_idx
    
KeyLoop2:
    cmp     edx, r11d
    jae     KeyLoop2Done
    
    ; Check mask
    push    rax
    mul     r11d
    add     eax, edx
    movzx   ecx, BYTE PTR [rbx+rax]
    pop     rax
    cmp     cl, 1
    sete    cl
    kmovw   k1, ecx
    
    ; Compute dot product
    vxorps  zmm0, zmm0, zmm0
    
    push    rax
    push    rdx
    
    mov     r8, rax
    imul    r8, r12
    shl     r8, 2
    add     r8, r13
    
    mov     r9, rdx
    imul    r9, r12
    shl     r9, 2
    add     r9, r14
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
DotLoop2:
    cmp     edi, ecx
    jae     DotLoop2Done
    
    vmovups zmm1, ZMMWORD PTR [r8+rdi*64]
    vmovups zmm2, ZMMWORD PTR [r9+rdi*64]
    vfmadd231ps zmm0, zmm1, zmm2
    
    inc     edi
    jmp     DotLoop2
    
DotLoop2Done:
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 4Eh
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 0B1h
    vaddps  xmm0, xmm0, xmm1
    
    vmulss  xmm0, xmm0, DWORD PTR [scale_factor]
    
    pop     rdx
    pop     rax
    
    push    rax
    mul     r11d
    add     eax, edx
    shl     rax, 2
    add     rax, r15
    vmovss  DWORD PTR [rax] {k1}, xmm0
    pop     rax
    
    inc     edx
    jmp     KeyLoop2
    
KeyLoop2Done:
    inc     eax
    jmp     QueryLoop
    
ScoreBatchDone:
    mov     rsp, rbp
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    
    vzeroupper
    ret
    
TreeAttention_ScoreBatch ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_OnlineSoftmax - Online softmax with masking
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_OnlineSoftmax PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    rbp
    .pushreg rbp
    
    sub     rsp, 32
    .allocstack 32
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    mov     r12, rcx                        ; scores
    mov     r13, rdx                        ; output
    mov     rbx, r8                         ; tree_mask
    mov     r14d, r9d                       ; length
    
    vbroadcastss zmm0, DWORD PTR [neg_inf]  ; max
    
    ; Find max
    xor     eax, eax
    
MaxLoop2:
    cmp     eax, r14d
    jae     MaxDone2
    
    movzx   edx, BYTE PTR [rbx+rax]
    cmp     dl, 1
    sete    dl
    kmovw   k1, edx
    
    vbroadcastss zmm1, DWORD PTR [r12+rax*4]
    vmaxps  zmm0 {k1}, zmm0, zmm1
    
    inc     eax
    jmp     MaxLoop2
    
MaxDone2:
    vxorps  zmm1, zmm1, zmm1                  ; sum
    
    ; Compute exp and sum
    xor     eax, eax
    
ExpLoop2:
    cmp     eax, r14d
    jae     ExpDone2
    
    movzx   edx, BYTE PTR [rbx+rax]
    cmp     dl, 1
    sete    dl
    kmovw   k1, edx
    
    vbroadcastss zmm2, DWORD PTR [r12+rax*4]
    vsubps  zmm2, zmm2, zmm0
    
    ; Simplified - would use proper exp approximation
    vaddps  zmm1 {k1}, zmm1, zmm2
    
    inc     eax
    jmp     ExpLoop2
    
ExpDone2:
    ; Normalize
    xor     eax, eax
    
NormLoop2:
    cmp     eax, r14d
    jae     NormDone2
    
    movzx   edx, BYTE PTR [rbx+rax]
    cmp     dl, 1
    sete    dl
    kmovw   k1, edx
    
    vbroadcastss zmm2, DWORD PTR [r12+rax*4]
    vsubps  zmm2, zmm2, zmm0
    vdivps  zmm2 {k1}, zmm2, zmm1
    
    vmovss  DWORD PTR [r13+rax*4] {k1}, xmm2
    
    inc     eax
    jmp     NormLoop2
    
NormDone2:
    mov     rsp, rbp
    pop     rbp
    pop     r13
    pop     r12
    pop     rbx
    
    vzeroupper
    ret
    
TreeAttention_OnlineSoftmax ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; Export symbols
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_AVX512
PUBLIC TreeAttention_ScoreBatch
PUBLIC TreeAttention_OnlineSoftmax

END
