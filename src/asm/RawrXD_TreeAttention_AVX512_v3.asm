; ═══════════════════════════════════════════════════════════════════════════════
; RawrXD Tree Attention AVX-512 Kernel (VAL-032)
; Branchless DAG traversal using k-mask registers
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
HEAD_DIM        EQU     128
BLOCK_M         EQU     64
BLOCK_N         EQU     64

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.DATA
scale_factor    REAL4   0.08838834764831843
neg_inf         REAL4   -3.4028235E38
zero_val        REAL4   0.0
log2e           REAL4   1.4426950408889634

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.CODE

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512
; RCX=Q, RDX=K, R8=V, R9=output
; Stack: tree_mask, num_nodes, head_dim
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
    
    ; Load parameters from stack
    mov     r10, QWORD PTR [rbp+128+40]
    mov     r11d, DWORD PTR [rbp+128+48]
    mov     r12d, DWORD PTR [rbp+128+56]
    
    ; Save matrix pointers
    mov     r13, rcx
    mov     r14, rdx
    mov     r15, r8
    mov     rbx, r9
    
    ; Broadcast scale factor
    vbroadcastss zmm30, DWORD PTR scale_factor
    vbroadcastss zmm31, DWORD PTR neg_inf
    
    ; Main node loop
    xor     r8d, r8d
    
NodeLoop:
    cmp     r8d, r11d
    jae     NodeLoopDone
    
    ; Init max to -inf
    vmovaps zmm0, zmm31
    
    ; Key loop
    xor     r9d, r9d
    
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
    
    ; Compute dot product Q[i] . K[j]
    vxorps  zmm1, zmm1, zmm1
    
    ; Calculate offsets
    mov     rax, r8
    imul    rax, r12
    mov     rcx, r13
    lea     rax, [rcx+rax*4]
    
    mov     rdx, r9
    imul    rdx, r12
    mov     rcx, r14
    lea     rdx, [rcx+rdx*4]
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
DotLoop:
    cmp     edi, ecx
    jae     DotDone
    
    shl     rdi, 6
    vmovups zmm2, ZMMWORD PTR [rax+rdi]
    vmovups zmm3, ZMMWORD PTR [rdx+rdi]
    vfmadd231ps zmm1, zmm2, zmm3
    shr     rdi, 6
    
    inc     edi
    jmp     DotLoop
    
DotDone:
    ; Horizontal sum
    vextractf64x4 ymm2, zmm1, 1
    vaddps  ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vmovshdup xmm2, xmm1
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 1
    vaddss  xmm1, xmm1, xmm2
    vbroadcastss zmm1, xmm1
    vmulps  zmm1, zmm1, zmm30
    
    ; Update max with masking
    vmaxps  zmm0 {k1}, zmm0, zmm1
    
    inc     r9d
    jmp     KeyLoop
    
KeyLoopDone:
    ; Softmax and weighted sum
    vxorps  zmm29, zmm29, zmm29
    xor     r9d, r9d
    
SoftmaxLoop:
    cmp     r9d, r11d
    jae     SoftmaxDone
    
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
    mov     rcx, r13
    lea     rax, [rcx+rax*4]
    
    mov     rdx, r9
    imul    rdx, r12
    mov     rcx, r14
    lea     rdx, [rcx+rdx*4]
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
ScoreLoop:
    cmp     edi, ecx
    jae     ScoreDone
    
    shl     rdi, 6
    vmovups zmm2, ZMMWORD PTR [rax+rdi]
    vmovups zmm3, ZMMWORD PTR [rdx+rdi]
    vfmadd231ps zmm1, zmm2, zmm3
    shr     rdi, 6
    
    inc     edi
    jmp     ScoreLoop
    
ScoreDone:
    vextractf64x4 ymm2, zmm1, 1
    vaddps  ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vmovshdup xmm2, xmm1
    vaddps  xmm1, xmm1, xmm2
    vshufps xmm2, xmm1, xmm1, 1
    vaddss  xmm1, xmm1, xmm2
    vbroadcastss zmm1, xmm1
    vmulps  zmm1, zmm1, zmm30
    
    vsubps  zmm1, zmm1, zmm0
    vaddps  zmm29 {k1}, zmm29, zmm1
    
    inc     r9d
    jmp     SoftmaxLoop
    
SoftmaxDone:
    ; Weighted sum of V
    vxorps  zmm28, zmm28, zmm28
    xor     r9d, r9d
    
SumLoop:
    cmp     r9d, r11d
    jae     SumDone
    
    mov     eax, r8d
    mul     r11d
    add     eax, r9d
    movzx   edx, BYTE PTR [r10+rax]
    cmp     dl, 1
    sete    al
    kmovw   k1, eax
    
    mov     rdx, r9
    imul    rdx, r12
    mov     rcx, r15
    lea     rdx, [rcx+rdx*4]
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
VLoop:
    cmp     edi, ecx
    jae     VDone
    
    shl     rdi, 6
    vmovups zmm2, ZMMWORD PTR [rdx+rdi]
    vaddps  zmm28 {k1}, zmm28, zmm2
    shr     rdi, 6
    
    inc     edi
    jmp     VLoop
    
VDone:
    inc     r9d
    jmp     SumLoop
    
SumDone:
    ; Store output
    mov     rax, r8
    imul    rax, r12
    mov     rcx, rbx
    lea     rax, [rcx+rax*4]
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
StoreLoop:
    cmp     edi, ecx
    jae     StoreDone
    
    shl     rdi, 6
    vmovups ZMMWORD PTR [rax+rdi], zmm28
    shr     rdi, 6
    
    inc     edi
    jmp     StoreLoop
    
StoreDone:
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
; TreeAttention_ScoreBatch
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
    
    mov     r10d, DWORD PTR [rbp+64+40]
    mov     r11d, DWORD PTR [rbp+64+48]
    mov     r12d, DWORD PTR [rbp+64+56]
    
    mov     r13, rcx
    mov     r14, rdx
    mov     r15, r8
    mov     rbx, r9
    
    vbroadcastss zmm30, DWORD PTR scale_factor
    
    xor     eax, eax
    
QueryLoop:
    cmp     eax, r10d
    jae     ScoreBatchDone
    
    xor     edx, edx
    
KeyLoop2:
    cmp     edx, r11d
    jae     KeyLoop2Done
    
    push    rax
    mul     r11d
    add     eax, edx
    movzx   ecx, BYTE PTR [rbx+rax]
    pop     rax
    cmp     cl, 1
    sete    cl
    kmovw   k1, ecx
    
    vxorps  zmm0, zmm0, zmm0
    
    push    rax
    push    rdx
    
    mov     r8, rax
    imul    r8, r12
    mov     rcx, r13
    lea     r8, [rcx+r8*4]
    
    mov     r9, rdx
    imul    r9, r12
    mov     rcx, r14
    lea     r9, [rcx+r9*4]
    
    mov     ecx, r12d
    shr     ecx, 4
    xor     edi, edi
    
DotLoop2:
    cmp     edi, ecx
    jae     DotLoop2Done
    
    shl     rdi, 6
    vmovups zmm1, ZMMWORD PTR [r8+rdi]
    vmovups zmm2, ZMMWORD PTR [r9+rdi]
    vfmadd231ps zmm0, zmm1, zmm2
    shr     rdi, 6
    
    inc     edi
    jmp     DotLoop2
    
DotLoop2Done:
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vmovshdup xmm1, xmm0
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vaddss  xmm0, xmm0, xmm1
    
    vmulss  xmm0, xmm0, DWORD PTR scale_factor
    
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
; TreeAttention_OnlineSoftmax
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
    
    mov     r12, rcx
    mov     r13, rdx
    mov     rbx, r8
    mov     r14d, r9d
    
    vbroadcastss zmm0, DWORD PTR neg_inf
    
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
    vxorps  zmm1, zmm1, zmm1
    
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
    vaddps  zmm1 {k1}, zmm1, zmm2
    
    inc     eax
    jmp     ExpLoop2
    
ExpDone2:
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
; Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_AVX512
PUBLIC TreeAttention_ScoreBatch
PUBLIC TreeAttention_OnlineSoftmax

END
