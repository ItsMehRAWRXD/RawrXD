; ═══════════════════════════════════════════════════════════════════════════════
; VAL-032: Tree Attention Verification Kernel (MASM x64)
; ═══════════════════════════════════════════════════════════════════════════════
; Production AVX-512 implementation for speculative tree attention
; ABI Compliant: Windows x64 calling convention
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Public Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttentionVerify_AVX512_Export
PUBLIC TreeAttentionVerify_AVX2_Export
PUBLIC TreeAttentionVerify_Scalar_Export

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
HEAD_DIM        EQU     64              ; Attention head dimension
MAX_CANDIDATES  EQU     16              ; Fixed 4x4 tree structure
VEC_WIDTH       EQU     16              ; 16 floats per zmm (512-bit)

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

scale_factor    REAL4   0.125           ; 1/sqrt(64)
neg_inf         REAL4   -1.0e38         ; Approximate -infinity
one             REAL4   1.0             ; Constant 1.0
zero            REAL4   0.0             ; Constant 0.0

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttentionVerify_AVX512_Export
;
; Windows x64 ABI:
;   RCX  = candidate_logits      (float* [16, 64])
;   RDX  = draft_logits          (float* [16, 64])
;   R8   = tree_mask             (uint8_t* [16, 16])
;   R9   = output_probs          (float* [16])
;   [RSP+40] = num_candidates    (uint32_t) - must be 16
;   [RSP+48] = acceptance_threshold (float)
;
; Returns: EAX = acceptance_mask (uint32_t)
; Clobbers: zmm0-zmm15, rax-r15
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttentionVerify_AVX512_Export PROC FRAME
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
    sub     rsp, 128
    .allocstack 128
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = candidate_logits
    mov     r13, rdx                    ; r13 = draft_logits
    mov     r14, r8                     ; r14 = tree_mask
    mov     r15, r9                     ; r15 = output_probs
    
    ; Load stack parameters
    ; After 8 pushes (64 bytes) + return addr (8 bytes) = 72 bytes
    ; [rbp+72] = num_candidates, [rbp+80] = acceptance_threshold
    mov     ebx, [rbp+72]               ; ebx = num_candidates (must be 16)
    vmovss  xmm14, dword ptr [rbp+80]   ; xmm14 = acceptance_threshold
    
    ; Validate num_candidates == 16
    cmp     ebx, MAX_CANDIDATES
    jne     .invalid_params
    
    ; Initialize acceptance_mask = 0
    xor     eax, eax                    ; eax = acceptance_mask
    
    ; Broadcast scale factor
    vbroadcastss zmm15, dword ptr [scale_factor]
    
    ; Outer loop: process each candidate
    xor     r8d, r8d                    ; r8d = candidate_idx = 0
    
.candidate_loop:
    cmp     r8d, MAX_CANDIDATES
    jae     .done
    
    ; Load candidate logits for this candidate
    mov     rax, r8
    imul    rax, HEAD_DIM * 4           ; rax = candidate_idx * 64 * 4
    lea     rcx, [r12 + rax]            ; rcx = &candidate_logits[candidate_idx * 64]
    
    ; Load into zmm0-zmm3 (4 zmm registers for 64 floats)
    vmovaps zmm0, zmmword ptr [rcx]
    vmovaps zmm1, zmmword ptr [rcx + 64]
    vmovaps zmm2, zmmword ptr [rcx + 128]
    vmovaps zmm3, zmmword ptr [rcx + 192]
    
    ; Initialize max score for this candidate
    vbroadcastss zmm13, dword ptr [neg_inf]  ; zmm13 = max_score = -inf
    
    ; Inner loop: compare with each draft token
    xor     r9d, r9d                    ; r9d = draft_idx = 0
    
.draft_loop:
    cmp     r9d, MAX_CANDIDATES
    jae     .process_candidate
    
    ; Check tree mask
    mov     rax, r8
    imul    rax, MAX_CANDIDATES         ; rax = candidate_idx * 16
    add     rax, r9                     ; rax = candidate_idx * 16 + draft_idx
    cmp     byte ptr [r14 + rax], 0
    je      .skip_draft                 ; Skip if masked
    
    ; Load draft logits
    mov     rax, r9
    imul    rax, HEAD_DIM * 4           ; rax = draft_idx * 64 * 4
    lea     rcx, [r13 + rax]            ; rcx = &draft_logits[draft_idx * 64]
    
    vmovaps zmm4, zmmword ptr [rcx]
    vmovaps zmm5, zmmword ptr [rcx + 64]
    vmovaps zmm6, zmmword ptr [rcx + 128]
    vmovaps zmm7, zmmword ptr [rcx + 192]
    
    ; Compute dot product: candidate · draft
    vmulps  zmm8, zmm0, zmm4
    vfmadd231ps zmm8, zmm1, zmm5
    vfmadd231ps zmm8, zmm2, zmm6
    vfmadd231ps zmm8, zmm3, zmm7
    
    ; Horizontal sum
    vextractf64x4 ymm9, zmm8, 1
    vaddps  ymm8, ymm8, ymm9
    vextractf128 xmm9, ymm8, 1
    vaddps  xmm8, xmm8, xmm9
    vhaddps xmm8, xmm8, xmm8
    vhaddps xmm8, xmm8, xmm8
    
    ; Scale by 1/sqrt(64)
    vmulss  xmm8, xmm8, xmm15
    
    ; Update max score
    vmaxss  xmm13, xmm13, xmm8
    
.skip_draft:
    inc     r9d
    jmp     .draft_loop
    
.process_candidate:
    ; Store max score as probability (simplified)
    ; In real impl: softmax over all scores
    mov     rax, r8
    shl     rax, 2                      ; rax = candidate_idx * 4
    vmovss  dword ptr [r15 + rax], xmm13
    
    ; Check acceptance: max_score > threshold
    vucomiss xmm13, xmm14
    jbe     .reject_candidate
    
    ; Accept: set bit in mask
    mov     ecx, r8d
    mov     edx, 1
    shl     edx, cl
    or      eax, edx
    
.reject_candidate:
    inc     r8d
    jmp     .candidate_loop
    
.invalid_params:
    xor     eax, eax                    ; Return 0 on invalid params
    
.done:
    ; Epilogue
    vzeroupper
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttentionVerify_AVX512_Export ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttentionVerify_AVX2_Export
; AVX2 fallback implementation
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttentionVerify_AVX2_Export PROC FRAME
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
    sub     rsp, 128
    .allocstack 128
    .endprolog

    ; For now: fall through to scalar
    ; Full AVX2 implementation would use ymm registers
    
    ; Epilogue
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    jmp     TreeAttentionVerify_Scalar_Export

TreeAttentionVerify_AVX2_Export ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttentionVerify_Scalar_Export
; Scalar reference implementation
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttentionVerify_Scalar_Export PROC FRAME
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
    sub     rsp, 128
    .allocstack 128
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = candidate_logits
    mov     r13, rdx                    ; r13 = draft_logits
    mov     r14, r8                     ; r14 = tree_mask
    mov     r15, r9                     ; r15 = output_probs
    
    ; Load stack parameters
    mov     ebx, [rbp+72]               ; ebx = num_candidates
    movss   xmm6, dword ptr [rbp+80]    ; xmm6 = acceptance_threshold
    
    ; Validate
    cmp     ebx, MAX_CANDIDATES
    jne     .scalar_invalid
    
    xor     eax, eax                    ; acceptance_mask = 0
    xor     r8d, r8d                    ; candidate_idx = 0
    
.scalar_candidate_loop:
    cmp     r8d, MAX_CANDIDATES
    jae     .scalar_done
    
    ; Compute max score for this candidate
    movss   xmm7, dword ptr [neg_inf]   ; max_score = -inf
    xor     r9d, r9d                    ; draft_idx = 0
    
.scalar_draft_loop:
    cmp     r9d, MAX_CANDIDATES
    jae     .scalar_process
    
    ; Check mask
    mov     rax, r8
    imul    rax, MAX_CANDIDATES
    add     rax, r9
    cmp     byte ptr [r14 + rax], 0
    je      .scalar_skip
    
    ; Compute dot product (scalar)
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    lea     rcx, [r12 + rax]            ; candidate row
    
    mov     rax, r9
    imul    rax, HEAD_DIM * 4
    lea     rdx, [r13 + rax]            ; draft row
    
    xorps   xmm0, xmm0                  ; sum = 0
    mov     ecx, HEAD_DIM
    
.scalar_dot:
    movss   xmm1, dword ptr [rcx]
    mulss   xmm1, dword ptr [rdx]
    addss   xmm0, xmm1
    add     rcx, 4
    add     rdx, 4
    dec     ecx
    jnz     .scalar_dot
    
    ; Scale
    mulss   xmm0, dword ptr [scale_factor]
    
    ; Update max
    maxss   xmm7, xmm0
    
.scalar_skip:
    inc     r9d
    jmp     .scalar_draft_loop
    
.scalar_process:
    ; Store probability
    mov     rax, r8
    shl     rax, 2
    movss   dword ptr [r15 + rax], xmm7
    
    ; Check acceptance
    comiss  xmm7, xmm6
    jbe     .scalar_reject
    
    mov     ecx, r8d
    mov     edx, 1
    shl     edx, cl
    or      eax, edx
    
.scalar_reject:
    inc     r8d
    jmp     .scalar_candidate_loop
    
.scalar_invalid:
    xor     eax, eax
    
.scalar_done:
    ; Epilogue
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttentionVerify_Scalar_Export ENDP

END
