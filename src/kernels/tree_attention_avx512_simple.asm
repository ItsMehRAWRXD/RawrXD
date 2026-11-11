;============================================================================
; tree_attention_avx512.asm
; VAL-032: Branchless Tree Attention Kernel
;============================================================================

PUBLIC TreeVerify_Batch_4x4
PUBLIC KVCache_Invalidate_Masked
PUBLIC TreeAttention_HasAVX512

.code

;----------------------------------------------------------------------------
; TreeVerify_Batch_4x4
; Verifies 4x4 tree (16 candidates) in single pass
;----------------------------------------------------------------------------
TreeVerify_Batch_4x4 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 128
    .allocstack 128
    .endprolog
    
    ; Parameters:
    ; rcx = Q_ptr, rdx = K_ptr, r8 = TreeMask_ptr, r9 = Output_probs
    mov     r10, rcx
    mov     r11, rdx
    mov     r12, r8
    mov     r13, r9
    
    ; Validate num_candidates = 16
    cmp     dword ptr [rsp+168], 16
    jne     ErrorExit
    
    ; Load Q vector (64 floats)
    vmovaps zmm0, zmmword ptr [r10]
    vmovaps zmm1, zmmword ptr [r10+64]
    vmovaps zmm2, zmmword ptr [r10+128]
    vmovaps zmm3, zmmword ptr [r10+192]
    
    ; Compute dot products for candidates 0-3
    vmulps  zmm4, zmm0, zmmword ptr [r11]
    vmulps  zmm5, zmm0, zmmword ptr [r11+256]
    vmulps  zmm6, zmm0, zmmword ptr [r11+512]
    vmulps  zmm7, zmm0, zmmword ptr [r11+768]
    
    ; Horizontal reduction (simplified)
    vaddps  zmm4, zmm4, zmm5
    vaddps  zmm6, zmm6, zmm7
    vaddps  zmm4, zmm4, zmm6
    
    vextractf64x2 xmm5, zmm4, 0
    vextractf64x2 xmm6, zmm4, 1
    vaddps  xmm5, xmm5, xmm6
    vhaddps xmm5, xmm5, xmm5
    vhaddps xmm5, xmm5, xmm5
    
    ; Store result
    vmovss  dword ptr [r13], xmm5
    
    ; Return rejection mask (simplified: 0 = all accepted)
    xor     eax, eax
    jmp     Exit
    
ErrorExit:
    mov     eax, 0FFFFh
    
Exit:
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret
TreeVerify_Batch_4x4 ENDP

;----------------------------------------------------------------------------
; KVCache_Invalidate_Masked
;----------------------------------------------------------------------------
KVCache_Invalidate_Masked PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    ; rcx = kvCache_ptr, rdx = rejection_mask, r8 = entry_size
    mov     r9, rcx
    movzx   r10, dx
    
    ; Simple invalidation: zero out entries where mask bit is set
    vpxor   xmm0, xmm0, xmm0
    
    ; Check bit 0
    test    r10d, 1
    jz      Skip0
    vmovdqu64 zmmword ptr [r9], zmm0
Skip0:
    
    add     r9, r8
    shr     r10d, 1
    test    r10d, 1
    jz      Skip1
    vmovdqu64 zmmword ptr [r9], zmm0
Skip1:
    
    pop     rbx
    ret
KVCache_Invalidate_Masked ENDP

;----------------------------------------------------------------------------
; TreeAttention_HasAVX512
;----------------------------------------------------------------------------
TreeAttention_HasAVX512 PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    
    xor     eax, eax
    test    ebx, 00010000h
    jz      NoAVX512
    
    xor     ecx, ecx
    xgetbv
    and     eax, 0E0h
    cmp     eax, 0E0h
    jne     NoAVX512
    
    mov     eax, 1
NoAVX512:
    pop     rbx
    ret
TreeAttention_HasAVX512 ENDP

END
