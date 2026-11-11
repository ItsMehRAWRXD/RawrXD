; VAL-038: Version without AVX-512 to test if AVX-512 is causing the hang
OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.code

TreeAttention_Fused_VAL038 PROC FRAME
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
    
    ; Load stack parameters (corrected offsets)
    mov     ebx, [rbp+104]              ; ebx = num_q
    mov     esi, [rbp+112]              ; esi = num_k
    mov     rdi, [rbp+120]              ; rdi = tree_mask
    
    ; Validate parameters
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Safety guard: max iterations = num_q * num_k * 2
    mov     eax, ebx
    imul    eax, esi
    shl     eax, 1
    mov     r10d, eax                   ; r10d = max iterations
    xor     r11d, r11d                  ; r11d = iteration counter
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0
    
    ; Debug: Store outer loop entry marker
    mov     dword ptr [r12], 0DDDDDDDDh

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Debug: Store query index
    mov     dword ptr [r12+4], r8d
    
    ; Initialize accumulators (scalar, no AVX-512)
    xorps   xmm4, xmm4                  ; xmm4 = accum output[0:3]
    xorps   xmm5, xmm5                  ; xmm5 = accum output[4:7]
    xorps   xmm6, xmm6                  ; xmm6 = accum output[8:11]
    xorps   xmm7, xmm7                  ; xmm7 = accum output[12:15]
    
    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0
    
    ; Debug: Store inner loop entry marker
    mov     dword ptr [r12+8], 0EEEEEEEEh

.key_loop:
    cmp     r9d, esi
    jae     .store_output
    
    ; Debug: Store key index
    mov     dword ptr [r12+12], r9d
    
    ; Safety guard
    inc     r11d
    cmp     r11d, r10d
    jae     .done
    
    ; Check tree mask
    mov     rax, r8
    imul    rax, rsi                    ; rax = q_idx * num_k
    add     rax, r9                     ; rax = q_idx * num_k + k_idx
    cmp     byte ptr [rdi + rax], 0
    je      .skip_key                   ; Skip if masked
    
    ; Simple scalar computation (no AVX-512)
    ; Just accumulate a constant value for testing
    movss   xmm0, dword ptr [r13]       ; Load Q[0]
    movss   xmm1, dword ptr [r14]       ; Load K[0]
    mulss   xmm0, xmm1                  ; Q[0] * K[0]
    addss   xmm4, xmm0                  ; Accumulate

.skip_key:
    inc     r9d
    jmp     .key_loop

.store_output:
    ; Store output row (just first element for testing)
    mov     rax, r8
    imul    rax, 64 * 4
    movss   dword ptr [r12 + rax], xmm4
    
    ; Next query
    inc     r8d
    jmp     .query_loop

.done:
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
