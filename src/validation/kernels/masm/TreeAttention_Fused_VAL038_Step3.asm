; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: STEP 3 - Add outer loop
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.code

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
    
    ; Load stack parameters
    mov     ebx, [rbp+72]               ; ebx = num_q
    mov     esi, [rbp+80]               ; esi = num_k
    mov     rdi, [rbp+88]               ; rdi = tree_mask
    
    ; Validate parameters
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Store marker for first query only
    cmp     r8d, 0
    jne     .skip_marker
    mov     dword ptr [r12], 0DDDDDDDDh
.skip_marker:
    
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
