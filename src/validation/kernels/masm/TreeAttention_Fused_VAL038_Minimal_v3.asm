; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: MINIMAL DEBUG VERSION - Step 3
; ═══════════════════════════════════════════════════════════════════════════════
; Step 3: Add inner loop (key loop)
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
    
    ; Safety guard: max iterations = num_q * num_k * 2
    mov     eax, ebx
    imul    eax, esi
    shl     eax, 1
    mov     r10d, eax                   ; r10d = max iterations
    xor     r11d, r11d                  ; r11d = iteration counter
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0

.key_loop:
    cmp     r9d, esi
    jae     .next_query
    
    ; Safety guard (inner loop)
    inc     r11d
    cmp     r11d, r10d
    jae     .done
    
    ; Store marker: output[q_idx][0] = k_idx + 1
    mov     rax, r8
    imul    rax, 64 * 4                 ; rax = q_idx * head_dim * 4
    lea     edx, [r9d + 1]              ; edx = k_idx + 1
    mov     dword ptr [r12 + rax], edx  ; Store marker
    
    ; Next key
    inc     r9d
    jmp     .key_loop

.next_query:
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
