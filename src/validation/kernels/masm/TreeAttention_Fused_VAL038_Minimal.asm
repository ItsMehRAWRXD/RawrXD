; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: MINIMAL DEBUG VERSION - Step 2
; ═══════════════════════════════════════════════════════════════════════════════
; Step 2: Add outer loop with safety guard
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
    
    ; Load stack parameters (corrected offsets)
    mov     ebx, [rbp+104]              ; ebx = num_q
    mov     esi, [rbp+112]              ; esi = num_k
    mov     rdi, [rbp+120]              ; rdi = tree_mask
    
    ; Validate parameters
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Safety guard: max iterations = num_q * 10
    mov     eax, ebx
    imul    eax, 10
    mov     r10d, eax                   ; r10d = max iterations
    xor     r11d, r11d                  ; r11d = iteration counter
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Safety guard
    inc     r11d
    cmp     r11d, r10d
    jae     .done
    
    ; Store marker for this query
    mov     rax, r8
    imul    rax, 64 * 4                 ; rax = q_idx * head_dim * 4
    mov     dword ptr [r12 + rax], 0x3F800000  ; Store 1.0
    
    ; Next query
    inc     r8d
    jmp     .query_loop
    mov     esi, [rbp+80]               ; esi = num_k
    mov     rdi, [rbp+88]               ; rdi = tree_mask
    
    ; Save params to debug
    mov     [debug_param_q], rbx
    mov     [debug_param_k], rsi
    
    ; Validate
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done

    ; Outer loop with iteration limit
    xor     r8d, r8d                    ; q_idx = 0
    mov     r10d, 10000               ; Max iterations (safety)

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Decrement safety counter
    dec     r10d
    jz      .done
    
    inc     qword ptr [debug_loop_q_enter]
    
    ; Inner loop with iteration limit
    xor     r9d, r9d                    ; k_idx = 0
    mov     r11d, 10000               ; Max inner iterations

.key_loop:
    cmp     r9d, esi
    jae     .query_next
    
    ; Decrement safety counter
    dec     r11d
    jz      .query_next
    
    inc     qword ptr [debug_loop_k_enter]
    
    ; Minimal work: just increment counters
    nop
    
    inc     qword ptr [debug_loop_k_exit]
    
    inc     r9d
    jmp     .key_loop

.query_next:
    inc     qword ptr [debug_loop_q_exit]
    inc     r8d
    jmp     .query_loop

.done:
    inc     qword ptr [debug_done_count]
    
    ; Epilogue
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
