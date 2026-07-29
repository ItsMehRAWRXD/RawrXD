; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: TRACE VERSION - Absolute minimum to find the hang
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

; Debug counters
.data
ALIGN 8
debug_marker_1    QWORD   0   ; Entry
debug_marker_2    QWORD   0   ; After prologue
debug_marker_3    QWORD   0   ; After param load
debug_marker_4    QWORD   0   ; Before outer loop
debug_marker_5    QWORD   0   ; In outer loop
debug_marker_6    QWORD   0   ; Before inner loop
debug_marker_7    QWORD   0   ; In inner loop
debug_marker_8    QWORD   0   ; After inner loop
debug_marker_9    QWORD   0   ; After outer loop
debug_marker_10   QWORD   0   ; Before epilogue
debug_marker_11   QWORD   0   ; Exit

.code

TreeAttention_Fused_VAL038 PROC FRAME
    ; Mark entry
    mov     qword ptr [debug_marker_1], 1
    
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
    sub     rsp, 64
    .allocstack 64
    .endprolog

    mov     qword ptr [debug_marker_2], 1

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    
    ; Load stack parameters
    mov     ebx, [rbp+72]               ; ebx = num_q
    mov     esi, [rbp+80]               ; esi = num_k
    mov     rdi, [rbp+88]               ; rdi = tree_mask
    
    mov     qword ptr [debug_marker_3], 1

    ; Validate
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done

    mov     qword ptr [debug_marker_4], 1

    ; Outer loop - just count to num_q
    xor     r8d, r8d                    ; q_idx = 0

.outer_loop:
    cmp     r8d, ebx
    jae     .outer_done
    
    mov     qword ptr [debug_marker_5], 1
    
    ; Inner loop - just count to num_k
    xor     r9d, r9d                    ; k_idx = 0
    
.inner_loop:
    cmp     r9d, esi
    jae     .inner_done
    
    mov     qword ptr [debug_marker_7], 1
    
    ; Do nothing - just iterate
    inc     r9d
    jmp     .inner_loop
    
.inner_done:
    mov     qword ptr [debug_marker_8], 1
    inc     r8d
    jmp     .outer_loop
    
.outer_done:
    mov     qword ptr [debug_marker_9], 1

.done:
    mov     qword ptr [debug_marker_10], 1
    
    ; Epilogue
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    
    mov     qword ptr [debug_marker_11], 1
    ret

TreeAttention_Fused_VAL038 ENDP

END
