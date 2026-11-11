; VAL-038: STEP 4 - Add inner loop with safety guard
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
    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9
    
    ; Load stack parameters
    mov     ebx, [rbp+72]
    mov     esi, [rbp+80]
    mov     rdi, [rbp+88]
    
    ; Validate
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Outer loop
    xor     r8d, r8d

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Inner loop with safety guard
    xor     r9d, r9d
    mov     r10d, 100

.key_loop:
    cmp     r9d, esi
    jae     .next_query
    
    dec     r10d
    jz      .done
    
    ; Marker for first iteration
    cmp     r8d, 0
    jne     .skip
    cmp     r9d, 0
    jne     .skip
    mov     dword ptr [r12], 0EEEEEEEEh
    mov     dword ptr [r12+4], esi
.skip:
    
    inc     r9d
    jmp     .key_loop

.next_query:
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
