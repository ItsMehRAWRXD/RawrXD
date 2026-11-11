; VAL-038: STEP 4 DEBUG - Check stack parameters
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
    
    ; Debug: Store raw stack values at various offsets
    mov     eax, [rbp+40]
    mov     dword ptr [r12], eax
    mov     eax, [rbp+48]
    mov     dword ptr [r12+4], eax
    mov     eax, [rbp+56]
    mov     dword ptr [r12+8], eax
    mov     eax, [rbp+64]
    mov     dword ptr [r12+12], eax
    mov     eax, [rbp+72]
    mov     dword ptr [r12+16], eax
    mov     eax, [rbp+80]
    mov     dword ptr [r12+20], eax
    mov     eax, [rbp+88]
    mov     dword ptr [r12+24], eax
    jmp     .done

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
