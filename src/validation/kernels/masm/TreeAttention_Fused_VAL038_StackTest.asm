; VAL-038: STACK TEST - Check all stack offsets
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

    ; Save output pointer
    mov     r12, rcx
    
    ; Store values from various stack offsets to find num_q=16 and num_k=16
    mov     eax, [rbp+40]
    mov     dword ptr [r12], eax      ; output[0] = [rbp+40]
    mov     eax, [rbp+48]
    mov     dword ptr [r12+4], eax     ; output[1] = [rbp+48]
    mov     eax, [rbp+56]
    mov     dword ptr [r12+8], eax     ; output[2] = [rbp+56]
    mov     eax, [rbp+64]
    mov     dword ptr [r12+12], eax    ; output[3] = [rbp+64]
    mov     eax, [rbp+72]
    mov     dword ptr [r12+16], eax    ; output[4] = [rbp+72]
    mov     eax, [rbp+80]
    mov     dword ptr [r12+20], eax    ; output[5] = [rbp+80]
    mov     eax, [rbp+88]
    mov     dword ptr [r12+24], eax    ; output[6] = [rbp+88]

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
