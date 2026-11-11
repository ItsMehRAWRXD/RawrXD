; VAL-038: Offset Test 2 - Try different stack offsets
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
    
    ; Try offsets from +32 to +96 to find num_q=16 and num_k=16
    ; Store all candidate values
    mov     eax, [rbp+32]
    mov     dword ptr [r12], eax      ; [rbp+32]
    mov     eax, [rbp+40]
    mov     dword ptr [r12+4], eax    ; [rbp+40]
    mov     eax, [rbp+48]
    mov     dword ptr [r12+8], eax    ; [rbp+48]
    mov     eax, [rbp+56]
    mov     dword ptr [r12+12], eax   ; [rbp+56]
    mov     eax, [rbp+64]
    mov     dword ptr [r12+16], eax   ; [rbp+64]
    mov     eax, [rbp+72]
    mov     dword ptr [r12+20], eax   ; [rbp+72]
    mov     eax, [rbp+80]
    mov     dword ptr [r12+24], eax   ; [rbp+80]
    mov     eax, [rbp+88]
    mov     dword ptr [r12+28], eax   ; [rbp+88]
    mov     eax, [rbp+96]
    mov     dword ptr [r12+32], eax   ; [rbp+96]

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
