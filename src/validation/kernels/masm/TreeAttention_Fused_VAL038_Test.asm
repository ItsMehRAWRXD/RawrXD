; VAL-038: Test version - verify calling convention
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
    
    ; Store marker
    mov     dword ptr [r12], 0AAAAAAAAh
    
    ; Try to find num_q and num_k on stack
    ; After 8 pushes (64 bytes) + return addr (8 bytes) = 72 bytes
    ; Stack params should be at [rbp+72], [rbp+80], [rbp+88]
    
    ; Store values from various offsets to find the correct one
    mov     eax, [rbp+72]
    mov     dword ptr [r12+4], eax
    mov     eax, [rbp+80]
    mov     dword ptr [r12+8], eax
    mov     eax, [rbp+88]
    mov     dword ptr [r12+12], eax

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
