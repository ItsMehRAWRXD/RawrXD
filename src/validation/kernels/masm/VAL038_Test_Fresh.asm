; VAL-038: TEST FRESH - Simple test with corrected offsets
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
    mov     dword ptr [r12], 0DDDDDDDDh
    
    ; Load stack parameters at corrected offsets
    mov     eax, [rbp+104]
    mov     dword ptr [r12+4], eax
    mov     eax, [rbp+112]
    mov     dword ptr [r12+8], eax

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
