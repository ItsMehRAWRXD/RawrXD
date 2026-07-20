; VAL-038: MINIMAL FRESH - Just return marker with corrected offsets
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
    
    ; Load stack parameters at [rbp+104], [rbp+112], [rbp+120]
    mov     ebx, [rbp+104]
    mov     esi, [rbp+112]
    mov     rdi, [rbp+120]
    
    ; Store marker with num_q and num_k
    mov     dword ptr [r12], 0AAAAAAAAh
    mov     dword ptr [r12+4], ebx
    mov     dword ptr [r12+8], esi

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
