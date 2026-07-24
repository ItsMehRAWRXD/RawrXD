; VAL-038: STEP 4 OFFSET TEST - Find correct stack offsets
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
    
    ; Try different offsets to find num_q and num_k
    ; After 8 pushes (64 bytes) + return addr (8 bytes) = 72 bytes
    ; First stack param should be at rbp+72
    
    ; Store markers to identify which offset has the values
    mov     eax, [rbp+40]
    cmp     eax, 16
    jne     .check48
    mov     dword ptr [r12], 11111111h    ; Found at +40
    jmp     .found
.check48:
    cmp     eax, 16
    jne     .check56
    mov     dword ptr [r12], 22222222h    ; Found at +48
    jmp     .found
.check56:
    mov     eax, [rbp+56]
    cmp     eax, 16
    jne     .check64
    mov     dword ptr [r12], 33333333h    ; Found at +56
    jmp     .found
.check64:
    mov     eax, [rbp+64]
    cmp     eax, 16
    jne     .check72
    mov     dword ptr [r12], 44444444h    ; Found at +64
    jmp     .found
.check72:
    mov     eax, [rbp+72]
    cmp     eax, 16
    jne     .check80
    mov     dword ptr [r12], 55555555h    ; Found at +72
    jmp     .found
.check80:
    mov     eax, [rbp+80]
    cmp     eax, 16
    jne     .notfound
    mov     dword ptr [r12], 66666666h    ; Found at +80
    jmp     .found
.notfound:
    mov     dword ptr [r12], 0FFFFFFFFh   ; Not found
.found:
    
    ; Also store the actual value found
    mov     eax, [rbp+72]
    mov     dword ptr [r12+4], eax
    mov     eax, [rbp+80]
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
