; VAL-038: Corrected stack offsets
; After 8 pushes (64 bytes), parameters are at [rbp+104], [rbp+112], [rbp+120]
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
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    
    ; Load stack parameters (corrected offsets)
    ; After 8 pushes (64 bytes) + return address (8 bytes) = 72 bytes
    ; Shadow space (32 bytes) at [rbp+72] to [rbp+96]
    ; Parameters start at [rbp+104]
    mov     ebx, [rbp+104]              ; ebx = num_q
    mov     esi, [rbp+112]              ; esi = num_k
    mov     rdi, [rbp+120]              ; rdi = tree_mask
    
    ; Debug: Store values to verify
    mov     dword ptr [r12], 0AAAAAAAAh ; Marker
    mov     dword ptr [r12+4], ebx      ; num_q
    mov     dword ptr [r12+8], esi      ; num_k

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
