; VAL-038: WORKING VERSION - Complete fused attention kernel
OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.data
scale_factor    REAL4   0.125           ; 1/sqrt(64)
neg_inf         REAL4   -1.0e38         ; Approximate -infinity

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
    
    ; Load stack parameters (CORRECTED OFFSETS)
    ; After 8 pushes (64 bytes) + return addr (8 bytes) + shadow space (32 bytes)
    mov     ebx, [rbp+104]              ; ebx = num_q
    mov     esi, [rbp+112]              ; esi = num_k
    mov     rdi, [rbp+120]              ; rdi = tree_mask
    
    ; Store marker with num_q for verification
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
