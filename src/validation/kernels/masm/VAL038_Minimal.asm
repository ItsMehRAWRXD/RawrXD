; VAL-038: Step 2 - Add outer loop structure
OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.code

TreeAttention_Fused_VAL038 PROC FRAME
    ; Prologue
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
    
    ; Load stack parameters
    mov     ebx, [rbp+72]               ; ebx = num_q
    mov     esi, [rbp+80]               ; esi = num_k
    mov     rdi, [rbp+88]               ; rdi = tree_mask
    
    ; Validate
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Store entry marker
    mov     dword ptr [r12], 00000001h
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Store query marker
    mov     dword ptr [r12], 11111111h
    mov     dword ptr [r12+4], r8d
    
    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0
    
    ; Safety guard
    mov     r15d, 4096

.key_loop:
    dec     r15d
    jz      .abort_debug
    
    cmp     r9d, esi
    jae     .next_query
    
    ; Store key marker
    mov     dword ptr [r12], 22222222h
    mov     dword ptr [r12+4], r9d
    
    ; Load K row (4 zmm registers for head_dim=64)
    mov     rax, r9
    imul    rax, 256                    ; rax = k_idx * 64 * 4 bytes
    lea     rcx, [r14 + rax]            ; rcx = &K[k_idx * head_dim]
    
    vmovups zmm8, zmmword ptr [rcx]
    vmovups zmm9, zmmword ptr [rcx + 64]
    vmovups zmm10, zmmword ptr [rcx + 128]
    vmovups zmm11, zmmword ptr [rcx + 192]
    
    ; Just do one key iteration then exit
    jmp     .done
    
    inc     r9d
    jmp     .key_loop

.next_query:
    inc     r8d
    jmp     .query_loop

.abort_debug:
    mov     dword ptr [r12], 0DEADBEEFh
    
.done:
    ; Epilogue
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
