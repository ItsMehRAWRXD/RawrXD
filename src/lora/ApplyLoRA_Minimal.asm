; LoRA Minimal Working Kernel
; ApplyLoRA_Minimal.asm
; ============================================================================
; Minimal working version - just copy input to result
; ============================================================================

.code

ApplyLoRA_Optimized PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Save non-volatile registers we'll use
    mov     [rbp-8], rbx
    mov     [rbp-16], r12
    mov     [rbp-24], r13
    mov     [rbp-32], r14
    mov     [rbp-40], r15
    
    ; RCX = base_output (unused in minimal version)
    ; RDX = input
    ; R8  = result
    ; R9  = beacon
    ; [RSP+40] = token_count (5th param)
    
    ; Simple copy: result[i] = input[i] for i=0 to 767
    mov     rsi, rdx        ; Source = input
    mov     rdi, r8         ; Dest = result
    mov     ecx, 768        ; Count = 768 floats
    
copy_loop:
    cmp     ecx, 0
    jle     copy_done
    mov     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     ecx
    jmp     copy_loop
    
copy_done:
    
    ; Epilogue
    mov     rbx, [rbp-8]
    mov     r12, [rbp-16]
    mov     r13, [rbp-24]
    mov     r14, [rbp-32]
    mov     r15, [rbp-40]
    
    mov     rsp, rbp
    pop     rbp
    xor     rax, rax        ; Return 0
    ret
ApplyLoRA_Optimized ENDP

END
