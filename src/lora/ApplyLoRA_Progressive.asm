; LoRA Progressive Test Kernel
; ApplyLoRA_Progressive.asm
; ============================================================================
; Tests increasing complexity to isolate the crash
; ============================================================================

.code

; Test Level 0: Just return success
ApplyLoRA_Level0 PROC
    mov     rax, 0
    ret
ApplyLoRA_Level0 ENDP

; Test Level 1: Access parameters, return success
ApplyLoRA_Level1 PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog
    
    ; Just verify we can read parameters
    mov     rax, rcx        ; base_output
    mov     rax, rdx        ; input
    mov     rax, r8         ; result
    mov     rax, r9         ; beacon
    
    mov     rsp, rbp
    pop     rbp
    xor     rax, rax        ; Return 0
    ret
ApplyLoRA_Level1 ENDP

; Test Level 2: Simple memory copy (no AVX)
ApplyLoRA_Level2 PROC FRAME
    push    rbp
    .pushreg rbp
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog
    
    ; Copy 768 floats from input to result
    mov     rsi, rdx        ; Source = input
    mov     rdi, r8         ; Dest = result
    mov     ecx, 768        ; Count
    
copy_loop:
    mov     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     ecx
    jnz     copy_loop
    
    mov     rsp, rbp
    pop     rdi
    pop     rsi
    pop     rbp
    xor     rax, rax
    ret
ApplyLoRA_Level2 ENDP

; Test Level 3: AVX load/store (no FMA)
ApplyLoRA_Level3 PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog
    
    ; Try a simple AVX load/store
    vmovups ymm0, [rdx]     ; Load from input
    vmovups [r8], ymm0      ; Store to result
    
    ; Clear upper YMM state
    vzeroupper
    
    mov     rsp, rbp
    pop     rbp
    xor     rax, rax
    ret
ApplyLoRA_Level3 ENDP

; Test Level 4: AVX FMA operation
ApplyLoRA_Level4 PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog
    
    ; Try FMA operation
    vmovups ymm0, [rdx]     ; Load input
    vmovups ymm1, [rdx+32]  ; Load more input
    vmulps  ymm2, ymm0, ymm1; Multiply
    vmovups [r8], ymm2      ; Store result
    
    vzeroupper
    
    mov     rsp, rbp
    pop     rbp
    xor     rax, rax
    ret
ApplyLoRA_Level4 ENDP

; Test Level 5: Full kernel (original)
EXTERN ApplyLoRA_Optimized:PROC

END
