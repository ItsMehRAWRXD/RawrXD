; Nop-Kernel Test - Minimal ABI verification
; NopKernel.asm
; ============================================================================
; Tests basic calling convention compliance without any computation
; ============================================================================

.code

; ============================================================================
; Function: NopKernel_Test
; Purpose: Minimal function to verify ABI compliance
; Input:  RCX, RDX, R8, R9 (standard x64 calling convention)
; Output: RAX = 0xDEADBEEF (success marker)
; ============================================================================
NopKernel_Test PROC FRAME
    ; Prologue - save non-volatile registers
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    
    ; Set up stack frame
    mov     rbp, rsp
    .setframe rbp, 0
    
    ; Allocate shadow space + align to 16 bytes
    sub     rsp, 64         ; 32 bytes shadow + 32 bytes local = 64 (16-byte aligned)
    .allocstack 64
    
    .endprolog
    
    ; === KERNEL BODY (MINIMAL) ===
    ; Just verify we can access parameters
    mov     rax, rcx        ; Copy first param to rax
    add     rax, rdx        ; Add second param
    
    ; Return success marker
    mov     rax, 0DEADBEEFh
    
    ; === EPILOGUE ===
    ; Restore stack
    mov     rsp, rbp
    
    ; Restore non-volatile registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    
    ret
NopKernel_Test ENDP

; ============================================================================
; Function: NopKernel_Simple
; Purpose: Even simpler - just return with success marker
; ============================================================================
NopKernel_Simple PROC
    mov     rax, 0BEEFh
    ret
NopKernel_Simple ENDP

END
