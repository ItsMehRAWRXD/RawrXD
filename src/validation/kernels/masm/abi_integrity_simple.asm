; ============================================================================
; abi_integrity_simple.asm - Simplified ABI Compliance Test
; ============================================================================
; 
; PURPOSE: Check if MASM kernel preserves non-volatile registers
; 
; This is a simplified version that:
; 1. Saves non-volatile registers (RBX, RSI, RDI, R12-R15)
; 2. Calls the MASM kernel
; 3. Checks if non-volatile registers are preserved
; 4. Returns 0 if compliant, 1 if violations detected
; 
; CRITICAL: This is for development/debugging ONLY.
; 
; ============================================================================

OPTION CASEMAP:NONE

; External MASM kernel to test
extern MASM_SiLU_Clamped : proc

.code

; ============================================================================
; TestABIIntegrity_Simple - Tests MASM_SiLU_Clamped for ABI compliance
; ============================================================================
; Parameters:
;   RCX = void* data       (pointer to float array)
;   RDX = size_t data_size (number of bytes)
; Returns:
;   RAX = 0 if ABI compliant, 1 if violations detected
; ============================================================================

TestABIIntegrity_Simple PROC FRAME

    ; Prologue - save non-volatile registers
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    
    ; Save non-volatile registers on stack
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Save parameters (RCX, RDX are volatile, but we need them after call)
    mov r12, rcx          ; r12 = data pointer (non-volatile)
    mov r13, rdx          ; r13 = data_size (non-volatile)
    
    ; Save original values of non-volatile registers
    mov [rbp-8], rbx      ; Save RBX
    mov [rbp-16], rsi     ; Save RSI
    mov [rbp-24], rdi     ; Save RDI
    mov [rbp-32], r12     ; Save R12 (original data pointer)
    mov [rbp-40], r13     ; Save R13 (original data_size)
    mov [rbp-48], r14     ; Save R14
    mov [rbp-56], r15     ; Save R15
    
    ; ========================================
    ; Call the MASM kernel
    ; ========================================
    
    mov rcx, r12          ; Restore data pointer
    mov rdx, r13          ; Restore data_size
    
    call MASM_SiLU_Clamped
    
    ; Save return value
    mov r15, rax          ; r15 = kernel return value
    
    ; ========================================
    ; Check non-volatile registers
    ; ========================================
    
    xor rax, rax          ; rax = 0 (assume pass)
    
    ; Check RBX
    cmp rbx, [rbp-8]
    je check_rsi
    mov rax, 1            ; Mark as failed
    
check_rsi:
    ; Check RSI
    cmp rsi, [rbp-16]
    je check_rdi
    mov rax, 1
    
check_rdi:
    ; Check RDI
    cmp rdi, [rbp-24]
    je check_r12
    mov rax, 1
    
check_r12:
    ; Check R12 (should still have our saved data pointer)
    cmp r12, [rbp-32]
    je check_r13
    mov rax, 1
    
check_r13:
    ; Check R13 (should still have our saved data_size)
    cmp r13, [rbp-40]
    je check_r14
    mov rax, 1
    
check_r14:
    ; Check R14
    cmp r14, [rbp-48]
    je check_r15
    mov rax, 1
    
check_r15:
    ; Check R15
    cmp r15, [rbp-56]
    je done_checking
    mov rax, 1
    
done_checking:
    ; RAX now contains 0 (pass) or 1 (fail)
    ; Also return the kernel's return value in R15
    test rax, rax
    jnz abi_failed
    
    ; ABI compliant - return kernel's result
    mov rax, r15
    jmp cleanup
    
abi_failed:
    ; ABI violation detected - return error code 100
    mov rax, 100
    
cleanup:
    ; Epilogue - restore stack
    add rsp, 32           ; Deallocate shadow space
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

TestABIIntegrity_Simple ENDP

END
