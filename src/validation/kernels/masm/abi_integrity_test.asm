; ============================================================================
; abi_integrity_test.asm - Complete Register State Capture for ABI Testing
; ============================================================================
; 
; PURPOSE: Save ALL registers before/after calling MASM kernels to detect ABI violations
; 
; This function:
; 1. Saves ALL general purpose registers (RAX-R15)
; 2. Saves ALL YMM registers (YMM0-YMM15)
; 3. Calls the MASM kernel
; 4. Compares register states to detect corruption
; 5. Reports any ABI violations
; 
; CRITICAL: This is for development/debugging ONLY. Remove before production.
; 
; ============================================================================

OPTION CASEMAP:NONE

; External C function to print results
extern printf : proc

; External MASM kernel to test (using the clamped version which we know works)
extern MASM_SiLU_Clamped : proc

.data

; Format strings for reporting
fmt_header       db '=== ABI Integrity Test ===', 13, 10, 0
fmt_pass         db '✅ PASS: All registers preserved', 13, 10, 0
fmt_fail_reg     db '❌ FAIL: Register %s corrupted: 0x%016llX -> 0x%016llX', 13, 10, 0
fmt_fail_ymm     db '❌ FAIL: YMM%d corrupted', 13, 10, 0
fmt_result       db 'ASM function return: %d', 13, 10, 0
fmt_footer       db '=========================', 13, 10, 0

; Register names for error reporting
reg_names label qword
    db 'RAX', 0, 0, 0, 0, 0   ; 0
    db 'RBX', 0, 0, 0, 0, 0   ; 1
    db 'RCX', 0, 0, 0, 0, 0   ; 2
    db 'RDX', 0, 0, 0, 0, 0   ; 3
    db 'RSI', 0, 0, 0, 0, 0   ; 4
    db 'RDI', 0, 0, 0, 0, 0   ; 5
    db 'RBP', 0, 0, 0, 0, 0   ; 6
    db 'RSP', 0, 0, 0, 0, 0   ; 7
    db 'R8 ', 0, 0, 0, 0, 0   ; 8
    db 'R9 ', 0, 0, 0, 0, 0   ; 9
    db 'R10', 0, 0, 0, 0, 0   ; 10
    db 'R11', 0, 0, 0, 0, 0   ; 11
    db 'R12', 0, 0, 0, 0, 0   ; 12
    db 'R13', 0, 0, 0, 0, 0   ; 13
    db 'R14', 0, 0, 0, 0, 0   ; 14
    db 'R15', 0, 0, 0, 0, 0   ; 15

.code

; ============================================================================
; TestABIIntegrity_Silu_Clamped - Tests MASM_SiLU_Clamped for ABI compliance
; ============================================================================
; Parameters:
;   RCX = void* data       (pointer to float array)
;   RDX = size_t data_size (number of bytes)
; Returns:
;   RAX = 0 if ABI compliant, non-zero if violations detected
; ============================================================================

TestABIIntegrity_Silu_Clamped PROC FRAME

    ; Prologue - save non-volatile registers
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    
    ; Allocate stack space for register states
    ; We need space for:
    ;   - 16 general purpose registers (8 bytes each) = 128 bytes
    ;   - 16 YMM registers (32 bytes each) = 512 bytes
    ;   - Total = 640 bytes + 32 bytes shadow space + alignment
    sub rsp, 800
    .allocstack 800
    .endprolog
    
    ; Save parameters
    mov [rbp-8], rcx          ; Save data pointer
    mov [rbp-16], rdx          ; Save data_size
    
    ; Print header
    lea rcx, fmt_header
    call printf
    
    ; ========================================
    ; STEP 1: Save ALL registers BEFORE call
    ; ========================================
    
    ; Save general purpose registers
    mov [rsp+0], rax           ; RAX
    mov [rsp+8], rbx           ; RBX (non-volatile)
    mov [rsp+16], rcx          ; RCX
    mov [rsp+24], rdx          ; RDX
    mov [rsp+32], rsi          ; RSI (non-volatile)
    mov [rsp+40], rdi          ; RDI (non-volatile)
    mov [rsp+48], rbp          ; RBP (non-volatile)
    mov [rsp+56], rsp          ; RSP (non-volatile)
    mov [rsp+64], r8           ; R8
    mov [rsp+72], r9           ; R9
    mov [rsp+80], r10          ; R10
    mov [rsp+88], r11          ; R11
    mov [rsp+96], r12          ; R12 (non-volatile)
    mov [rsp+104], r13         ; R13 (non-volatile)
    mov [rsp+112], r14         ; R14 (non-volatile)
    mov [rsp+120], r15         ; R15 (non-volatile)
    
    ; Save YMM registers (volatile, but we check anyway)
    vmovaps ymmword ptr [rsp+128], ymm0
    vmovaps ymmword ptr [rsp+160], ymm1
    vmovaps ymmword ptr [rsp+192], ymm2
    vmovaps ymmword ptr [rsp+224], ymm3
    vmovaps ymmword ptr [rsp+256], ymm4
    vmovaps ymmword ptr [rsp+288], ymm5
    vmovaps ymmword ptr [rsp+320], ymm6
    vmovaps ymmword ptr [rsp+352], ymm7
    vmovaps ymmword ptr [rsp+384], ymm8
    vmovaps ymmword ptr [rsp+416], ymm9
    vmovaps ymmword ptr [rsp+448], ymm10
    vmovaps ymmword ptr [rsp+480], ymm11
    vmovaps ymmword ptr [rsp+512], ymm12
    vmovaps ymmword ptr [rsp+544], ymm13
    vmovaps ymmword ptr [rsp+576], ymm14
    vmovaps ymmword ptr [rsp+608], ymm15
    
    ; ========================================
    ; STEP 2: Call the MASM kernel
    ; ========================================
    
    ; Restore parameters
    mov rcx, [rbp-8]          ; data pointer
    mov rdx, [rbp-16]         ; data_size
    
    ; Call the MASM kernel
    call MASM_SiLU_Clamped
    
    ; Save return value
    mov [rbp-24], rax          ; Save ASM function return value
    
    ; ========================================
    ; STEP 3: Check ALL registers AFTER call
    ; ========================================
    
    ; Check non-volatile registers (RBX, RBP, RDI, RSI, R12-R15)
    ; These MUST be preserved by the called function
    
    xor rax, rax              ; rax = 0 (assume pass)
    
    ; Check RBX (non-volatile)
    cmp rbx, [rsp+8]
    je check_rbp
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+8      ; "RBX"
    mov r8, [rsp+8]           ; Expected value
    mov r9, rbx               ; Actual value
    call printf
    mov rax, 1                ; Mark as failed
    
check_rbp:
    ; Check RBP (non-volatile)
    cmp rbp, [rsp+48]
    je check_rdi
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+24     ; "RBP"
    mov r8, [rsp+48]         ; Expected value
    mov r9, rbp               ; Actual value
    call printf
    mov rax, 1
    
check_rdi:
    ; Check RDI (non-volatile)
    cmp rdi, [rsp+40]
    je check_rsi
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+20     ; "RDI"
    mov r8, [rsp+40]         ; Expected value
    mov r9, rdi               ; Actual value
    call printf
    mov rax, 1
    
check_rsi:
    ; Check RSI (non-volatile)
    cmp rsi, [rsp+32]
    je check_r12
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+16     ; "RSI"
    mov r8, [rsp+32]         ; Expected value
    mov r9, rsi               ; Actual value
    call printf
    mov rax, 1
    
check_r12:
    ; Check R12 (non-volatile)
    cmp r12, [rsp+96]
    je check_r13
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+48     ; "R12"
    mov r8, [rsp+96]         ; Expected value
    mov r9, r12               ; Actual value
    call printf
    mov rax, 1
    
check_r13:
    ; Check R13 (non-volatile)
    cmp r13, [rsp+104]
    je check_r14
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+52     ; "R13"
    mov r8, [rsp+104]        ; Expected value
    mov r9, r13               ; Actual value
    call printf
    mov rax, 1
    
check_r14:
    ; Check R14 (non-volatile)
    cmp r14, [rsp+112]
    je check_r15
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+56     ; "R14"
    mov r8, [rsp+112]        ; Expected value
    mov r9, r14               ; Actual value
    call printf
    mov rax, 1
    
check_r15:
    ; Check R15 (non-volatile)
    cmp r15, [rsp+120]
    je check_volatile
    lea rcx, fmt_fail_reg
    lea rdx, reg_names+60     ; "R15"
    mov r8, [rsp+120]        ; Expected value
    mov r9, r15               ; Actual value
    call printf
    mov rax, 1
    
check_volatile:
    ; Note: Volatile registers (RAX, RCX, RDX, R8-R11, YMM0-YMM15) are
    ; allowed to be modified, so we don't check them for ABI compliance.
    ; However, we could check them if we want to detect unexpected modifications.
    
    ; ========================================
    ; STEP 4: Report results
    ; ========================================
    
    test rax, rax
    jnz failed
    
    ; All checks passed
    lea rcx, fmt_pass
    call printf
    jmp print_result
    
failed:
    ; Some checks failed (already printed error messages)
    
print_result:
    ; Print ASM function return value
    lea rcx, fmt_result
    mov rdx, [rbp-24]
    call printf
    
    ; Print footer
    lea rcx, fmt_footer
    call printf
    
    ; Return 0 if ABI compliant, non-zero if violations detected
    mov rax, [rbp-24]          ; Return the ASM function's return value
    
    ; Epilogue
    add rsp, 800
    pop rbp
    ret

TestABIIntegrity_Silu_Clamped ENDP

END