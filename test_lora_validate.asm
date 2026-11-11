; LoRA Kernel Shadow Run Test - With Validation
; test_lora_validate.asm
; ============================================================================
; Test harness that validates LoRA kernel output
; ============================================================================

; Constants
RANK            EQU 8
HIDDEN_DIM      EQU 768

; External function
EXTERN ApplyLoRA_Optimized:PROC

; Data section
.data
    ; Test data
    base_output     REAL4 HIDDEN_DIM DUP (0.001)
    input_vec       REAL4 HIDDEN_DIM DUP (0.01)
    result_vec      REAL4 HIDDEN_DIM DUP (0.0)
    matrix_A        REAL4 (HIDDEN_DIM * RANK) DUP (0.001)
    matrix_B        REAL4 (HIDDEN_DIM * RANK) DUP (0.001)
    
    ; LoRAContext structure
    ALIGN 8
    lora_context LABEL QWORD
        context_magic       DQ 4141524F4Ch
        context_rank        DD RANK
        context_hidden_dim  DD HIDDEN_DIM
        context_input_dim   DD HIDDEN_DIM
        context_reserved    DD 0
        context_ptr_A       DQ matrix_A
        context_ptr_B       DQ matrix_B
        context_alpha       REAL4 1.0
        context_scale       REAL4 1.0
        context_status      DQ 0

    ; Validation counters
    pass_count      DQ 0
    fail_count      DQ 0
    
    ; Threshold for floating point comparison
    epsilon         REAL4 0.0001

; Code section
.code

; ============================================================================
; Check if result contains valid values (not NaN or Inf)
; Returns: RAX = 1 if valid, 0 if invalid
; ============================================================================
check_valid PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    
    mov     r12, 0              ; Valid count
    mov     rbx, 0              ; Index
    
check_loop:
    cmp     rbx, HIDDEN_DIM
    jge     check_done
    
    ; Load result value
    lea     rax, result_vec
    movss   xmm0, dword ptr [rax + rbx*4]
    
    ; Check for NaN (value != value)
    movss   xmm1, xmm0
    cmpss   xmm1, xmm0, 0       ; Compare equal
    movd    eax, xmm1
    test    eax, eax
    jz      invalid_value       ; If not equal, it's NaN
    
    ; Check for Inf (exponent all 1s, mantissa 0)
    movd    eax, xmm0
    and     eax, 07F800000h     ; Isolate exponent
    cmp     eax, 07F800000h
    je      invalid_value       ; If exponent all 1s, it's Inf
    
    inc     r12
    
invalid_value:
    inc     rbx
    jmp     check_loop
    
check_done:
    ; Return 1 if all values valid
    mov     rax, 1
    cmp     r12, HIDDEN_DIM
    je      check_return
    xor     rax, rax
    
check_return:
    pop     r12
    pop     rbx
    mov     rsp, rbp
    pop     rbp
    ret
check_valid ENDP

; ============================================================================
; Entry point
; ============================================================================
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Setup parameters for ApplyLoRA_Optimized
    lea     rcx, base_output
    lea     rdx, input_vec
    lea     r8, result_vec
    lea     r9, lora_context
    mov     r10d, 1
    
    ; Call the kernel
    call    ApplyLoRA_Optimized
    
    ; Check return value
    test    rax, rax
    jnz     kernel_failed
    
    ; Validate output
    call    check_valid
    test    rax, rax
    jz      validation_failed
    
    ; Success - return 0
    xor     rax, rax
    jmp     main_exit
    
kernel_failed:
    mov     rax, 1
    jmp     main_exit
    
validation_failed:
    mov     rax, 2
    
main_exit:
    mov     rsp, rbp
    pop     rbp
    ret
    
main ENDP

END
