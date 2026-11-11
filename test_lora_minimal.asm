; LoRA Kernel Shadow Run Test - Minimal
; test_lora_minimal.asm
; ============================================================================
; Minimal test harness for ApplyLoRA_Optimized
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

; Code section
.code

; ============================================================================
; Entry point
; ============================================================================
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Setup parameters for ApplyLoRA_Optimized
    ; RCX = base_output
    ; RDX = input
    ; R8  = result
    ; R9  = context
    ; R10 = token_count
    
    lea     rcx, base_output
    lea     rdx, input_vec
    lea     r8, result_vec
    lea     r9, lora_context
    mov     r10d, 1
    
    ; Call the kernel
    call    ApplyLoRA_Optimized
    
    ; Return the kernel's return value
    mov     rsp, rbp
    pop     rbp
    ret
    
main ENDP

END
