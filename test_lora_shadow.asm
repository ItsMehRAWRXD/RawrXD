; LoRA Kernel Shadow Run Test - MASM Only
; test_lora_shadow.asm
; ============================================================================
; Simple test harness for ApplyLoRA_Optimized
; ============================================================================

; Constants
RANK            EQU 8
HIDDEN_DIM      EQU 768
CACHE_LINE_SIZE EQU 64

; External function
EXTERN ApplyLoRA_Optimized:PROC

; Data section
.data
    ; Test data (simplified for testing)
    base_output     REAL4 HIDDEN_DIM DUP (0.001)
    input_vec       REAL4 HIDDEN_DIM DUP (0.01)
    result_vec      REAL4 HIDDEN_DIM DUP (0.0)
    matrix_A        REAL4 (HIDDEN_DIM * RANK) DUP (0.001)
    matrix_B        REAL4 (HIDDEN_DIM * RANK) DUP (0.001)
    
    ; LoRAContext structure (64-byte aligned)
    ALIGN 8
    lora_context LABEL QWORD
        context_magic       DQ 4141524F4Ch       ; "LORAA"
        context_rank        DD RANK
        context_hidden_dim  DD HIDDEN_DIM
        context_input_dim   DD HIDDEN_DIM
        context_reserved    DD 0
        context_ptr_A       DQ matrix_A
        context_ptr_B       DQ matrix_B
        context_alpha       REAL4 1.0
        context_scale       REAL4 1.0
        context_status      DQ 0
        ALIGN 8

    ; Output message
    msg_start       DB "LoRA Kernel Shadow Run Test", 13, 10, 0
    msg_done        DB "Test complete.", 13, 10, 0
    msg_pass        DB "Shadow Run PASSED", 13, 10, 0
    msg_fail        DB "Shadow Run FAILED", 13, 10, 0
    newline         DB 13, 10, 0

; Code section
.code

; ============================================================================
; Entry point
; ============================================================================
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    
    ; Print start message
    lea     rcx, msg_start
    call    print_string
    
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
    
    ; Check return value
    test    rax, rax
    jnz     test_failed
    
    ; Print success
    lea     rcx, msg_pass
    call    print_string
    jmp     test_done
    
test_failed:
    lea     rcx, msg_fail
    call    print_string
    
test_done:
    lea     rcx, msg_done
    call    print_string
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
main ENDP

; ============================================================================
; Simple string print (using WriteConsoleA)
; Input: RCX = string pointer
; ============================================================================
print_string PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Get string length
    mov     rsi, rcx
    xor     rcx, rcx
    
count_loop LABEL NEAR
    cmp     byte ptr [rsi + rcx], 0
    je      do_print
    inc     rcx
    jmp     count_loop
    
do_print LABEL NEAR
    ; RCX now has length
    mov     rdx, rcx          ; Length
    mov     r8, rsi           ; String
    
    ; Get stdout handle
    mov     rcx, -11          ; STD_OUTPUT_HANDLE
    call    GetStdHandle
    
    ; Write to console
    mov     rcx, rax          ; Handle
    ; r8 already has string
    ; rdx already has length
    xor     r9, r9            ; Bytes written (optional)
    push    r9
    lea     r9, [rsp]         ; Pointer to bytes written
    mov     qword ptr [rsp+8], 0  ; Reserved
    call    WriteConsoleA
    add     rsp, 8
    
    mov     rsp, rbp
    pop     rbp
    ret
print_string ENDP

; External imports
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

END
