; LoRA Diagnostic Kernel - Phase 20
; ApplyLoRA_Diagnostic.asm
; ============================================================================
; Version with runtime checks to isolate the crash
; ============================================================================

; Constants
CACHE_LINE_SIZE     EQU 64
BEACON_RANK         EQU 8
BEACON_HIDDEN_DIM   EQU 12
BEACON_PTR_A        EQU 16
BEACON_PTR_B        EQU 24
BEACON_SCALE        EQU 32

; Return codes
RET_SUCCESS         EQU 0
RET_NULL_PTR        EQU 1
RET_ALIGN_ERROR     EQU 2
RET_MAGIC_FAIL      EQU 3

.code

; ============================================================================
; Function: ApplyLoRA_Diagnostic
; Purpose: LoRA kernel with runtime validation
; Input:  RCX = base_output pointer
;         RDX = input pointer
;         R8  = result pointer
;         R9  = beacon state pointer
;         [RSP+40] = token_count (5th param on stack)
; Output: RAX = return code (0=success)
; ============================================================================
ApplyLoRA_Diagnostic PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
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
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; === VALIDATION 1: Check for NULL pointers ===
    test    rcx, rcx
    jz      error_null_ptr
    test    rdx, rdx
    jz      error_null_ptr
    test    r8, r8
    jz      error_null_ptr
    test    r9, r9
    jz      error_null_ptr
    
    ; === VALIDATION 2: Check beacon magic ===
    mov     rax, [r9]           ; Load magic
    mov     rbx, 4141524F4Ch    ; "LORAA" in RBX
    cmp     rax, rbx
    jne     error_magic
    
    ; === VALIDATION 3: Load beacon parameters ===
    mov     r15, r9             ; R15 = beacon
    mov     r14d, dword ptr [r15 + BEACON_RANK]
    mov     r13d, dword ptr [r15 + BEACON_HIDDEN_DIM]
    
    ; Validate dimensions
    cmp     r14d, 0
    jle     error_param
    cmp     r13d, 0
    jle     error_param
    cmp     r14d, 1024          ; Sanity check: rank < 1024
    jg      error_param
    cmp     r13d, 100000        ; Sanity check: hidden_dim < 100k
    jg      error_param
    
    ; === VALIDATION 4: Check matrix pointers ===
    mov     r12, qword ptr [r15 + BEACON_PTR_A]
    mov     r11, qword ptr [r15 + BEACON_PTR_B]
    
    test    r12, r12
    jz      error_null_ptr
    test    r11, r11
    jz      error_null_ptr
    
    ; === VALIDATION 5: Check alignment ===
    mov     rax, r12
    and     rax, 31             ; Check 32-byte alignment
    jnz     error_align
    
    mov     rax, r11
    and     rax, 31
    jnz     error_align
    
    ; === SUCCESS PATH ===
    ; Just copy input to result (minimal work)
    mov     rsi, rdx            ; Source = input
    mov     rdi, r8             ; Dest = result
    mov     ecx, r13d           ; Count = hidden_dim
    
    ; Simple copy loop
    xor     eax, eax
copy_loop:
    cmp     eax, ecx
    jge     copy_done
    movss   xmm0, dword ptr [rsi + rax*4]
    movss   dword ptr [rdi + rax*4], xmm0
    inc     eax
    jmp     copy_loop
    
copy_done:
    ; Return success
    mov     rax, RET_SUCCESS
    jmp     done
    
    ; === ERROR HANDLERS ===
error_null_ptr:
    mov     rax, RET_NULL_PTR
    jmp     done
    
error_magic:
    mov     rax, RET_MAGIC_FAIL
    jmp     done
    
error_align:
    mov     rax, RET_ALIGN_ERROR
    jmp     done
    
error_param:
    mov     rax, 4              ; Invalid parameter
    
done:
    ; Epilogue
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
ApplyLoRA_Diagnostic ENDP

END
