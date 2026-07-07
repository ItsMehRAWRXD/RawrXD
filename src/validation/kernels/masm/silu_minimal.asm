; ============================================================================
; silu_minimal.asm - Minimal working SiLU for testing
; ============================================================================
; This is a simplified version that just copies input to output
; Used to verify the C++ to MASM linkage works
; ============================================================================

OPTION CASEMAP:NONE

.code

; Simple function that just returns 0 (success)
; Used to test if the linkage works at all
MASM_Test_Linkage PROC
    xor rax, rax    ; Return 0 (success)
    ret
MASM_Test_Linkage ENDP

; Minimal SiLU that just multiplies by 0.5
; Parameters:
;   RCX = float* data (32-byte aligned)
;   RDX = size_t data_size (bytes, multiple of 32)
; Returns: RAX = 0 on success
MASM_SiLU_Minimal PROC
    ; Save non-volatile registers
    push rbx
    push rsi
    
    ; Validate inputs
    test rcx, rcx
    jz error_null
    test rdx, rdx
    jz error_zero
    
    ; Check alignment
    test rcx, 31
    jnz error_align
    test rdx, 31
    jnz error_size
    
    ; Setup
    mov rsi, rcx        ; rsi = data pointer
    mov rbx, rdx        ; rbx = data_size
    shr rbx, 2          ; rbx = number of floats (divide by 4)
    
    ; Create 0.5 in YMM register
    vbroadcastss ymm0, DWORD PTR [g_half]
    
loop_start:
    cmp rbx, 0
    jle done
    
    ; Load 8 floats
    vmovaps ymm1, YMMWORD PTR [rsi]
    
    ; Multiply by 0.5 (simple operation for testing)
    vmulps ymm1, ymm1, ymm0
    
    ; Store result
    vmovaps YMMWORD PTR [rsi], ymm1
    
    ; Advance
    add rsi, 32
    sub rbx, 8
    jmp loop_start

done:
    vzeroupper
    xor rax, rax
    jmp cleanup

error_null:
    mov rax, 1
    jmp cleanup

error_zero:
    mov rax, 2
    jmp cleanup

error_align:
    mov rax, 3
    jmp cleanup

error_size:
    mov rax, 4

cleanup:
    pop rsi
    pop rbx
    ret

MASM_SiLU_Minimal ENDP

.const
ALIGN 32
g_half REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5

END
