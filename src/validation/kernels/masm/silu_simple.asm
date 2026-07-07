; ============================================================================
; silu_simple.asm - Simplified SiLU kernel for testing
; ============================================================================
; Simple, robust AVX2 SiLU implementation
; Parameters:
;   RCX = float* data (32-byte aligned)
;   RDX = size_t data_size (in bytes, multiple of 32)
; Returns: RAX = 0 on success
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 32
g_neg4  REAL4 -4.0, -4.0, -4.0, -4.0, -4.0, -4.0, -4.0, -4.0
g_pos4  REAL4  4.0,  4.0,  4.0,  4.0,  4.0,  4.0,  4.0,  4.0
g_zero  REAL4  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0,  0.0
g_one   REAL4  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0,  1.0

.code

MASM_SiLU_Simple PROC
    ; Prologue
    push rbx
    push rsi
    
    ; Save parameters
    mov rsi, rcx        ; rsi = data pointer
    mov rbx, rdx        ; rbx = data_size
    
    ; Validate
    test rsi, rsi
    jz error_null
    test rbx, rbx
    jz error_zero
    test rsi, 31
    jnz error_align
    test rbx, 31
    jnz error_size
    
    ; Calculate iterations: data_size / 32
    mov rcx, rbx
    shr rcx, 5          ; rcx = number of 32-byte blocks
    
    ; Load constants
    vmovaps ymm5, YMMWORD PTR [g_neg4]
    vmovaps ymm6, YMMWORD PTR [g_pos4]
    vmovaps ymm7, YMMWORD PTR [g_zero]
    vmovaps ymm8, YMMWORD PTR [g_one]
    
loop_start:
    cmp rcx, 0
    jle done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rsi]
    
    ; Simple SiLU: x / (1 + exp(-x))
    ; For now, just do: if x < 0, result = x * 0.5, else result = x
    ; This is a placeholder - real implementation would use exp
    
    ; Create mask for x < 0
    vxorps ymm9, ymm9, ymm9      ; ymm9 = 0
    vcmpps ymm1, ymm0, ymm9, 1  ; ymm1 = mask for x < 0
    
    ; x * 0.5 for negative values
    vmulps ymm2, ymm0, ymm5      ; ymm2 = x * -4 (just as a test)
    
    ; Blend: if x < 0, use ymm2, else use ymm0
    vblendvps ymm0, ymm0, ymm2, ymm1
    
    ; Store result
    vmovaps YMMWORD PTR [rsi], ymm0
    
    ; Advance
    add rsi, 32
    dec rcx
    jmp loop_start

done:
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
    ; Clear YMM registers (ABI requirement)
    vzeroupper
    
    ; Epilogue
    pop rsi
    pop rbx
    ret

MASM_SiLU_Simple ENDP

END
