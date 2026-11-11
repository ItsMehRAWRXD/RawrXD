; ============================================================================
; SiLU (Swish) Activation - Final Production Version
; SiLU(x) = x * sigmoid(x)
; ============================================================================

.CODE

MASM_Silu_Activation_AVX512 PROC FRAME
    .PUSHREG rbx
    .PUSHREG r12
    .PUSHREG r13
    .ALLOCSTACK 64
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    sub rsp, 64
    
    ; Validate inputs
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    mov rbx, rcx                    ; rbx = data pointer
    mov r12, rdx                    ; r12 = data_size in bytes
    shr r12, 2                      ; r12 = number of floats
    
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants
    vbroadcastss zmm15, DWORD PTR [One]
    vbroadcastss zmm14, DWORD PTR [Zero]
    vbroadcastss zmm13, DWORD PTR [Half]
    vbroadcastss zmm12, DWORD PTR [OneSixth]
    
    xor r13, r13
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    vmovaps zmm0, ZMMWORD PTR [rbx + r13*4]
    
    ; Compute -x
    vsubps zmm1, zmm14, zmm0
    
    ; exp(-x) using polynomial: 1 + (-x) + (-x)^2/2 + (-x)^3/6
    vmulps zmm2, zmm1, zmm1         ; (-x)^2
    vmulps zmm3, zmm2, zmm1         ; (-x)^3
    
    vmulps zmm2, zmm2, zmm13        ; (-x)^2 / 2
    vmulps zmm3, zmm3, zmm12        ; (-x)^3 / 6
    
    vaddps zmm4, zmm15, zmm1        ; 1 + (-x)
    vaddps zmm4, zmm4, zmm2         ; + (-x)^2/2
    vaddps zmm4, zmm4, zmm3         ; + (-x)^3/6
    
    ; sigmoid = 1 / (1 + exp(-x))
    vaddps zmm5, zmm15, zmm4
    vdivps zmm6, zmm15, zmm5
    
    ; SiLU = x * sigmoid(x)
    vmulps zmm7, zmm0, zmm6
    
    vmovaps ZMMWORD PTR [rbx + r13*4], zmm7
    
    add r13, 16
    jmp Process_Loop
    
Process_Done:
    xor rax, rax
    jmp Exit
    
Error_NullPointer:
    mov rax, 1
    jmp Exit
Error_ZeroSize:
    mov rax, 2
    jmp Exit
Error_InvalidSize:
    mov rax, 4
    
Exit:
    vzeroupper
    add rsp, 64
    pop r13
    pop r12
    pop rbx
    ret
MASM_Silu_Activation_AVX512 ENDP

.DATA
    ALIGN 16
    One      REAL4 1.0
    Zero     REAL4 0.0
    Half     REAL4 0.5
    OneSixth REAL4 0.16666667

END
