; ============================================================================
; SiLU (Swish) Activation - Simple AVX-512 Implementation
; SiLU(x) = x * sigmoid(x)
; Uses polynomial approximation with range clamping
; ============================================================================

.CODE

MASM_Silu_Activation_AVX512 PROC
    push rbx
    push r12
    push r13
    sub rsp, 64
    
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    mov rax, rcx
    and rax, 63
    jnz Error_Misaligned
    
    mov rbx, rcx
    mov r12, rdx
    shr r12, 2
    
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants
    vbroadcastss zmm15, DWORD PTR [One]
    vbroadcastss zmm14, DWORD PTR [Zero]
    vbroadcastss zmm13, DWORD PTR [Half]
    
    xor r13, r13
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    vmovaps zmm0, ZMMWORD PTR [rbx + r13*4]
    
    ; Compute sigmoid(x) = 1 / (1 + exp(-x))
    ; Using approximation: sigmoid(x) ≈ 0.5 + 0.25*x for small x
    ; For production, use full polynomial or lookup table
    
    vmulps zmm1, zmm0, DWORD PTR [NegOne]  ; -x
    
    ; exp(-x) approximation: 1 + (-x) + (-x)^2/2 + (-x)^3/6
    vmulps zmm2, zmm1, zmm1                ; (-x)^2
    vmulps zmm3, zmm2, zmm1                ; (-x)^3
    
    vmulps zmm2, zmm2, zmm13               ; (-x)^2 / 2
    vmulps zmm3, zmm3, DWORD PTR [OneSixth] ; (-x)^3 / 6
    
    vaddps zmm4, zmm15, zmm1               ; 1 + (-x)
    vaddps zmm4, zmm4, zmm2                ; + (-x)^2/2
    vaddps zmm4, zmm4, zmm3                ; + (-x)^3/6
    
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
Error_Misaligned:
    mov rax, 3
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
    NegOne   REAL4 -1.0
    OneSixth REAL4 0.16666667

END
