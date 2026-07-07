; ============================================================================
; SiLU (Swish) Activation - AVX-512 Implementation
; SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
; ============================================================================

.CODE

MASM_Silu_Activation_AVX512 PROC
    ; Parameters:
    ;   RCX = float* data (64-byte aligned)
    ;   RDX = size_t data_size (in bytes, multiple of 64)
    ; Returns: RAX = 0 on success
    
    push rbx
    push r12
    push r13
    sub rsp, 64
    
    ; Validate inputs
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    ; Check 64-byte alignment
    mov rax, rcx
    and rax, 63
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx
    mov r12, rdx
    shr r12, 2
    
    ; Need at least 16 floats for AVX-512
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants
    vbroadcastss zmm15, DWORD PTR [One]
    vbroadcastss zmm14, DWORD PTR [NegOne]
    vbroadcastss zmm13, DWORD PTR [Half]
    vbroadcastss zmm12, DWORD PTR [OneSixth]
    
    ; Main loop: process 16 floats at a time
    xor r13, r13
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    ; Load 16 floats
    vmovaps zmm0, ZMMWORD PTR [rbx + r13*4]
    
    ; Compute -x
    vmulps zmm1, zmm0, zmm14
    
    ; Compute exp(-x) using polynomial: 1 + x + x^2/2 + x^3/6
    vmulps zmm2, zmm1, zmm1
    vmulps zmm3, zmm2, zmm1
    vmulps zmm2, zmm2, zmm13
    vmulps zmm3, zmm3, zmm12
    vaddps zmm4, zmm1, zmm15
    vaddps zmm4, zmm4, zmm2
    vaddps zmm4, zmm4, zmm3
    
    ; Compute sigmoid: 1 / (1 + exp(-x))
    vaddps zmm5, zmm15, zmm4
    vdivps zmm6, zmm15, zmm5
    
    ; Compute SiLU: x * sigmoid(x)
    vmulps zmm0, zmm0, zmm6
    
    ; Store result
    vmovaps ZMMWORD PTR [rbx + r13*4], zmm0
    
    add r13, 16
    jmp Process_Loop
    
Process_Done:
    
    ; Success
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
    NegOne   REAL4 -1.0
    Half     REAL4 0.5
    OneSixth REAL4 0.16666667

END
