; ============================================================================
; Softmax Forward - AVX2 Implementation
; ============================================================================

.CODE

MASM_Softmax_Forward_AVX2 PROC
    ; Parameters:
    ;   RCX = float* data (32-byte aligned)
    ;   RDX = size_t data_size (in bytes, multiple of 32)
    ; Returns: RAX = 0 on success
    
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64
    
    ; Validate inputs
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    ; Check alignment
    mov rax, rcx
    and rax, 31
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx
    mov r12, rdx
    shr r12, 2
    
    cmp r12, 8
    jl Error_InvalidSize
    
    ; Phase 1: Find max
    vmovaps ymm0, YMMWORD PTR [rbx]
    vmaxps ymm7, ymm0, ymm0
    
    mov r13, 8
FindMax_Loop:
    cmp r13, r12
    jge FindMax_Done
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vmaxps ymm7, ymm7, ymm0
    add r13, 8
    jmp FindMax_Loop
FindMax_Done:
    
    ; Horizontal max
    vextractf128 xmm0, ymm7, 1
    vmaxps xmm1, xmm7, xmm0
    vmovshdup xmm2, xmm1
    vmaxps xmm1, xmm1, xmm2
    vmovhlps xmm2, xmm1, xmm1
    vmaxps xmm1, xmm1, xmm2
    vbroadcastss ymm7, xmm1
    
    ; Phase 2: Exp and sum
    xor r13, r13
    vxorps ymm6, ymm6, ymm6
    
ExpSum_Loop:
    cmp r13, r12
    jge ExpSum_Done
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vsubps ymm0, ymm0, ymm7
    
    ; exp(x) = 1 + x + x^2/2 + x^3/6
    vmulps ymm1, ymm0, ymm0
    vmulps ymm2, ymm1, ymm0
    vmulps ymm1, ymm1, DWORD PTR [Half]
    vmulps ymm2, ymm2, DWORD PTR [OneSixth]
    vaddps ymm3, ymm0, DWORD PTR [One]
    vaddps ymm3, ymm3, ymm1
    vaddps ymm3, ymm3, ymm2
    
    vaddps ymm6, ymm6, ymm3
    vmovaps YMMWORD PTR [rbx + r13*4], ymm3
    add r13, 8
    jmp ExpSum_Loop
ExpSum_Done:
    
    ; Horizontal sum
    vextractf128 xmm0, ymm6, 1
    vaddps xmm1, xmm6, xmm0
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    vbroadcastss ymm6, xmm1
    
    ; Phase 3: Normalize
    xor r13, r13
Normalize_Loop:
    cmp r13, r12
    jge Normalize_Done
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vdivps ymm0, ymm0, ymm6
    vmovaps YMMWORD PTR [rbx + r13*4], ymm0
    add r13, 8
    jmp Normalize_Loop
Normalize_Done:
    
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
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
MASM_Softmax_Forward_AVX2 ENDP

.DATA
    ALIGN 16
    One      REAL4 1.0
    Half     REAL4 0.5
    OneSixth REAL4 0.16666667

END
