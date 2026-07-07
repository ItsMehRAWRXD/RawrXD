; ============================================================================
; Softmax Forward - AVX2 Implementation (Fast Sigmoid Approximation)
; Uses bit-hack exp() for numerical stability
; ============================================================================

.CODE

MASM_Softmax_Forward_AVX2 PROC
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
    
    mov rax, rcx
    and rax, 31
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx
    mov r12, rdx
    shr r12, 2
    
    cmp r12, 8
    jl Error_InvalidSize
    
    ; ============================================================================
    ; PHASE 1: Find max for numerical stability
    ; ============================================================================
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
    
    ; Horizontal max reduction
    vextractf128 xmm0, ymm7, 1
    vmaxps xmm1, xmm7, xmm0
    vmovshdup xmm2, xmm1
    vmaxps xmm1, xmm1, xmm2
    vmovhlps xmm2, xmm1, xmm1
    vmaxps xmm1, xmm1, xmm2
    vbroadcastss ymm7, xmm1         ; ymm7 = max_val
    
    ; ============================================================================
    ; PHASE 2: Compute exp(x - max) using fast approximation
    ; Uses: exp(x) ≈ 2^(x * 1.442695) with bit manipulation
    ; ============================================================================
    xor r13, r13
    vxorps ymm6, ymm6, ymm6         ; ymm6 = sum accumulator
    
    ; Load constants
    vbroadcastss ymm8, DWORD PTR [Log2E]      ; 1.442695 (log2(e))
    vbroadcastss ymm9, DWORD PTR [ExpC1]      ; 126.943733 (127 - 0.045)
    vbroadcastss ymm10, DWORD PTR [ExpC2]     ; 0.045 (correction)
    
ExpSum_Loop:
    cmp r13, r12
    jge ExpSum_Done
    
    ; Load and subtract max
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vsubps ymm0, ymm0, ymm7         ; ymm0 = x - max (now <= 0)
    
    ; Fast exp approximation using bit-hack
    ; exp(x) ≈ 2^(x * log2(e))
    ; Method: cast(float) = (1 << 23) * (x * log2(e) + 127 - 0.045)
    
    vmulps ymm1, ymm0, ymm8         ; ymm1 = x * log2(e)
    vaddps ymm1, ymm1, ymm9         ; ymm1 = x * log2(e) + 126.943733
    
    ; Convert to integers (this is the bit-hack)
    vcvtps2dq ymm2, ymm1            ; ymm2 = int32 representation
    vcvtdq2ps ymm3, ymm2            ; ymm3 = back to float (2^integer part)
    
    ; Get fractional part
    vsubps ymm4, ymm1, ymm3         ; ymm4 = fractional part
    
    ; Approximate 2^fraction using polynomial
    ; 2^f ≈ 1 + f * (0.6931 + f * (0.2401 + f * 0.0555))
    vbroadcastss ymm11, DWORD PTR [ExpP0]     ; 0.693147
    vbroadcastss ymm12, DWORD PTR [ExpP1]     ; 0.240153
    vbroadcastss ymm13, DWORD PTR [ExpP2]     ; 0.055828
    vbroadcastss ymm14, DWORD PTR [One]       ; 1.0
    
    vmulps ymm5, ymm4, ymm13        ; f * p2
    vaddps ymm5, ymm5, ymm12        ; + p1
    vmulps ymm5, ymm5, ymm4         ; * f
    vaddps ymm5, ymm5, ymm11        ; + p0
    vmulps ymm5, ymm5, ymm4         ; * f
    vaddps ymm5, ymm5, ymm14        ; + 1.0
    
    ; exp(x) = 2^integer * 2^fraction
    vmulps ymm0, ymm3, ymm5
    
    ; Accumulate sum
    vaddps ymm6, ymm6, ymm0
    
    ; Store exp values
    vmovaps YMMWORD PTR [rbx + r13*4], ymm0
    
    add r13, 8
    jmp ExpSum_Loop
ExpSum_Done:
    
    ; ============================================================================
    ; PHASE 3: Horizontal sum reduction
    ; ============================================================================
    vextractf128 xmm0, ymm6, 1
    vaddps xmm1, xmm6, xmm0
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    vbroadcastss ymm6, xmm1         ; ymm6 = sum
    
    ; ============================================================================
    ; PHASE 4: Normalize
    ; ============================================================================
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
    Log2E       REAL4 1.442695041   ; log2(e)
    ExpC1       REAL4 126.943733   ; 127.0 - 0.045
    ExpC2       REAL4 0.045        ; correction
    ExpP0       REAL4 0.693147     ; polynomial for 2^x
    ExpP1       REAL4 0.240153
    ExpP2       REAL4 0.055828
    One         REAL4 1.0

END
