; ============================================================================
; Softmax Forward - AVX2 Implementation (Numerically Stable)
; Uses x - max reduction + higher-order exp approximation
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
    ; PHASE 2: Compute exp(x - max) and accumulate sum
    ; Uses 5th order Taylor series for better accuracy
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24 + x^5/120
    ; ============================================================================
    xor r13, r13
    vxorps ymm6, ymm6, ymm6         ; ymm6 = sum accumulator
    
    ; Load coefficients
    vbroadcastss ymm8, DWORD PTR [One]          ; 1.0
    vbroadcastss ymm9, DWORD PTR [Half]         ; 0.5
    vbroadcastss ymm10, DWORD PTR [OneSixth]    ; 0.16666667
    vbroadcastss ymm11, DWORD PTR [One24th]     ; 0.04166667
    vbroadcastss ymm12, DWORD PTR [One120th]      ; 0.00833333
    
ExpSum_Loop:
    cmp r13, r12
    jge ExpSum_Done
    
    ; Load and subtract max: x = x - max_val
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vsubps ymm0, ymm0, ymm7         ; ymm0 = x - max (now x <= 0)
    
    ; Compute powers
    vmulps ymm1, ymm0, ymm0         ; ymm1 = x^2
    vmulps ymm2, ymm1, ymm0         ; ymm2 = x^3
    vmulps ymm3, ymm2, ymm0         ; ymm3 = x^4
    vmulps ymm4, ymm3, ymm0         ; ymm4 = x^5
    
    ; Apply coefficients
    vmulps ymm1, ymm1, ymm9         ; ymm1 = x^2 / 2
    vmulps ymm2, ymm2, ymm10        ; ymm2 = x^3 / 6
    vmulps ymm3, ymm3, ymm11        ; ymm3 = x^4 / 24
    vmulps ymm4, ymm4, ymm12        ; ymm4 = x^5 / 120
    
    ; Sum the series: 1 + x + x^2/2 + x^3/6 + x^4/24 + x^5/120
    vaddps ymm5, ymm8, ymm0         ; ymm5 = 1 + x
    vaddps ymm5, ymm5, ymm1         ; + x^2/2
    vaddps ymm5, ymm5, ymm2         ; + x^3/6
    vaddps ymm5, ymm5, ymm3         ; + x^4/24
    vaddps ymm5, ymm5, ymm4         ; + x^5/120
    
    ; Accumulate sum
    vaddps ymm6, ymm6, ymm5
    
    ; Store exp values
    vmovaps YMMWORD PTR [rbx + r13*4], ymm5
    
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
    ; PHASE 4: Normalize (divide by sum)
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
    One         REAL4 1.0
    Half        REAL4 0.5
    OneSixth    REAL4 0.16666667
    One24th     REAL4 0.04166667
    One120th    REAL4 0.00833333

END
