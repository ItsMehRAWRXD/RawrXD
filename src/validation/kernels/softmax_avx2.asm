; ============================================================================
; Softmax Forward - AVX2 Implementation
; Optimized for x86-64 Windows (Microsoft x64 calling convention)
;
; PERFORMANCE TARGET: 5-8x speedup over scalar
; STRATEGY: Vectorized max-finding + exp() approximation + normalization
; ============================================================================

.CODE

; ============================================================================
; MASM_Softmax_Forward_AVX2
; Parameters:
;   RCX = float* data (32-byte aligned, in-place)
;   RDX = size_t data_size (in bytes, multiple of 32)
; Returns:
;   RAX = 0 on success, non-zero on error
; ============================================================================
MASM_Softmax_Forward_AVX2 PROC FRAME
    ; Save non-volatile registers
    push rbx
    .PUSHREG rbx
    push r12
    .PUSHREG r12
    push r13
    .PUSHREG r13
    push r14
    .PUSHREG r14
    sub rsp, 64
    .ALLOCSTACK 64
    .ENDPROLOG
    
    ; Validate inputs (defensive programming)
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    ; Check alignment
    mov rax, rcx
    and rax, 31
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx                    ; rbx = data pointer
    mov r12, rdx                    ; r12 = data_size in bytes
    shr r12, 2                      ; r12 = number of floats (divide by 4)
    
    ; Early exit for small sizes
    cmp r12, 8
    jl Error_InvalidSize
    
    ; ============================================================================
    ; PHASE 1: Find maximum value (for numerical stability)
    ; ============================================================================
    
    ; Initialize max with first 8 floats
    vmovaps ymm0, YMMWORD PTR [rbx]
    vmaxps ymm7, ymm0, ymm0         ; ymm7 = current max (8-wide)
    
    ; Process remaining elements in chunks of 8
    mov r13, 8                      ; r13 = index
    mov r14, r12
    sub r14, 8                      ; r14 = remaining count
    
FindMax_Loop:
    cmp r13, r12
    jge FindMax_Done
    
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    vmaxps ymm7, ymm7, ymm0
    
    add r13, 8
    jmp FindMax_Loop
    
FindMax_Done:
    ; Horizontal max reduction: find max of ymm7
    ; ymm7 = [a, b, c, d, e, f, g, h]
    ; We need: max(a, b, c, d, e, f, g, h)
    
    vextractf128 xmm0, ymm7, 1      ; xmm0 = upper 4 floats
    vmaxps xmm1, xmm7, xmm0         ; xmm1 = [max(a,e), max(b,f), max(c,g), max(d,h)]
    
    ; Now reduce xmm1
    vmovshdup xmm2, xmm1            ; xmm2 = [max(b,f), max(b,f), max(d,h), max(d,h)]
    vmaxps xmm1, xmm1, xmm2         ; xmm1 = [max(a,b,e,f), ..., max(c,d,g,h), ...]
    
    vmovhlps xmm2, xmm1, xmm1     ; xmm2 = [max(c,d,g,h), max(c,d,g,h), ...]
    vmaxps xmm1, xmm1, xmm2         ; xmm1 = [global_max, ...]
    
    ; Broadcast max to all elements of ymm7
    vbroadcastss ymm7, xmm1         ; ymm7 = [max, max, max, max, max, max, max, max]
    
    ; ============================================================================
    ; PHASE 2: Compute exp(x - max) and sum
    ; ============================================================================
    
    ; We'll use a fast exp approximation: exp(x) ≈ 2^(x * log2(e))
    ; For now, use scalar fallback for exp (can be optimized further)
    
    xor r13, r13                    ; r13 = index
    vxorps ymm6, ymm6, ymm6         ; ymm6 = sum accumulator (8-wide)
    
    ; First pass: compute exp and accumulate sum
ExpSum_Loop:
    cmp r13, r12
    jge ExpSum_Done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    
    ; Subtract max: x - max
    vsubps ymm0, ymm0, ymm7
    
    ; Compute exp for each element (using scalar fallback for accuracy)
    ; This is the bottleneck - real implementation would use polynomial approx
    
    ; Store temporarily
    vmovaps YMMWORD PTR [rsp], ymm0
    
    ; Process each of 8 elements with scalar exp
    mov r14d, DWORD PTR [rsp]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp], r14d
    
    mov r14d, DWORD PTR [rsp+4]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+4], r14d
    
    mov r14d, DWORD PTR [rsp+8]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+8], r14d
    
    mov r14d, DWORD PTR [rsp+12]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+12], r14d
    
    mov r14d, DWORD PTR [rsp+16]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+16], r14d
    
    mov r14d, DWORD PTR [rsp+20]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+20], r14d
    
    mov r14d, DWORD PTR [rsp+24]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+24], r14d
    
    mov r14d, DWORD PTR [rsp+28]
    movd xmm1, r14d
    call FastExp_Scalar
    movd r14d, xmm0
    mov DWORD PTR [rsp+28], r14d
    
    ; Load back and accumulate
    vmovaps ymm0, YMMWORD PTR [rsp]
    vaddps ymm6, ymm6, ymm0
    
    ; Store exp values back to array
    vmovaps YMMWORD PTR [rbx + r13*4], ymm0
    
    add r13, 8
    jmp ExpSum_Loop
    
ExpSum_Done:
    ; Horizontal sum reduction
    vextractf128 xmm0, ymm6, 1
    vaddps xmm1, xmm6, xmm0
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    
    ; Broadcast sum
    vbroadcastss ymm6, xmm1         ; ymm6 = [sum, sum, sum, sum, ...]
    
    ; ============================================================================
    ; PHASE 3: Normalize (divide by sum)
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
    
    ; Success
    xor rax, rax
    jmp Exit
    
MASM_Softmax_Forward_AVX2 ENDP

; ============================================================================
; FastExp_Scalar - Fast exponential approximation
; Input: xmm1 = x (float)
; Output: xmm0 = exp(x) (float)
; ============================================================================
FastExp_Scalar PROC
    ; exp(x) = 2^(x * log2(e))
    ; Use bit-hack: exp(x) ≈ (1 << 23) * (x * 1.442695 + 127.0 - 0.045)
    
    ; Load constants
    movss xmm2, DWORD PTR [Log2E]
    movss xmm3, DWORD PTR [ExpC1]
    movss xmm4, DWORD PTR [ExpC2]
    
    mulss xmm1, xmm2                ; x * log2(e)
    addss xmm1, xmm3              ; + 127.0 - 0.045
    
    ; Convert to int and back to get 2^integer
    cvttps2dq xmm0, xmm1
    cvtdq2ps xmm0, xmm0
    
    ; Calculate fractional part
    subss xmm1, xmm0              ; fractional part
    
    ; Polynomial approximation for 2^fraction
    ; 2^f ≈ 1 + f * (0.6931 + f * (0.2401 + f * 0.0555))
    movss xmm2, DWORD PTR [ExpP0]
    movss xmm3, DWORD PTR [ExpP1]
    movss xmm4, DWORD PTR [ExpP2]
    movss xmm5, DWORD PTR [ExpP3]
    
    mulss xmm4, xmm1              ; f * p2
    addss xmm4, xmm3              ; + p1
    mulss xmm4, xmm1              ; * f
    addss xmm4, xmm2              ; + p0
    mulss xmm4, xmm1              ; * f
    addss xmm4, xmm5              ; + 1.0 (p3)
    
    ; Combine: result = 2^integer * 2^fraction
    mulss xmm0, xmm4
    
    ret
FastExp_Scalar ENDP
    
; ============================================================================
; Error Handlers
; ============================================================================
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
    jmp Exit
    
Exit:
    ; Restore registers
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    
; ============================================================================
; Data Section
; ============================================================================
.DATA
    ALIGN 16
    Log2E REAL4 1.442695041      ; log2(e)
    ExpC1  REAL4 126.943733      ; 127.0 - 0.045
    ExpC2  REAL4 0.045           ; correction factor
    ExpP0  REAL4 0.693147       ; polynomial coefficients for 2^x
    ExpP1  REAL4 0.240153
    ExpP2  REAL4 0.055828
    ExpP3  REAL4 1.0

END
