; ============================================================================
; Softmax Forward - AVX2 Implementation (Simplified)
; Optimized for x86-64 Windows
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
    mov rbx, rcx                    ; rbx = data pointer
    mov r12, rdx                    ; r12 = data_size in bytes
    shr r12, 2                      ; r12 = number of floats
    
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
    ; Horizontal max reduction
    vextractf128 xmm0, ymm7, 1      ; xmm0 = upper 4 floats
    vmaxps xmm1, xmm7, xmm0         ; xmm1 = [max(a,e), max(b,f), max(c,g), max(d,h)]
    
    ; Reduce xmm1
    vmovshdup xmm2, xmm1            
    vmaxps xmm1, xmm1, xmm2         
    vmovhlps xmm2, xmm1, xmm1     
    vmaxps xmm1, xmm1, xmm2         
    
    ; Broadcast max to all elements
    vbroadcastss ymm7, xmm1         
    
    ; ============================================================================
    ; PHASE 2: Compute exp(x - max) and sum
    ; Uses polynomial approximation for exp
    ; ============================================================================
    
    xor r13, r13                    ; r13 = index
    vxorps ymm6, ymm6, ymm6         ; ymm6 = sum accumulator
    
    ; Load polynomial coefficients
    vbroadcastss ymm8, DWORD PTR [ExpCoeff0]  ; 1.0
    vbroadcastss ymm9, DWORD PTR [ExpCoeff1]  ; 1.0
    vbroadcastss ymm10, DWORD PTR [ExpCoeff2] ; 0.5
    vbroadcastss ymm11, DWORD PTR [ExpCoeff3] ; 0.166667
    vbroadcastss ymm12, DWORD PTR [ExpCoeff4] ; 0.041667
    
ExpSum_Loop:
    cmp r13, r12
    jge ExpSum_Done
    
    ; Load 8 floats
    vmovaps ymm0, YMMWORD PTR [rbx + r13*4]
    
    ; Subtract max: x - max
    vsubps ymm0, ymm0, ymm7
    
    ; Polynomial approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmulps ymm1, ymm0, ymm0         ; ymm1 = x^2
    vmulps ymm2, ymm1, ymm0         ; ymm2 = x^3
    vmulps ymm3, ymm2, ymm0         ; ymm3 = x^4
    
    vmulps ymm1, ymm1, ymm10        ; ymm1 = x^2 * 0.5
    vmulps ymm2, ymm2, ymm11        ; ymm2 = x^3 * 0.166667
    vmulps ymm3, ymm3, ymm12        ; ymm3 = x^4 * 0.041667
    
    vaddps ymm4, ymm8, ymm0         ; ymm4 = 1 + x
    vaddps ymm4, ymm4, ymm1         ; ymm4 += x^2/2
    vaddps ymm4, ymm4, ymm2         ; ymm4 += x^3/6
    vaddps ymm4, ymm4, ymm3         ; ymm4 += x^4/24
    
    ; Accumulate sum
    vaddps ymm6, ymm6, ymm4
    
    ; Store exp values
    vmovaps YMMWORD PTR [rbx + r13*4], ymm4
    
    add r13, 8
    jmp ExpSum_Loop
    
ExpSum_Done:
    ; Horizontal sum reduction
    vextractf128 xmm0, ymm6, 1
    vaddps xmm1, xmm6, xmm0
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    
    ; Broadcast sum
    vbroadcastss ymm6, xmm1         
    
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
    ExpCoeff0 REAL4 1.0           ; 1
    ExpCoeff1 REAL4 1.0           ; 1  
    ExpCoeff2 REAL4 0.5           ; 1/2
    ExpCoeff3 REAL4 0.16666667    ; 1/6
    ExpCoeff4 REAL4 0.04166667    ; 1/24

MASM_Softmax_Forward_AVX2 ENDP

END
