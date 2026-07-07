; ============================================================================
; SiLU (Swish) Activation - AVX-512 Implementation
; SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
;
; PERFORMANCE TARGET: 33x speedup over scalar
; STRATEGY: Vectorized exp approximation with AVX-512
; ============================================================================

.CODE

; ============================================================================
; MASM_Silu_Activation_AVX512
; Parameters:
;   RCX = float* data (64-byte aligned, in-place)
;   RDX = size_t data_size (in bytes, multiple of 64)
; Returns:
;   RAX = 0 on success, non-zero on error
; ============================================================================
MASM_Silu_Activation_AVX512 PROC FRAME
    ; Save non-volatile registers
    push rbx
    .PUSHREG rbx
    push r12
    .PUSHREG r12
    push r13
    .PUSHREG r13
    sub rsp, 64
    .ALLOCSTACK 64
    .ENDPROLOG
    
    ; Validate inputs
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_ZeroSize
    
    ; Check 64-byte alignment for AVX-512
    mov rax, rcx
    and rax, 63
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx                    ; rbx = data pointer
    mov r12, rdx                    ; r12 = data_size in bytes
    shr r12, 2                      ; r12 = number of floats
    
    ; Need at least 16 floats for AVX-512 (16 floats = 64 bytes)
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants into zmm registers
    vbroadcastss zmm15, DWORD PTR [One]      ; zmm15 = 1.0
    vbroadcastss zmm14, DWORD PTR [NegOne]   ; zmm14 = -1.0
    vbroadcastss zmm13, DWORD PTR [Log2E]    ; zmm13 = log2(e)
    vbroadcastss zmm12, DWORD PTR [ExpC1]    ; zmm12 = 126.943733
    vbroadcastss zmm11, DWORD PTR [ExpP0]    ; zmm11 = 0.693147
    vbroadcastss zmm10, DWORD PTR [ExpP1]    ; zmm10 = 0.240153
    vbroadcastss zmm9,  DWORD PTR [ExpP2]    ; zmm9  = 0.055828
    vbroadcastss zmm8,  DWORD PTR [ExpP3]    ; zmm8  = 1.0
    
    ; Main loop: process 16 floats at a time
    xor r13, r13                    ; r13 = index
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    ; Load 16 floats
    vmovaps zmm0, ZMMWORD PTR [rbx + r13*4]
    
    ; Compute -x
    vmulps zmm1, zmm0, zmm14        ; zmm1 = -x
    
    ; Compute exp(-x) using fast approximation
    ; exp(x) ≈ 2^(x * log2(e))
    vmulps zmm2, zmm1, zmm13        ; zmm2 = -x * log2(e)
    vaddps zmm2, zmm2, zmm12        ; zmm2 = -x * log2(e) + 126.943733
    
    ; Convert to int and back (get 2^integer part)
    vcvttps2dq zmm3, zmm2
    vcvtdq2ps zmm3, zmm3
    
    ; Get fractional part
    vsubps zmm4, zmm2, zmm3         ; zmm4 = fractional part
    
    ; Polynomial: 2^f ≈ 1 + f * (0.6931 + f * (0.2401 + f * 0.0555))
    vfmadd213ps zmm9, zmm4, zmm10   ; zmm9 = 0.055828 * f + 0.240153
    vfmadd213ps zmm9, zmm4, zmm11   ; zmm9 = result * f + 0.693147
    vfmadd213ps zmm9, zmm4, zmm8    ; zmm9 = result * f + 1.0
    
    ; exp(-x) = 2^integer * 2^fraction
    vmulps zmm5, zmm3, zmm9         ; zmm5 = exp(-x)
    
    ; Compute sigmoid: 1 / (1 + exp(-x))
    vaddps zmm6, zmm15, zmm5        ; zmm6 = 1 + exp(-x)
    vdivps zmm7, zmm15, zmm6        ; zmm7 = sigmoid(x)
    
    ; Compute SiLU: x * sigmoid(x)
    vmulps zmm0, zmm0, zmm7
    
    ; Store result
    vmovaps ZMMWORD PTR [rbx + r13*4], zmm0
    
    add r13, 16
    jmp Process_Loop
    
Process_Done:
    
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
    vzeroupper                      ; Required after using AVX-512
    add rsp, 64
    pop r13
    pop r12
    pop rbx
    ret
    
; ============================================================================
; Data Section
; ============================================================================
.DATA
    ALIGN 64
    One      REAL4 1.0
    NegOne   REAL4 -1.0
    Log2E    REAL4 1.442695041
    ExpC1    REAL4 126.943733
    ExpP0    REAL4 0.693147
    ExpP1    REAL4 0.240153
    ExpP2    REAL4 0.055828
    ExpP3    REAL4 1.0

MASM_Silu_Activation_AVX512 ENDP

END
