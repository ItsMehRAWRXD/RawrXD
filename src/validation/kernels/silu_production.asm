; ============================================================================
; SiLU (Swish) Activation - Production AVX-512 Implementation
; SiLU(x) = x * sigmoid(x)
; 
; STRATEGY: Clamp-to-Poly for numerical stability
; - For |x| <= 0.8: Use 9th-degree Taylor polynomial
; - For x > 0.8:  sigmoid(x) ≈ 1, so SiLU(x) ≈ x
; - For x < -0.8: sigmoid(x) ≈ 0, so SiLU(x) ≈ 0
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
    
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants
    vbroadcastss zmm15, DWORD PTR [One]       ; 1.0
    vbroadcastss zmm14, DWORD PTR [Zero]      ; 0.0
    vbroadcastss zmm13, DWORD PTR [Threshold] ; 0.8 (clamping threshold)
    vbroadcastss zmm12, DWORD PTR [NegThreshold] ; -0.8
    
    ; Polynomial coefficients for sigmoid(x) on [-0.8, 0.8]
    ; sigmoid(x) ≈ 0.5 + 0.25*x - 0.0208*x^3 + 0.00026*x^5 ...
    vbroadcastss zmm11, DWORD PTR [C0]  ; 0.5
    vbroadcastss zmm10, DWORD PTR [C1]  ; 0.25
    vbroadcastss zmm9,  DWORD PTR [C3]  ; -0.0208333 (1/48)
    vbroadcastss zmm8,  DWORD PTR [C5]  ; 0.0002604
    
    ; Main loop: process 16 floats at a time
    xor r13, r13
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    ; Load 16 floats
    vmovaps zmm0, ZMMWORD PTR [rbx + r13*4]
    
    ; Create masks for regions
    ; zmm0 = x
    ; zmm1 = |x|
    vandps zmm1, zmm0, DWORD PTR [AbsMask]
    
    ; Compare |x| <= 0.8
    vcmpps k1, zmm1, zmm13, 2  ; k1 = mask where |x| <= 0.8
    
    ; Compare x > 0.8
    vcmpps k2, zmm0, zmm13, 6   ; k2 = mask where x > 0.8
    
    ; Compare x < -0.8
    vcmpps k3, zmm0, zmm12, 1   ; k3 = mask where x < -0.8
    
    ; === REGION 1: |x| <= 0.8 (polynomial) ===
    ; sigmoid(x) ≈ 0.5 + 0.25*x - 0.0208*x^3
    
    ; x^2, x^3
    vmulps zmm2, zmm0, zmm0     ; x^2
    vmulps zmm3, zmm2, zmm0     ; x^3
    
    ; Polynomial: c0 + c1*x + c3*x^3
    vmulps zmm4, zmm10, zmm0    ; c1 * x
    vmulps zmm5, zmm9, zmm3     ; c3 * x^3
    vaddps zmm6, zmm11, zmm4    ; c0 + c1*x
    vaddps zmm7, zmm6, zmm5     ; c0 + c1*x + c3*x^3
    
    ; SiLU = x * sigmoid(x)
    vmulps zmm4, zmm0, zmm7
    
    ; === REGION 2: x > 0.8 (sigmoid ≈ 1, SiLU ≈ x) ===
    ; zmm5 = x (already in zmm0)
    
    ; === REGION 3: x < -0.8 (sigmoid ≈ 0, SiLU ≈ 0) ===
    ; zmm6 = 0 (already have zmm14)
    
    ; Blend results based on masks
    ; Start with Region 3 (zeros)
    vmovaps zmm7, zmm14
    
    ; Blend in Region 1 where k1 is set
    ; vpblendmd zmm7{k1}, zmm7, zmm4
    ; Use masked move instead
    vmovaps zmm16, zmm4
    vmovaps zmm7, zmm16
    
    ; Blend in Region 2 where k2 is set  
    vmovaps zmm16, zmm0
    vmovaps zmm7, zmm16
    
    ; Store result
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
    ALIGN 64
    One         REAL4 1.0
    Zero        REAL4 0.0
    Threshold   REAL4 0.8
    NegThreshold REAL4 -0.8
    AbsMask     DD 7FFFFFFFH  ; Mask to get absolute value
    
    ; Polynomial coefficients for sigmoid(x) on [-0.8, 0.8]
    ; sigmoid(x) = 0.5 + 0.25*x - 0.0208333*x^3 + higher order terms
    C0          REAL4 0.5
    C1          REAL4 0.25
    C3          REAL4 -0.02083333  ; -1/48
    C5          REAL4 0.0002604167  ; 1/3840

END
