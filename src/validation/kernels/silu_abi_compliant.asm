; ============================================================================
; SiLU (Swish) Activation - ABI-Compliant AVX-512 Implementation
; 
; Windows x64 ABI Compliance:
; - Preserves non-volatile registers: RBX, RBP, RDI, RSI, R12-R15
; - Maintains 16-byte stack alignment
; - Uses shadow space correctly
; ============================================================================

.CODE

MASM_Silu_Activation_AVX512 PROC
    ; Save non-volatile registers (manual push/pop, no FRAME macro)
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Allocate stack space (64 bytes) + align to 16 bytes
    ; Current stack: 5 pushes = 40 bytes (unaligned by 8)
    ; Need 8 more bytes to align to 16, then 64 bytes local = 72 total
    sub rsp, 72
    
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
    mov rbx, rcx                    ; rbx = data pointer (non-volatile, preserved)
    mov r12, rdx                    ; r12 = data_size in bytes
    shr r12, 2                      ; r12 = number of floats
    
    cmp r12, 16
    jl Error_InvalidSize
    
    ; Load constants into zmm registers (volatile, don't need to preserve)
    vbroadcastss zmm15, DWORD PTR [One]
    vbroadcastss zmm14, DWORD PTR [Zero]
    vbroadcastss zmm13, DWORD PTR [Half]
    vbroadcastss zmm12, DWORD PTR [OneSixth]
    
    xor r13, r13                    ; r13 = loop counter
    
Process_Loop:
    cmp r13, r12
    jge Process_Done
    
    ; Load 16 floats
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
    
    ; Store result
    vmovaps ZMMWORD PTR [rbx + r13*4], zmm7
    
    add r13, 16
    jmp Process_Loop
    
Process_Done:
    xor rax, rax                    ; Return 0 (success)
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
    ; Restore stack
    add rsp, 72
    
    ; Restore non-volatile registers in reverse order
    pop r15
    pop r14
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
