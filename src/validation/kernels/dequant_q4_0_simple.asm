; ============================================================================
; Q4_0 Dequantization Kernel - Simple Working Version
; ============================================================================

.CODE

MASM_Dequant_Q4_0_AVX2 PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    ; Validate inputs
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_NullPointer
    test r8, r8
    jz Error_ZeroSize
    
    ; Check alignment
    mov rax, rcx
    and rax, 31
    jnz Error_Misaligned
    
    mov rax, rdx
    and rax, 31
    jnz Error_Misaligned
    
    ; Setup
    mov rbx, rcx                    ; blocks
    mov r12, rdx                    ; output
    mov r13, r8                     ; num_blocks
    xor r14, r14                    ; counter
    
    vbroadcastss ymm15, DWORD PTR [Bias8]    ; ymm15 = 8.0
    
Dequant_Loop:
    cmp r14, r13
    jge Dequant_Done
    
    ; Load scale
    vbroadcastss ymm0, DWORD PTR [rbx]
    
    ; Load 16 bytes of qs
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]
    
    ; Process first 8 bytes (16 weights)
    ; Extract low nibbles
    vpmovzxbw ymm2, xmm1              ; bytes to words
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask]  ; low nibbles
    
    ; Extract high nibbles  
    vpsrlw ymm4, ymm2, 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask]  ; high nibbles
    
    ; Interleave: high[0], low[0], high[1], low[1]...
    vpunpcklwd ymm5, ymm4, ymm3       ; first 8 interleaved
    vpunpckhwd ymm6, ymm4, ymm3       ; next 8 interleaved
    
    ; Convert and store first 8
    vpmovzxwd ymm7, xmm5
    vextracti128 xmm8, ymm5, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm7
    vmovaps YMMWORD PTR [r12 + 32], ymm9
    
    ; Convert and store next 8
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12 + 64], ymm7
    vmovaps YMMWORD PTR [r12 + 96], ymm9
    
    ; Process next 8 bytes (16 weights) - shift and repeat
    vpsrldq xmm1, xmm1, 8
    vpmovzxbw ymm2, xmm1
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask]
    vpsrlw ymm4, ymm2, 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask]
    vpunpcklwd ymm5, ymm4, ymm3
    vpunpckhwd ymm6, ymm4, ymm3
    
    vpmovzxwd ymm7, xmm5
    vextracti128 xmm8, ymm5, 1
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 128], ymm7
    vmovaps YMMWORD PTR [r12 + 160], ymm9
    
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 192], ymm7
    vmovaps YMMWORD PTR [r12 + 224], ymm9
    
    add rbx, 20
    add r12, 128                      ; 32 floats * 4 bytes = 128
    inc r14
    jmp Dequant_Loop
    
Dequant_Done:
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
    
Exit:
    vzeroupper
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    
MASM_Dequant_Q4_0_AVX2 ENDP

.DATA
    ALIGN 16
    NibbleMask DWORD 8 DUP(0000F0Fh)
    Bias8 REAL4 8.0

END
