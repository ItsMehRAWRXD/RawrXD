; ============================================================================
; Q4_0 Dequantization Kernel - Final Correct Version
; ============================================================================
; 
; Correctly unpacks 16 bytes (32 nibbles) to 32 floats
;
; ============================================================================

.CODE

MASM_Dequant_Q4_0_AVX2 PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_NullPointer
    test r8, r8
    jz Error_ZeroSize
    
    mov rax, rcx
    and rax, 31
    jnz Error_Misaligned
    
    mov rax, rdx
    and rax, 31
    jnz Error_Misaligned
    
    mov rbx, rcx
    mov r12, rdx
    mov r13, r8
    xor r14, r14
    
    vbroadcastss ymm15, DWORD PTR [Bias8]
    
Dequant_Loop:
    cmp r14, r13
    jge Dequant_Done
    
    ; Load scale
    vbroadcastss ymm0, DWORD PTR [rbx]
    
    ; Load 16 bytes of qs data
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]
    
    ; === Process first 8 bytes (16 weights) ===
    ; Extract to ymm2: bytes 0-7 in words
    vpmovzxbw ymm2, xmm1
    
    ; Low nibbles: AND with 0x0F
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask]
    
    ; High nibbles: shift right 4, AND
    vpsrlw ymm4, ymm2, 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask]
    
    ; Interleave: vpunpcklwd(ymm4, ymm3) gives [h0,l0,h1,l1,h2,l2,h3,l3]
    vpunpcklwd ymm5, ymm4, ymm3
    vpunpckhwd ymm6, ymm4, ymm3
    
    ; Convert first 8 weights (ymm5 low)
    vpmovzxwd ymm7, xmm5
    vextracti128 xmm8, ymm5, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm7       ; weights 0-3
    vmovaps YMMWORD PTR [r12 + 32], ymm9  ; weights 4-7
    
    ; Convert next 8 weights (ymm6)
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12 + 64], ymm7  ; weights 8-11
    vmovaps YMMWORD PTR [r12 + 96], ymm9  ; weights 12-15
    
    ; === Process next 8 bytes (16 weights) ===
    vpsrldq xmm1, xmm1, 8               ; Shift to bytes 8-15
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
    
    vmovaps YMMWORD PTR [r12 + 128], ymm7 ; weights 16-19
    vmovaps YMMWORD PTR [r12 + 160], ymm9 ; weights 20-23
    
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12 + 192], ymm7 ; weights 24-27
    vmovaps YMMWORD PTR [r12 + 224], ymm9 ; weights 28-31
    
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
