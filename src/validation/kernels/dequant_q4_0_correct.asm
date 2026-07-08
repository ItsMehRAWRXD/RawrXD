; ============================================================================
; Q4_0 Dequantization Kernel - Corrected Version
; ============================================================================
; 
; Fixed: Process 16 bytes correctly without lane duplication
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
    
    ; === Process first 8 bytes (weights 0-15) ===
    ; Extract to xmm2: bytes 0-7 in words
    vpmovzxbw xmm2, xmm1
    
    ; Low nibbles
    vpand xmm3, xmm2, XMMWORD PTR [NibbleMask]
    
    ; High nibbles
    vpsrlw xmm4, xmm2, 4
    vpand xmm4, xmm4, XMMWORD PTR [NibbleMask]
    
    ; Interleave: vpunpcklwd gives [h0,l0,h1,l1,h2,l2,h3,l3]
    vpunpcklwd xmm5, xmm4, xmm3
    vpunpckhwd xmm6, xmm4, xmm3
    
    ; Convert first 4 weights from xmm5 low
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12], ymm7       ; weights 0-3
    
    ; Convert next 4 weights from xmm5 high
    vpsrldq xmm8, xmm5, 8
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm9, ymm9
    vsubps ymm9, ymm9, ymm15
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 32], ymm9  ; weights 4-7
    
    ; Convert next 4 weights from xmm6 low
    vpmovzxwd ymm7, xmm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 64], ymm7  ; weights 8-11
    
    ; Convert last 4 weights from xmm6 high
    vpsrldq xmm8, xmm6, 8
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm9, ymm9
    vsubps ymm9, ymm9, ymm15
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 96], ymm9  ; weights 12-15
    
    ; === Process next 8 bytes (weights 16-31) ===
    vpsrldq xmm1, xmm1, 8
    vpmovzxbw xmm2, xmm1
    
    vpand xmm3, xmm2, XMMWORD PTR [NibbleMask]
    vpsrlw xmm4, xmm2, 4
    vpand xmm4, xmm4, XMMWORD PTR [NibbleMask]
    
    vpunpcklwd xmm5, xmm4, xmm3
    vpunpckhwd xmm6, xmm4, xmm3
    
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 128], ymm7 ; weights 16-19
    
    vpsrldq xmm8, xmm5, 8
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm9, ymm9
    vsubps ymm9, ymm9, ymm15
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 160], ymm9 ; weights 20-23
    
    vpmovzxwd ymm7, xmm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 192], ymm7 ; weights 24-27
    
    vpsrldq xmm8, xmm6, 8
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm9, ymm9
    vsubps ymm9, ymm9, ymm15
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 224], ymm9 ; weights 28-31
    
    add rbx, 20
    add r12, 128
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
    NibbleMask DWORD 4 DUP(0000F0Fh)
    Bias8 REAL4 8.0

END
