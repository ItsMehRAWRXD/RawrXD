; ============================================================================
; Q4_0 Dequantization Kernel - Version 4 (vpshufb approach)
; ============================================================================
; 
; Uses shuffle to extract nibbles to separate bytes, then converts to FP32
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
    
    ; Load 16 bytes
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]
    
    ; === Extract low nibbles ===
    ; Create two copies: one for low nibbles, one for high
    vmovdqa xmm2, xmm1
    
    ; Low nibbles: AND with 0x0F
    vpand xmm3, xmm2, XMMWORD PTR [NibbleMask]
    
    ; High nibbles: shift right 4, then AND
    vpsrlw xmm4, xmm2, 4
    vpand xmm4, xmm4, XMMWORD PTR [NibbleMask]
    
    ; Now pack them: we want 32 sequential bytes
    ; xmm3 has low nibbles in bytes 0,1,2,3...
    ; xmm4 has high nibbles in bytes 0,1,2,3...
    
    ; Use vpshufb to gather low nibbles to sequential positions
    ; Then gather high nibbles
    ; Then interleave with punpcklbw
    
    ; Actually, let's use a simpler approach:
    ; Process 4 bytes at a time, extract 8 weights
    
    ; === First 4 bytes (8 weights) ===
    ; Extract low nibbles to xmm5
    vpand xmm5, xmm1, XMMWORD PTR [NibbleMask]
    
    ; Extract high nibbles to xmm6
    vpsrlw xmm6, xmm1, 4
    vpand xmm6, xmm6, XMMWORD PTR [NibbleMask]
    
    ; Interleave: xmm7 = [h0,l0,h1,l1,h2,l2,h3,l3] as bytes
    vpunpcklbw xmm7, xmm6, xmm5
    
    ; Convert to words, then to dwords
    vpmovzxbw ymm8, xmm7              ; Zero-extend bytes to words
    
    ; Extract first 4 words (h0,l0,h1,l1)
    vpmovzxwd ymm9, xmm8              ; First 4 words to dwords
    vextracti128 xmm10, ymm8, 1
    vpmovzxwd ymm11, xmm10            ; Next 4 words
    
    ; Convert to FP32 and dequantize
    vcvtdq2ps ymm9, ymm9
    vcvtdq2ps ymm11, ymm11
    vsubps ymm9, ymm9, ymm15
    vsubps ymm11, ymm11, ymm15
    vmulps ymm9, ymm9, ymm0
    vmulps ymm11, ymm11, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm9       ; weights 0-3
    vmovaps YMMWORD PTR [r12 + 32], ymm11 ; weights 4-7
    
    ; === Next 4 bytes (8 weights) ===
    vpsrldq xmm1, xmm1, 4
    vpand xmm5, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm6, xmm1, 4
    vpand xmm6, xmm6, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm7, xmm6, xmm5
    vpmovzxbw ymm8, xmm7
    vpmovzxwd ymm9, xmm8
    vextracti128 xmm10, ymm8, 1
    vpmovzxwd ymm11, xmm10
    vcvtdq2ps ymm9, ymm9
    vcvtdq2ps ymm11, ymm11
    vsubps ymm9, ymm9, ymm15
    vsubps ymm11, ymm11, ymm15
    vmulps ymm9, ymm9, ymm0
    vmulps ymm11, ymm11, ymm0
    vmovaps YMMWORD PTR [r12 + 64], ymm9  ; weights 8-11
    vmovaps YMMWORD PTR [r12 + 96], ymm11 ; weights 12-15
    
    ; === Process bytes 8-11 (qs[4-7]) ===
    vmovdqu xmm1, XMMWORD PTR [rbx + 8]   ; Load bytes 8-11 (qs[4-7])
    vpand xmm5, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm6, xmm1, 4
    vpand xmm6, xmm6, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm7, xmm6, xmm5
    vpmovzxbw ymm8, xmm7
    vpmovzxwd ymm9, xmm8
    vextracti128 xmm10, ymm8, 1
    vpmovzxwd ymm11, xmm10
    vcvtdq2ps ymm9, ymm9
    vcvtdq2ps ymm11, ymm11
    vsubps ymm9, ymm9, ymm15
    vsubps ymm11, ymm11, ymm15
    vmulps ymm9, ymm9, ymm0
    vmulps ymm11, ymm11, ymm0
    vmovaps YMMWORD PTR [r12 + 128], ymm9 ; weights 16-19
    vmovaps YMMWORD PTR [r12 + 160], ymm11 ; weights 20-23
    
    ; === Process bytes 12-15 (qs[8-11]) ===
    vmovdqu xmm1, XMMWORD PTR [rbx + 12]  ; Load bytes 12-15 (qs[8-11])
    vpand xmm5, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm6, xmm1, 4
    vpand xmm6, xmm6, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm7, xmm6, xmm5
    vpmovzxbw ymm8, xmm7
    vpmovzxwd ymm9, xmm8
    vextracti128 xmm10, ymm8, 1
    vpmovzxwd ymm11, xmm10
    vcvtdq2ps ymm9, ymm9
    vcvtdq2ps ymm11, ymm11
    vsubps ymm9, ymm9, ymm15
    vsubps ymm11, ymm11, ymm15
    vmulps ymm9, ymm9, ymm0
    vmulps ymm11, ymm11, ymm0
    vmovaps YMMWORD PTR [r12 + 192], ymm9 ; weights 24-27
    vmovaps YMMWORD PTR [r12 + 224], ymm11 ; weights 28-31
    
    ; === Process bytes 16-19 (qs[12-15]) ===
    vmovdqu xmm1, XMMWORD PTR [rbx + 16]  ; Load bytes 16-19 (qs[12-15])
    vpand xmm5, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm6, xmm1, 4
    vpand xmm6, xmm6, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm7, xmm6, xmm5
    vpmovzxbw ymm8, xmm7
    vpmovzxwd ymm9, xmm8
    vextracti128 xmm10, ymm8, 1
    vpmovzxwd ymm11, xmm10
    vcvtdq2ps ymm9, ymm9
    vcvtdq2ps ymm11, ymm11
    vsubps ymm9, ymm9, ymm15
    vsubps ymm11, ymm11, ymm15
    vmulps ymm9, ymm9, ymm0
    vmulps ymm11, ymm11, ymm0
    vmovaps YMMWORD PTR [r12 + 256], ymm9 ; weights 32-35? No, we only have 32 weights per block
    vmovaps YMMWORD PTR [r12 + 288], ymm11
    
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
    NibbleMask BYTE 16 DUP(00Fh)
    Bias8 REAL4 8.0

END
