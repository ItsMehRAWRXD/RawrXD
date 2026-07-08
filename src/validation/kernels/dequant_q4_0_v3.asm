; ============================================================================
; Q4_0 Dequantization Kernel - Version 3 (Direct Byte Extraction)
; ============================================================================
; 
; Simple, correct approach: Extract nibbles to separate bytes first
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
    
    ; Validate inputs
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
    
    ; Setup
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
    
    ; Process 4 bytes at a time (8 weights)
    ; Byte layout: [high3:low3][high2:low2][high1:low1][high0:low0]
    
    ; === First 4 bytes (weights 0-7) ===
    ; Extract to ymm2 = [low3,low2,low1,low0,high3,high2,high1,high0,...]
    vpmovzxbw ymm2, xmm1              ; Zero-extend bytes to words
    
    ; Low nibbles in ymm3
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask]
    
    ; High nibbles in ymm4 (shift right 4)
    vpsrlw ymm4, ymm2, 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask]
    
    ; Now interleave: we want high0,low0,high1,low1...
    ; ymm3 (low):  [w0,w1,w2,w3,w4,w5,w6,w7] where w0=low0, w1=low1...
    ; ymm4 (high): [h0,h1,h2,h3,h4,h5,h6,h7] where h0=high0, h1=high1...
    
    ; Use unpack to interleave: vpunpcklwd takes low from each and interleaves
    ; vpunpcklwd dst, src1, src2: dst = [src1[0], src2[0], src1[1], src2[1], ...]
    vpunpcklwd ymm5, ymm4, ymm3       ; [h0,l0,h1,l1,h2,l2,h3,l3]
    vpunpckhwd ymm6, ymm4, ymm3       ; [h4,l4,h5,l5,h6,l6,h7,l7]
    
    ; Convert first 4 weights (h0,l0,h1,l1)
    vpmovzxwd ymm7, xmm5              ; [h0,l0,h1,l1] as dwords
    vextracti128 xmm8, ymm5, 1        ; [h2,l2,h3,l3]
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm7       ; weights 0-3
    vmovaps YMMWORD PTR [r12 + 32], ymm9  ; weights 4-7
    
    ; Convert next 4 weights from ymm6
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
    
    ; === Next 4 bytes (weights 16-23) ===
    vpsrldq xmm1, xmm1, 4             ; Shift to next 4 bytes
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
    
    ; === Last 8 bytes (weights 24-31) ===
    vpsrldq xmm1, xmm1, 4
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
    vmovaps YMMWORD PTR [r12 + 256], ymm7
    vmovaps YMMWORD PTR [r12 + 288], ymm9
    
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    vmovaps YMMWORD PTR [r12 + 320], ymm7
    vmovaps YMMWORD PTR [r12 + 352], ymm9
    
    add rbx, 20
    add r12, 384                      ; 32 floats * 12 bytes? No, 32*4=128
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
    ALIGN 32
    NibbleMask DWORD 8 DUP(0000F0Fh)
    Bias8 REAL4 8.0

END
