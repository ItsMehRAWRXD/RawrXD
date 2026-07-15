; ============================================================================
; Q4_0 Dequantization Kernel - Clean Implementation
; ============================================================================
; 
; Processes exactly 16 bytes (32 nibbles) -> 32 floats per block
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
    
    ; Process in 4 chunks of 4 bytes each (8 weights per chunk)
    
    ; === Chunk 1: bytes 0-3 (weights 0-7) ===
    vpand xmm2, xmm1, XMMWORD PTR [NibbleMask]   ; Low nibbles
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [NibbleMask]   ; High nibbles
    vpunpcklbw xmm4, xmm3, xmm2                  ; Interleave: h0,l0,h1,l1...
    vpmovzxbw ymm5, xmm4                         ; Bytes to words
    vpmovzxwd ymm6, xmm5                         ; Words to dwords (first 4)
    vpsrldq xmm5, xmm5, 8
    vpmovzxwd ymm7, xmm5                         ; Next 4 dwords
    vcvtdq2ps ymm6, ymm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm6, ymm6, ymm15
    vsubps ymm7, ymm7, ymm15
    vmulps ymm6, ymm6, ymm0
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12], ymm6              ; weights 0-3
    vmovaps YMMWORD PTR [r12 + 32], ymm7          ; weights 4-7
    
    ; === Chunk 2: bytes 4-7 (weights 8-15) ===
    vpsrldq xmm1, xmm1, 4                        ; Shift to bytes 4-7
    vpand xmm2, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm4, xmm3, xmm2
    vpmovzxbw ymm5, xmm4
    vpmovzxwd ymm6, xmm5
    vpsrldq xmm5, xmm5, 8
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm6, ymm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm6, ymm6, ymm15
    vsubps ymm7, ymm7, ymm15
    vmulps ymm6, ymm6, ymm0
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 64], ymm6         ; weights 8-11
    vmovaps YMMWORD PTR [r12 + 96], ymm7         ; weights 12-15
    
    ; === Chunk 3: bytes 12-15 (weights 16-23) ===
    ; Reload xmm1 from memory at offset 12
    vmovdqu xmm1, XMMWORD PTR [rbx + 12]         ; Load bytes 12-15 (qs[8-11])
    vpand xmm2, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm4, xmm3, xmm2
    vpmovzxbw ymm5, xmm4
    vpmovzxwd ymm6, xmm5
    vpsrldq xmm5, xmm5, 8
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm6, ymm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm6, ymm6, ymm15
    vsubps ymm7, ymm7, ymm15
    vmulps ymm6, ymm6, ymm0
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 128], ymm6        ; weights 16-19
    vmovaps YMMWORD PTR [r12 + 160], ymm7        ; weights 20-23
    
    ; === Chunk 4: bytes 16-19 (weights 24-31) ===
    vmovdqu xmm1, XMMWORD PTR [rbx + 16]         ; Load bytes 16-19 (qs[12-15])
    vpand xmm2, xmm1, XMMWORD PTR [NibbleMask]
    vpsrlw xmm3, xmm1, 4
    vpand xmm3, xmm3, XMMWORD PTR [NibbleMask]
    vpunpcklbw xmm4, xmm3, xmm2
    vpmovzxbw ymm5, xmm4
    vpmovzxwd ymm6, xmm5
    vpsrldq xmm5, xmm5, 8
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm6, ymm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm6, ymm6, ymm15
    vsubps ymm7, ymm7, ymm15
    vmulps ymm6, ymm6, ymm0
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 192], ymm6        ; weights 24-27
    vmovaps YMMWORD PTR [r12 + 224], ymm7        ; weights 28-31
    
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
