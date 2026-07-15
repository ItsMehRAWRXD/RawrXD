; ============================================================================
; Q4_0 Dequantization Kernel - Fixed Version with vpshufb
; ============================================================================
; 
; Uses shuffle-based nibble extraction for correct unpacking
;
; ============================================================================

.CODE

MASM_Dequant_Q4_0_AVX2 PROC
    ; ABI Prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    ; Input Validation
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
    
    ; Load constants
    vbroadcastss ymm15, DWORD PTR [Bias8]    ; ymm15 = 8.0
    
    ; Load shuffle masks
    vmovdqa ymm13, YMMWORD PTR [LowNibbleMask]   ; 0x0F mask
    vmovdqa ymm14, YMMWORD PTR [UnpackLow]       ; Shuffle for low nibbles
    vmovdqa ymm11, YMMWORD PTR [UnpackHigh]      ; Shuffle for high nibbles
    
Dequant_Loop:
    cmp r14, r13
    jge Dequant_Done
    
    ; Load scale
    vbroadcastss ymm0, DWORD PTR [rbx]
    
    ; Load 16 bytes (32 nibbles)
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]
    
    ; Duplicate to both lanes of YMM
    vinserti128 ymm1, ymm1, xmm1, 1
    
    ; === Extract Low Nibbles ===
    ; Use vpshufb with index pattern to extract low nibbles
    ; Each byte: [high][low]
    ; We want: low[0], low[1], low[2], ... in sequential bytes
    vpand ymm2, ymm1, ymm13             ; Mask to low nibbles (0x0F)
    vpshufb ymm3, ymm2, ymm14           ; Shuffle to sequential positions
    
    ; === Extract High Nibbles ===
    ; Shift right 4, then mask
    vpsrlw ymm4, ymm1, 4
    vpand ymm4, ymm4, ymm13             ; Mask to low position
    vpshufb ymm5, ymm4, ymm11           ; Shuffle to sequential positions
    
    ; === Interleave Low and High ===
    ; Now ymm3 has low nibbles in bytes 0,2,4,6...
    ; and ymm5 has high nibbles in bytes 0,2,4,6...
    ; Use vpunpcklbw to interleave them
    vpunpcklbw ymm6, ymm5, ymm3         ; Interleave bytes: high[0],low[0],high[1],low[1]...
    vpunpckhbw ymm7, ymm5, ymm3         ; High 16 bytes
    
    ; === Convert to FP32 and Dequantize ===
    ; Process first 8 values from ymm6
    vpmovzxbd ymm8, xmm6                ; Zero-extend first 4 bytes
    vextracti128 xmm9, ymm6, 1
    vpmovzxbd ymm10, xmm9               ; Next 4 bytes
    
    vcvtdq2ps ymm8, ymm8
    vcvtdq2ps ymm10, ymm10
    vsubps ymm8, ymm8, ymm15            ; Subtract 8
    vsubps ymm10, ymm10, ymm15
    vmulps ymm8, ymm8, ymm0             ; Scale
    vmulps ymm10, ymm10, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm8
    vmovaps YMMWORD PTR [r12 + 32], ymm10
    
    ; Process next 8 values from ymm6 (bytes 8-15)
    vpsrldq xmm6, xmm6, 8               ; Shift right 8 bytes
    vpmovzxbd ymm8, xmm6
    vextracti128 xmm9, ymm6, 1
    vpsrldq xmm9, xmm9, 8
    vpmovzxbd ymm10, xmm9
    
    vcvtdq2ps ymm8, ymm8
    vcvtdq2ps ymm10, ymm10
    vsubps ymm8, ymm8, ymm15
    vsubps ymm10, ymm10, ymm15
    vmulps ymm8, ymm8, ymm0
    vmulps ymm10, ymm10, ymm0
    
    vmovaps YMMWORD PTR [r12 + 64], ymm8
    vmovaps YMMWORD PTR [r12 + 96], ymm10
    
    ; Process ymm7 (remaining 16 values)
    vpmovzxbd ymm8, xmm7
    vextracti128 xmm9, ymm7, 1
    vpmovzxbd ymm10, xmm9
    
    vcvtdq2ps ymm8, ymm8
    vcvtdq2ps ymm10, ymm10
    vsubps ymm8, ymm8, ymm15
    vsubps ymm10, ymm10, ymm15
    vmulps ymm8, ymm8, ymm0
    vmulps ymm10, ymm10, ymm0
    
    vmovaps YMMWORD PTR [r12 + 128], ymm8
    vmovaps YMMWORD PTR [r12 + 160], ymm10
    
    vpsrldq xmm7, xmm7, 8
    vpmovzxbd ymm8, xmm7
    vextracti128 xmm9, ymm7, 1
    vpsrldq xmm9, xmm9, 8
    vpmovzxbd ymm10, xmm9
    
    vcvtdq2ps ymm8, ymm8
    vcvtdq2ps ymm10, ymm10
    vsubps ymm8, ymm8, ymm15
    vsubps ymm10, ymm10, ymm15
    vmulps ymm8, ymm8, ymm0
    vmulps ymm10, ymm10, ymm0
    
    vmovaps YMMWORD PTR [r12 + 192], ymm8
    vmovaps YMMWORD PTR [r12 + 224], ymm10
    
    add rbx, 20
    add r12, 128                      ; 32 floats * 4 bytes
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

; ============================================================================
; Data Section
; ============================================================================

.DATA
    ALIGN 32
    
    ; Mask for low nibble extraction
    LowNibbleMask BYTE 32 DUP(00Fh)
    
    ; Shuffle mask for unpacking low nibbles
    ; Extracts bytes 0, 2, 4, 6, 8, 10, 12, 14 (low positions after masking)
    UnpackLow BYTE 0, 2, 4, 6, 8, 10, 12, 14, 128, 128, 128, 128, 128, 128, 128, 128
              BYTE 0, 2, 4, 6, 8, 10, 12, 14, 128, 128, 128, 128, 128, 128, 128, 128
    
    ; Shuffle mask for unpacking high nibbles
    UnpackHigh BYTE 1, 3, 5, 7, 9, 11, 13, 15, 128, 128, 128, 128, 128, 128, 128, 128
               BYTE 1, 3, 5, 7, 9, 11, 13, 15, 128, 128, 128, 128, 128, 128, 128, 128
    
    ; Constant 8.0 for bias subtraction
    Bias8 REAL4 8.0

END
