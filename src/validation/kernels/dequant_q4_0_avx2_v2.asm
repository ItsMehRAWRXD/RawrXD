; ============================================================================
; Q4_0 Dequantization Kernel - AVX2 Implementation (v2)
; ============================================================================
; 
; Dequantizes GGUF Q4_0 blocks to FP32 values.
; 
; Q4_0 Block Format:
;   - 4 bytes: scale (float32, shared for 32 weights)
;   - 16 bytes: qs[16] (32 nibbles packed, 4 bits each)
;   - Total: 20 bytes for 32 weights = 5 bits/weight
;
; Dequantization Formula:
;   weight[i] = ((qs[i/2] >> (4*(i&1))) & 0xF - 8) * scale
;
; For sequential indices:
;   weight[0] = (qs[0] >> 4) & 0xF  (high nibble of byte 0)
;   weight[1] = qs[0] & 0xF        (low nibble of byte 0)
;   weight[2] = (qs[1] >> 4) & 0xF  (high nibble of byte 1)
;   weight[3] = qs[1] & 0xF        (low nibble of byte 1)
;   ...
;
; Parameters:
;   RCX = const block_q4_0* blocks (32-byte aligned)
;   RDX = float* output (32-byte aligned)
;   R8  = size_t num_blocks
; Returns:
;   RAX = 0 on success, error code on failure
;
; ============================================================================

.CODE

MASM_Dequant_Q4_0_AVX2 PROC
    ; =========================================================================
    ; ABI Prologue
    ; =========================================================================
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    ; =========================================================================
    ; Input Validation
    ; =========================================================================
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
    
    ; =========================================================================
    ; Setup
    ; =========================================================================
    mov rbx, rcx                    ; RBX = blocks pointer
    mov r12, rdx                    ; R12 = output pointer
    mov r13, r8                     ; R13 = num_blocks
    xor r14, r14                    ; R14 = block counter
    
    ; Load constants
    vbroadcastss ymm15, DWORD PTR [Bias8]    ; YMM15 = 8.0
    
    ; =========================================================================
    ; Main Loop - Process 1 block (32 weights) per iteration
    ; =========================================================================
Dequant_Loop:
    cmp r14, r13
    jge Dequant_Done
    
    ; Load scale
    vbroadcastss ymm0, DWORD PTR [rbx]      ; YMM0 = scale
    
    ; Load qs[16] bytes
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]     ; XMM1 = 16 bytes
    
    ; Process all 16 bytes to extract 32 nibbles
    ; Strategy: Process 4 bytes at a time (8 weights)
    
    ; === First 4 bytes (weights 0-7) ===
    ; Extract bytes and split into high/low nibbles
    vpmovzxbw ymm2, xmm1                    ; Zero-extend to words
    
    ; Get low nibbles: AND with 0x0F
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask]
    
    ; Get high nibbles: shift right 4, then AND
    vpsrlw ymm4, ymm2, 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask]
    
    ; Now interleave: for each byte position i:
    ; output[2*i] = high[i], output[2*i+1] = low[i]
    ; Use unpack instructions
    vpunpcklwd ymm5, ymm4, ymm3             ; Interleave low 8 words
    vpunpckhwd ymm6, ymm4, ymm3             ; Interleave high 8 words
    
    ; ymm5 now has: high[0], low[0], high[1], low[1], ... high[3], low[3]
    ; ymm6 now has: high[4], low[4], high[5], low[5], ... high[7], low[7]
    
    ; Convert first 8 weights (ymm5)
    vpmovzxwd ymm7, xmm5                    ; First 4 to dwords
    vextracti128 xmm8, ymm5, 1
    vpmovzxwd ymm9, xmm8                    ; Next 4 to dwords
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12], ymm7         ; Weights 0-3
    vmovaps YMMWORD PTR [r12 + 32], ymm9    ; Weights 4-7
    
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
    
    vmovaps YMMWORD PTR [r12 + 64], ymm7    ; Weights 8-11
    vmovaps YMMWORD PTR [r12 + 96], ymm9    ; Weights 12-15
    
    ; === Next 4 bytes (weights 16-23) ===
    ; Shift xmm1 right by 4 bytes and repeat
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
    
    vmovaps YMMWORD PTR [r12 + 128], ymm7   ; Weights 16-19
    vmovaps YMMWORD PTR [r12 + 160], ymm9   ; Weights 20-23
    
    vpmovzxwd ymm7, xmm6
    vextracti128 xmm8, ymm6, 1
    vpmovzxwd ymm9, xmm8
    
    vcvtdq2ps ymm7, ymm7
    vcvtdq2ps ymm9, ymm9
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    vmovaps YMMWORD PTR [r12 + 192], ymm7   ; Weights 24-27
    vmovaps YMMWORD PTR [r12 + 224], ymm9   ; Weights 28-31
    
    ; Advance
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

; ============================================================================
; Data Section
; ============================================================================

.DATA
    ALIGN 16
    
    NibbleMask DWORD 8 DUP(0000F0Fh)
    Bias8 REAL4 8.0

END
