; ============================================================================
; Q4_0 Dequantization Kernel - AVX2 Implementation
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
    ; ABI Prologue - Manual register preservation
    ; =========================================================================
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                     ; 32-byte shadow + alignment + locals
    
    ; =========================================================================
    ; Input Validation
    ; =========================================================================
    test rcx, rcx
    jz Error_NullPointer
    test rdx, rdx
    jz Error_NullPointer
    test r8, r8
    jz Error_ZeroSize
    
    ; Check alignment (32-byte for AVX2)
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
    vbroadcastss ymm15, DWORD PTR [Bias8]    ; YMM15 = 8.0 for subtraction
    
    ; =========================================================================
    ; Main Dequantization Loop
    ; Process 1 block (32 weights) per iteration
    ; =========================================================================
Dequant_Loop:
    cmp r14, r13
    jge Dequant_Done
    
    ; Load scale (broadcast to all elements of YMM)
    vbroadcastss ymm0, DWORD PTR [rbx]      ; YMM0 = scale (8x float)
    
    ; Load qs[16] bytes (32 nibbles packed)
    vmovdqu xmm1, XMMWORD PTR [rbx + 4]     ; XMM1 = 16 bytes of nibbles
    
    ; Unpack nibbles using shuffle approach
    ; Each byte contains 2 nibbles: [high_nibble][low_nibble]
    
    ; Create low nibbles: AND with 0x0F
    vpmovzxbw ymm2, xmm1                    ; Zero-extend bytes to words
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask] ; YMM3 = low nibbles as words
    
    ; Create high nibbles: Shift right 4, then AND
    vpsrlw ymm4, ymm2, 4                    ; Shift right by 4
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask] ; YMM4 = high nibbles as words
    
    ; Now we have 16 low nibbles in ymm3 and 16 high nibbles in ymm4
    ; Need to interleave them to get 32 sequential values
    
    ; Pack pairs into dwords for conversion
    ; First 8 values: interleave low and high from first 8 positions
    vpunpcklwd ymm5, ymm3, ymm4             ; Interleave low and high
    vpunpckhwd ymm6, ymm3, ymm4             ; Interleave high positions
    
    ; Convert first 8 values to FP32
    vpmovzxwd ymm7, xmm5                    ; Zero-extend to dwords
    vcvtdq2ps ymm7, ymm7                    ; Convert to FP32
    
    ; Apply dequantization: (nibble - 8) * scale
    vsubps ymm7, ymm7, ymm15                ; Subtract 8
    vmulps ymm7, ymm7, ymm0                 ; Multiply by scale
    
    ; Store first 8 results
    vmovaps YMMWORD PTR [r12], ymm7
    
    ; Process next 8 values
    vextracti128 xmm5, ymm5, 1              ; Get high 128 bits
    vpmovzxwd ymm7, xmm5
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 32], ymm7
    
    ; Process next 8 values from ymm6
    vpmovzxwd ymm7, xmm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 64], ymm7
    
    ; Process last 8 values
    vextracti128 xmm6, ymm6, 1
    vpmovzxwd ymm7, xmm6
    vcvtdq2ps ymm7, ymm7
    vsubps ymm7, ymm7, ymm15
    vmulps ymm7, ymm7, ymm0
    vmovaps YMMWORD PTR [r12 + 96], ymm7
    
    ; Advance pointers
    add rbx, 20                             ; Next block (20 bytes)
    add r12, 128                            ; 32 floats = 128 bytes
    inc r14
    jmp Dequant_Loop
    
Dequant_Done:
    xor rax, rax                            ; Return 0 (success)
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
    ; =========================================================================
    ; ABI Epilogue - Restore registers
    ; =========================================================================
    vzeroupper                              ; Required after using YMM
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    
MASM_Dequant_Q4_0_AVX2 ENDP

; ============================================================================
; Data Section - Constants
; ============================================================================

.DATA
    ALIGN 32
    
    ; Mask for extracting low nibble (0x0F)
    NibbleMask DWORD 8 DUP(0x0F0F0F0F)
    
    ; Constant 8.0 for bias subtraction
    Bias8 REAL4 8.0

END
