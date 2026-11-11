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
    
    ; Unpack nibbles:
    ; Each byte: [high_nibble][low_nibble]
    ; We need to extract all 32 nibbles as separate bytes
    
    ; Step 1: Create low nibbles (AND with 0x0F)
    vpmovzxbw ymm2, xmm1                    ; Zero-extend bytes to words: [00|high][00|low]
    vpand ymm3, ymm2, YMMWORD PTR [NibbleMask] ; YMM3 = low nibbles in low byte of each word
    
    ; Step 2: Create high nibbles (shift right 4, then AND)
    vpsrlw ymm4, ymm2, 4                    ; Shift right by 4: high nibble moves to low position
    vpand ymm4, ymm4, YMMWORD PTR [NibbleMask] ; YMM4 = high nibbles in low byte of each word
    
    ; Step 3: Pack low and high nibbles into sequential order
    ; We have 16 low nibbles in ymm3[0..15] and 16 high nibbles in ymm4[0..15]
    ; Need to interleave: high[0], low[0], high[1], low[1], ...
    ; Actually for Q4_0: qs[0] contains high=nibble[1], low=nibble[0]
    ; So order should be: nibble[0], nibble[1], nibble[2], nibble[3]...
    ; Which is: low[0], high[0], low[1], high[1]...
    
    ; Use vpackuswb to pack words back to bytes with saturation
    ; This interleaves ymm3 and ymm4 properly
    vpackuswb ymm5, ymm3, ymm4              ; Pack: low[0], high[0], low[1], high[1]...
    vpermq ymm5, ymm5, 216                  ; Fix lane ordering (0xD8 = 216)
    
    ; Step 4: Zero-extend bytes to dwords and convert to FP32
    ; Process first 8 values (64 bytes)
    vpmovzxbd ymm7, xmm5                    ; Zero-extend first 4 bytes to dwords
    vextracti128 xmm8, ymm5, 1              ; Get high 128 bits
    vpmovzxbd ymm9, xmm8                    ; Zero-extend next 4 bytes
    
    ; Convert to FP32
    vcvtdq2ps ymm7, ymm7                    ; First 8 values
    vcvtdq2ps ymm9, ymm9                    ; Next 8 values
    
    ; Apply dequantization: (nibble - 8) * scale
    vsubps ymm7, ymm7, ymm15
    vsubps ymm9, ymm9, ymm15
    vmulps ymm7, ymm7, ymm0
    vmulps ymm9, ymm9, ymm0
    
    ; Store first 16 results
    vmovaps YMMWORD PTR [r12], ymm7
    vmovaps YMMWORD PTR [r12 + 32], ymm9
    
    ; Process remaining 16 values from packed data
    ; Need to extract bytes 8-15 and 24-31 from ymm5
    vpsrldq xmm10, xmm5, 8                  ; Shift right by 8 bytes
    vpmovzxbd ymm11, xmm10                  ; Bytes 8-11
    
    vpsrldq xmm12, xmm8, 8                  ; Shift high lane by 8 bytes
    vpmovzxbd ymm13, xmm12                  ; Bytes 24-27
    
    ; Convert and dequantize
    vcvtdq2ps ymm11, ymm11
    vcvtdq2ps ymm13, ymm13
    vsubps ymm11, ymm11, ymm15
    vsubps ymm13, ymm13, ymm15
    vmulps ymm11, ymm11, ymm0
    vmulps ymm13, ymm13, ymm0
    
    ; Store
    vmovaps YMMWORD PTR [r12 + 64], ymm11
    vmovaps YMMWORD PTR [r12 + 96], ymm13
    
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
    ALIGN 16
    
    ; Mask for extracting low nibble (0x0F)
    NibbleMask DWORD 8 DUP(0000F0Fh)
    
    ; Constant 8.0 for bias subtraction
    Bias8 REAL4 8.0

END
