; ============================================================================
; Aperture Q4_0 Dequantization Kernel - AVX-512 Optimized
; ============================================================================
; High-performance Q4_0 dequantization using AVX-512
; 
; Performance Target: 50-100 GB/s throughput
; Latency Target: <1 cycle per weight
;
; Q4_0 Format:
;   - Block size: 32 weights
;   - Block bytes: 18 (2 scale + 16 packed weights)
;   - Weight packing: 4 bits per weight, 2 weights per byte
;   - Dequant: weight = (q - 8) * scale
;
; Architecture: x86-64 (AMD64), AVX-512F/BW/DQ
; Calling Convention: Windows x64
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------------------

; Q4_0 format constants
Q4_0_BLOCK_SIZE     EQU     32      ; Weights per block
Q4_0_BLOCK_BYTES    EQU     18      ; Bytes per block
Q4_0_SCALE_BYTES    EQU     2       ; Scale is float16
Q4_0_WEIGHT_BYTES   EQU     16      ; Packed weights

; AVX-512 constants
ZMM_BYTES           EQU     64
ZMM_FLOATS          EQU     16      ; 64 bytes / 4 bytes per float

; ----------------------------------------------------------------------------
; DATA SECTION
; ----------------------------------------------------------------------------

.data

; Float 8.0 for dequantization
eight_float         DD      8.0

; ----------------------------------------------------------------------------
; CODE SECTION
; ----------------------------------------------------------------------------

.code

; ============================================================================
; PUBLIC API
; ============================================================================

; ----------------------------------------------------------------------------
; Aperture_Q4_0_Dequant_AVX512
;
; Description:
;   Dequantizes Q4_0 blocks to float32 using AVX-512
;
; Parameters (Windows x64):
;   RCX = source pointer (Q4_0 blocks)
;   RDX = destination pointer (float32 output)
;   R8  = number of blocks
;
; Returns:
;   RAX = 0 on success, -1 on error
; ----------------------------------------------------------------------------
Aperture_Q4_0_Dequant_AVX512 PROC EXPORT FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Store parameters
    mov     r12, rcx            ; src
    mov     r13, rdx            ; dst
    mov     r14, r8             ; num_blocks
    
    ; Validate inputs
    test    r12, r12
    jz      error_invalid_param
    test    r13, r13
    jz      error_invalid_param
    test    r14, r14
    jz      error_invalid_param
    
    ; Setup constants
    ; ZMM14 = 8.0f (for subtract)
    vbroadcastss zmm14, DWORD PTR [eight_float]
    
    ; ZMM15 = 0x0F (nibble mask)
    mov     rax, 0F0F0F0F0F0F0F0Fh
    vpbroadcastq zmm15, rax
    
    ; Process single blocks
    mov     r15, r14
    
block_loop:
    ; Process single block
    ; Load scale (float16) and convert to float32
    movzx   eax, WORD PTR [r12]     ; Load scale (float16)
    
    ; Convert float16 to float32 manually
    ; Extract components
    movzx   edx, ax
    mov     ecx, edx
    shr     ecx, 15                 ; Sign
    mov     ebx, edx
    shr     ebx, 10
    and     ebx, 01Fh              ; Exponent
    and     edx, 03FFh              ; Mantissa
    
    ; Handle special cases
    test    ebx, ebx
    jz      zero_or_denormal
    cmp     ebx, 31
    je      infinity_or_nan
    
    ; Normal number
    add     ebx, 112                ; Adjust exponent bias (127 - 15)
    shl     ecx, 31                 ; Sign bit
    shl     ebx, 23                 ; Exponent bits
    shl     edx, 13                 ; Mantissa bits
    mov     eax, ecx
    or      eax, ebx
    or      eax, edx
    jmp     scale_ready
    
zero_or_denormal:
    xor     eax, eax                ; Return 0 for denormal
    jmp     scale_ready
    
infinity_or_nan:
    shl     ecx, 31                 ; Sign
    mov     eax, 07F800000h         ; Infinity
    or      eax, ecx
    test    edx, edx
    jz      scale_ready
    or      eax, 000400000h         ; NaN
    
scale_ready:
    movd    xmm0, eax
    vbroadcastss zmm0, xmm0         ; Broadcast scale to ZMM0
    
    ; Load 16 bytes of packed weights (32 nibbles)
    vmovdqu64 xmm1, XMMWORD PTR [r12 + 2]
    
    ; Zero-extend bytes to words
    vpmovzxbw ymm1, xmm1            ; YMM1 = 16 words from low 16 bytes
    
    ; Extract low nibbles: byte & 0x0F
    vpandd  zmm2, zmm1, zmm15       ; ZMM15 = 0x0F mask
    
    ; Extract high nibbles: (byte >> 4) & 0x0F
    vpsrlw  zmm3, zmm1, 4
    vpandd  zmm3, zmm3, zmm15
    
    ; Convert words to dwords
    vpmovzxwd zmm4, ymm2            ; Low nibbles as dwords
    vpmovzxwd zmm5, ymm3            ; High nibbles as dwords
    
    ; Subtract 8
    vpsubd  zmm4, zmm4, zmm14       ; ZMM14 = 8
    vpsubd  zmm5, zmm5, zmm14
    
    ; Convert to float
    vcvtdq2ps zmm4, zmm4
    vcvtdq2ps zmm5, zmm5
    
    ; Multiply by scale
    vmulps  zmm4, zmm4, zmm0
    vmulps  zmm5, zmm5, zmm0
    
    ; Store results
    vmovups [r13 + 0], zmm4
    vmovups [r13 + 64], zmm5
    
    ; Advance pointers
    add     r12, 18                 ; Next block
    add     r13, 128                ; 32 floats
    
    dec     r15
    jnz     block_loop
    
success:
    xor     eax, eax                ; Return 0 (success)
    jmp     cleanup
    
error_invalid_param:
    mov     eax, -1                 ; Return -1 (error)
    
cleanup:
    vzeroupper                      ; Required after AVX-512
    
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

Aperture_Q4_0_Dequant_AVX512 ENDP

END
