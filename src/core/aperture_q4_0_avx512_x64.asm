; ============================================================================
; Aperture Q4_0 Dequantization Kernel - AVX-512 Optimized
; ============================================================================
; x64 MASM version - simplified for compatibility
; ============================================================================

; No 32-bit directives in x64 mode

; ----------------------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------------------

Q4_0_BLOCK_SIZE     EQU     32
Q4_0_BLOCK_BYTES    EQU     18

; ----------------------------------------------------------------------------
; DATA SECTION
; ----------------------------------------------------------------------------

.data

ALIGN 16
eight_float DWORD 8

; ----------------------------------------------------------------------------
; CODE SECTION
; ----------------------------------------------------------------------------

.code

; ----------------------------------------------------------------------------
; Aperture_Q4_0_Dequant_AVX512
; RCX=src, RDX=dst, R8=num_blocks
; Returns: RAX=0 on success, -1 on error
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
    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    
    ; Validate inputs
    test    r12, r12
    jz      error_invalid_param
    test    r13, r13
    jz      error_invalid_param
    test    r14, r14
    jz      error_invalid_param
    
    ; Setup constants
    vpbroadcastd zmm14, DWORD PTR [eight_float]
    vcvtdq2ps zmm14, zmm14
    
    mov     rax, 0F0F0F0F0F0F0F0Fh
    vpbroadcastq zmm15, rax
    
    ; Process blocks
    mov     r15, r14

block_loop:
    test    r15, r15
    jz      success
    
    ; Load scale
    movzx   eax, WORD PTR [r12]
    vbroadcastss zmm0, eax
    
    ; Load packed weights
    vmovdqu64 xmm1, XMMWORD PTR [r12+2]
    
    ; Unpack nibbles
    vpmovzxbw ymm1, xmm1
    vpandd  zmm2, zmm1, zmm15
    vpsrlw  zmm3, zmm1, 4
    vpandd  zmm3, zmm3, zmm15
    
    ; Convert to int32
    vpmovzxwd zmm4, ymm2
    vpmovzxwd zmm5, ymm3
    
    ; Subtract 8
    vpsubd  zmm4, zmm4, zmm14
    vpsubd  zmm5, zmm5, zmm14
    
    ; Convert to float and scale
    vcvtdq2ps zmm4, zmm4
    vcvtdq2ps zmm5, zmm5
    vmulps  zmm4, zmm4, zmm0
    vmulps  zmm5, zmm5, zmm0
    
    ; Store
    vmovups [r13], zmm4
    vmovups [r13+64], zmm5
    
    ; Advance
    add     r12, 18
    add     r13, 128
    dec     r15
    jmp     block_loop
    
error_invalid_param:
    mov     rax, -1
    jmp     cleanup
    
success:
    xor     rax, rax
    
cleanup:
    vzeroupper
    
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

; ----------------------------------------------------------------------------
; EXPORTS
; ----------------------------------------------------------------------------

PUBLIC Aperture_Q4_0_Dequant_AVX512

END
