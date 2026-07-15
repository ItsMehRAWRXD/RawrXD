; ============================================================================
; Aperture Q4_0 Dequantization Kernel - AVX-512 Optimized
; ============================================================================
; High-performance Q4_0 dequantization using AVX-512
; Architecture: x86-64 (AMD64), AVX-512F/BW/DQ
; Calling Convention: Windows x64
; ============================================================================

; ----------------------------------------------------------------------------
; ASSEMBLY DIRECTIVES
; ----------------------------------------------------------------------------

.686P
.XMM
.MODEL FLAT, C
OPTION CASEMAP:NONE

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
eight_float LABEL DWORD
    DD 8

; ----------------------------------------------------------------------------
; CODE SECTION
; ----------------------------------------------------------------------------

.code

; ----------------------------------------------------------------------------
; Aperture_Q4_0_Dequant_AVX512
; Parameters: RCX=src, RDX=dst, R8=num_blocks
; Returns: RAX=0 on success, -1 on error
; ----------------------------------------------------------------------------
Aperture_Q4_0_Dequant_AVX512 PROC EXPORT FRAME
    ; Save non-volatile registers
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
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
    
    mov     rax, 0x0F0F0F0F0F0F0F0Fh
    vpbroadcastq zmm15, rax
    
    ; Process blocks
    mov     r15, r14

block_loop LABEL NEAR
    test    r15, r15
    jz      success
    
    ; Load scale (first 2 bytes as uint16)
    movzx   eax, WORD PTR [r12]
    
    ; Simple scale conversion (treat as uint16 for now)
    ; TODO: Proper float16 to float32 conversion
    vbroadcastss zmm0, eax
    
    ; Load packed weights (16 bytes)
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
    
error_invalid_param LABEL NEAR
    mov     rax, -1
    jmp     cleanup
    
success LABEL NEAR
    xor     rax, rax
    
cleanup LABEL NEAR
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
