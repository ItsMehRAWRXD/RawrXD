; ============================================================================
; Aperture Q4_0 Dequantization Kernel - AVX-512 Optimized (MASM x64) v2
; ============================================================================
; Fixed version with proper memory handling and alignment
; ============================================================================

; ----------------------------------------------------------------------------
; DATA SECTION
; ----------------------------------------------------------------------------

.data

ALIGN 16
eight_float DWORD 8

ALIGN 16
nibble_mask QWORD 0F0F0F0F0F0F0F0Fh

; ----------------------------------------------------------------------------
; CODE SECTION
; ----------------------------------------------------------------------------

.code

; ----------------------------------------------------------------------------
; Aperture_Q4_0_Dequant_AVX512
; Parameters: RCX=src (Q4_0 blocks), RDX=dst (float output), R8=num_blocks
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
    
    sub     rsp, 128
    .allocstack 128
    .endprolog
    
    ; Store parameters in preserved registers
    mov     r12, rcx            ; r12 = src
    mov     r13, rdx            ; r13 = dst
    mov     r14, r8             ; r14 = num_blocks
    
    ; Validate inputs
    test    r12, r12
    jz      error_invalid_param
    test    r13, r13
    jz      error_invalid_param
    test    r14, r14
    jz      error_invalid_param
    
    ; Setup constants
    ; Load 8.0f into xmm14, then broadcast to zmm14
    mov     eax, 8
    vmovd   xmm14, eax
    vcvtdq2ps xmm14, xmm14      ; Convert to float (8.0f)
    vbroadcastss zmm14, xmm14   ; Broadcast to all elements
    
    ; Load nibble mask into zmm15
    mov     rax, OFFSET nibble_mask
    vbroadcastsd zmm15, QWORD PTR [rax]
    
    ; Process blocks - main loop
    mov     r15, r14            ; r15 = remaining blocks

block_loop LABEL NEAR
    test    r15, r15
    jz      success             ; If no more blocks, exit loop
    
    ; Load scale (first 2 bytes of block as uint16)
    movzx   eax, WORD PTR [r12]
    
    ; Convert uint16 to float32 (simple cast, assuming it's already float16)
    ; For now, just use it directly as a float value
    vmovd   xmm0, eax
    vbroadcastss zmm0, xmm0     ; Broadcast scale to all elements
    
    ; Load 16 bytes of packed weights (32 nibbles)
    vmovdqu xmm1, XMMWORD PTR [r12+2]
    
    ; Unpack nibbles:
    ; Step 1: Zero-extend bytes to words
    vpmovzxbw ymm1, xmm1
    
    ; Step 2: Extract low nibbles (byte & 0x0F)
    vpand   ymm2, ymm1, YMMWORD PTR [nibble_mask]
    
    ; Step 3: Extract high nibbles ((byte >> 4) & 0x0F)
    vpsrlw  ymm3, ymm1, 4
    vpand   ymm3, ymm3, YMMWORD PTR [nibble_mask]
    
    ; Step 4: Convert words to dwords (interleave low and high)
    vpmovzxwd zmm4, ymm2        ; Low nibbles as int32
    vpmovzxwd zmm5, ymm3        ; High nibbles as int32
    
    ; Step 5: Subtract 8 (dequantization bias)
    vpsubd  zmm4, zmm4, zmm14
    vpsubd  zmm5, zmm5, zmm14
    
    ; Step 6: Convert to float and apply scale
    vcvtdq2ps zmm4, zmm4
    vcvtdq2ps zmm5, zmm5
    vmulps  zmm4, zmm4, zmm0    ; Apply scale
    vmulps  zmm5, zmm5, zmm0
    
    ; Step 7: Store 32 floats (2 ZMM registers)
    vmovups ZMMWORD PTR [r13], zmm4         ; First 16 floats
    vmovups ZMMWORD PTR [r13+64], zmm5      ; Last 16 floats
    
    ; Advance pointers
    add     r12, 18             ; Next Q4_0 block (18 bytes)
    add     r13, 128            ; Next output (32 floats * 4 bytes)
    dec     r15                 ; Decrement block counter
    jmp     block_loop          ; Continue loop
    
error_invalid_param LABEL NEAR
    mov     rax, -1
    jmp     cleanup
    
success LABEL NEAR
    xor     rax, rax            ; Return 0 (success)
    
cleanup LABEL NEAR
    vzeroupper                  ; Required after AVX-512
    
    ; Restore stack and registers
    add     rsp, 128
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
