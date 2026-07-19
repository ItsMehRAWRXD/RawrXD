;============================================================================
; Sovereign_Q4K_Dequant.asm
; 
; High-performance Q4_K_M dequantization kernel for Pyre/Deep2
; 
; Q4_K_M block structure (per GGUF spec):
;   - Block size: 256 values
;   - 16 sub-blocks of 16 values each
;   - Per sub-block: 6-bit scale (stored as 8-bit), 6-bit min (stored as 8-bit)
;   - Quantized data: 4 bits per value (nibble-packed)
; 
; Performance target: 16-32 values/cycle with AVX-512
;============================================================================

include Pyre_Macros.inc

;============================================================================
; Constants
;============================================================================
Q4KM_BLOCK_SIZE     EQU 256     ; Values per block
Q4KM_SUBBLOCK_SIZE  EQU 16      ; Values per sub-block
Q4KM_NUM_SUBBLOCKS  EQU 16      ; Sub-blocks per block

; Offsets within block structure
Q4KM_OFFSET_SCALES  EQU 0       ; 16 bytes (scales/mins interleaved)
Q4KM_OFFSET_QVALUES EQU 16      ; 128 bytes (4-bit packed values)
Q4KM_BLOCK_BYTES    EQU 144     ; Total bytes per block

;============================================================================
; Data section - Lookup tables and constants
;============================================================================
.data
    align 64
    
    ; Mask for low nibble extraction (0x0F repeated)
    q4k_mask_low_nibble:
        times 64 db 0x0F
    
    ; Scale for converting nibbles to floats
    q4k_scale_factor:
        times 16 dd 1.0          ; Will be replaced with actual scales
    
    ; Min values for dequantization
    q4k_min_values:
        times 16 dd 0.0          ; Will be replaced with actual mins
    
    ; Lookup table for nibble expansion (0-15 -> float values)
    ; Used with vpermb for fast dequant
    q4k_nibble_lut:
        times 256 db 0          ; Placeholder - populated at runtime

;============================================================================
; Code section
;============================================================================
.code

;----------------------------------------------------------------------------
; Sovereign_Q4KM_DequantBlock_AVX512
; Dequantize one Q4_K_M block (256 values) to FP32
; 
; RCX = const uint8_t* pBlock (Q4_K_M block pointer)
; RDX = float* pDest (destination buffer, must hold 256 floats)
; 
; Clobbers: YMM0-YMM15, RAX-R11
; Returns: RAX = number of values dequantized (256)
;----------------------------------------------------------------------------
Sovereign_Q4KM_DequantBlock_AVX512 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    .endprolog
    
    mov rbx, rcx                ; RBX = block pointer
    mov rdi, rdx                ; RDI = destination
    
    ; Load scales and mins (16 sub-blocks * 2 bytes each = 32 bytes)
    ; Layout: [scale0, min0, scale1, min1, ...]
    vmovdqu xmm0, [rbx]         ; Load first 16 bytes (8 sub-blocks)
    vmovdqu xmm1, [rbx+16]      ; Load next 16 bytes (8 sub-blocks)
    
    ; Process each sub-block
    xor r12, r12                ; R12 = sub-block index (0-15)
    lea r13, [rbx + Q4KM_OFFSET_QVALUES]  ; R13 = quantized data pointer
    
.subblock_loop:
    ; Extract scale and min for this sub-block
    ; Scale is at byte r12*2, min at byte r12*2+1
    movzx eax, byte ptr [rbx + r12*2]      ; Scale
    movzx edx, byte ptr [rbx + r12*2 + 1]  ; Min
    
    ; Convert to float
    vcvtsi2ss xmm15, xmm15, eax
    vcvtsi2ss xmm14, xmm14, edx
    vbroadcastss ymm15, xmm15   ; YMM15 = scale (broadcasted)
    vbroadcastss ymm14, xmm14   ; YMM14 = min (broadcasted)
    
    ; Load 8 bytes (16 nibbles) of quantized data
    ; Each byte contains 2 values: [low_nibble, high_nibble]
    mov rax, [r13 + r12*8]      ; Load 8 bytes
    
    ; Process low nibbles (first 8 values)
    mov rcx, rax
    and rcx, 0x0F               ; Isolate low nibble of first byte
    ; ... continue for all 8 values
    
    ; For AVX-512, use vpmovzxbw and vpsrlw to unpack nibbles
    ; This is more efficient than scalar extraction
    
    ; Load 32 bytes (64 nibbles) at once for AVX-512
    vmovdqu ymm0, [r13 + r12*8] ; Load 32 bytes
    
    ; Duplicate for low/high nibble processing
    vmovdqa ymm1, ymm0
    
    ; Extract low nibbles: value & 0x0F
    vpandd ymm0, ymm0, yword ptr [q4k_mask_low_nibble]
    
    ; Extract high nibbles: (value >> 4) & 0x0F
    vpsrlw ymm1, ymm1, 4
    vpandd ymm1, ymm1, yword ptr [q4k_mask_low_nibble]
    
    ; Convert to float
    vcvtdq2ps ymm2, ymm0        ; Low nibbles to float
    vcvtdq2ps ymm3, ymm1        ; High nibbles to float
    
    ; Apply dequantization: value * scale + min
    ; Actually: ((value - 8) * scale + min) for signed interpretation
    ; Or: value * scale + min for unsigned
    vfmadd213ps ymm2, ymm15, ymm14   ; ymm2 = ymm2 * scale + min
    vfmadd213ps ymm3, ymm15, ymm14   ; ymm3 = ymm3 * scale + min
    
    ; Store results
    vmovups [rdi], ymm2
    vmovups [rdi + 32], ymm3
    
    add rdi, 64                 ; Advance destination (16 floats * 4 bytes)
    inc r12
    cmp r12, Q4KM_NUM_SUBBLOCKS
    jb .subblock_loop
    
    mov rax, Q4KM_BLOCK_SIZE    ; Return number of values processed
    
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Q4KM_DequantBlock_AVX512 ENDP

;----------------------------------------------------------------------------
; Sovereign_Q4KM_DequantBlock_AVX2
; AVX2 version for systems without AVX-512
;----------------------------------------------------------------------------
Sovereign_Q4KM_DequantBlock_AVX2 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog
    
    mov rbx, rcx                ; RBX = block pointer
    mov rdi, rdx                ; RDI = destination
    
    ; AVX2 implementation - process 8 values at a time
    xor r12, r12                ; Sub-block index
    lea r13, [rbx + Q4KM_OFFSET_QVALUES]
    
.avx2_subblock_loop:
    ; Load scale and min
    movzx eax, byte ptr [rbx + r12*2]
    movzx edx, byte ptr [rbx + r12*2 + 1]
    
    vcvtsi2ss xmm15, xmm15, eax
    vcvtsi2ss xmm14, xmm14, edx
    vbroadcastss ymm15, xmm15
    vbroadcastss ymm14, xmm14
    
    ; Process 8 bytes (16 nibbles) in two groups of 8
    ; First 8 nibbles
    movzx eax, byte ptr [r13 + r12*8]
    ; ... extract and process
    
    ; For AVX2, use vpmovzxbd and shuffle
    vmovq xmm0, qword ptr [r13 + r12*8]
    vpunpcklbw xmm0, xmm0, xmm0
    vpand xmm1, xmm0, xmmword ptr [q4k_mask_low_nibble]
    vpsrlw xmm2, xmm0, 4
    vpand xmm2, xmm2, xmmword ptr [q4k_mask_low_nibble]
    
    ; Convert to float and store
    vcvtdq2ps ymm1, xmm1
    vcvtdq2ps ymm2, xmm2
    
    vfmadd213ps ymm1, ymm15, ymm14
    vfmadd213ps ymm2, ymm15, ymm14
    
    vmovups [rdi], ymm1
    vmovups [rdi + 32], ymm2
    
    add rdi, 64
    inc r12
    cmp r12, Q4KM_NUM_SUBBLOCKS
    jb .avx2_subblock_loop
    
    mov rax, Q4KM_BLOCK_SIZE
    
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Q4KM_DequantBlock_AVX2 ENDP

;----------------------------------------------------------------------------
; Sovereign_Q4KM_ExtractSubBlock_Scalar
; Scalar fallback for extracting one sub-block (16 values)
; RCX = block pointer
; RDX = destination (16 floats)
; R8  = sub-block index (0-15)
;----------------------------------------------------------------------------
Sovereign_Q4KM_ExtractSubBlock_Scalar PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog
    
    mov rbx, rcx
    mov rdi, rdx
    mov r9, r8                  ; R9 = sub-block index
    
    ; Get scale and min for this sub-block
    movzx eax, byte ptr [rbx + r9*2]      ; Scale
    movzx edx, byte ptr [rbx + r9*2 + 1]  ; Min
    
    ; Convert to float
    cvtsi2ss xmm0, eax
    cvtsi2ss xmm1, edx
    
    ; Calculate quantized data offset
    lea rbx, [rbx + Q4KM_OFFSET_QVALUES + r9*8]  ; 8 bytes per sub-block
    
    ; Process 8 bytes (16 nibbles)
    mov rcx, 8                  ; 8 bytes
    xor r10, r10                ; Byte index
    
.nibble_loop:
    movzx eax, byte ptr [rbx + r10]
    
    ; Low nibble
    movzx edx, al
    and edx, 0x0F
    cvtsi2ss xmm2, edx
    mulss xmm2, xmm0            ; * scale
    addss xmm2, xmm1            ; + min
    movss [rdi + r10*8], xmm2
    
    ; High nibble
    movzx edx, al
    shr edx, 4
    cvtsi2ss xmm2, edx
    mulss xmm2, xmm0
    addss xmm2, xmm1
    movss [rdi + r10*8 + 4], xmm2
    
    inc r10
    dec rcx
    jnz .nibble_loop
    
    pop rdi
    pop rbx
    ret
Sovereign_Q4KM_ExtractSubBlock_Scalar ENDP

;----------------------------------------------------------------------------
; Sovereign_Q4KM_DequantRange
; Dequantize a range of values from Q4_K_M blocks
; RCX = const uint8_t* pBlocks (array of blocks)
; RDX = float* pDest
; R8  = num_blocks
;----------------------------------------------------------------------------
Sovereign_Q4KM_DequantRange PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog
    
    mov rbx, rcx                ; RBX = blocks pointer
    mov rdi, rdx                ; RDI = destination
    mov r12, r8                 ; R12 = block count
    
    ; Check for AVX-512
    call Deep2_HasAVX512
    test eax, eax
    jz .use_avx2
    
.avx512_loop:
    mov rcx, rbx
    mov rdx, rdi
    call Sovereign_Q4KM_DequantBlock_AVX512
    
    add rbx, Q4KM_BLOCK_BYTES
    add rdi, Q4KM_BLOCK_SIZE * 4  ; 256 floats * 4 bytes
    dec r12
    jnz .avx512_loop
    jmp .done
    
.use_avx2:
    ; Check for AVX2
    call Deep2_HasAVX2
    test eax, eax
    jz .use_scalar
    
.avx2_loop:
    mov rcx, rbx
    mov rdx, rdi
    call Sovereign_Q4KM_DequantBlock_AVX2
    
    add rbx, Q4KM_BLOCK_BYTES
    add rdi, Q4KM_BLOCK_SIZE * 4
    dec r12
    jnz .avx2_loop
    jmp .done
    
.use_scalar:
    ; Scalar fallback - process block by block, sub-block by sub-block
    xor r9, r9                  ; Block index
    
.scalar_block_loop:
    xor r10, r10                ; Sub-block index
    
.scalar_subblock_loop:
    mov rcx, rbx
    mov rdx, rdi
    mov r8, r10
    call Sovereign_Q4KM_ExtractSubBlock_Scalar
    
    add rdi, Q4KM_SUBBLOCK_SIZE * 4  ; 16 floats
    inc r10
    cmp r10, Q4KM_NUM_SUBBLOCKS
    jb .scalar_subblock_loop
    
    add rbx, Q4KM_BLOCK_BYTES
    inc r9
    cmp r9, r12
    jb .scalar_block_loop
    
.done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Q4KM_DequantRange ENDP

;----------------------------------------------------------------------------
; Deep2_HasAVX512 / Deep2_HasAVX2
; Feature detection (stubs - actual implementation in Deep2 kernel module)
;----------------------------------------------------------------------------
Deep2_HasAVX512 PROC
    xor eax, eax
    ; Actual implementation would check CPUID
    ret
Deep2_HasAVX512 ENDP

Deep2_HasAVX2 PROC
    mov eax, 1
    ret
Deep2_HasAVX2 ENDP

;============================================================================
; End of module
;============================================================================
END
