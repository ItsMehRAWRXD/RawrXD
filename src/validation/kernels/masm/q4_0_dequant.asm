; ============================================================================
; q4_0_dequant.asm - Q4_0 Dequantization Kernel (AVX2) - FIXED VERSION
; ============================================================================
; 
; Q4_0 Block Layout (18 bytes total):
;   bytes 0-3:   float32 scale (d)
;   bytes 4-11:  8 bytes containing 16 nibbles (qs[0..7])
;                Each byte contains 2 weights:
;                  - Low nibble (bits 0-3) = weight index 0, 2, 4, 6, 8, 10, 12, 14
;                  - High nibble (bits 4-7) = weight index 1, 3, 5, 7, 9, 11, 13, 15
;
; Dequantization formula:
;   weight = nibble_value - 8   (convert [0,15] to [-8,7])
;   output = weight * scale
;
; CRITICAL FIX: The previous version had incorrect nibble extraction.
; Each byte in qs[] contains 2 adjacent weights, not separated by 8 positions.
;
; Parameters:
;   RCX = const void* input (Q4_0 blocks)
;   RDX = float* output (dequantized floats, 16 per block)
;   R8  = size_t num_blocks
;
; Returns: RAX = 0 on success
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
; Low nibble mask (0x0F) - 32 bytes for ymm operations
nibble_mask    DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
               DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
               DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
               DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh

ALIGN 16
; Subtract 8 constant (as float)
sub8_const     REAL4 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0

.code

; ============================================================================
; MASM_Q4_0_Dequantize - Dequantize Q4_0 blocks to float32
; ============================================================================
MASM_Q4_0_Dequantize PROC FRAME
    ; Prologue - save non-volatile registers
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Save parameters
    mov rsi, rcx           ; rsi = input (Q4_0 blocks)
    mov rdi, rdx           ; rdi = output (float buffer)
    mov rbx, r8            ; rbx = num_blocks

    ; Validate inputs
    test rsi, rsi
    jz error_null
    test rdi, rdi
    jz error_null
    test rbx, rbx
    jz error_zero

    ; No need to load constants here - reload inside loop to avoid YMM preservation issues

    ; Process each block
block_loop:
    cmp rbx, 0
    jle done

    ; ================================================================
    ; Load Q4_0 block
    ; ================================================================

    ; Load scale (4 bytes) and broadcast to all lanes
    vbroadcastss ymm0, DWORD PTR [rsi]           ; ymm0 = scale

    ; ================================================================
    ; Load constants (reload each iteration to avoid YMM preservation issues)
    vbroadcastss ymm9, DWORD PTR [sub8_const]    ; ymm9 = 8.0f repeated
    
    ; Process first 4 qs bytes (weights 0-7)
    ; ================================================================
    
    vmovd xmm10, DWORD PTR [rsi+4]               ; Load first 4 qs bytes
    
    ; Extract low nibbles: qs[i] & 0x0F
    vpand xmm11, xmm10, XMMWORD PTR [nibble_mask] ; xmm11 = low nibbles
    
    ; Extract high nibbles: (qs[i] >> 4) & 0x0F
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, XMMWORD PTR [nibble_mask] ; xmm12 = high nibbles
    
    ; Interleave low and high nibbles
    vpunpcklbw xmm13, xmm11, xmm12               ; xmm13 = interleaved nibbles
    
    ; Zero extend bytes to 32-bit integers and convert to float
    vpmovzxbd ymm14, xmm13                       ; ymm14 = 8 int32 weights
    vcvtdq2ps ymm15, ymm14                       ; ymm15 = float weights
    vsubps ymm15, ymm15, ymm9                    ; ymm15 = weights - 8
    vmulps ymm15, ymm15, ymm0                    ; ymm15 = dequantized weights
    
    ; Store first 8 weights
    vmovups YMMWORD PTR [rdi], ymm15
    
    ; ================================================================
    ; Process next 4 qs bytes (weights 8-15)
    ; ================================================================
    
    vmovd xmm10, DWORD PTR [rsi+8]               ; Load next 4 qs bytes
    
    ; Extract low nibbles
    vpand xmm11, xmm10, XMMWORD PTR [nibble_mask]
    
    ; Extract high nibbles
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, XMMWORD PTR [nibble_mask]
    
    ; Interleave
    vpunpcklbw xmm13, xmm11, xmm12
    
    ; Convert and scale
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm9
    vmulps ymm15, ymm15, ymm0
    
    ; Store next 8 weights
    vmovups YMMWORD PTR [rdi+32], ymm15

    ; Advance pointers
    add rsi, 18                ; Next Q4_0 block (18 bytes)
    add rdi, 64                ; Next output block (16 floats * 4 bytes)
    dec rbx
    jmp block_loop

done:
    xor rax, rax               ; Return 0 (success)
    jmp cleanup

error_null:
    mov rax, 1
    jmp cleanup

error_zero:
    mov rax, 2

cleanup:
    vzeroupper
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

MASM_Q4_0_Dequantize ENDP

END
