; ============================================================================
; q4_0_dequant_optimized.asm - Q4_0 Dequantization Kernel (AVX2) - OPTIMIZED
; ============================================================================
; 
; OPTIMIZATIONS APPLIED:
;   1. Constant hoisting: sub8_const loaded once before loop
;   2. 2x unrolling: Process 2 blocks per iteration to amortize loop overhead
;   3. Coalesced loads: Use 8-byte loads where possible
;
; Q4_0 Block Layout (18 bytes total):
;   bytes 0-3:   float32 scale (d)
;   bytes 4-11:  8 bytes containing 16 nibbles (qs[0..7])
;   bytes 12-17: padding
;
; Dequantization formula:
;   weight = nibble_value - 8
;   output = weight * scale
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
; Low nibble mask (0x0F) - 16 bytes for xmm operations
nibble_mask    DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
               DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh

ALIGN 16
; Subtract 8 constant (as float) - loaded once and broadcast
sub8_const     REAL4 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0

.code

; ============================================================================
; MASM_Q4_0_Dequantize_Optimized - Optimized Q4_0 dequantization
; ============================================================================
MASM_Q4_0_Dequantize_Optimized PROC FRAME
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
    push r13
    .pushreg r13
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

    ; ========================================================================
    ; OPTIMIZATION 1: Hoist constant loading outside the loop
    ; ========================================================================
    vbroadcastss ymm8, DWORD PTR [sub8_const]    ; ymm8 = 8.0f (preserved)
    vmovdqa xmm7, XMMWORD PTR [nibble_mask]      ; xmm7 = nibble mask

    ; Calculate num_blocks / 2 for unrolled loop
    mov r12, rbx
    shr r12, 1                 ; r12 = num_blocks / 2 (pairs to process)
    test r12, r12
    jz single_block_loop       ; If less than 2 blocks, use simple loop

    ; ========================================================================
    ; OPTIMIZATION 2: 2x unrolled main loop
    ; Process 2 blocks per iteration to amortize loop overhead
    ; ========================================================================
unrolled_loop:
    ; Process BLOCK 1 (at rsi)
    ; -------------------------------------------------
    vbroadcastss ymm0, DWORD PTR [rsi]           ; ymm0 = scale1
    
    ; Load 8 bytes of qs data at once (more efficient than two 4-byte loads)
    vmovq xmm10, QWORD PTR [rsi+4]             ; xmm10 = qs[0..7]
    
    ; Extract low nibbles for first 4 bytes
    vpand xmm11, xmm10, xmm7                     ; xmm11 = low nibbles
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7                     ; xmm12 = high nibbles
    
    ; Process first 8 weights (from first 4 qs bytes)
    vpunpcklbw xmm13, xmm11, xmm12               ; Interleave
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm0
    vmovups YMMWORD PTR [rdi], ymm15             ; Store weights 0-7
    
    ; Process next 8 weights (from next 4 qs bytes)
    vpsrldq xmm10, xmm10, 4                      ; Shift to next 4 bytes
    vpand xmm11, xmm10, xmm7
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7
    vpunpcklbw xmm13, xmm11, xmm12
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm0
    vmovups YMMWORD PTR [rdi+32], ymm15          ; Store weights 8-15

    ; Process BLOCK 2 (at rsi+18)
    ; -------------------------------------------------
    vbroadcastss ymm1, DWORD PTR [rsi+18]        ; ymm1 = scale2
    
    vmovq xmm10, QWORD PTR [rsi+22]            ; xmm10 = qs[0..7] for block 2
    
    ; First 8 weights
    vpand xmm11, xmm10, xmm7
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7
    vpunpcklbw xmm13, xmm11, xmm12
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm1
    vmovups YMMWORD PTR [rdi+64], ymm15          ; Store weights 0-7 of block 2
    
    ; Next 8 weights
    vpsrldq xmm10, xmm10, 4
    vpand xmm11, xmm10, xmm7
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7
    vpunpcklbw xmm13, xmm11, xmm12
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm1
    vmovups YMMWORD PTR [rdi+96], ymm15          ; Store weights 8-15 of block 2

    ; Advance pointers
    add rsi, 36                ; 2 blocks * 18 bytes
    add rdi, 128               ; 2 blocks * 16 floats * 4 bytes
    dec r12
    jnz unrolled_loop

    ; Handle remaining block (if odd count)
    test rbx, 1
    jz done

    ; ========================================================================
    ; Single block loop for remaining blocks
    ; ========================================================================
single_block_loop:
    vbroadcastss ymm0, DWORD PTR [rsi]           ; ymm0 = scale
    
    vmovq xmm10, QWORD PTR [rsi+4]             ; Load 8 qs bytes
    
    ; First 8 weights
    vpand xmm11, xmm10, xmm7
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7
    vpunpcklbw xmm13, xmm11, xmm12
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm0
    vmovups YMMWORD PTR [rdi], ymm15
    
    ; Next 8 weights
    vpsrldq xmm10, xmm10, 4
    vpand xmm11, xmm10, xmm7
    vpsrlw xmm12, xmm10, 4
    vpand xmm12, xmm12, xmm7
    vpunpcklbw xmm13, xmm11, xmm12
    vpmovzxbd ymm14, xmm13
    vcvtdq2ps ymm15, ymm14
    vsubps ymm15, ymm15, ymm8
    vmulps ymm15, ymm15, ymm0
    vmovups YMMWORD PTR [rdi+32], ymm15

    add rsi, 18
    add rdi, 64

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
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

MASM_Q4_0_Dequantize_Optimized ENDP

END
