; ============================================================================
; rmsnorm_tiled.asm - Cache-optimized Tiled RMSNorm implementation
; ============================================================================
; Overcomes memory bandwidth wall at 32K+ elements by processing in L1-sized tiles
;
; Algorithm:
;   1. Divide input into tiles that fit in L1 cache (16KB = 4096 floats)
;   2. For each tile:
;      a. Load tile into L1 (streaming load)
;      b. Compute local sum of squares
;      c. Accumulate to global sum
;   3. Compute global RMS from total sum of squares
;   4. For each tile:
;      a. Load tile, weights
;      b. Normalize using global RMS
;      c. Store result
;
; Tile size: 4096 floats (16KB) - fits in L1 cache with room for weights
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
epsilon_const     REAL4 1.0e-5
one_over_tile     REAL4 0.000244140625  ; 1/4096 for tile mean calculation

; Tile configuration
TILE_SIZE_FLOATS  EQU 4096
TILE_SIZE_BYTES   EQU 16384  ; 4096 * 4

.code

; ============================================================================
; MASM_RMSNorm_Tiled - Cache-optimized RMSNorm with tiling
; ============================================================================
; Parameters:
;   RCX = float* input (64-byte aligned)
;   RDX = float* output (64-byte aligned)
;   R8  = float* weights (64-byte aligned)
;   R9  = size_t size (multiple of 64 for AVX-512, or 32 for AVX2)
; Returns: RAX = 0 on success
; ============================================================================

MASM_RMSNorm_Tiled PROC FRAME
    ; Prologue - CRITICAL: Save non-volatile registers BEFORE .endprolog
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
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 64
    .allocstack 64
    .endprolog

    ; Validate parameters
    test rcx, rcx
    jz error_null
    test rdx, rdx
    jz error_null
    test r8, r8
    jz error_null
    test r9, r9
    jz error_zero

    ; Check alignment (64-byte for AVX-512)
    test rcx, 63
    jnz error_align
    test rdx, 63
    jnz error_align
    test r8, 63
    jnz error_align

    ; Save parameters
    mov rsi, rcx          ; rsi = input base
    mov rdi, rdx          ; rdi = output base
    mov r12, r8           ; r12 = weights base
    mov rbx, r9           ; rbx = total size
    mov r13, r9           ; r13 = total size (preserve)
    mov r14, rcx          ; r14 = input base (preserve)
    mov r15, r8           ; r15 = weights base (preserve)

    ; ============================================================================
    ; Phase 1: Compute global sum of squares using tiles
    ; ============================================================================

    vxorps xmm0, xmm0, xmm0    ; xmm0 = global sum accumulator (scalar)

phase1_tile_loop:
    cmp rbx, 0
    jle phase1_done

    ; Determine current tile size (min of remaining, TILE_SIZE)
    mov r8, rbx
    cmp r8, TILE_SIZE_FLOATS
    jle tile_size_ok
    mov r8, TILE_SIZE_FLOATS
tile_size_ok:

    ; Save tile size
    push r8

    ; Compute sum of squares for this tile
    vxorps zmm1, zmm1, zmm1    ; zmm1 = tile sum accumulator
    vxorps ymm4, ymm4, ymm4    ; ymm4 = 16/8-element remainder accumulator
    vxorps xmm5, xmm5, xmm5    ; xmm5 = 4-element remainder accumulator
    vxorps xmm6, xmm6, xmm6    ; xmm6 = scalar remainder accumulator

    ; Process tile in 16-float (64-byte) chunks using AVX-512
    mov r9, r8                 ; r9 = remaining in tile

tile_sum_loop:
    cmp r9, 16
    jl tile_sum_remainder

    ; Load 16 floats (full AVX-512 register)
    vmovaps zmm2, ZMMWORD PTR [rsi]

    ; Compute x^2 and accumulate
    vmulps zmm3, zmm2, zmm2
    vaddps zmm1, zmm1, zmm3

    add rsi, 64                ; 16 floats * 4 bytes
    sub r9, 16
    jmp tile_sum_loop

tile_sum_remainder:
    ; Handle remaining elements (less than 16)
    cmp r9, 0
    jle tile_sum_done

    ; Process 8 at a time using AVX
    cmp r9, 8
    jl tile_sum_remainder_4

    vmovaps ymm2, YMMWORD PTR [rsi]
    vmulps ymm3, ymm2, ymm2
    vaddps ymm4, ymm4, ymm3    ; Use ymm4 for remainder accumulation

    add rsi, 32
    sub r9, 8
    jmp tile_sum_remainder

tile_sum_remainder_4:
    ; Process remaining 4 or less
    cmp r9, 4
    jl tile_sum_remainder_1
    ; Process remaining 4 or less
    cmp r9, 4
    jl tile_sum_remainder_1

    vmovaps xmm2, XMMWORD PTR [rsi]
    vmulps xmm3, xmm2, xmm2
    vaddps xmm5, xmm5, xmm3    ; Use xmm5 for small remainder

    add rsi, 16
    sub r9, 4
    jmp tile_sum_remainder

tile_sum_remainder_1:
    ; Process remaining 1-3 elements
    cmp r9, 0
    jle tile_sum_done

    ; Scalar fallback for last few elements
    movss xmm2, DWORD PTR [rsi]
    mulss xmm2, xmm2
    addss xmm6, xmm2           ; Use xmm6 for scalar remainder

    add rsi, 4
    dec r9
    jmp tile_sum_remainder_1

tile_sum_done:
    ; Horizontal reduce zmm1 (tile sum) to scalar in xmm1
    vextractf64x4 ymm2, zmm1, 1      ; ymm2 = upper 256 bits
    vaddps ymm1, ymm1, ymm2          ; ymm1 = sum of both halves
    vextractf128 xmm2, ymm1, 1       ; xmm2 = upper 128 bits
    vaddps xmm1, xmm1, xmm2          ; xmm1 = sum of both 128-bit halves
    vmovshdup xmm2, xmm1             ; xmm2 = duplicate high 64 bits
    vaddps xmm1, xmm1, xmm2          ; xmm1 = [x0+x1, x0+x1, x2+x3, x2+x3]
    vmovhlps xmm2, xmm1, xmm1        ; xmm2 = [x2+x3, x2+x3, x2+x3, x2+x3] (move high 64 bits to low)
    vaddss xmm1, xmm1, xmm2          ; xmm1[0] = sum of 64-element chunks

    ; Add remainders to zmm1[0]
    ; First reduce ymm4 to scalar and add
    vextractf128 xmm2, ymm4, 1       ; xmm2 = upper 128 bits of ymm4
    vaddps xmm4, xmm4, xmm2          ; xmm4 = sum of both 128-bit halves
    vmovshdup xmm2, xmm4             ; xmm2 = duplicate high 64 bits
    vaddps xmm4, xmm4, xmm2          ; xmm4 = [y0+y1, y0+y1, y2+y3, y2+y3]
    vmovhlps xmm2, xmm4, xmm4        ; xmm2 = [y2+y3, y2+y3, y2+y3, y2+y3]
    vaddss xmm4, xmm4, xmm2          ; xmm4[0] = sum of 16/8-element remainders
    addss xmm1, xmm4                 ; Add to tile sum

    ; Add xmm5 (4-element remainder)
    addss xmm1, xmm5

    ; Add xmm6 (scalar remainder)
    addss xmm1, xmm6

    ; Add complete tile sum to global accumulator
    vaddss xmm0, xmm0, xmm1

    ; Restore tile size and subtract from remaining
    pop r8
    sub rbx, r8
    jmp phase1_tile_loop

phase1_done:
    ; xmm0[0] already contains the total sum of squares (scalar accumulator)
    ; No horizontal reduction needed

    ; Compute mean_sq = sum_sq / n
    ; Clear xmm15 before using it for integer conversion
    vxorps xmm15, xmm15, xmm15
    vcvtsi2ss xmm15, xmm15, r13  ; xmm15 = (float)n
    vdivss xmm0, xmm0, xmm15     ; xmm0 = mean_sq

    ; Add epsilon
    vmovss xmm2, DWORD PTR [epsilon_const]
    vaddss xmm0, xmm0, xmm2    ; xmm0 = mean_sq + epsilon

    ; Compute rms = sqrt(mean_sq + epsilon)
    vsqrtss xmm0, xmm0, xmm0   ; xmm0 = rms

    ; Broadcast rms to all lanes of zmm7 (preserve across phase 2)
    vbroadcastss zmm7, xmm0    ; zmm7 = [rms, rms, ...]

    ; ============================================================================
    ; Phase 2: Normalize using global RMS, processing tiles
    ; ============================================================================

    ; Reset pointers
    mov rsi, r14          ; reset input
    mov rdi, rdi          ; output (already set)
    mov r12, r15          ; reset weights
    mov rbx, r13          ; reset size

phase2_tile_loop:
    cmp rbx, 0
    jle normalize_done

    ; Determine current tile size
    mov r8, rbx
    cmp r8, TILE_SIZE_FLOATS
    jle tile_size_ok2
    mov r8, TILE_SIZE_FLOATS
tile_size_ok2:

    push r8

    ; Process tile in 16-float chunks (64 bytes per zmm register)
    mov r9, r8

tile_normalize_loop:
    cmp r9, 16
    jl tile_norm_remainder

    ; Load input and weights
    vmovaps zmm0, ZMMWORD PTR [rsi]
    vmovaps zmm1, ZMMWORD PTR [r12]

    ; Normalize: y = x / rms * weight
    vdivps zmm2, zmm0, zmm7    ; zmm2 = x / rms
    vmulps zmm2, zmm2, zmm1    ; zmm2 = y * weight

    ; Store result
    vmovaps ZMMWORD PTR [rdi], zmm2

    add rsi, 64                ; 16 floats * 4 bytes
    add rdi, 64
    add r12, 64
    sub r9, 16
    jmp tile_normalize_loop

tile_norm_remainder:
    ; Handle remaining elements (less than 16)
    cmp r9, 0
    jle tile_norm_done

    cmp r9, 8
    jl tile_norm_remainder_4
    cmp r9, 8
    jl tile_norm_remainder_4

    vmovaps ymm0, YMMWORD PTR [rsi]
    vmovaps ymm1, YMMWORD PTR [r12]
    vdivps ymm2, ymm0, ymm7
    vmulps ymm2, ymm2, ymm1
    vmovaps YMMWORD PTR [rdi], ymm2

    add rsi, 32
    add rdi, 32
    add r12, 32
    sub r9, 8
    jmp tile_norm_remainder

tile_norm_remainder_4:
    cmp r9, 4
    jl tile_norm_remainder_1

    vmovaps xmm0, XMMWORD PTR [rsi]
    vmovaps xmm1, XMMWORD PTR [r12]
    vdivps xmm2, xmm0, xmm7
    vmulps xmm2, xmm2, xmm1
    vmovaps XMMWORD PTR [rdi], xmm2

    add rsi, 16
    add rdi, 16
    add r12, 16
    sub r9, 4
    jmp tile_norm_remainder

tile_norm_remainder_1:
    cmp r9, 0
    jle tile_norm_done

    movss xmm0, DWORD PTR [rsi]
    movss xmm1, DWORD PTR [r12]
    divss xmm0, xmm7
    mulss xmm0, xmm1
    movss DWORD PTR [rdi], xmm0

    add rsi, 4
    add rdi, 4
    add r12, 4
    dec r9
    jmp tile_norm_remainder_1

tile_norm_done:
    pop r8
    sub rbx, r8
    jmp phase2_tile_loop

normalize_done:
    xor rax, rax
    jmp cleanup

error_null:
    mov rax, 1
    jmp cleanup

error_zero:
    mov rax, 2
    jmp cleanup

error_align:
    mov rax, 3
    jmp cleanup

cleanup:
    vzeroupper
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    add rsp, 64
    pop rbp
    ret

MASM_RMSNorm_Tiled ENDP

END
