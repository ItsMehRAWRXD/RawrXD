; ============================================================================
; sovereign_q4k_gemv_v2.asm - Q4_K_M GEMV Kernel v2 (AVX2)
; Optimized: 8-wide FMA per group, SIMD nibble unpack
; Target: >=5x speedup over scalar reference
;
; Q4_K block layout (144 bytes per 256 weights):
;   +0:   d     (fp16) - super-block scale
;   +2:   dmin  (fp16) - super-block minimum
;   +4:   scales[12] - packed 6-bit scale/min pairs
;   +16:  qs[128] - 256 x 4-bit packed weights
;
; C prototype:
;   void Sovereign_Q4K_GEMV_AVX2_V2(
;       const void* q4_weights, const float* input, float* output,
;       unsigned int num_blocks, unsigned int rows);
; ============================================================================

OPTION CASEMAP:NONE

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Q4K_GEMV_AVX2_V2
; ----------------------------------------------------------------------------
Sovereign_Q4K_GEMV_AVX2_V2 PROC FRAME
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    .endprolog

    mov r12, rcx            ; r12 = q4_weights
    mov r13, rdx            ; r13 = input
    mov r14, r8             ; r14 = output
    mov r15d, r9d           ; r15 = num_blocks
    mov ebx, [rsp+96]       ; ebx = rows (6th arg, after shadow space + 7 pushes)

    test ebx, ebx
    jz done
    test r15d, r15d
    jz done

    ; Precompute row stride = num_blocks * 144
    mov eax, r15d
    imul eax, eax, 144
    mov r9d, eax              ; r9 = row stride in bytes

    xor r10d, r10d          ; r10 = current row

; ============================================================================
; Row loop
; ============================================================================
row_loop:
    vxorps ymm0, ymm0, ymm0     ; ymm0 = accumulator
    xor r11d, r11d              ; r11 = current block
    mov rsi, r12                  ; rsi = current row's block data

; ============================================================================
; Block loop
; ============================================================================
block_loop:
    ; Load d and dmin (FP16) from block header
    movzx eax, word ptr [rsi]
    vmovd xmm1, eax
    vcvtph2ps xmm1, xmm1          ; xmm1 = d

    movzx eax, word ptr [rsi + 2]
    vmovd xmm2, eax
    vcvtph2ps xmm2, xmm2          ; xmm2 = dmin

    ; Process 8 sub-blocks, each with 32 weights
    ; Each sub-block: scale = d * sc, min = dmin * m
    xor rdi, rdi                  ; rdi = sub-block index 0..7

subblock_loop:
    ; --- Unpack scale and min for sub-block rdi ---
    ; scales[12] at offset 4
    ; j < 4: sc = scales[j] & 63, m = scales[j+4] & 63
    ; j >= 4: sc = (scales[j+4] & 0x0F) | ((scales[j-4] >> 6) << 4)
    ;          m  = (scales[j+4] >> 4) | ((scales[j] >> 6) << 4)

    cmp rdi, 4
    jae subblock_high

    ; j = 0..3
    movzx eax, byte ptr [rsi + 4 + rdi]
    and eax, 63
    movzx ecx, byte ptr [rsi + 4 + rdi + 4]
    and ecx, 63
    jmp subblock_scale_ready

subblock_high:
    ; j = 4..7
    ; sc = (scales[j+4] & 0x0F) | ((scales[j-4] >> 6) << 4)
    ; m  = (scales[j+4] >> 4) | ((scales[j] >> 6) << 4)
    lea edx, [rdi - 4]            ; edx = j-4
    movzx eax, byte ptr [rsi + 4 + rdx]  ; eax = scales[j-4]
    shr eax, 6
    shl eax, 4
    movzx ecx, byte ptr [rsi + 4 + rdi + 4]  ; ecx = scales[j+4] & 0x0F
    and ecx, 0Fh
    or ecx, eax                   ; ecx = sc

    movzx eax, byte ptr [rsi + 4 + rdi]   ; eax = scales[j]
    shr eax, 6
    shl eax, 4
    movzx edx, byte ptr [rsi + 4 + rdi + 4]  ; edx = scales[j+4]
    shr edx, 4
    or edx, eax                   ; edx = m
    mov eax, ecx                  ; eax = sc
    mov ecx, edx                  ; ecx = m

subblock_scale_ready:
    ; xmm3 = scale = d * sc
    vcvtsi2ss xmm3, xmm3, eax
    vmulss xmm3, xmm3, xmm1
    vbroadcastss ymm3, xmm3       ; ymm3 = scale (8 floats)

    ; xmm4 = min = dmin * m
    vcvtsi2ss xmm4, xmm4, ecx
    vmulss xmm4, xmm4, xmm2
    vbroadcastss ymm4, xmm4       ; ymm4 = min (8 floats)

    ; Load 16 bytes of qs for this sub-block (32 nibbles)
    ; qs starts at offset 16, each sub-block has 16 bytes
    mov rax, rdi
    shl rax, 4
    add rax, rsi
    add rax, 16
    vmovdqu xmm5, xmmword ptr [rax]

    ; Extract low nibbles: xmm6 = xmm5 & 0Fh
    vmovdqa xmm6, xmm5
    pand xmm6, xmmword ptr [nibble_mask]

    ; Extract high nibbles: xmm7 = (xmm5 >> 4) & 0Fh
    movdqa xmm7, xmm5
    psrlw xmm7, 4
    pand xmm7, xmmword ptr [nibble_mask]

    ; Combine into ymm8 = [low16 | high16] = 32 x 8-bit values
    vinsertf128 ymm8, ymm6, xmm7, 1

    ; Process 32 values in 4 iterations of 8
    ; Iteration 0: values 0..7 (from low nibbles, bytes 0..7)
    vpmovzxbd ymm9, xmm6          ; zero-extend 8 bytes to 8 dwords
    vcvtdq2ps ymm9, ymm9          ; convert to float
    vmulps ymm9, ymm9, ymm3       ; scale * q
    vsubps ymm9, ymm9, ymm4       ; scale * q - min

    ; Load 8 input floats
    mov rdx, r11
    shl rdx, 8                    ; block * 256
    mov rcx, rdi
    shl rcx, 5                    ; sub-block * 32
    add rdx, rcx                  ; offset = block*256 + sub*32
    vmovups ymm10, [r13 + rdx * 4]
    vfmadd231ps ymm0, ymm9, ymm10

    ; Iteration 1: values 8..15 (from low nibbles, bytes 8..15)
    vpsrldq xmm11, xmm6, 8        ; shift right by 8 bytes
    vpmovzxbd ymm9, xmm11
    vcvtdq2ps ymm9, ymm9
    vmulps ymm9, ymm9, ymm3
    vsubps ymm9, ymm9, ymm4
    vmovups ymm10, [r13 + rdx * 4 + 32]
    vfmadd231ps ymm0, ymm9, ymm10

    ; Iteration 2: values 16..23 (from high nibbles, bytes 0..7)
    vpmovzxbd ymm9, xmm7
    vcvtdq2ps ymm9, ymm9
    vmulps ymm9, ymm9, ymm3
    vsubps ymm9, ymm9, ymm4
    vmovups ymm10, [r13 + rdx * 4 + 64]
    vfmadd231ps ymm0, ymm9, ymm10

    ; Iteration 3: values 24..31 (from high nibbles, bytes 8..15)
    vpsrldq xmm11, xmm7, 8
    vpmovzxbd ymm9, xmm11
    vcvtdq2ps ymm9, ymm9
    vmulps ymm9, ymm9, ymm3
    vsubps ymm9, ymm9, ymm4
    vmovups ymm10, [r13 + rdx * 4 + 96]
    vfmadd231ps ymm0, ymm9, ymm10

    inc rdi
    cmp rdi, 8
    jl subblock_loop

    ; Move to next block
    add rsi, 144                  ; sizeof(Q4_K_Block) = 144
    inc r11d
    cmp r11d, r15d
    jl block_loop

    ; Horizontal sum of ymm0 accumulator
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    movss dword ptr [r14 + r10 * 4], xmm0

    inc r10d
    add r12, r9                   ; next row's blocks (row stride)
    cmp r10d, ebx
    jl row_loop

done:
    vzeroupper
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

Sovereign_Q4K_GEMV_AVX2_V2 ENDP

; ============================================================================
; Data section (read-only constants in .rdata)
; ============================================================================
.data
ALIGN 16
nibble_mask:
    db 16 dup(0Fh)

END
