;=============================================================================
; Q4_0 Preprocessed Weight AVX-512 Kernel
; Fast dot product using byte-planar weights
;
; Input: Preprocessed block (128 bytes):
;   [0:1]   scale (fp16)
;   [2:66]  64 unpacked int8 weights (-8 to +7)
;   [67:127] padding
;
; Process: 64 weights in 4 chunks of 16
;   Load 16 int8 weights
;   Sign-extend to int32
;   Convert to float
;   Multiply by scale
;   FMA with 16 activations
;=============================================================================

.code

;-----------------------------------------------------------------------------
; q4_preprocessed_dot_avx512_asm
; Input:  rcx = PreprocessedQ4Block* (128 bytes, aligned)
;         rdx = activations* (64 x fp32, aligned)
; Output: xmm0 = dot product (fp32)
;-----------------------------------------------------------------------------
q4_preprocessed_dot_avx512_asm PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    .endprolog

    mov rbx, rcx                        ; block ptr
    mov r12, rdx                        ; activations ptr

    ; Load scale (fp32, already converted during preprocessing)
    ; Header is 16 bytes, scale is at offset 16
    vbroadcastss zmm7, DWORD PTR [rbx + 16]  ; zmm7 = scale (all 16 lanes)

    ; Initialize accumulator
    vpxord zmm0, zmm0, zmm0              ; zmm0 = accumulator

    ; === Pass 1: Weights 0-15 ===
    ; Weights start at offset 20 (header 16 + scale 4)
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 20]   ; sign-extend 16 int8 -> int32
    vcvtdq2ps zmm1, zmm1                 ; int32 -> fp32
    vmulps zmm1, zmm1, zmm7              ; * scale

    ; Load 16 activations
    vmovaps zmm2, ZMMWORD PTR [r12]      ; activations[0:15]

    ; FMA: acc += weight * activation
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 2: Weights 16-31 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 36]  ; weights[16:31] (offset 20 + 16)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 64]    ; activations[16:31]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 3: Weights 32-47 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 52]  ; weights[32:47] (offset 20 + 32)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 128]   ; activations[32:47]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Pass 4: Weights 48-63 ===
    vpmovsxbd zmm1, XMMWORD PTR [rbx + 68]  ; weights[48:63] (offset 20 + 48)
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [r12 + 192]   ; activations[48:63]
    vfmadd231ps zmm0, zmm1, zmm2

    ; === Horizontal sum of zmm0 ===
    ; zmm0 has 16 partial sums
    ; Reduce to single float in xmm0

    ; Extract high 8 floats and add to low 8
    vextractf64x4 ymm1, zmm0, 1         ; high 8 floats
    vaddps ymm0, ymm0, ymm1             ; 8 floats

    ; Extract high 4 floats and add to low 4
    vextractf128 xmm1, ymm0, 1          ; high 4 floats
    vaddps xmm0, xmm0, xmm1             ; 4 floats

    ; Horizontal add within xmm0
    vshufps xmm1, xmm0, xmm0, 0x4E      ; [2,3,0,1]
    vaddps xmm0, xmm0, xmm1             ; [0+2, 1+3, ...]

    vshufps xmm1, xmm0, xmm0, 0xB1      ; [1,0,3,2]
    vaddss xmm0, xmm0, xmm1             ; final sum in xmm0[0]

    pop r12
    pop rbx
    ret

q4_preprocessed_dot_avx512_asm ENDP

;-----------------------------------------------------------------------------
; q4_preprocessed_gemm_row_avx512_asm
; Computes one row of GEMM: output[j] = sum_k(blocks[k] dot activations[k])
;
; Input:  rcx = blocks* (array of PreprocessedQ4Block)
;         rdx = activations* (K x 64 fp32)
;         r8  = output* (N x fp32)
;         r9  = num_blocks (K dimension)
;         [rsp+40] = num_outputs (N dimension)
;-----------------------------------------------------------------------------
q4_preprocessed_gemm_row_avx512_asm PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    .endprolog

    mov rbx, rcx                        ; blocks ptr
    mov r12, rdx                        ; activations ptr
    mov r13, r8                         ; output ptr
    mov r14, r9                         ; num_blocks
    mov r15, QWORD PTR [rsp + 72]       ; num_outputs (after pushed regs + ret addr)

    ; For each output element
    xor r8, r8                          ; j = 0
.output_loop:
    cmp r8, r15
    jge .done

    ; Initialize accumulator for this output
    vpxord zmm0, zmm0, zmm0             ; zmm0 = 0

    ; For each block
    xor r9, r9                          ; k = 0
    xor r10, r10                        ; activation offset
.block_loop:
    cmp r9, r14
    jge .next_output

    ; Compute block offset: blocks + k * 128
    mov rax, r9
    shl rax, 7                          ; k * 128 (block size)
    lea rcx, [rbx + rax]                ; block ptr

    ; Compute activation offset: activations + k * 64 * 4
    mov rdx, r12
    add rdx, r10                        ; + activation offset

    ; Load scale from block
    vpxord xmm1, xmm1, xmm1
    vpinsrw xmm1, xmm1, WORD PTR [rcx], 0
    vcvtph2ps xmm1, xmm1
    vbroadcastss zmm7, xmm1             ; scale

    ; Process 4 chunks of 16 weights each
    ; Chunk 0
    vpmovsxbd zmm1, XMMWORD PTR [rcx + 2]
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [rdx]
    vfmadd231ps zmm0, zmm1, zmm2

    ; Chunk 1
    vpmovsxbd zmm1, XMMWORD PTR [rcx + 18]
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [rdx + 64]
    vfmadd231ps zmm0, zmm1, zmm2

    ; Chunk 2
    vpmovsxbd zmm1, XMMWORD PTR [rcx + 34]
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [rdx + 128]
    vfmadd231ps zmm0, zmm1, zmm2

    ; Chunk 3
    vpmovsxbd zmm1, XMMWORD PTR [rcx + 50]
    vcvtdq2ps zmm1, zmm1
    vmulps zmm1, zmm1, zmm7
    vmovaps zmm2, ZMMWORD PTR [rdx + 192]
    vfmadd231ps zmm0, zmm1, zmm2

    ; Next block
    inc r9
    add r10, 256                        ; + 64 floats * 4 bytes
    jmp .block_loop

.next_output:
    ; Horizontal sum zmm0 to scalar
    vextractf64x4 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 0x4E
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 0xB1
    vaddss xmm0, xmm0, xmm1

    ; Store result
    movss DWORD PTR [r13 + r8 * 4], xmm0

    ; Next output
    inc r8
    jmp .output_loop

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

q4_preprocessed_gemm_row_avx512_asm ENDP

END
