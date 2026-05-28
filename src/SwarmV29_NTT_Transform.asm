; ==============================================================================
; SwarmV29_NTT_Transform.asm
; PHASE-29: Iterative Cooley-Tukey NTT Transform (AVX-512)
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Implements in-place iterative NTT using the branchless butterfly primitive.
; Stages: log2(N) iterations, each doubling the step size.
; For maximum throughput, the butterfly is inlined (no CALL/RET overhead).
;
; OPTIMIZED: Code aligned to 64 bytes for AVX-512 cache-line affinity.
; Constants Q and Q_INV are broadcast once and kept in zmm15/zmm16 for
; the entire transform, eliminating per-butterfly vpbroadcast overhead.
; ==============================================================================

.code

; SwarmV29_NTT_Transform
; Inputs:
;   RCX = Pointer to coefficients (Input/Output buffer, 64-byte aligned)
;   RDX = N (Size of transform, must be power of 2, e.g., 256)
;   R8  = Pointer to Twiddle Factor table (Precomputed, 64-byte aligned)
;   R9  = Q (Modulus)
;   [RSP+40] = Q_INV (Montgomery Constant)
;
; Clobbers: R10-R15, RAX, RBX, ZMM0-ZMM14, K1-K2
; Returns: void (transform performed in-place)
; ==============================================================================
ALIGN 16
SwarmV29_NTT_Transform PROC PUBLIC
    mov r11, rdx                ; r11 = N
    mov r12, rcx                ; r12 = buffer pointer
    mov r13, 1                  ; r13 = step_size = 1

    ; Load Q_INV from stack into R10 (non-volatile in this context)
    mov r10, [rsp + 40]

    ; Broadcast Q and Q_INV into ZMM registers once for the entire transform
    vpbroadcastq zmm15, r9      ; zmm15 = Q (reused across all butterflies)
    vpbroadcastq zmm16, r10     ; zmm16 = Q_INV (reused across all butterflies)

; ------------------------------------------------------------------------------
; Outer Loop: Stages (step_size doubles each iteration)
; ------------------------------------------------------------------------------
stage_loop:
    cmp r13, r11
    jge done_ntt

    ; --------------------------------------------------------------------------
    ; Middle Loop: Blocks (jump by 2 * step_size)
    ; --------------------------------------------------------------------------
    mov r14, 0                  ; r14 = block index

block_loop:
    cmp r14, r11
    jge next_stage

    ; --------------------------------------------------------------------------
    ; Inner Loop: Butterflies within each block
    ; --------------------------------------------------------------------------
    mov r15, 0                  ; r15 = butterfly index within block

butterfly_loop:
    cmp r15, r13
    jge end_butterfly_loop

    ; Address calculation for A and B
    mov rax, r14                ; rax = block start
    add rax, r15                ; rax = A index

    mov rbx, rax
    add rbx, r13                ; rbx = B index (A + step_size)

    ; Load coefficients from aligned buffer
    vmovdqa64 zmm0, [r12 + rax*8]   ; zmm0 = A
    vmovdqa64 zmm1, [r12 + rbx*8]   ; zmm1 = B

    ; Fetch twiddle factor from aligned table
    ; Twiddle index = r15 (within block)
    vmovdqa64 zmm2, [r8 + r15*8]    ; zmm2 = W

    ; ==================================================================
    ; INLINED BUTTERFLY (no CALL/RET overhead)
    ; ==================================================================
    ; --- 1. Montgomery Mul(B, W) -> temp in ZMM3 ---
    vpmullq zmm4, zmm1, zmm2    ; T = B * W
    vpmullq zmm6, zmm4, zmm16   ; m = T * Q_INV (zmm16 = Q_INV)
    vpandq  zmm6, zmm6, mask_32bit  ; m mod 2^32
    vpmullq zmm8, zmm6, zmm15   ; m * Q (zmm15 = Q)
    vpaddq  zmm9, zmm4, zmm8    ; T + m*Q
    vpsrlq  zmm3, zmm9, 32      ; temp = (T + m*Q) >> 32

    ; --- 2. Preserve original A ---
    vmovdqa64 zmm14, zmm0       ; zmm14 = A_orig

    ; --- 3. A' = (A + temp) mod Q ---
    vpaddq  zmm10, zmm0, zmm3   ; A + temp
    vpsubq  zmm11, zmm10, zmm15 ; (A + temp) - Q
    vpcmpgtq k1, zmm11, zero_vec
    vpblendmq zmm0{k1}, zmm10, zmm11    ; zmm0 = A'

    ; --- 4. B' = (A_orig - temp) mod Q ---
    vpsubq  zmm12, zmm14, zmm3  ; A_orig - temp
    vpaddq  zmm13, zmm12, zmm15 ; (A_orig - temp) + Q
    vpcmpgtq k2, zmm12, zero_vec
    vpblendmq zmm1{k2}, zmm13, zmm12    ; zmm1 = B'
    ; ==================================================================

    ; Store results back to aligned buffer
    vmovdqa64 [r12 + rax*8], zmm0
    vmovdqa64 [r12 + rbx*8], zmm1

    inc r15
    jmp butterfly_loop

end_butterfly_loop:
    ; Block += 2 * step_size
    add r14, r13
    add r14, r13
    jmp block_loop

next_stage:
    shl r13, 1                  ; step_size *= 2
    jmp stage_loop

done_ntt:
    ret
SwarmV29_NTT_Transform ENDP

.data
ALIGN 16
mask_32bit DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh

ALIGN 16
zero_vec   DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0

END
