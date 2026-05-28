; ==============================================================================
; SwarmV29_INTT_Transform.asm
; PHASE-29: Iterative Inverse Cooley-Tukey NTT Transform (AVX-512)
; Target: 70B @ 150TPS via AVX-512 Vectorized INTT
; ------------------------------------------------------------------------------
; Implements in-place iterative INTT using the branchless butterfly primitive.
; Stages: log2(N) iterations, each doubling the step size.
; For maximum throughput, the butterfly is inlined (no CALL/RET overhead).
;
; After all stages, applies final scaling by N^-1 mod Q.
; ==============================================================================

.code

; SwarmV29_INTT_Transform
; Inputs:
;   RCX = Pointer to coefficients (Input/Output buffer, 64-byte aligned)
;   RDX = N (Size of transform, must be power of 2, e.g., 256)
;   R8  = Pointer to Inverse Twiddle Factor table (Precomputed, 64-byte aligned)
;   R9  = Q (Modulus)
;   [RSP+40] = Q_INV (Montgomery Constant)
;   [RSP+48] = N_INV (Modular inverse of N, for final scaling)
;
; Clobbers: R10-R15, RAX, RBX, ZMM0-ZMM14, K1-K2
; Returns: void (transform performed in-place)
; ==============================================================================
ALIGN 16
SwarmV29_INTT_Transform PROC PUBLIC
    mov r11, rdx                ; r11 = N
    mov r12, rcx                ; r12 = buffer pointer
    mov r13, 1                  ; r13 = step_size = 1

    ; Load Q_INV from stack into R10
    mov r10, [rsp + 40]

    ; Load N_INV from stack for final scaling
    mov r14, [rsp + 48]

    ; Broadcast Q and Q_INV into ZMM registers once for the entire transform
    vpbroadcastq zmm15, r9      ; zmm15 = Q (reused across all butterflies)
    vpbroadcastq zmm16, r10     ; zmm16 = Q_INV (reused across all butterflies)

; ------------------------------------------------------------------------------
; Outer Loop: Stages (step_size doubles each iteration)
; ------------------------------------------------------------------------------
stage_loop:
    cmp r13, r11
    jge final_scale

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

    ; Fetch INVERSE twiddle factor from aligned table
    vmovdqa64 zmm2, [r8 + r15*8]    ; zmm2 = W_inv

    ; ==================================================================
    ; INLINED INTT BUTTERFLY (no CALL/RET overhead)
    ; ==================================================================
    ; --- 1. Montgomery Mul(B, W_inv) -> temp in ZMM3 ---
    vpmullq zmm4, zmm1, zmm2    ; T = B * W_inv
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

; ------------------------------------------------------------------------------
; Final Scale: Multiply all coefficients by N^-1 mod Q
; This is required for the Inverse NTT to recover the original polynomial.
; ------------------------------------------------------------------------------
final_scale:
    ; Broadcast N_INV into ZMM17 for the scaling pass
    mov rax, [rsp + 48]         ; rax = N_INV
    vpbroadcastq zmm17, rax     ; zmm17 = N_INV

    ; Reset buffer pointer and count
    mov rcx, r12                ; rcx = buffer pointer
    mov rdx, r11                ; rdx = N (count)
    shr rdx, 3                  ; rdx = N / 8 (number of 8-lane blocks)

scale_loop:
    cmp rdx, 0
    jle done_intt

    ; Load 8 coefficients
    vmovdqa64 zmm0, [rcx]

    ; Montgomery Multiply: coeff * N_INV
    vpmullq zmm4, zmm0, zmm17   ; T = coeff * N_INV
    vpmullq zmm6, zmm4, zmm16   ; m = T * Q_INV
    vpandq  zmm6, zmm6, mask_32bit  ; m mod 2^32
    vpmullq zmm8, zmm6, zmm15   ; m * Q
    vpaddq  zmm9, zmm4, zmm8    ; T + m*Q
    vpsrlq  zmm0, zmm9, 32      ; result = (T + m*Q) >> 32

    ; Final conditional subtraction to ensure [0, Q-1]
    vpsubq  zmm10, zmm0, zmm15  ; result - Q
    vpcmpgtq k1, zmm10, zero_vec
    vpblendmq zmm0{k1}, zmm0, zmm10    ; if result >= Q, use result - Q

    ; Store scaled coefficients
    vmovdqa64 [rcx], zmm0

    add rcx, 64                 ; Move to next 8-lane block
    dec rdx
    jmp scale_loop

done_intt:
    ret
SwarmV29_INTT_Transform ENDP

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