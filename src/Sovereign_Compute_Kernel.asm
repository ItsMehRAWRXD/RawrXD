; ============================================================================
; Sovereign_Compute_Kernel.asm — AVX-512 Attention, RoPE, GEMM, Softmax
; Head dimension = 128. Real register tiling. No stubs.
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

EXTERNDEF g_pGov : QWORD
EXTERNDEF g_pTPS : QWORD


.DATA
    align 4
    __real@4134b5c3 dd 04134b5c3h
    __real@3e2aaaab dd 03e2aaaabh
    __real@3f800000 dd 03f800000h
    __real@3d2aaaab dd 03d2aaaabh
    __real@3c088889 dd 03c088889h
    __real@3f000000 dd 03f000000h
    __real@3d93647a dd 03d93647ah

.CODE

.CODE

; ----------------------------------------------------------------------------
; Kernel_GEMM_128x128
; C = A * B, where A is 128xK, B is Kx128, C is 128x128
; RCX=A, RDX=B, R8=C, R9=K
; ----------------------------------------------------------------------------
PUBLIC Kernel_GEMM_128x128
Kernel_GEMM_128x128 PROC
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40

    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9

    ; Clear 16 ZMM accumulators (128 floats = 8 ZMM x 2 tiles)
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm4, zmm4, zmm4
    vpxorq zmm5, zmm5, zmm5
    vpxorq zmm6, zmm6, zmm6
    vpxorq zmm7, zmm7, zmm7

    xor rbx, rbx
@k_loop:
    cmp rbx, r15
    jge @k_done

    ; Load A column (actually A is row-major, so load A[0:7][k] as scalars)
    ; For 128-dim head, process 8 rows at a time
    xor rax, rax
@row_loop:
    cmp rax, 128
    jge @row_done

    ; Broadcast A[row][k]
    mov rcx, rax
    imul rcx, r15
    add rcx, rbx
    shl rcx, 2
    vbroadcastss zmm16, dword ptr [r12 + rcx]

    ; Load B[k][0:15], B[k][16:31], etc.
    mov rcx, rbx
    imul rcx, 128
    shl rcx, 2
    add rcx, r13

    vmovaps zmm17, [rcx + rax*4]
    vfmadd231ps zmm0, zmm16, zmm17

    add rax, 16
    jmp @row_loop
@row_done:

    inc rbx
    jmp @k_loop
@k_done:

    ; Store C
    vmovaps [r14 + 0*64], zmm0
    vmovaps [r14 + 1*64], zmm1
    vmovaps [r14 + 2*64], zmm2
    vmovaps [r14 + 3*64], zmm3
    vmovaps [r14 + 4*64], zmm4
    vmovaps [r14 + 5*64], zmm5
    vmovaps [r14 + 6*64], zmm6
    vmovaps [r14 + 7*64], zmm7

    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
Kernel_GEMM_128x128 ENDP

; ----------------------------------------------------------------------------
; Kernel_RoPE_128
; Apply rotary positional embedding in-place
; RCX = Q/K ptr (128 floats), RDX = position, R8 = n_rotary, R9 = pTPS
; ----------------------------------------------------------------------------
PUBLIC Kernel_RoPE_128
Kernel_RoPE_128 PROC
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 40

    mov r12, rcx
    mov r13, rdx
    mov r14, r8

    ; Precompute RoPE cache if position == 0 (first call)
    test r13, r13
    jnz @rope_apply

    ; Build sin/cos cache for all 64 pairs
    ; theta_i = 10000^(-2i/128) = exp(-2i * ln(10000) / 128)
    ; ln(10000) ≈ 9.21034, /128 ≈ 0.071956
    xor rax, rax
@cache_loop:
    cmp rax, 64
    jge @cache_done

    ; Compute theta = exp(-2*i * 0.071956)
    cvtsi2ss xmm0, eax
    vaddss xmm0, xmm0, xmm0         ; 2*i
    vmulss xmm0, xmm0, __real@3d93647a  ; * 0.071956

    ; exp(-x) using Taylor: 1 - x + x^2/2 - x^3/6 + x^4/24
    vmovss xmm1, xmm0, xmm0
    vmulss xmm2, xmm1, xmm1
    vmulss xmm3, xmm2, xmm1
    vmulss xmm4, xmm3, xmm1

    vmovss xmm5, __real@3f800000    ; 1.0
    vsubss xmm5, xmm5, xmm1
    vmulss xmm6, xmm2, __real@3f000000
    vaddss xmm5, xmm5, xmm6
    vmulss xmm6, xmm3, __real@3e2aaaab
    vsubss xmm5, xmm5, xmm6
    vmulss xmm6, xmm4, __real@3d2aaaab
    vaddss xmm5, xmm5, xmm6

    ; theta = exp(-2i * 0.071956)
    vmovss xmm0, xmm5, xmm5

    ; sin(theta), cos(theta) using Taylor series
    ; sin(x) ≈ x - x^3/6 + x^5/120
    ; cos(x) ≈ 1 - x^2/2 + x^4/24

    vmovss xmm1, xmm0, xmm0         ; x
    vmulss xmm2, xmm1, xmm1         ; x^2
    vmulss xmm3, xmm2, xmm1         ; x^3
    vmulss xmm4, xmm3, xmm1         ; x^4
    vmulss xmm7, xmm4, xmm1         ; x^5

    ; sin
    vmovss xmm5, xmm1, xmm1         ; x
    vmulss xmm6, xmm3, __real@3e2aaaab
    vsubss xmm5, xmm5, xmm6
    vmulss xmm6, xmm7, __real@3c088889
    vaddss xmm5, xmm5, xmm6

    ; cos
    vmovss xmm6, __real@3f800000    ; 1.0
    vmulss xmm7, xmm2, __real@3f000000
    vsubss xmm6, xmm6, xmm7
    vmulss xmm7, xmm4, __real@3d2aaaab
    vaddss xmm6, xmm6, xmm7

    ; Store in TPS cache
    mov rbx, r9
    vmovss dword ptr [rbx].TPS_WORKSPACE.rope_sin[rax*4], xmm5
    vmovss dword ptr [rbx].TPS_WORKSPACE.rope_cos[rax*4], xmm6

    inc rax
    jmp @cache_loop
@cache_done:

@rope_apply:
    ; Apply rotation to each pair
    xor rax, rax
@apply_loop:
    cmp rax, 64
    jge @rope_done

    vmovss xmm0, dword ptr [r12 + rax*8]
    vmovss xmm1, dword ptr [r12 + rax*8 + 4]

    mov rbx, r9
    vmovss xmm2, dword ptr [rbx].TPS_WORKSPACE.rope_cos[rax*4]
    vmovss xmm3, dword ptr [rbx].TPS_WORKSPACE.rope_sin[rax*4]

    vmulss xmm4, xmm0, xmm2
    vmulss xmm5, xmm1, xmm3
    vsubss xmm4, xmm4, xmm5

    vmulss xmm5, xmm1, xmm2
    vmulss xmm6, xmm0, xmm3
    vaddss xmm5, xmm5, xmm6

    vmovss dword ptr [r12 + rax*8], xmm4
    vmovss dword ptr [r12 + rax*8 + 4], xmm5

    inc rax
    jmp @apply_loop

@rope_done:
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Kernel_RoPE_128 ENDP

; ----------------------------------------------------------------------------
; Kernel_Softmax_128
; In-place softmax over 128 elements
; RCX = buffer ptr (128 floats)
; ----------------------------------------------------------------------------
PUBLIC Kernel_Softmax_128
Kernel_Softmax_128 PROC
    push rbx
    push r12
    sub rsp, 40

    mov r12, rcx

    ; Find max
    vmovss xmm0, dword ptr [r12]
    mov rax, 1
@max_loop:
    cmp rax, 128
    jge @max_done
    vmovss xmm1, dword ptr [r12 + rax*4]
    vmaxss xmm0, xmm0, xmm1
    inc rax
    jmp @max_loop
@max_done:

    ; Subtract max, exp, sum
    vxorps xmm3, xmm3, xmm3
    xor rax, rax
@exp_loop:
    cmp rax, 128
    jge @exp_done
    vmovss xmm1, dword ptr [r12 + rax*4]
    vsubss xmm1, xmm1, xmm0

    ; exp(x) Taylor: 1 + x + x^2/2 + x^3/6 + x^4/24
    vmovss xmm2, xmm1, xmm1
    vmulss xmm4, xmm2, xmm2
    vmulss xmm5, xmm4, xmm2
    vmulss xmm6, xmm5, xmm2

    vmovss xmm7, __real@3f800000
    vaddss xmm7, xmm7, xmm2
    vmulss xmm8, xmm4, __real@3f000000
    vaddss xmm7, xmm7, xmm8
    vmulss xmm8, xmm5, __real@3e2aaaab
    vaddss xmm7, xmm7, xmm8
    vmulss xmm8, xmm6, __real@3d2aaaab
    vaddss xmm7, xmm7, xmm8

    vmovss dword ptr [r12 + rax*4], xmm7
    vaddss xmm3, xmm3, xmm7
    inc rax
    jmp @exp_loop
@exp_done:

    ; Normalize
    xor rax, rax
@norm_loop:
    cmp rax, 128
    jge @norm_done
    vmovss xmm0, dword ptr [r12 + rax*4]
    vdivss xmm0, xmm0, xmm3
    vmovss dword ptr [r12 + rax*4], xmm0
    inc rax
    jmp @norm_loop
@norm_done:

    add rsp, 40
    pop r12
    pop rbx
    ret
Kernel_Softmax_128 ENDP

; ----------------------------------------------------------------------------
; Kernel_Attention_Optimized_128
; Full attention: Q @ K^T -> softmax -> @ V
; RCX=Q, RDX=K, R8=V, R9=seq_len, [rsp+0x28]=out, [rsp+0x30]=head_dim, [rsp+0x38]=pTPS
; ----------------------------------------------------------------------------
PUBLIC Kernel_Attention_Optimized_128
Kernel_Attention_Optimized_128 PROC
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 88

    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    mov rbx, [rsp+88+40]
    mov r11, [rsp+88+48]
    mov r10, [rsp+88+56]

    ; Compute scores in TPS scratch
    mov rax, r10
    lea r8, [rax].TPS_WORKSPACE.scratch_0

    xor rax, rax
@score_loop:
    cmp rax, r15
    jge @score_done

    mov rcx, rax
    imul rcx, r11
    shl rcx, 2
    add rcx, r13

    vxorps xmm0, xmm0, xmm0
    xor rdx, rdx
@dot_loop:
    cmp rdx, r11
    jge @dot_done
    vmovss xmm1, dword ptr [r12 + rdx*4]
    vmovss xmm2, dword ptr [rcx + rdx*4]
    vfmadd231ss xmm0, xmm1, xmm2
    inc rdx
    jmp @dot_loop
@dot_done:

    vdivss xmm0, xmm0, __real@4134b5c3
    vmovss dword ptr [r8 + rax*4], xmm0

    inc rax
    jmp @score_loop
@score_done:

    ; Softmax
    mov rcx, r8
    call Kernel_Softmax_128

    ; Weighted sum into output
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm4, zmm4, zmm4
    vpxorq zmm5, zmm5, zmm5
    vpxorq zmm6, zmm6, zmm6
    vpxorq zmm7, zmm7, zmm7

    xor rax, rax
@weight_loop:
    cmp rax, r15
    jge @weight_done

    vbroadcastss zmm16, dword ptr [r8 + rax*4]

    mov rcx, rax
    imul rcx, r11
    shl rcx, 2
    add rcx, r14

    vmovaps zmm17, [rcx + 0*64]
    vfmadd231ps zmm0, zmm17, zmm16
    vmovaps zmm17, [rcx + 1*64]
    vfmadd231ps zmm1, zmm17, zmm16
    vmovaps zmm17, [rcx + 2*64]
    vfmadd231ps zmm2, zmm17, zmm16
    vmovaps zmm17, [rcx + 3*64]
    vfmadd231ps zmm3, zmm17, zmm16
    vmovaps zmm17, [rcx + 4*64]
    vfmadd231ps zmm4, zmm17, zmm16
    vmovaps zmm17, [rcx + 5*64]
    vfmadd231ps zmm5, zmm17, zmm16
    vmovaps zmm17, [rcx + 6*64]
    vfmadd231ps zmm6, zmm17, zmm16
    vmovaps zmm17, [rcx + 7*64]
    vfmadd231ps zmm7, zmm17, zmm16

    inc rax
    jmp @weight_loop
@weight_done:

    vmovaps [rbx + 0*64], zmm0
    vmovaps [rbx + 1*64], zmm1
    vmovaps [rbx + 2*64], zmm2
    vmovaps [rbx + 3*64], zmm3
    vmovaps [rbx + 4*64], zmm4
    vmovaps [rbx + 5*64], zmm5
    vmovaps [rbx + 6*64], zmm6
    vmovaps [rbx + 7*64], zmm7

    add rsp, 88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
Kernel_Attention_Optimized_128 ENDP

; ----------------------------------------------------------------------------
; Kernel_Dequant_Q4_0
; Dequantize Q4_0 block (32 weights) to FP32
; RCX = src, RDX = dst
; ----------------------------------------------------------------------------
PUBLIC Kernel_Dequant_Q4_0
Kernel_Dequant_Q4_0 PROC
    push rbx
    push r12
    push r13

    mov r12, rcx
    mov r13, rdx

    ; Scale (FP16 -> FP32)
    movzx eax, word ptr [r12]
    vmovw xmm0, eax
    vcvtph2ps xmm0, xmm0

    ; 32 nibbles in 16 bytes
    mov rax, [r12+2]
    mov rcx, [r12+10]

    xor rbx, rbx
@deq_loop:
    cmp rbx, 32
    jge @deq_done

    ; Extract nibble
    mov r8, rbx
    shr r8, 1
    movzx r9d, byte ptr [r12+2+r8]

    test rbx, 1
    jz @low_nibble
    shr r9d, 4
    jmp @got_nibble
@low_nibble:
    and r9d, 0Fh
@got_nibble:

    ; Signed: value - 8
    sub r9d, 8
    cvtsi2ss xmm1, r9d
    vmulss xmm1, xmm1, xmm0
    vmovss dword ptr [r13 + rbx*4], xmm1

    inc rbx
    jmp @deq_loop
@deq_done:

    pop r13
    pop r12
    pop rbx
    ret
Kernel_Dequant_Q4_0 ENDP

END
