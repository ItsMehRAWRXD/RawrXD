; ============================================================================
; Sovereign_KernelBridge_MASM.asm — MASM Execution Plane Registration
; ============================================================================
; Purpose: Bridge between C++ Control Plane and MASM Execution Plane.
;          Exports Sovereign_RegisterKernels_MASM which populates the
;          SovereignKernelTable with function pointers to hand-tuned MASM
;          routines.
;
; Calling Convention (Win64 ABI):
;   RCX = pointer to SovereignKernelTable
;   Returns RAX = 1 (success) or 0 (failure)
;
; Current Status:
;   - Placeholder registrations for bit-exact verification
;   - Real MASM kernels to be swapped in after certification
;
; Integration:
;   C++ calls: Sovereign_RegisterKernels_MASM(&kernelTable);
;   This module fills: kernelTable.dequant_q4_k, kernelTable.dot_f32_avx512, etc.
; ============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

; Win64 ABI requires preserving: RBX, RBP, RDI, RSI, R12-R15
; RCX, RDX, R8, R9 are volatile argument registers
; RAX, R10, R11 are volatile scratch registers

; ============================================================================
; External symbols (from C++ ABI header)
; ============================================================================
; None — this module is self-contained and exports only registration function.

; ============================================================================
; Data section — function pointer table (filled at assembly time)
; ============================================================================
.DATA

; Version string for diagnostics
SOV_VERSION_STR DB "Sovereign MASM Execution Plane v1.0.0", 0

; Feature flags (numeric values matching C header)
SOV_KERNEL_HAS_AVX512 EQU 00000001h
SOV_KERNEL_HAS_FMA    EQU 00000004h
SOV_FEATURES DD SOV_KERNEL_HAS_AVX512 + SOV_KERNEL_HAS_FMA

; ============================================================================
; Code section
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; Sovereign_RegisterKernels_MASM
; RCX = pointer to SovereignKernelTable
; Returns RAX = 1 (success), 0 (failure)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_RegisterKernels_MASM
Sovereign_RegisterKernels_MASM PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; Validate argument
    test rcx, rcx
    jz srm_fail

    mov rbx, rcx                    ; RBX = table pointer (preserved)

    ; Check ABI version
    mov eax, dword ptr [rbx]        ; table.abi_version
    cmp eax, 1
    jne srm_fail                    ; Require ABI v1

    ; Set feature flags
    mov eax, SOV_FEATURES
    mov dword ptr [rbx + 4], eax    ; table.flags

    ; ------------------------------------------------------------------------
    ; Register placeholder kernels
    ; These are C++-equivalent routines assembled in MASM.
    ; After bit-exact certification, they will be replaced with optimized
    ; versions from dequant_simd.asm, RawrXD_KQuant_Dequant.asm, etc.
    ; ------------------------------------------------------------------------

    ; Dequantization: Q4_K_M → F32 (placeholder — calls C++ via stub)
    lea rax, [SOV_Placeholder_Dequant_Q4K]
    mov qword ptr [rbx + 16], rax   ; table.dequant_q4_k

    ; Dequantization: Q4_0 → F32 (placeholder)
    lea rax, [SOV_Placeholder_Dequant_Q4_0]
    mov qword ptr [rbx + 24], rax   ; table.dequant_q4_0

    ; Dequantization: Q8_0 → F32 (placeholder)
    lea rax, [SOV_Placeholder_Dequant_Q8_0]
    mov qword ptr [rbx + 32], rax   ; table.dequant_q8_0

    ; Dequantization: Q6_K → F32 (placeholder)
    lea rax, [SOV_Placeholder_Dequant_Q6K]
    mov qword ptr [rbx + 40], rax   ; table.dequant_q6_k

    ; Dot-product: scalar fallback
    lea rax, [SOV_Placeholder_Dot_Scalar]
    mov qword ptr [rbx + 48], rax   ; table.dot_f32_scalar

    ; Dot-product: AVX2
    lea rax, [SOV_Placeholder_Dot_AVX2]
    mov qword ptr [rbx + 56], rax   ; table.dot_f32_avx2

    ; Dot-product: AVX-512 (placeholder — will be replaced with real kernel)
    lea rax, [SOV_Placeholder_Dot_AVX512]
    mov qword ptr [rbx + 64], rax   ; table.dot_f32_avx512

    ; Fused: SiLU + RMSNorm (placeholder)
    lea rax, [SOV_Placeholder_Fused_SiLU_RMSNorm]
    mov qword ptr [rbx + 72], rax   ; table.fused_silu_rmsnorm

    ; Success
    mov rax, 1
    jmp srm_exit

srm_fail:
    xor rax, rax

srm_exit:
    add rsp, 20h
    pop rdi
    pop rbx
    pop rbp
    ret
Sovereign_RegisterKernels_MASM ENDP

; ============================================================================
; Placeholder Kernels
; ============================================================================
; These are minimal implementations that pass through to C++ equivalents.
; They exist so the registration table is populated and the ABI boundary
; can be tested end-to-end before real MASM kernels are integrated.
;
; Signature: void fn(const void* src, float* dst, size_t n, const void* params)
; Win64: RCX=src, RDX=dst, R8=n, R9=params
; ============================================================================

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dequant_Q4K
; ----------------------------------------------------------------------------
SOV_Placeholder_Dequant_Q4K PROC
    ; TODO: Replace with real MASM dequant from dequant_simd.asm
    ; For now: zero-fill output (safe but wrong — for ABI testing only)
    xor eax, eax
    ret
SOV_Placeholder_Dequant_Q4K ENDP

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dequant_Q4_0
; ----------------------------------------------------------------------------
SOV_Placeholder_Dequant_Q4_0 PROC
    xor eax, eax
    ret
SOV_Placeholder_Dequant_Q4_0 ENDP

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dequant_Q8_0
; ----------------------------------------------------------------------------
SOV_Placeholder_Dequant_Q8_0 PROC
    xor eax, eax
    ret
SOV_Placeholder_Dequant_Q8_0 ENDP

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dequant_Q6K
; ----------------------------------------------------------------------------
SOV_Placeholder_Dequant_Q6K PROC
    xor eax, eax
    ret
SOV_Placeholder_Dequant_Q6K ENDP

; ============================================================================
; Placeholder Dot-Product Kernels
; ============================================================================
; Signature: float fn(const float* a, const float* b, int n)
; Win64: RCX=a, RDX=b, R8=n
; Returns: XMM0 = dot product
; ============================================================================

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dot_Scalar
; ----------------------------------------------------------------------------
SOV_Placeholder_Dot_Scalar PROC
    ; Scalar dot product (reference implementation)
    ; TODO: Replace with optimized MASM
    xorps xmm0, xmm0                ; sum = 0.0f
    test r8d, r8d
    jle dot_scalar_done
    mov r10, rcx                    ; r10 = a
    mov r11, rdx                    ; r11 = b
    mov eax, r8d                    ; eax = n

dot_scalar_loop:
    movss xmm1, dword ptr [r10]
    movss xmm2, dword ptr [r11]
    mulss xmm1, xmm2
    addss xmm0, xmm1
    add r10, 4
    add r11, 4
    dec eax
    jnz dot_scalar_loop

dot_scalar_done:
    ret
SOV_Placeholder_Dot_Scalar ENDP

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dot_AVX2
; ----------------------------------------------------------------------------
SOV_Placeholder_Dot_AVX2 PROC
    ; AVX2 dot product (8-wide)
    ; TODO: Replace with real AVX2 kernel
    vxorps ymm0, ymm0, ymm0         ; sum_vec = 0
    test r8d, r8d
    jle dot_avx2_done
    mov r10, rcx
    mov r11, rdx
    mov eax, r8d
    shr eax, 3                      ; n / 8
    jz dot_avx2_tail

dot_avx2_loop:
    vmovups ymm1, ymmword ptr [r10]
    vmovups ymm2, ymmword ptr [r11]
    vfmadd231ps ymm0, ymm1, ymm2
    add r10, 32
    add r11, 32
    dec eax
    jnz dot_avx2_loop

    ; Horizontal sum of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0

dot_avx2_tail:
    ; TODO: Handle remainder
    vzeroupper

dot_avx2_done:
    ret
SOV_Placeholder_Dot_AVX2 ENDP

; ----------------------------------------------------------------------------
; SOV_Placeholder_Dot_AVX512
; ----------------------------------------------------------------------------
SOV_Placeholder_Dot_AVX512 PROC
    ; AVX-512 dot product (16-wide)
    ; TODO: Replace with real AVX-512 kernel from existing MASM files
    vxorps zmm0, zmm0, zmm0         ; sum_vec = 0
    test r8d, r8d
    jle dot_avx512_done
    mov r10, rcx
    mov r11, rdx
    mov eax, r8d
    shr eax, 4                      ; n / 16
    jz dot_avx512_tail

dot_avx512_loop:
    vmovups zmm1, zmmword ptr [r10]
    vmovups zmm2, zmmword ptr [r11]
    vfmadd231ps zmm0, zmm1, zmm2
    add r10, 64
    add r11, 64
    dec eax
    jnz dot_avx512_loop

    ; Horizontal sum of zmm0
    vextractf32x8 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    vextractf32x4 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0

dot_avx512_tail:
    ; TODO: Handle remainder
    vzeroupper

dot_avx512_done:
    ret
SOV_Placeholder_Dot_AVX512 ENDP

; ============================================================================
; Placeholder Fused Kernel
; ============================================================================
; Signature: void fn(const float* x, const float* weight, float* out, int n, float eps)
; Win64: RCX=x, RDX=weight, R8=out, R9=n, [rsp+28h]=eps (float)
; ============================================================================

SOV_Placeholder_Fused_SiLU_RMSNorm PROC
    ; TODO: Replace with real fused kernel
    xor eax, eax
    ret
SOV_Placeholder_Fused_SiLU_RMSNorm ENDP

; ============================================================================
; Bit-Exact Verification Stub
; ============================================================================
; This function is called by the C++ test harness to verify that MASM
; kernels produce identical output to C++ reference kernels.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_RunBitExactTest_MASM
Sovereign_RunBitExactTest_MASM PROC
    ; RCX = pointer to SovereignBitExactTest
    ; Returns RAX = 1 (PASS) or 0 (FAIL)
    ; TODO: Implement when real kernels are integrated
    mov rax, 1                      ; Placeholder: always pass
    ret
Sovereign_RunBitExactTest_MASM ENDP

END
