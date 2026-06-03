; ============================================================================
; accumulate_row_masm.asm
; Pure x64 MASM — Weighted Row Accumulator with Software Prefetch
; out += weight * vRow  (headDim must be multiple of 8 for fast path)
;
; Inputs (Microsoft x64 ABI):
;   RCX = out ptr         (float*)
;   RDX = vRow ptr        (float*)
;   R8  = headDim         (int, count of floats)
;   XMM0 = weight         (scalar float, low 32 bits)
;   R9  = nextVRow ptr    (float*, prefetch target; NULL = skip prefetch)
;
; Clobbers: YMM0-YMM2, RCX, RDX, R8, R9, RAX
; No stack frame — zero prologue/epilogue overhead.
; ============================================================================

.CODE

    ALIGN 16

; ---------------------------------------------------------------------------
; accumulate_row_avx2_asm
; ---------------------------------------------------------------------------
accumulate_row_avx2_asm PROC PUBLIC

    ; Broadcast scalar weight (XMM0) into all 8 lanes of YMM0
    vbroadcastss ymm0, xmm0

    ; Pre-check: if headDim < 8, jump to scalar tail
    cmp r8, 8
    jl  scalar_tail

    ; Prefetch next V row if caller provided it (R9 != NULL)
    test r9, r9
    jz  skip_prefetch
    prefetcht0 [r9]
    prefetcht0 [r9 + 64]
skip_prefetch:

    ALIGN 16
loop_start:
    ; Load 8 floats from vRow -> YMM1
    vmovups ymm1, YMMWORD PTR [rdx]

    ; Load 8 floats from out -> YMM2
    vmovups ymm2, YMMWORD PTR [rcx]

    ; FMA: YMM2 = (YMM0 * YMM1) + YMM2
    vfmadd231ps ymm2, ymm0, ymm1

    ; Store result back to out
    vmovups YMMWORD PTR [rcx], ymm2

    ; Advance pointers by 32 bytes (8 floats)
    add rcx, 32
    add rdx, 32

    ; Decrement remaining count by 8
    sub r8, 8

    ; Continue if we still have 8+ elements
    cmp r8, 8
    jge loop_start

    ; Fall through to scalar tail for remaining 0-7 elements
scalar_tail:
    test r8, r8
    jz done

    ; Scalar FMA for tail elements
    ; weight is still in XMM0 (low lane of YMM0)
scalar_loop:
    movss   xmm1, DWORD PTR [rdx]      ; load vRow[i]
    movss   xmm2, DWORD PTR [rcx]      ; load out[i]
    vfmadd231ss xmm2, xmm0, xmm1       ; out += weight * vRow
    movss   DWORD PTR [rcx], xmm2      ; store back

    add rcx, 4
    add rdx, 4
    dec r8
    jnz scalar_loop

done:
    ret

accumulate_row_avx2_asm ENDP

END
