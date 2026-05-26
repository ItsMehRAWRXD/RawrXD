; ==============================================================================
; TITAN_FUSED_8WAY_KERNEL.asm
; ==============================================================================
; ARCHITECTURE: x86-64 / AVX2
; REGIME:       Compute-Bound (Stage C)
; DESCRIPTION:  8-way unrolled decoupled accumulator kernel.
;               Fully hides FMA 4-cycle latency via spatial interleaving.
; ==============================================================================

.code

; extern "C" void RunFused8WayKernel(
;     const float* activations,  // RCX
;     const float* weights,      // RDX
;     uint64_t step_count,       // R8
;     AccumulatorState* state    // R9
; );

RunFused8WayKernel PROC
    ; 1. Load the existing accumulator state directly into YMM0-YMM7
    vmovups ymm0, [r9 + 000h]
    vmovups ymm1, [r9 + 020h]
    vmovups ymm2, [r9 + 040h]
    vmovups ymm3, [r9 + 060h]
    vmovups ymm4, [r9 + 080h]
    vmovups ymm5, [r9 + 0A0h]
    vmovups ymm6, [r9 + 0C0h]
    vmovups ymm7, [r9 + 0E0h]

    ALIGN 32
.unrolled_loop:
    ; 2. L1 Prefetch Hinting (fetch for future iterations)
    ; Prefetch cache-lines ahead on both streams
    prefetcht0 [rcx + 200h]
    prefetcht0 [rdx + 200h]

    ; 3. Interleaved execution wave (8 Independent FMA chains)
    ; Transient streaming loads to YMM8-YMM15 to feed the MAC
    vmovups ymm8, [rdx + 000h]
    vfmadd231ps ymm0, ymm8, [rcx + 000h]  ; Chain 1

    vmovups ymm9, [rdx + 020h]
    vfmadd231ps ymm1, ymm9, [rcx + 020h]  ; Chain 2

    vmovups ymm10, [rdx + 040h]
    vfmadd231ps ymm2, ymm10, [rcx + 040h] ; Chain 3

    vmovups ymm11, [rdx + 060h]
    vfmadd231ps ymm3, ymm11, [rcx + 060h] ; Chain 4

    vmovups ymm12, [rdx + 080h]
    vfmadd231ps ymm4, ymm12, [rcx + 080h] ; Chain 5

    vmovups ymm13, [rdx + 0A0h]
    vfmadd231ps ymm5, ymm13, [rcx + 0A0h] ; Chain 6

    vmovups ymm14, [rdx + 0C0h]
    vfmadd231ps ymm6, ymm14, [rcx + 0C0h] ; Chain 7

    vmovups ymm15, [rdx + 0E0h]
    vfmadd231ps ymm7, ymm15, [rcx + 0E0h] ; Chain 8

    ; 4. Stride advancing (256 bytes per iteration)
    add rcx, 100h  
    add rdx, 100h  
    
    ; 5. Loop decrement
    dec r8
    jnz .unrolled_loop

    ; 6. Store out to the C++ AccumulatorState ABI Boundary
    vmovups [r9 + 000h], ymm0
    vmovups [r9 + 020h], ymm1
    vmovups [r9 + 040h], ymm2
    vmovups [r9 + 060h], ymm3
    vmovups [r9 + 080h], ymm4
    vmovups [r9 + 0A0h], ymm5
    vmovups [r9 + 0C0h], ymm6
    vmovups [r9 + 0E0h], ymm7

    ; Implicit vzeroupper recommended before returning to C++ compiler code
    ; depending on the surrounding mix of SSE/AVX
    vzeroupper
    ret

RunFused8WayKernel ENDP

END