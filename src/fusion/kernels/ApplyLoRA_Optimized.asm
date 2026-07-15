; Phase 20: Optimized LoRA Kernel with Loop Unrolling and Prefetching
; ApplyLoRA_Optimized.asm - High-performance FMA throughput target
;
; Optimization targets:
;   - Loop unrolling (factor 8) to reduce branch overhead
;   - AVX-512 FMA (vfmadd231ps) for 16 floats/cycle
;   - Memory prefetching (prefetcht0) for L1 cache
;   - Target: <42M cycles (10ms @ 4.2GHz) for 1M elements
;
; Mathematical operation: h = W0x + alpha * (B * A * x)
;
; Build: ml64.exe /c /W3 /Zd /Zi ApplyLoRA_Optimized.asm

; External C++ symbols
EXTERN g_loraContextBeacon:QWORD

; Constants
LORA_FLAG_READY     EQU 00000001h
LORA_FLAG_AVX512    EQU 00000002h
LORA_FLAG_FMA3      EQU 00000004h
LORA_FLAG_VALID     EQU 80000000h

; Structure offsets (must match LoRAContext.h)
LOCTX_ALPHA         EQU 0
LOCTX_RANK          EQU 4
LOCTX_INPUT_DIM     EQU 8
LOCTX_FLAGS         EQU 12
LOCTX_MATRIX_A      EQU 16
LOCTX_MATRIX_B      EQU 24
LOCTX_ACTIVE        EQU 32

; Uninitialized data segment for cache line optimization
.data?
lora_temp_buffer    REAL4 64 DUP(?)      ; Temporary buffer for Ax (max rank 64)
scratch_pad         REAL4 64 DUP(?)      ; Scratch space for prefetching

.code

; =============================================================================
; ApplyLoRA_Optimized - High-performance entry point
; =============================================================================
; C++ prototype: void ApplyLoRA_Optimized(float* output, const float* input, int64_t dim)
; RCX = output buffer (W0x + delta)
; RDX = input vector x
; R8  = dimension d
;
; Returns: Nothing (modifies output in place)
; =============================================================================
ApplyLoRA_Optimized PROC FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 128
    .allocstack 128
    .endprolog

    ; Check if LoRA is active via beacon
    mov     rax, g_loraContextBeacon
    test    rax, rax
    jz      @@done                      ; No beacon, nothing to do
    
    mov     r15, rax                    ; R15 = LoRAContext pointer
    
    ; Check active flag
    cmp     QWORD PTR [r15 + LOCTX_ACTIVE], 0
    je      @@done                      ; Not active
    
    ; Check flags
    mov     eax, [r15 + LOCTX_FLAGS]
    test    eax, LORA_FLAG_VALID
    jz      @@done                      ; Invalid context
    test    eax, LORA_FLAG_READY
    jz      @@done                      ; Not ready
    
    ; Load parameters
    movss   xmm0, REAL4 PTR [r15 + LOCTX_ALPHA]     ; XMM0 = alpha
    vbroadcastss zmm0, xmm0                         ; ZMM0 = alpha (broadcasted)
    
    mov     r12d, [r15 + LOCTX_RANK]                ; R12 = rank r
    mov     r13d, [r15 + LOCTX_INPUT_DIM]           ; R13 = input dim d
    
    mov     r14, [r15 + LOCTX_MATRIX_A]             ; R14 = matrix A pointer
    mov     r15, [r15 + LOCTX_MATRIX_B]             ; R15 = matrix B pointer
    
    mov     rbx, rcx                                ; RBX = output buffer
    mov     r11, rdx                                ; R11 = input vector

    ; =================================================================
    ; Step 1: Compute x' = A * x (down-projection with unrolling)
    ; =================================================================
    
    xor     r8d, r8d                                ; R8 = row index
    
@@row_loop:
    cmp     r8d, r12d
    jge     @@projection_done
    
    ; Initialize 8 accumulators for unrolled loop
    vxorps  zmm1, zmm1, zmm1                        ; Accumulator 1
    vxorps  zmm2, zmm2, zmm2                        ; Accumulator 2
    vxorps  zmm3, zmm3, zmm3                        ; Accumulator 3
    vxorps  zmm4, zmm4, zmm4                        ; Accumulator 4
    vxorps  zmm5, zmm5, zmm5                        ; Accumulator 5
    vxorps  zmm6, zmm6, zmm6                        ; Accumulator 6
    vxorps  zmm7, zmm7, zmm7                        ; Accumulator 7
    vxorps  zmm8, zmm8, zmm8                        ; Accumulator 8
    
    ; Compute dot product with 8x unrolling
    xor     r9d, r9d                                ; R9 = column index
    mov     r10d, r13d
    and     r10d, NOT 127                           ; R10 = dim rounded down to 128
    
@@col_loop_unrolled:
    cmp     r9d, r10d
    jge     @@col_loop_remainder
    
    ; Prefetch next cache line (8 cache lines ahead)
    prefetcht0 [r14 + r9*4 + 512]
    prefetcht0 [r11 + r9*4 + 512]
    
    ; Unrolled 8x: Process 128 floats (8 * 16) per iteration
    ; Each iteration: 8 FMAs * 16 floats = 128 FLOPs
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 0]     ; A[row][0:15]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 0]     ; x[0:15]
    vfmadd231ps zmm1, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 64]    ; A[row][16:31]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 64]    ; x[16:31]
    vfmadd231ps zmm2, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 128]   ; A[row][32:47]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 128]   ; x[32:47]
    vfmadd231ps zmm3, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 192]   ; A[row][48:63]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 192]   ; x[48:63]
    vfmadd231ps zmm4, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 256]   ; A[row][64:79]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 256]   ; x[64:79]
    vfmadd231ps zmm5, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 320]   ; A[row][80:95]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 320]   ; x[80:95]
    vfmadd231ps zmm6, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 384]   ; A[row][96:111]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 384]   ; x[96:111]
    vfmadd231ps zmm7, zmm9, zmm10
    
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4 + 448]   ; A[row][112:127]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4 + 448]   ; x[112:127]
    vfmadd231ps zmm8, zmm9, zmm10
    
    add     r9d, 128
    jmp     @@col_loop_unrolled
    
@@col_loop_remainder:
    ; Handle remaining elements (less than 128)
    cmp     r9d, r13d
    jge     @@sum_accumulators
    
@@col_loop_scalar:
    vmovups zmm9,  ZMMWORD PTR [r14 + r9*4]
    vmovups zmm10, ZMMWORD PTR [r11 + r9*4]
    vfmadd231ps zmm1, zmm9, zmm10
    
    add     r9d, 16
    cmp     r9d, r13d
    jl      @@col_loop_scalar
    
@@sum_accumulators:
    ; Sum all 8 accumulators into zmm1
    vaddps  zmm1, zmm1, zmm2
    vaddps  zmm3, zmm3, zmm4
    vaddps  zmm5, zmm5, zmm6
    vaddps  zmm7, zmm7, zmm8
    vaddps  zmm1, zmm1, zmm3
    vaddps  zmm5, zmm5, zmm7
    vaddps  zmm1, zmm1, zmm5
    
    ; Horizontal sum of zmm1 into single float
    vextractf64x4 ymm2, zmm1, 1                    ; Extract high 256 bits
    vaddps  ymm1, ymm1, ymm2                      ; Add high to low
    vextractf128 xmm2, ymm1, 1                    ; Extract high 128 bits
    vaddps  xmm1, xmm1, xmm2                      ; Add high to low
    vhaddps xmm1, xmm1, xmm1                      ; Horizontal add
    vhaddps xmm1, xmm1, xmm1                      ; Final horizontal add
    
    ; Store result in temp buffer (use R15 as temp buffer pointer)
    lea     rax, lora_temp_buffer
    movss   REAL4 PTR [rax + r8*4], xmm1
    
    ; Move to next row of A
    mov     eax, r13d
    shl     eax, 2                                  ; EAX = d * 4
    add     r14, rax                                ; R14 = next row of A
    
    inc     r8d
    jmp     @@row_loop
    
@@projection_done:
    
    ; =================================================================
    ; Step 2: Compute delta = alpha * B * x' (up-projection with unrolling)
    ; =================================================================
    
    xor     r8d, r8d                                ; R8 = output index
    mov     r10d, r13d
    and     r10d, NOT 127                           ; R10 = dim rounded down to 128
    
@@output_loop_unrolled:
    cmp     r8d, r10d
    jge     @@output_loop_remainder
    
    ; Prefetch output buffer
    prefetcht0 [rbx + r8*4 + 512]
    
    ; Initialize 8 accumulators
    vxorps  zmm1, zmm1, zmm1
    vxorps  zmm2, zmm2, zmm2
    vxorps  zmm3, zmm3, zmm3
    vxorps  zmm4, zmm4, zmm4
    vxorps  zmm5, zmm5, zmm5
    vxorps  zmm6, zmm6, zmm6
    vxorps  zmm7, zmm7, zmm7
    vxorps  zmm8, zmm8, zmm8
    
    ; Compute 8 output elements simultaneously
    ; Each processes 16 floats from B and x'
    xor     r9d, r9d                                ; R9 = rank index
    
@@rank_loop_unrolled:
    cmp     r9d, r12d
    jge     @@rank_done
    
    ; Load x'[rank] once, broadcast to all accumulators
    lea     rcx, lora_temp_buffer
    vbroadcastss zmm9, REAL4 PTR [rcx + r9*4]
    
    ; B is (d x r), so B[row][rank] = B + (row * r + rank) * 4
    ; For unrolled output, we compute 8 rows at once
    
    mov     eax, r8d
    imul    eax, r12d
    add     eax, r9d
    
    ; Row 0
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm1, zmm10, zmm9
    
    ; Row 1
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm2, zmm10, zmm9
    
    ; Row 2
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm3, zmm10, zmm9
    
    ; Row 3
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm4, zmm10, zmm9
    
    ; Row 4
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm5, zmm10, zmm9
    
    ; Row 5
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm6, zmm10, zmm9
    
    ; Row 6
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm7, zmm10, zmm9
    
    ; Row 7
    add     eax, r12d
    vbroadcastss zmm10, REAL4 PTR [r15 + rax*4]
    vfmadd231ps zmm8, zmm10, zmm9
    
    inc     r9d
    jmp     @@rank_loop_unrolled
    
@@rank_done:
    ; Scale by alpha
    vmulps  zmm1, zmm1, zmm0
    vmulps  zmm2, zmm2, zmm0
    vmulps  zmm3, zmm3, zmm0
    vmulps  zmm4, zmm4, zmm0
    vmulps  zmm5, zmm5, zmm0
    vmulps  zmm6, zmm6, zmm0
    vmulps  zmm7, zmm7, zmm0
    vmulps  zmm8, zmm8, zmm0
    
    ; Load current output and add delta
    vmovups zmm9,  ZMMWORD PTR [rbx + r8*4 + 0]
    vmovups zmm10, ZMMWORD PTR [rbx + r8*4 + 64]
    vmovups zmm11, ZMMWORD PTR [rbx + r8*4 + 128]
    vmovups zmm12, ZMMWORD PTR [rbx + r8*4 + 192]
    vmovups zmm13, ZMMWORD PTR [rbx + r8*4 + 256]
    vmovups zmm14, ZMMWORD PTR [rbx + r8*4 + 320]
    vmovups zmm15, ZMMWORD PTR [rbx + r8*4 + 384]
    vmovups zmm16, ZMMWORD PTR [rbx + r8*4 + 448]
    
    vaddps  zmm9,  zmm9,  zmm1
    vaddps  zmm10, zmm10, zmm2
    vaddps  zmm11, zmm11, zmm3
    vaddps  zmm12, zmm12, zmm4
    vaddps  zmm13, zmm13, zmm5
    vaddps  zmm14, zmm14, zmm6
    vaddps  zmm15, zmm15, zmm7
    vaddps  zmm16, zmm16, zmm8
    
    vmovups ZMMWORD PTR [rbx + r8*4 + 0],   zmm9
    vmovups ZMMWORD PTR [rbx + r8*4 + 64],  zmm10
    vmovups ZMMWORD PTR [rbx + r8*4 + 128], zmm11
    vmovups ZMMWORD PTR [rbx + r8*4 + 192], zmm12
    vmovups ZMMWORD PTR [rbx + r8*4 + 256], zmm13
    vmovups ZMMWORD PTR [rbx + r8*4 + 320], zmm14
    vmovups ZMMWORD PTR [rbx + r8*4 + 384], zmm15
    vmovups ZMMWORD PTR [rbx + r8*4 + 448], zmm16
    
    add     r8d, 128
    jmp     @@output_loop_unrolled
    
@@output_loop_remainder:
    ; Handle remaining elements
    cmp     r8d, r13d
    jge     @@done
    
@@output_loop_scalar:
    vxorps  zmm1, zmm1, zmm1
    xor     r9d, r9d
    
@@rank_loop_scalar:
    cmp     r9d, r12d
    jge     @@store_scalar
    
    mov     eax, r8d
    imul    eax, r12d
    add     eax, r9d
    
    vbroadcastss zmm2, REAL4 PTR [r15 + rax*4]
    lea     rcx, lora_temp_buffer
    vbroadcastss zmm3, REAL4 PTR [rcx + r9*4]
    vfmadd231ps zmm1, zmm2, zmm3
    
    inc     r9d
    jmp     @@rank_loop_scalar
    
@@store_scalar:
    vmulps  zmm1, zmm1, zmm0
    vmovups zmm2, ZMMWORD PTR [rbx + r8*4]
    vaddps  zmm2, zmm2, zmm1
    vmovups ZMMWORD PTR [rbx + r8*4], zmm2
    
    add     r8d, 16
    cmp     r8d, r13d
    jl      @@output_loop_scalar
    
@@done:
    ; Restore non-volatile registers
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

ApplyLoRA_Optimized ENDP

; =============================================================================
; ApplyLoRA_Baseline - Original implementation for comparison
; =============================================================================
ApplyLoRA_Baseline PROC FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 128
    .allocstack 128
    .endprolog

    ; Check if LoRA is active
    mov     rax, g_loraContextBeacon
    test    rax, rax
    jz      @@baseline_done
    
    mov     r15, rax
    cmp     QWORD PTR [r15 + LOCTX_ACTIVE], 0
    je      @@baseline_done
    
    mov     eax, [r15 + LOCTX_FLAGS]
    test    eax, LORA_FLAG_VALID
    jz      @@baseline_done
    test    eax, LORA_FLAG_READY
    jz      @@baseline_done
    
    ; Load parameters
    movss   xmm0, REAL4 PTR [r15 + LOCTX_ALPHA]
    vbroadcastss zmm0, xmm0
    
    mov     r12d, [r15 + LOCTX_RANK]
    mov     r13d, [r15 + LOCTX_INPUT_DIM]
    
    mov     r14, [r15 + LOCTX_MATRIX_A]
    mov     r15, [r15 + LOCTX_MATRIX_B]
    
    mov     rbx, rcx
    mov     r11, rdx
    
    ; Simple baseline implementation
    xor     r8d, r8d
    
@@baseline_row_loop:
    cmp     r8d, r12d
    jge     @@baseline_projection_done
    
    vxorps  zmm1, zmm1, zmm1
    xor     r9d, r9d
    
@@baseline_col_loop:
    cmp     r9d, r13d
    jge     @@baseline_row_done
    
    vmovups zmm2, ZMMWORD PTR [r14 + r9*4]
    vmovups zmm3, ZMMWORD PTR [r11 + r9*4]
    vfmadd231ps zmm1, zmm2, zmm3
    
    add     r9d, 16
    jmp     @@baseline_col_loop
    
@@baseline_row_done:
    vextractf64x4 ymm2, zmm1, 1
    vaddps  ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    
    lea     rax, lora_temp_buffer
    movss   REAL4 PTR [rax + r8*4], xmm1
    
    mov     eax, r13d
    shl     eax, 2
    add     r14, rax
    inc     r8d
    jmp     @@baseline_row_loop
    
@@baseline_projection_done:
    xor     r8d, r8d
    
@@baseline_output_loop:
    cmp     r8d, r13d
    jge     @@baseline_done
    
    vxorps  zmm1, zmm1, zmm1
    xor     r9d, r9d
    
@@baseline_rank_loop:
    cmp     r9d, r12d
    jge     @@baseline_scale
    
    mov     eax, r8d
    imul    eax, r12d
    add     eax, r9d
    
    vbroadcastss zmm2, REAL4 PTR [r15 + rax*4]
    lea     rcx, lora_temp_buffer
    vbroadcastss zmm3, REAL4 PTR [rcx + r9*4]
    vfmadd231ps zmm1, zmm2, zmm3
    
    inc     r9d
    jmp     @@baseline_rank_loop
    
@@baseline_scale:
    vmulps  zmm1, zmm1, zmm0
    vmovups zmm2, ZMMWORD PTR [rbx + r8*4]
    vaddps  zmm2, zmm2, zmm1
    vmovups ZMMWORD PTR [rbx + r8*4], zmm2
    
    add     r8d, 16
    jmp     @@baseline_output_loop
    
@@baseline_done:
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

ApplyLoRA_Baseline ENDP

END
