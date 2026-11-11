; LoRA Optimized Kernel - Phase 20
; ApplyLoRA_Optimized.asm
; ============================================================================
; High-performance LoRA inference kernel with:
; - 4x loop unrolling for FMA latency hiding
; - Register blocking with YMM registers (AVX2)
; - Software prefetching (PREFETCHT0)
; - 64-byte aligned memory access
; - Tiled computation for L1 cache residency
;
; Target: < 10ms for rank=8, hidden_dim=768
; ============================================================================

; Constants
CACHE_LINE_SIZE     EQU 64
L1_CACHE_SIZE       EQU 32768    ; 32KB L1 data cache
TILE_SIZE_A         EQU 256      ; A matrix tile (fits in L1)
TILE_SIZE_B         EQU 256      ; B matrix tile (fits in L1)
UNROLL_FACTOR       EQU 4        ; Unroll inner loop by 4

; Offsets in LoRABeaconState (must match C++ struct)
BEACON_RANK         EQU 8
BEACON_HIDDEN_DIM   EQU 12
BEACON_PTR_A        EQU 16
BEACON_PTR_B        EQU 24
BEACON_SCALE        EQU 32
BEACON_NEXT         EQU 40

; ============================================================================
; Macro: PREFETCH_MATRIX_BLOCK
; Purpose: Prefetch next matrix block into L1 cache
; Input:  addr = address to prefetch
; ============================================================================
PREFETCH_MATRIX_BLOCK MACRO addr
    prefetcht0 [addr]           ; Prefetch to L1
ENDM

; ============================================================================
; Macro: COMPUTE_LORA_TILE
; Purpose: Compute LoRA for a single tile with 4x unrolling
; Input:  R8  = A matrix pointer (tile start)
;         R9  = B matrix pointer (tile start)
;         R10 = input vector pointer
;         R11 = output accumulator pointer
;         R12D = tile_rows (number of rows in this tile)
;         R13D = tile_cols (number of cols in this tile)
;         R14D = rank
;         XMM15 = scale factor
; Clobbers: YMM0-YMM14, RAX-RDX
; ============================================================================
COMPUTE_LORA_TILE MACRO
    LOCAL row_loop, col_loop, process_remainder, compute_output, tile_done
    
    ; Outer loop: over output rows (hidden_dim)
row_loop:
    cmp     r12d, 0
    jle     tile_done
    
    ; Initialize accumulators for 4 output elements
    vxorps  ymm0, ymm0, ymm0      ; acc[0]
    vxorps  ymm1, ymm1, ymm1      ; acc[1]
    vxorps  ymm2, ymm2, ymm2      ; acc[2]
    vxorps  ymm3, ymm3, ymm3      ; acc[3]
    
    ; Inner loop: over rank with 4x unrolling
    mov     ecx, r14d             ; ECX = rank counter
    xor     edx, edx              ; EDX = rank index
    
    ; Prefetch next A block
    lea     rax, [r8 + TILE_SIZE_A * 4]
    PREFETCH_MATRIX_BLOCK rax
    
col_loop:
    cmp     ecx, UNROLL_FACTOR
    jl      process_remainder
    
    ; Unrolled rank loop - process 4 rank elements at once
    ; This hides FMA latency (4-6 cycles) by having independent chains
    
    ; Load input[r+0..r+3]
    vbroadcastss ymm4, dword ptr [r10 + rdx*4 + 0*4]
    vbroadcastss ymm5, dword ptr [r10 + rdx*4 + 1*4]
    vbroadcastss ymm6, dword ptr [r10 + rdx*4 + 2*4]
    vbroadcastss ymm7, dword ptr [r10 + rdx*4 + 3*4]
    
    ; Load A[row, r+0..r+3] - 4 consecutive elements
    ; Use 32-bit index for scaled addressing
    vmovups ymm8,  [r8 + rdx*4]           ; A[row][r:r+7]
    vmovups ymm9,  [r8 + rdx*4 + 32]      ; A[row][r+8:r+15]
    vmovups ymm10, [r8 + rdx*4 + 64]      ; etc
    vmovups ymm11, [r8 + rdx*4 + 96]
    
    ; FMA: acc += A[row][r] * input[r] (4 independent chains)
    vfmadd231ps ymm0, ymm8,  ymm4   ; acc0 += A[row][r+0..7] * input[r+0]
    vfmadd231ps ymm1, ymm9,  ymm5   ; acc1 += A[row][r+8..15] * input[r+1]
    vfmadd231ps ymm2, ymm10, ymm6   ; acc2 += ...
    vfmadd231ps ymm3, ymm11, ymm7   ; acc3 += ...
    
    add     edx, UNROLL_FACTOR
    sub     ecx, UNROLL_FACTOR
    jmp     col_loop
    
process_remainder:
    ; Handle remaining rank elements (if rank % 4 != 0)
    test    ecx, ecx
    jz      compute_output
    
    ; Process remaining elements one at a time
    vbroadcastss ymm4, dword ptr [r10 + rdx*4]
    vmovups      ymm5, [r8 + rdx*4]
    vfmadd231ps  ymm0, ymm5, ymm4
    inc     edx
    dec     ecx
    jmp     process_remainder
    
compute_output:
    ; Now compute: output[row] += scale * (B[row] dot temp)
    ; where temp = A[row] dot input (stored in ymm0-ymm3)
    
    ; Horizontal sum of ymm0-ymm3 into single value
    vaddps  ymm0, ymm0, ymm1
    vaddps  ymm2, ymm2, ymm3
    vaddps  ymm0, ymm0, ymm2
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; xmm0 now contains temp = A[row] dot input
    
    ; Load B[row, :] and compute dot with temp
    ; For rank=8, B[row] is 8 floats
    vmovups ymm2, [r9]            ; Load B[row][0:7]
    vbroadcastss ymm3, xmm0       ; Broadcast temp to all elements
    vmulps  ymm2, ymm2, ymm3      ; B[row][i] * temp
    
    ; Apply scale
    vmulps  ymm2, ymm2, ymm15    ; scale * B[row][i] * temp
    
    ; Add to output (accumulate)
    vaddps  ymm0, ymm2, [r11]     ; Load current output and add
    vmovups [r11], ymm0           ; Store back
    
    ; Advance pointers
    mov     eax, r14d
    shl     rax, 2                ; rank * 4
    add     r8, rax               ; Next row of A
    add     r9, rax               ; Next row of B
    add     r11, 32               ; Next 8 output elements
    dec     r12d
    jmp     row_loop
    
tile_done:
ENDM

; ============================================================================
; Code Segment
; ============================================================================
.CODE

; ============================================================================
; Function: ApplyLoRA_Optimized
; Purpose: Optimized LoRA application with tiling and prefetching
; Input:  RCX = base_output pointer (W_0 * x)
;         RDX = input pointer (x)
;         R8  = result pointer (output accumulator)
;         R9  = beacon state pointer
;         R10 = token_count
; Output: Result accumulated in R8
; ============================================================================
ApplyLoRA_Optimized PROC FRAME
    push    rbp
    .pushreg rbp
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
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64                 ; Local storage + alignment
    .allocstack 64
    .endprolog
    
    ; Load beacon parameters
    mov     r15, r9                 ; R15 = beacon state
    mov     eax, dword ptr [r15 + BEACON_RANK]
    mov     r14d, eax               ; R14D = rank
    mov     eax, dword ptr [r15 + BEACON_HIDDEN_DIM]
    mov     r13d, eax               ; R13D = hidden_dim
    
    ; Load matrix pointers
    mov     r12, qword ptr [r15 + BEACON_PTR_A]  ; R12 = A
    mov     r11, qword ptr [r15 + BEACON_PTR_B]  ; R11 = B
    
    ; Load scale factor
    vbroadcastss ymm15, dword ptr [r15 + BEACON_SCALE]
    
    ; Initialize result with base_output
    mov     rsi, rcx                ; RSI = base_output
    mov     rdi, r8               ; RDI = result
    mov     rcx, r10              ; RCX = token_count
    imul    rcx, r13              ; RCX = token_count * hidden_dim
    ; Copy base to result
    rep movsd
    
    ; Restore pointers after rep movsd
    mov     r10, rdx              ; R10 = input
    mov     r11, r8               ; R11 = result (save before we clobber r8)
    mov     r8, r12               ; R8 = A
    mov     r9, qword ptr [r15 + BEACON_PTR_B]  ; R9 = B (reload from beacon)
    
    ; Compute number of tiles
    mov     eax, r13d
    xor     edx, edx
    mov     ecx, TILE_SIZE_B
    div     ecx                   ; EAX = num_tiles, EDX = remainder
    mov     r12d, eax             ; R12D = tile count
    
    ; Process tiles
    test    r12d, r12d
    jz      process_remainder_rows
    
tile_loop:
    push    r12                   ; Save tile counter
    
    ; Prefetch next tile
    mov     eax, r12d
    dec     eax
    jz      skip_prefetch
    mov     rax, r14
    imul    rax, TILE_SIZE_A * 4
    add     rax, r8
    PREFETCH_MATRIX_BLOCK rax
    mov     rax, r14
    imul    rax, TILE_SIZE_B * 4
    add     rax, r9
    PREFETCH_MATRIX_BLOCK rax
    
skip_prefetch:
    ; Process this tile - INLINED from COMPUTE_LORA_TILE macro
    ; R12D = tile rows, R13D = rank, R14D = rank (preserved)
    
    ; Set row counter for this tile
    mov     r12d, TILE_SIZE_B     ; R12D = rows to process in this tile
    
tile_row_loop:
    cmp     r12d, 0
    jle     tile_complete
    
    ; Initialize accumulators
    vxorps  ymm0, ymm0, ymm0
    vxorps  ymm1, ymm1, ymm1
    vxorps  ymm2, ymm2, ymm2
    vxorps  ymm3, ymm3, ymm3
    
    ; Inner loop over rank
    mov     ecx, r14d
    xor     edx, edx
    
tile_col_loop:
    cmp     ecx, 4
    jl      tile_process_remainder
    
    vbroadcastss ymm4, dword ptr [r10 + rdx*4 + 0*4]
    vbroadcastss ymm5, dword ptr [r10 + rdx*4 + 1*4]
    vbroadcastss ymm6, dword ptr [r10 + rdx*4 + 2*4]
    vbroadcastss ymm7, dword ptr [r10 + rdx*4 + 3*4]
    
    vmovups ymm8,  [r8 + rdx*4 + 0*32]
    vmovups ymm9,  [r8 + rdx*4 + 1*32]
    vmovups ymm10, [r8 + rdx*4 + 2*32]
    vmovups ymm11, [r8 + rdx*4 + 3*32]
    
    vfmadd231ps ymm0, ymm8,  ymm4
    vfmadd231ps ymm1, ymm9,  ymm5
    vfmadd231ps ymm2, ymm10, ymm6
    vfmadd231ps ymm3, ymm11, ymm7
    
    add     edx, 4
    sub     ecx, 4
    jmp     tile_col_loop
    
tile_process_remainder:
    test    ecx, ecx
    jz      tile_compute_output
    vbroadcastss ymm4, dword ptr [r10 + rdx*4]
    vmovups      ymm5, [r8 + rdx*4]
    vfmadd231ps  ymm0, ymm5, ymm4
    inc     edx
    dec     ecx
    jmp     tile_process_remainder
    
tile_compute_output:
    vaddps  ymm0, ymm0, ymm1
    vaddps  ymm2, ymm2, ymm3
    vaddps  ymm0, ymm0, ymm2
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    vmovups ymm2, [r9]
    vbroadcastss ymm3, xmm0
    vmulps  ymm2, ymm2, ymm3
    vmulps  ymm2, ymm2, ymm15
    vaddps  ymm0, ymm2, [r11]
    vmovups [r11], ymm0
    
    mov     eax, r14d
    shl     rax, 2
    add     r8, rax
    add     r9, rax
    add     r11, 32
    dec     r12d
    jmp     tile_row_loop
    
tile_complete:
    pop     r12
    dec     r12d
    jnz     tile_loop
    
process_remainder_rows:
    mov     eax, r13d
    and     eax, (TILE_SIZE_B - 1)
    jz      done
    
    mov     r12d, eax
    mov     r13d, r14d
    ; Remainder processing - same as tile processing above
    
rem_row_loop:
    cmp     r12d, 0
    jle     done
    
    vxorps  ymm0, ymm0, ymm0
    vxorps  ymm1, ymm1, ymm1
    vxorps  ymm2, ymm2, ymm2
    vxorps  ymm3, ymm3, ymm3
    
    mov     ecx, r14d
    xor     edx, edx
    
rem_col_loop:
    cmp     ecx, 4
    jl      rem_process_remainder
    
    vbroadcastss ymm4, dword ptr [r10 + rdx*4 + 0*4]
    vbroadcastss ymm5, dword ptr [r10 + rdx*4 + 1*4]
    vbroadcastss ymm6, dword ptr [r10 + rdx*4 + 2*4]
    vbroadcastss ymm7, dword ptr [r10 + rdx*4 + 3*4]
    
    vmovups ymm8,  [r8 + rdx*4]
    vmovups ymm9,  [r8 + rdx*4 + 32]
    vmovups ymm10, [r8 + rdx*4 + 64]
    vmovups ymm11, [r8 + rdx*4 + 96]
    
    vfmadd231ps ymm0, ymm8,  ymm4
    vfmadd231ps ymm1, ymm9,  ymm5
    vfmadd231ps ymm2, ymm10, ymm6
    vfmadd231ps ymm3, ymm11, ymm7
    
    add     edx, 4
    sub     ecx, 4
    jmp     rem_col_loop
    
rem_process_remainder:
    test    ecx, ecx
    jz      rem_compute_output
    vbroadcastss ymm4, dword ptr [r10 + rdx*4]
    vmovups      ymm5, [r8 + rdx*4]
    vfmadd231ps  ymm0, ymm5, ymm4
    inc     edx
    dec     ecx
    jmp     rem_process_remainder
    
rem_compute_output:
    vaddps  ymm0, ymm0, ymm1
    vaddps  ymm2, ymm2, ymm3
    vaddps  ymm0, ymm0, ymm2
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    vmovups ymm2, [r9]
    vbroadcastss ymm3, xmm0
    vmulps  ymm2, ymm2, ymm3
    vmulps  ymm2, ymm2, ymm15
    vaddps  ymm0, ymm2, [r11]
    vmovups [r11], ymm0
    
    mov     eax, r14d
    shl     rax, 2
    add     r8, rax
    add     r9, rax
    add     r11, 32
    dec     r12d
    jmp     rem_row_loop
    
done:
    ; Cleanup
    vzeroupper                      ; Clear upper YMM bits
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    xor     rax, rax                ; Return 0 (success)
    ret
ApplyLoRA_Optimized ENDP

; ============================================================================
; Function: ApplyLoRA_Chain_Optimized
; Purpose: Optimized chain traversal with prefetching
; Input:  RCX = base_output pointer
;         RDX = input pointer
;         R8  = result pointer
;         R9  = chain head pointer
;         R10 = token_count
; Output: Result in R8
; ============================================================================
ApplyLoRA_Chain_Optimized PROC FRAME
    push    rbp
    .pushreg rbp
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
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    ; Initialize result with base
    mov     rsi, rcx
    mov     rdi, r8
    mov     rcx, r10
    imul    rcx, qword ptr [r9 + BEACON_HIDDEN_DIM]
    rep movsd
    
    ; R15 = current beacon, R14 = next beacon
    mov     r15, r9
    mov     r14, qword ptr [r15 + BEACON_NEXT]
    
chain_loop:
    test    r15, r15
    jz      chain_done
    
    ; Prefetch next beacon's matrices
    test    r14, r14
    jz      skip_chain_prefetch
    mov     rax, qword ptr [r14 + BEACON_PTR_A]
    PREFETCH_MATRIX_BLOCK rax
    mov     rax, qword ptr [r14 + BEACON_PTR_B]
    PREFETCH_MATRIX_BLOCK rax
    
skip_chain_prefetch:
    ; Apply current beacon (additive)
    mov     rcx, r8               ; result (accumulator)
    mov     rdx, rdx              ; input
    mov     r9, r15               ; beacon
    mov     r10, r10            ; token_count
    call    ApplyLoRA_Optimized
    
    ; Move to next beacon
    mov     r15, r14
    mov     r14, qword ptr [r15 + BEACON_NEXT]
    jmp     chain_loop
    
chain_done:
    vzeroupper
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    xor     rax, rax
    ret
ApplyLoRA_Chain_Optimized ENDP

END
