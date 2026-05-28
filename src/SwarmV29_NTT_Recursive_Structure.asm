; ==============================================================================
; SwarmV29_NTT_Recursive_Structure.asm
; PHASE-29: Full Cooley-Tukey NTT Transform (Iterative, In-Place)
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Implements iterative Cooley-Tukey NTT with three nested loop layers:
;   1. Outer Loop (Stages):     1 to log2(N)
;   2. Middle Loop (Blocks):    Jump by 2*step_size
;   3. Inner Loop (Butterflies): Process pairs within each block
;
; NOTE: For maximum performance, the butterfly call should be inlined
; via a macro in production builds. The CALL/RET overhead is acceptable
; for clarity during integration testing.
; ==============================================================================

.code

; SwarmV29_NTT_Transform
; Inputs:
;   RCX = Pointer to coefficients (64-byte aligned, Input/Output buffer)
;   RDX = N (Size of transform, must be power of 2, e.g., 256)
;   R8  = Pointer to Twiddle Factor table (64-byte aligned, precomputed)
;   R9  = Q (Modulus)
;   [RSP+40] = Q_INV (Montgomery Constant)
;
; Clobbers: R10-R15, RAX, RBX, ZMM0-ZMM13
; Returns: void (transform done in-place)
; ==============================================================================
ALIGN 16
SwarmV29_NTT_Transform PROC PUBLIC
    mov r11, rdx                ; r11 = N
    mov r12, rcx                ; r12 = buffer pointer
    mov r13, 1                  ; r13 = step_size = 1

    ; Load Q and Q_INV into R9/R10 for butterfly calls
    mov r10, [rsp + 40]         ; r10 = Q_INV

; --- Stage Loop: step_size doubles each iteration ---
stage_loop:
    cmp r13, r11
    jge done_ntt

    ; --- Block Loop: iterate through polynomial ---
    mov r14, 0                  ; r14 = block index

block_loop:
    cmp r14, r11
    jge next_stage

    ; --- Butterfly Loop: process pairs within block ---
    mov r15, 0                  ; r15 = butterfly index within block

butterfly_loop:
    cmp r15, r13
    jge end_butterfly_loop

    ; Address calculation for A and B
    mov rax, r14                ; rax = block start
    add rax, r15                ; rax = A index

    mov rbx, rax
    add rbx, r13                ; rbx = B index (A + step_size)

    ; Load coefficients from aligned memory
    vmovdqa64 zmm0, [r12 + rax*8]   ; A = buffer[A_index]
    vmovdqa64 zmm1, [r12 + rbx*8]   ; B = buffer[B_index]

    ; Fetch twiddle factor from aligned table
    vmovdqa64 zmm2, [r8 + r15*8]    ; W = twiddle_table[butterfly_idx]

    ; Execute butterfly (branchless, constant-time)
    call SwarmV29_NTT_Butterfly

    ; Store results back to aligned memory
    vmovdqa64 [r12 + rax*8], zmm0   ; buffer[A_index] = A'
    vmovdqa64 [r12 + rbx*8], zmm1   ; buffer[B_index] = B'

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

; ==============================================================================
; SwarmV29_NTT_Butterfly (External Reference)
; This is declared in SwarmV29_NTT_Butterfly.asm and linked together.
; For single-obj builds, include both files or use EXTERN.
; ==============================================================================
EXTERN SwarmV29_NTT_Butterfly : PROC

END
