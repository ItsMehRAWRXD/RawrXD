; Phase 18C.2: LoRA Forward Pass Kernel (MASM x64)
; ApplyLoRA.asm - Vectorized matrix multiplication for LoRA adaptation
;
; Mathematical operation: h = W0x + alpha * (B * A * x)
; Where:
;   x = input vector (d-dimensional)
;   A = down-projection matrix (r x d)
;   B = up-projection matrix (d x r)
;   alpha = scaling factor
;
; This routine is called from the inference pipeline after W0x is computed
; and accumulates the LoRA delta into the output buffer.

include \masm64\include\rawrxd_win64.inc

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

; 32-byte aligned data segment
.data?
align 32
lora_temp_buffer    REAL4 64 DUP(?)      ; Temporary buffer for Ax (max rank 64)

.code

; =============================================================================
; ApplyLoRA_AVX512
; =============================================================================
; C++ prototype: void ApplyLoRA_AVX512(float* output, const float* input, int64_t dim)
; RCX = output buffer (W0x + delta)
; RDX = input vector x
; R8  = dimension d
;
; Returns: Nothing (modifies output in place)
; =============================================================================
ApplyLoRA_AVX512 PROC FRAME
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
    ; Step 1: Compute x' = A * x (down-projection)
    ; A is (r x d), x is (d), result x' is (r)
    ; =================================================================
    
    xor     r8d, r8d                                ; R8 = row index (0 to r-1)
    
@@row_loop:
    cmp     r8d, r12d
    jge     @@projection_done
    
    ; Initialize accumulator for this row
    vxorps  zmm1, zmm1, zmm1                        ; ZMM1 = accumulator (8 floats)
    
    ; Compute dot product of A[row] with x
    xor     r9d, r9d                                ; R9 = column index
    
@@col_loop_avx512:
    cmp     r9d, r13d
    jge     @@row_done
    
    ; Load 16 elements from A[row] and x
    vmovups zmm2, ZMMWORD PTR [r14 + r9*4]          ; ZMM2 = A[row][col:col+15]
    vmovups zmm3, ZMMWORD PTR [r11 + r9*4]          ; ZMM3 = x[col:col+15]
    
    ; FMA: accumulator += A * x
    vfmadd231ps zmm1, zmm2, zmm3
    
    add     r9d, 16
    jmp     @@col_loop_avx512
    
@@row_done:
    ; Horizontal sum of ZMM1 into single float
    vextractf64x4 ymm2, zmm1, 1                    ; Extract high 256 bits
    vaddps  ymm1, ymm1, ymm2                      ; Add high to low
    vextractf128 xmm2, ymm1, 1                    ; Extract high 128 bits
    vaddps  xmm1, xmm1, xmm2                      ; Add high to low
    vhaddps xmm1, xmm1, xmm1                      ; Horizontal add
    vhaddps xmm1, xmm1, xmm1                      ; Final horizontal add
    
    ; Store result in temp buffer
    movss   REAL4 PTR lora_temp_buffer[r8*4], xmm1
    
    ; Move to next row of A
    mov     eax, r13d
    shl     eax, 2                                  ; EAX = d * 4 (bytes per row)
    add     r14, rax                                ; R14 = next row of A
    
    inc     r8d
    jmp     @@row_loop
    
@@projection_done:
    
    ; =================================================================
    ; Step 2: Compute delta = alpha * B * x' (up-projection)
    ; B is (d x r), x' is (r), result is (d)
    ; =================================================================
    
    xor     r8d, r8d                                ; R8 = output index (0 to d-1)
    
@@output_loop:
    cmp     r8d, r13d
    jge     @@done
    
    ; Initialize accumulator
    vxorps  zmm1, zmm1, zmm1                        ; ZMM1 = accumulator
    
    ; Compute dot product of B[row] with x'
    ; B is stored column-major for better cache efficiency
    xor     r9d, r9d                                ; R9 = rank index
    
@@rank_loop:
    cmp     r9d, r12d
    jge     @@scale_and_store
    
    ; Load B[row][rank] and x'[rank]
    ; B is (d x r), so B[row][rank] = B + (row * r + rank) * 4
    mov     eax, r8d
    imul    eax, r12d                               ; EAX = row * r
    add     eax, r9d                                ; EAX = row * r + rank
    
    vbroadcastss zmm2, REAL4 PTR [r15 + rax*4]      ; ZMM2 = B[row][rank] (broadcasted)
    vbroadcastss zmm3, REAL4 PTR lora_temp_buffer[r9*4] ; ZMM3 = x'[rank] (broadcasted)
    
    ; FMA: accumulator += B * x'
    vfmadd231ps zmm1, zmm2, zmm3
    
    inc     r9d
    jmp     @@rank_loop
    
@@scale_and_store:
    ; Scale by alpha
    vmulps  zmm1, zmm1, zmm0                        ; ZMM1 *= alpha
    
    ; Load current output and add delta
    vmovups zmm2, ZMMWORD PTR [rbx + r8*4]          ; ZMM2 = output[row:row+15]
    vaddps  zmm2, zmm2, zmm1                        ; ZMM2 += delta
    vmovups ZMMWORD PTR [rbx + r8*4], zmm2          ; Store back
    
    add     r8d, 16
    jmp     @@output_loop
    
@@done:
    ; Restore state
    vzeroupper
    
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
    
ApplyLoRA_AVX512 ENDP

; =============================================================================
; ApplyLoRA_FMA3 (AVX2 version for older CPUs)
; =============================================================================
; Same interface as ApplyLoRA_AVX512 but uses 256-bit AVX2
; =============================================================================
ApplyLoRA_FMA3 PROC FRAME
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
    jz      @@done_fma3
    
    mov     r15, rax
    cmp     QWORD PTR [r15 + LOCTX_ACTIVE], 0
    je      @@done_fma3
    
    mov     eax, [r15 + LOCTX_FLAGS]
    test    eax, LORA_FLAG_VALID OR LORA_FLAG_READY
    jz      @@done_fma3
    
    ; Load parameters
    movss   xmm0, REAL4 PTR [r15 + LOCTX_ALPHA]
    vbroadcastss ymm0, xmm0
    
    mov     r12d, [r15 + LOCTX_RANK]
    mov     r13d, [r15 + LOCTX_INPUT_DIM]
    mov     r14, [r15 + LOCTX_MATRIX_A]
    mov     r15, [r15 + LOCTX_MATRIX_B]
    
    mov     rbx, rcx
    mov     r11, rdx
    
    ; Step 1: Compute x' = A * x (AVX2 version)
    xor     r8d, r8d
    
@@row_loop_fma3:
    cmp     r8d, r12d
    jge     @@projection_done_fma3
    
    vxorps  ymm1, ymm1, ymm1
    xor     r9d, r9d
    
@@col_loop_avx2:
    cmp     r9d, r13d
    jge     @@row_done_fma3
    
    vmovups ymm2, YMMWORD PTR [r14 + r9*4]
    vmovups ymm3, YMMWORD PTR [r11 + r9*4]
    vfmadd231ps ymm1, ymm2, ymm3
    
    add     r9d, 8
    jmp     @@col_loop_avx2
    
@@row_done_fma3:
    ; Horizontal sum
    vextractf128 xmm2, ymm1, 1
    vaddps  xmm1, xmm1, xmm2
    vhaddps xmm1, xmm1, xmm1
    vhaddps xmm1, xmm1, xmm1
    
    movss   REAL4 PTR lora_temp_buffer[r8*4], xmm1
    
    mov     eax, r13d
    shl     eax, 2
    add     r14, rax
    
    inc     r8d
    jmp     @@row_loop_fma3
    
@@projection_done_fma3:
    
    ; Step 2: Compute delta = alpha * B * x'
    xor     r8d, r8d
    
@@output_loop_fma3:
    cmp     r8d, r13d
    jge     @@done_fma3
    
    vxorps  ymm1, ymm1, ymm1
    xor     r9d, r9d
    
@@rank_loop_fma3:
    cmp     r9d, r12d
    jge     @@scale_and_store_fma3
    
    mov     eax, r8d
    imul    eax, r12d
    add     eax, r9d
    
    vbroadcastss ymm2, REAL4 PTR [r15 + rax*4]
    vbroadcastss ymm3, REAL4 PTR lora_temp_buffer[r9*4]
    
    vfmadd231ps ymm1, ymm2, ymm3
    
    inc     r9d
    jmp     @@rank_loop_fma3
    
@@scale_and_store_fma3:
    vmulps  ymm1, ymm1, ymm0
    
    vmovups ymm2, YMMWORD PTR [rbx + r8*4]
    vaddps  ymm2, ymm2, ymm1
    vmovups YMMWORD PTR [rbx + r8*4], ymm2
    
    add     r8d, 8
    jmp     @@output_loop_fma3
    
@@done_fma3:
    vzeroupper
    
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
    
ApplyLoRA_FMA3 ENDP

; =============================================================================
; LoRA_Dispatch - Runtime dispatch based on CPU features
; =============================================================================
; C++ prototype: void LoRA_Dispatch(float* output, const float* input, int64_t dim)
; Automatically selects AVX-512 or AVX2 path
; =============================================================================
LoRA_Dispatch PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Check CPU features via beacon flags
    mov     rax, g_loraContextBeacon
    test    rax, rax
    jz      @@dispatch_done
    
    mov     edx, [rax + LOCTX_FLAGS]
    test    edx, LORA_FLAG_AVX512
    jz      @@try_fma3
    
    ; AVX-512 path
    call    ApplyLoRA_AVX512
    jmp     @@dispatch_done
    
@@try_fma3:
    test    edx, LORA_FLAG_FMA3
    jz      @@dispatch_done
    
    ; AVX2/FMA3 path
    call    ApplyLoRA_FMA3
    
@@dispatch_done:
    add     rsp, 32
    pop     rbx
    ret
    
LoRA_Dispatch ENDP

END
