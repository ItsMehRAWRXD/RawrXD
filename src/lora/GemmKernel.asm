; ============================================================================
; GemmKernel.asm - AVX GEMM Microkernel
; ============================================================================
; C = A × B (8x8 tile, single-threaded)
; A: 8×K packed (column-major for the 8 rows: A[0,k], A[1,k], ... A[7,k])
; B: K×8 row-major (8 consecutive floats per K)
; C: 8×8 row-major
; ============================================================================

.code

; ============================================================================
; Gemm_8x8_Microkernel
; Computes an 8×8 tile of C: C[0:7, 0:7] += A[0:7, 0:K] × B[0:K, 0:7]
; 
; Parameters:
;   RCX = A pointer (packed 8×K: K groups of 8 floats)
;   RDX = B pointer (K×8 row-major)
;   R8  = C pointer (8×8 row-major)
;   R9  = K (inner dimension)
;   [RBP+56] = ldc (C row stride in elements, typically N)
; ============================================================================
Gemm_8x8_Microkernel PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 80
    .allocstack 80
    .endprolog
    
    ; Debug: mark entry
    nop
    
    ; Save non-volatile registers
    mov     [rbp-8], rbx
    mov     [rbp-16], r12
    mov     [rbp-24], r13
    mov     [rbp-32], r14
    mov     [rbp-40], r15
    
    ; Load parameters
    mov     r12, rcx        ; R12 = A (packed)
    mov     r13, rdx        ; R13 = B
    mov     r14, r8         ; R14 = C
    mov     r15, r9         ; R15 = K (counter)
    
    ; Initialize 8 accumulators (one per row of C)
    vxorps  ymm0, ymm0, ymm0    ; Row 0 accumulator
    vxorps  ymm1, ymm1, ymm1    ; Row 1 accumulator
    vxorps  ymm2, ymm2, ymm2    ; Row 2 accumulator
    vxorps  ymm3, ymm3, ymm3    ; Row 3 accumulator
    vxorps  ymm4, ymm4, ymm4    ; Row 4 accumulator
    vxorps  ymm5, ymm5, ymm5    ; Row 5 accumulator
    vxorps  ymm6, ymm6, ymm6    ; Row 6 accumulator
    vxorps  ymm7, ymm7, ymm7    ; Row 7 accumulator
    
    ; Main K loop
    test    r15, r15
    jz      StoreResults
    
    ; Debug: check K counter
    nop
    
KLoop:
    ; Load B row (8 floats from current K)
    vmovups ymm8, [r13]         ; YMM8 = B[k, 0:7]
    
    ; Row 0: A[0,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12]      ; YMM9 = A[0,k]
    vfmadd231ps ymm0, ymm9, ymm8            ; YMM0 += A[0,k] × B[k,:]
    
    ; Row 1: A[1,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 4]  ; YMM9 = A[1,k]
    vfmadd231ps ymm1, ymm9, ymm8            ; YMM1 += A[1,k] × B[k,:]
    
    ; Row 2: A[2,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 8]  ; YMM9 = A[2,k]
    vfmadd231ps ymm2, ymm9, ymm8            ; YMM2 += A[2,k] × B[k,:]
    
    ; Row 3: A[3,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 12] ; YMM9 = A[3,k]
    vfmadd231ps ymm3, ymm9, ymm8            ; YMM3 += A[3,k] × B[k,:]
    
    ; Row 4: A[4,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 16] ; YMM9 = A[4,k]
    vfmadd231ps ymm4, ymm9, ymm8            ; YMM4 += A[4,k] × B[k,:]
    
    ; Row 5: A[5,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 20] ; YMM9 = A[5,k]
    vfmadd231ps ymm5, ymm9, ymm8            ; YMM5 += A[5,k] × B[k,:]
    
    ; Row 6: A[6,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 24] ; YMM9 = A[6,k]
    vfmadd231ps ymm6, ymm9, ymm8            ; YMM6 += A[6,k] × B[k,:]
    
    ; Row 7: A[7,k] × B[k,:]
    vbroadcastss ymm9, dword ptr [r12 + 28] ; YMM9 = A[7,k]
    vfmadd231ps ymm7, ymm9, ymm8            ; YMM7 += A[7,k] × B[k,:]
    
    ; Advance pointers
    add     r12, 32             ; A += 8 floats (next K)
    add     r13, 32             ; B += 8 floats (next K)
    
    dec     r15
    jnz     KLoop
    
    ; Load initial C values (for accumulation: C += A×B)
    ; Fifth parameter = ldc (C row stride in elements)
    ; Stack layout: [RSP+40] = 5th param (ldc) after home space + return address
    mov     rax, [rsp+40]       ; RAX = ldc (leading dimension of C)
    shl     rax, 2              ; Convert to bytes (×4)
    
    ; Load existing C values into accumulators
    vaddps  ymm0, ymm0, [r14]           ; YMM0 += C[0, 0:7]
    vaddps  ymm1, ymm1, [r14 + rax]     ; YMM1 += C[1, 0:7]  
    vaddps  ymm2, ymm2, [r14 + rax*2]   ; YMM2 += C[2, 0:7]
    ; For row 3, use rax*3
    mov     rbx, rax
    shl     rbx, 1
    add     rbx, rax            ; RBX = rax * 3
    vaddps  ymm3, ymm3, [r14 + rbx]     ; YMM3 += C[3, 0:7]
    vaddps  ymm4, ymm4, [r14 + rax*4]   ; YMM4 += C[4, 0:7]
    ; For row 5, use rax*5
    mov     rbx, rax
    shl     rbx, 2
    add     rbx, rax            ; RBX = rax * 5
    vaddps  ymm5, ymm5, [r14 + rbx]     ; YMM5 += C[5, 0:7]
    ; For row 6, use rax*6
    mov     rbx, rax
    shl     rbx, 2
    add     rbx, rax
    add     rbx, rax            ; RBX = rax * 6
    vaddps  ymm6, ymm6, [r14 + rbx]     ; YMM6 += C[6, 0:7]
    ; For row 7, use rax*7
    mov     rbx, rax
    shl     rbx, 3
    sub     rbx, rax            ; RBX = rax * 7
    vaddps  ymm7, ymm7, [r14 + rbx]     ; YMM7 += C[7, 0:7]
    
StoreResults:
    ; Store 8×8 tile to C
    mov     rax, [rsp+40]       ; RAX = ldc
    shl     rax, 2              ; Convert to bytes
    
    vmovups [r14], ymm0         ; C[0, 0:7]
    vmovups [r14 + rax], ymm1   ; C[1, 0:7]
    vmovups [r14 + rax*2], ymm2 ; C[2, 0:7]
    mov     rbx, rax
    shl     rbx, 1
    add     rbx, rax            ; RBX = rax * 3
    vmovups [r14 + rbx], ymm3   ; C[3, 0:7]
    vmovups [r14 + rax*4], ymm4 ; C[4, 0:7]
    mov     rbx, rax
    shl     rbx, 2
    add     rbx, rax            ; RBX = rax * 5
    vmovups [r14 + rbx], ymm5   ; C[5, 0:7]
    mov     rbx, rax
    shl     rbx, 2
    add     rbx, rax
    add     rbx, rax            ; RBX = rax * 6
    vmovups [r14 + rbx], ymm6   ; C[6, 0:7]
    mov     rbx, rax
    shl     rbx, 3
    sub     rbx, rax            ; RBX = rax * 7
    vmovups [r14 + rbx], ymm7   ; C[7, 0:7]
    
    ; Clear YMM state
    vzeroupper
    
    ; Restore non-volatile registers
    mov     rbx, [rbp-8]
    mov     r12, [rbp-16]
    mov     r13, [rbp-24]
    mov     r14, [rbp-32]
    mov     r15, [rbp-40]
    
    ; Epilogue
    mov     rsp, rbp
    pop     rbp
    xor     rax, rax            ; Return 0
    ret
Gemm_8x8_Microkernel ENDP

END
