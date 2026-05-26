; ==============================================================================
; Sovereign_Compute_Kernels.asm - High Performance Inference Kernels
; AVX-512 / AVX2 / Scalar
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Gemv_F32_Scalar
; RCX = Dest (Float32 Vector)
; RDX = Source (Weights Matrix Float32)
; R8  = Source (Input Vector Float32)
; R9  = Rows
; [RSP+40] = Cols
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Gemv_F32_Scalar
Sovereign_Gemv_F32_Scalar PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov r12, [rsp + 48 + 40] ; Cols (Adjusted for pushes)
    
    xor r10, r10            ; r10 = row index
@RowLoop:
    pxor xmm0, xmm0         ; Sum = 0
    xor r11, r11            ; r11 = col index
    
@ColLoop:
    ; weight = Matrix[row * Cols + col]
    mov rax, r10
    mul r12
    add rax, r11
    movss xmm1, DWORD PTR [rdx + rax*4]
    
    ; input = Input[col]
    movss xmm2, DWORD PTR [r8 + r11*4]
    
    mulss xmm1, xmm2
    addss xmm0, xmm1
    
    inc r11
    cmp r11, r12
    jb @ColLoop
    
    movss DWORD PTR [rcx + r10*4], xmm0
    
    inc r10
    cmp r10, r9
    jb @RowLoop

    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Gemv_F32_Scalar ENDP

; ----------------------------------------------------------------------------
; Sovereign_Gemv_F32_AVX512
; Optimized for AVX-512 Foundation
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Gemv_F32_AVX512
Sovereign_Gemv_F32_AVX512 PROC
    push rbx
    push rsi
    push rdi
    push r12
    
    mov r12, [rsp + 40 + 40] ; Cols
    
    xor r10, r10            ; Row Index
@RowLoop:
    vpxord zmm0, zmm0, zmm0 ; Accumulator (16 floats)
    xor r11, r11            ; Col Index
    
@ColLoop:
    mov rax, r10
    mul r12
    add rax, r11
    
    ; Load 16 weights
    vmovdqu32 zmm1, [rdx + rax*4]
    ; Load 16 inputs
    vmovdqu32 zmm2, [r8 + r11*4]
    
    ; FMA: zmm0 = zmm1 * zmm2 + zmm0
    vfmadd231ps zmm0, zmm1, zmm2
    
    add r11, 16
    cmp r11, r12
    jb @ColLoop
    
    ; Horizontal reduction of ZMM0
    ; This is a bit complex in AVX-512 without VNNI but doable
    vextractf32x4 xmm1, zmm0, 1
    vextractf32x4 xmm2, zmm0, 2
    vextractf32x4 xmm3, zmm0, 3
    addps xmm0, xmm1
    addps xmm0, xmm2
    addps xmm0, xmm3
    haddps xmm0, xmm0
    haddps xmm0, xmm0
    
    movss DWORD PTR [rcx + r10*4], xmm0
    
    inc r10
    cmp r10, r9
    jb @RowLoop

    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Gemv_F32_AVX512 ENDP

; placeholder for AVX2...
PUBLIC Sovereign_Gemv_F32_AVX2
Sovereign_Gemv_F32_AVX2 PROC
    jmp Sovereign_Gemv_F32_Scalar ; Fallback for now
Sovereign_Gemv_F32_AVX2 ENDP

END
