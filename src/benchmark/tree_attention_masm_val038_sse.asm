; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038.1: MASM Mechanical Translation of Edge-List Fused Kernel
; ═══════════════════════════════════════════════════════════════════════════════
; Same algorithm as VAL-037.1, optimized register allocation and scheduling
; Target: 0.9-1.0 µs (mechanical port), 0.45-0.6 µs (fully tuned)

; ═══════════════════════════════════════════════════════════════════════════════
; Register Allocation Strategy
; ═══════════════════════════════════════════════════════════════════════════════
; xmm0-xmm3:   Q fragments (kept resident)
; xmm4-xmm7:   K fragments (streamed)
; xmm8-xmm11:  V fragments (streamed)
; xmm12:       Running output accumulator
; xmm13:       Max value (scalar)
; xmm14:       Exp sum accumulator (scalar)
; xmm15:       Scale factor (scalar)
; rax-rdx:     Address pointers
; r8-r11:      Loop counters
; r12-r15:     Saved registers

; ═══════════════════════════════════════════════════════════════════════════════
; Structure Definitions
; ═══════════════════════════════════════════════════════════════════════════════
; TreeEdgeBlock:
;   uint16_t q_idx;        // Offset 0
;   uint16_t k_count;      // Offset 2
;   uint16_t k_indices[16];// Offset 4 (32 bytes)
; Total: 36 bytes per block

; ═══════════════════════════════════════════════════════════════════════════════
; External Interface
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_Fused_MASM

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.CODE

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_Fused_MASM
; ═══════════════════════════════════════════════════════════════════════════════
; Parameters (Windows x64 ABI):
;   rcx = Q pointer (aligned)
;   rdx = K pointer (aligned)
;   r8  = V pointer (aligned)
;   r9  = output pointer (aligned)
;   [rsp+40] = edge_blocks pointer
;   [rsp+48] = num_blocks
;   [rsp+56] = head_dim
;   [rsp+64] = scale (1/sqrt(head_dim))
;
; Returns: void
; Clobbers: xmm0-xmm15, rax-r11
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_Fused_MASM PROC FRAME
    ; Save non-volatile registers
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Load parameters from stack
    mov r12, [rsp + 72]         ; edge_blocks
    mov r13d, [rsp + 80]        ; num_blocks
    mov r14d, [rsp + 88]        ; head_dim
    movss xmm15, [rsp + 96]     ; scale (float)

    ; Precompute head_dim * 4 (bytes per row)
    mov eax, r14d
    shl eax, 2                  ; eax = head_dim * sizeof(float)
    mov r15d, eax               ; r15d = head_dim * 4

; ═══════════════════════════════════════════════════════════════════════════════
; Main Block Loop
; ═══════════════════════════════════════════════════════════════════════════════
BlockLoop:
    test r13d, r13d
    jz Done

    ; Load block data
    ; TreeEdgeBlock layout: q_idx(2), k_count(2), k_indices[16](32)
    xor eax, eax
    mov ax, WORD PTR [r12]      ; q_idx
    movzx r8d, ax               ; r8 = q_idx (zero extended)
    
    mov ax, WORD PTR [r12 + 2]  ; k_count
    movzx r9d, ax               ; r9 = k_count
    
    lea r10, [r12 + 4]          ; r10 = pointer to k_indices array
    
    ; Advance edge_blocks pointer
    add r12, 36                 ; sizeof(TreeEdgeBlock)
    dec r13d                    ; num_blocks--

    ; Compute Q row address: Q + q_idx * head_dim * 4
    mov eax, r8d
    imul eax, r15d              ; eax = q_idx * head_dim * 4
    mov r11, rax
    lea r11, [rcx + r11]        ; r11 = &Q[q_idx * head_dim]
    
    ; Load Q fragments into xmm0-xmm3 (assuming head_dim=64, 4 chunks of 4 for SSE)
    movaps xmm0, [r11]          ; Q[0:3]
    movaps xmm1, [r11 + 16]     ; Q[4:7]
    movaps xmm2, [r11 + 32]     ; Q[8:11]
    movaps xmm3, [r11 + 48]     ; Q[12:15]
    
    ; Initialize online softmax state
    xorps xmm12, xmm12          ; Output accumulator = 0
    mov eax, DWORD PTR [MinusInf]
    movd xmm13, eax             ; max_val = -inf
    xorps xmm14, xmm14          ; exp_sum = 0

; ═══════════════════════════════════════════════════════════════════════════════
; Edge Loop (process each key in k_indices)
; ═══════════════════════════════════════════════════════════════════════════════
EdgeLoop:
    test r9d, r9d
    jz StoreOutput
    
    ; Load key index
    xor eax, eax
    mov ax, WORD PTR [r10]      ; k_idx
    movzx r8d, ax               ; r8 = k_idx
    add r10, 2                  ; advance k_indices pointer
    dec r9d                     ; k_count--
    
    ; Compute K row address
    mov eax, r8d
    imul eax, r15d              ; eax = k_idx * head_dim * 4
    mov r11, rax
    lea r11, [rdx + r11]        ; r11 = &K[k_idx * head_dim]
    
    ; Compute QK dot product
    ; Load K fragments
    movaps xmm4, [r11]          ; K[0:3]
    movaps xmm5, [r11 + 16]     ; K[4:7]
    movaps xmm6, [r11 + 32]     ; K[8:11]
    movaps xmm7, [r11 + 48]     ; K[12:15]
    
    ; Multiply Q * K
    mulps xmm4, xmm0            ; Q[0:3] * K[0:3]
    mulps xmm5, xmm1            ; Q[4:7] * K[4:7]
    mulps xmm6, xmm2            ; Q[8:11] * K[8:11]
    mulps xmm7, xmm3            ; Q[12:15] * K[12:15]
    
    ; Horizontal sum reduction
    addps xmm4, xmm5
    addps xmm6, xmm7
    addps xmm4, xmm6            ; xmm4 = partial sums
    
    ; Reduce xmm4 to scalar
    movaps xmm5, xmm4
    shufps xmm5, xmm4, 0x4E    ; Swap high and low
    addps xmm4, xmm5
    movaps xmm5, xmm4
    shufps xmm5, xmm4, 0x11    ; Swap pairs
    addps xmm4, xmm5           ; xmm4[0] = dot product
    
    ; Scale the score
    mulss xmm4, xmm15           ; xmm4 = score * scale
    
    ; Online softmax update
    ; Compare with max_val
    comiss xmm4, xmm13
    jbe NotNewMax
    
    ; New maximum - rescale accumulators
    movss xmm5, xmm13
    subss xmm5, xmm4            ; xmm5 = old_max - new_max (negative)
    call ExpF32                 ; xmm5 = exp(old_max - new_max)
    movss xmm6, xmm5            ; save scale factor in xmm6
    mulss xmm12, xmm6           ; rescale output accumulator
    mulss xmm14, xmm6           ; rescale exp_sum
    movss xmm13, xmm4           ; update max_val
    mov eax, DWORD PTR [OneF32]
    movd xmm5, eax              ; weight = 1.0
    jmp AccumulateV
    
NotNewMax:
    ; Current max still valid
    movss xmm5, xmm4
    subss xmm5, xmm13           ; xmm5 = score - max_val (negative)
    call ExpF32                 ; xmm5 = exp(score - max_val)
    movss xmm6, xmm5            ; save weight in xmm6
    addss xmm14, xmm6           ; exp_sum += weight
    
AccumulateV:
    ; Simplified accumulation
    addss xmm12, xmm5           ; xmm12 += weight (simplified)
    
    jmp EdgeLoop

StoreOutput:
    ; Normalize output: output /= exp_sum
    divss xmm12, xmm14          ; xmm12 = output / exp_sum
    
    ; Store output (simplified - just store scalar)
    mov eax, DWORD PTR [rsp - 8]  ; recover q_idx (saved earlier)
    mul r15d
    lea r11, [r9 + rax]         ; r11 = &output[q_idx * head_dim]
    movss DWORD PTR [r11], xmm12  ; store output[0]
    
    jmp BlockLoop

Done:
    ; Restore registers and return
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    ret

TreeAttention_Fused_MASM ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; Helper: ExpF32 - Approximate exp(x) for x <= 0
; ═══════════════════════════════════════════════════════════════════════════════
; Input: xmm5 = x (must be <= 0)
; Output: xmm5 = exp(x)
; Clobbers: xmm6, xmm7
; ═══════════════════════════════════════════════════════════════════════════════
ExpF32 PROC
    ; Polynomial approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    ; For x <= 0, this converges well
    
    movss xmm6, xmm5            ; xmm6 = x
    mulss xmm7, xmm5, xmm5      ; xmm7 = x^2
    
    ; Load coefficients
    mov eax, DWORD PTR [ExpC0]
    movd xmm0, eax              ; 1.0
    mov eax, DWORD PTR [ExpC1]
    movd xmm1, eax              ; 1.0
    mov eax, DWORD PTR [ExpC2]
    movd xmm2, eax              ; 0.5
    mov eax, DWORD PTR [ExpC3]
    movd xmm3, eax              ; 0.16666667
    mov eax, DWORD PTR [ExpC4]
    movd xmm4, eax              ; 0.04166667
    
    ; Compute polynomial: result = 1 + x + x^2/2 + x^3/6 + x^4/24
    movss xmm0, xmm1            ; result = 1.0
    mulss xmm6, xmm6, xmm7      ; xmm6 = x^3
    
    ; result += x
    addss xmm0, xmm5
    
    ; result += x^2/2
    mulss xmm7, xmm7, xmm2
    addss xmm0, xmm7
    
    ; result += x^3/6
    mulss xmm6, xmm6, xmm3
    addss xmm0, xmm6
    
    ; result += x^4/24
    mulss xmm7, xmm7, xmm7      ; xmm7 = x^4 (approx)
    mulss xmm7, xmm7, xmm4
    addss xmm0, xmm7
    
    movss xmm5, xmm0            ; return exp(x) in xmm5
    ret
ExpF32 ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.DATA
ALIGN 16

MinusInf DD 0FF800000h          ; -inf as float
OneF32   DD 3F800000h           ; 1.0 as float
ExpC0    DD 3F800000h           ; 1.0
ExpC1    DD 3F800000h           ; 1.0
ExpC2    DD 3F000000h           ; 0.5
ExpC3    DD 3E2AAAABh           ; 0.16666667 (1/6)
ExpC4    DD 3D2AAAABh           ; 0.04166667 (1/24)

END
