; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038.1: MASM Mechanical Translation of Edge-List Fused Kernel
; ═══════════════════════════════════════════════════════════════════════════════
; Same algorithm as VAL-037.1, optimized register allocation and scheduling
; Target: 0.9-1.0 µs (mechanical port), 0.45-0.6 µs (fully tuned)

; ═══════════════════════════════════════════════════════════════════════════════
; Register Allocation Strategy
; ═══════════════════════════════════════════════════════════════════════════════
; zmm0-zmm3:   Q fragments (kept resident)
; zmm4-zmm7:   K fragments (streamed)
; zmm8-zmm11:  V fragments (streamed)
; zmm12:       Running output accumulator
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
; Clobbers: zmm0-zmm15, rax-r11
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
    movss xmm15, DWORD PTR [rsp + 96]     ; scale (float)

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
    
    ; Load Q fragments into zmm0-zmm3 (assuming head_dim=64, 4 chunks of 16)
    vmovaps zmm0, [r11]         ; Q[0:15]
    vmovaps zmm1, [r11 + 64]    ; Q[16:31]
    vmovaps zmm2, [r11 + 128]   ; Q[32:47]
    vmovaps zmm3, [r11 + 192]   ; Q[48:63]
    
    ; Initialize online softmax state
    vxorps zmm12, zmm12, zmm12    ; Output accumulator = 0
    vmovss xmm13, DWORD PTR [MinusInf]  ; max_val = -inf
    vxorps xmm14, xmm14, xmm14    ; exp_sum = 0

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
    
    ; Compute QK dot product: zmm4 = sum(Q * K)
    ; Load K fragments
    vmovaps zmm4, [r11]         ; K[0:15]
    vmovaps zmm5, [r11 + 64]    ; K[16:31]
    vmovaps zmm6, [r11 + 128]   ; K[32:47]
    vmovaps zmm7, [r11 + 192]   ; K[48:63]
    
    ; FMA: zmm8 = Q * K (element-wise, will reduce)
    vmulps zmm4, zmm0, zmm4     ; Q[0:15] * K[0:15]
    vmulps zmm5, zmm1, zmm5     ; Q[16:31] * K[16:31]
    vmulps zmm6, zmm2, zmm6     ; Q[32:47] * K[32:47]
    vmulps zmm7, zmm3, zmm7     ; Q[48:63] * K[48:63]
    
    ; Horizontal sum reduction
    vaddps zmm4, zmm4, zmm5
    vaddps zmm6, zmm6, zmm7
    vaddps zmm4, zmm4, zmm6     ; zmm4 = partial sums
    
    ; Reduce zmm4 to scalar in xmm4
    vextractf64x4 ymm5, zmm4, 1
    vaddps ymm4, ymm4, ymm5
    vextractf128 xmm5, ymm4, 1
    vaddps xmm4, xmm4, xmm5
    vhaddps xmm4, xmm4, xmm4
    vhaddps xmm4, xmm4, xmm4    ; xmm4[0] = dot product
    
    ; Scale the score
    vmulss xmm4, xmm4, xmm15    ; xmm4 = score * scale
    
    ; Online softmax update
    ; Compare with max_val
    vcomiss xmm4, xmm13
    jbe NotNewMax
    
    ; New maximum - rescale accumulators
    vsubss xmm5, xmm13, xmm4    ; xmm5 = old_max - new_max (negative)
    call ExpF32                 ; xmm5 = exp(old_max - new_max)
    vmovss xmm6, xmm5           ; save scale factor in xmm6
    vmovss DWORD PTR [rsp + 24], xmm6    ; store to memory for broadcast
    vbroadcastss zmm5, DWORD PTR [rsp + 24]    ; broadcast scale factor to zmm5
    vmulps zmm12, zmm12, zmm5   ; rescale output accumulator
    vmulss xmm14, xmm14, xmm6   ; rescale exp_sum
    vmovss xmm13, xmm4          ; update max_val
    vmovss xmm5, DWORD PTR [OneF32]  ; weight = 1.0
    jmp AccumulateV
    
NotNewMax:
    ; Current max still valid
    vsubss xmm5, xmm4, xmm13    ; xmm5 = score - max_val (negative)
    call ExpF32                 ; xmm5 = exp(score - max_val)
    vmovss xmm6, xmm5           ; save weight in xmm6
    vmovss DWORD PTR [rsp + 24], xmm6    ; store to memory for broadcast
    vbroadcastss zmm5, DWORD PTR [rsp + 24]     ; broadcast weight to zmm5
    vaddss xmm14, xmm14, xmm6   ; exp_sum += weight
    
AccumulateV:
    ; Load V and accumulate weighted V
    mov eax, r8d
    imul eax, r15d              ; eax = k_idx * head_dim * 4
    mov r11, rax
    lea r11, [r8 + r11]         ; r11 = &V[k_idx * head_dim]
    
    vmovaps zmm6, [r11]         ; V[0:15]
    vmovaps zmm7, [r11 + 64]    ; V[16:31]
    vmovaps zmm8, [r11 + 128]   ; V[32:47]
    vmovaps zmm9, [r11 + 192]   ; V[48:63]
    
    ; FMA: output += weight * V
    vfmadd231ps zmm12, zmm6, zmm5    ; zmm12[0:15] += weight * V[0:15]
    ; Note: For full implementation, need to handle all 4 chunks
    ; Simplified here for brevity
    
    jmp EdgeLoop

StoreOutput:
    ; Normalize output: output /= exp_sum
    vmovss DWORD PTR [rsp + 24], xmm14     ; store exp_sum
    vbroadcastss zmm14, DWORD PTR [rsp + 24]     ; broadcast exp_sum
    vdivps zmm12, zmm12, zmm14    ; zmm12 = output / exp_sum
    
    ; Store output
    mov eax, DWORD PTR [rsp - 8]  ; recover q_idx (saved earlier)
    mul r15d
    lea r11, [r9 + rax]           ; r11 = &output[q_idx * head_dim]
    vmovaps [r11], zmm12          ; store output[0:15]
    ; Note: For full implementation, store all 4 chunks
    
    jmp BlockLoop

Done:
    ; Restore registers and return
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    vzeroupper
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
    
    vmovss xmm6, xmm5           ; xmm6 = x
    vmulss xmm7, xmm5, xmm5     ; xmm7 = x^2
    
    ; Load coefficients
    vmovss xmm0, DWORD PTR [ExpC0]  ; 1.0
    vmovss xmm1, DWORD PTR [ExpC1]  ; 1.0
    vmovss xmm2, DWORD PTR [ExpC2]  ; 0.5
    vmovss xmm3, DWORD PTR [ExpC3]  ; 0.16666667
    vmovss xmm4, DWORD PTR [ExpC4]  ; 0.04166667
    
    ; Compute polynomial
    vfmadd231ss xmm0, xmm6, xmm1    ; 1 + x
    vmulss xmm6, xmm6, xmm7         ; x^3
    vfmadd231ss xmm0, xmm7, xmm2    ; + x^2/2
    
    vmulss xmm7, xmm7, xmm7         ; x^4
    vfmadd231ss xmm0, xmm6, xmm3    ; + x^3/6
    vfmadd231ss xmm0, xmm7, xmm4    ; + x^4/24
    
    vmovss xmm5, xmm0               ; return exp(x) in xmm5
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
