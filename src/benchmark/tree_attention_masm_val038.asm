; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038.1: MASM Mechanical Translation - Fused Online Softmax with Edge-List
; ═══════════════════════════════════════════════════════════════════════════════
; Target: 500ns (2.2x from 1.09 µs C++ implementation)
; Strategy: Optimal register allocation, minimal spills, no function calls
;
; Algorithm: Fused online softmax with edge-list traversal
;   For each edge (q_idx, k_idx):
;     1. Compute dot(Q[q_idx], K[k_idx]) - single AVX-512 FMA chain
;     2. Online softmax: m_new = max(m_old, dot), update running sum
;   Then: output[q_idx] = sum(exp(dot - m_final) * V[k_idx]) / sum
;
; Register Map (preserves ABI: RBX, RBP, RDI, RSI, R12-R15 must be saved):
;   ZMM16-ZMM31: AVX-512 registers (caller-saved, no preservation needed)
;   ZMM16-ZMM23: Q vectors (8x head_dim floats, processed in chunks)
;   ZMM24-ZMM27: K vectors
;   ZMM28:       Accumulator for dot product
;   ZMM29:       Running max (m) for online softmax
;   ZMM30:       Running sum (sum_exp) for online softmax
;   ZMM31:       Temp/scratch
;   RAX-R11:     General purpose (caller-saved)
;   RCX, RDX, R8, R9: Arguments (Windows x64 ABI)
;   R10-R11:     Edge list iteration
;   R12-R15:     Saved callee-saved registers (if needed)
; ═══════════════════════════════════════════════════════════════════════════════

PUBLIC TreeAttention_FusedSparse_MASM

.CODE

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_FusedSparse_MASM
; ═══════════════════════════════════════════════════════════════════════════════
; Parameters (Windows x64 ABI):
;   RCX = Q pointer (const float*)
;   RDX = K pointer (const float*)
;   R8  = V pointer (const float*)
;   R9  = output pointer (float*)
;   [RSP+0x28] = edge_list pointer (const uint16_t*)
;   [RSP+0x30] = num_edges (uint32_t)
;   [RSP+0x38] = head_dim (uint32_t)
;   [RSP+0x40] = scale (float)
;
; Local stack frame:
;   [RSP+0x00] - [RSP+0x20]: Shadow space for calls (not used, but reserved)
;   [RSP+0x28]: Edge list pointer (from stack arg)
;   [RSP+0x30]: Num edges
;   [RSP+0x38]: Head dim
;   [RSP+0x40]: Scale
;   [RSP+0x48]: Current edge index
;   [RSP+0x50]: Saved RBX
;   [RSP+0x58]: Saved RBP
;   [RSP+0x60]: Saved R12
;   [RSP+0x68]: Saved R13
;   [RSP+0x70]: Saved R14
;   [RSP+0x78]: Saved R15
; ═══════════════════════════════════════════════════════════════════════════════

TreeAttention_FusedSparse_MASM PROC FRAME
    ; Save callee-saved registers
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    
    sub     rsp, 128                  ; Allocate stack space
    .allocstack 128
    
    .endprolog
    
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Load parameters from stack (Windows x64: first 4 in regs, rest on stack)
    ; Shadow space is 32 bytes at [RSP+0x20] after pushes
    ; Stack args start at [RSP+0x20+0x28] = [RSP+0x48] before sub
    ; After sub rsp, 128: stack args at [RSP+128+0x48] = [RSP+176]
    ; ═══════════════════════════════════════════════════════════════════════════
    mov     r12, rcx                  ; R12 = Q
    mov     r13, rdx                  ; R13 = K
    mov     r14, r8                   ; R14 = V
    mov     r15, r9                   ; R15 = output
    
    ; Load stack arguments (after shadow space + our alloc)
    mov     rax, [rsp + 128 + 48]     ; edge_list pointer
    mov     [rsp + 0], rax            ; save edge_list locally
    mov     eax, [rsp + 128 + 56]     ; num_edges
    mov     [rsp + 8], eax            ; save num_edges
    mov     eax, [rsp + 128 + 64]     ; head_dim
    mov     [rsp + 16], eax           ; save head_dim
    movss   xmm0, dword ptr [rsp + 128 + 72]  ; scale
    movss   dword ptr [rsp + 24], xmm0        ; save scale
    
    ; Initialize edge index = 0
    mov     dword ptr [rsp + 32], 0
    
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Main edge loop
    ; ═══════════════════════════════════════════════════════════════════════════
EdgeLoop:
    mov     eax, [rsp + 32]           ; current edge index
    cmp     eax, [rsp + 8]            ; compare with num_edges
    jae     EdgeLoopDone              ; if index >= num_edges, done
    
    ; Load edge: [q_idx, k_idx] pair
    mov     rcx, [rsp + 0]            ; edge_list pointer
    movzx   edx, word ptr [rcx + rax*4]      ; q_idx (first uint16_t)
    movzx   r8d, word ptr [rcx + rax*4 + 2]  ; k_idx (second uint16_t)
    
    ; Compute Q pointer: Q + q_idx * head_dim
    mov     eax, [rsp + 16]           ; head_dim
    imul    rdx, rax                  ; RDX = q_idx * head_dim
    lea     r10, [r12 + rdx*4]        ; R10 = &Q[q_idx * head_dim]
    
    ; Compute K pointer: K + k_idx * head_dim
    imul    r8, rax                   ; R8 = k_idx * head_dim
    lea     r11, [r13 + r8*4]         ; R11 = &K[k_idx * head_dim]
    
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Compute dot product Q · K using AVX-512
    ; Process head_dim elements in chunks of 16 (AVX-512 floats)
    ; ═══════════════════════════════════════════════════════════════════════════
    vxorps  zmm28, zmm28, zmm28     ; Clear accumulator
    
    mov     eax, [rsp + 16]           ; head_dim
    xor     ecx, ecx                  ; offset = 0
    
DotProductLoop:
    cmp     ecx, eax
    jae     DotProductDone
    
    ; Load 16 floats from Q and K
    vmovups zmm16, zmmword ptr [r10 + rcx*4]
    vmovups zmm17, zmmword ptr [r11 + rcx*4]
    
    ; FMA: accumulator += Q * K
    vfmadd231ps zmm28, zmm16, zmm17
    
    add     ecx, 16
    jmp     DotProductLoop
    
DotProductDone:
    ; Horizontal sum of zmm28 to get final dot product
    ; Use vshuff to reduce across lanes
    ; zmm28 contains 16 floats, need to sum them all
    ; First: zmm28 = [a0-a15], extract high 8 to ymm17
    vextractf64x4 ymm17, zmm28, 1     ; Extract high 256 bits (imm8=1)
    vaddps  ymm16, ymm28, ymm17       ; Add low and high 256 -> ymm16 has 8 partial sums
    vextractf128 xmm17, ymm16, 1      ; Extract high 128 bits to xmm17
    vaddps  xmm16, xmm16, xmm17       ; Add low and high 128 -> xmm16 has 4 partial sums
    vshufps xmm17, xmm16, xmm16, 4Eh  ; 0x4E: shuffle for horizontal add
    vaddps  xmm16, xmm16, xmm17       ; xmm16 has 2 partial sums
    vshufps xmm17, xmm16, xmm16, 0B1h ; 0xB1: another shuffle
    vaddps  xmm16, xmm16, xmm17       ; xmm16 has final sum in all elements
    
    ; xmm16 now contains the dot product (broadcasted across all elements)
    ; Apply scale
    movss   xmm1, dword ptr [rsp + 24]  ; scale
    vbroadcastss zmm29, xmm1            ; broadcast scale to zmm29
    vbroadcastss zmm30, xmm16           ; broadcast dot to zmm30
    vmulps  zmm30, zmm30, zmm29         ; dot * scale
    
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Online softmax update
    ; m_new = max(m_old, dot_scaled)
    ; sum_new = sum_old * exp(m_old - m_new) + exp(dot_scaled - m_new)
    ; ═══════════════════════════════════════════════════════════════════════════
    
    ; For now: simplified - just accumulate (full softmax needs exp approximation)
    ; This is the mechanical translation stub - full implementation continues
    
    ; Increment edge index
    inc     dword ptr [rsp + 32]
    jmp     EdgeLoop
    
EdgeLoopDone:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Finalize and write output
    ; ═══════════════════════════════════════════════════════════════════════════
    
    ; Restore stack and registers
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    
    ret
TreeAttention_FusedSparse_MASM ENDP

END
