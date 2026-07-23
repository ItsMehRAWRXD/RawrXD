; ============================================================================
; sovereign_moe_fused.asm - Fused MoE Expert Kernel
; Single kernel: gate_proj + SiLU + up_proj + mul + down_proj
; ============================================================================

IFDEF RAX
.code

; ============================================================================
; Sovereign_MoE_Fused_Q4K_AVX512
; Fused MoE expert: gate_up + SiLU + mul + down
; Input: hidden state
; Output: expert output
; All weights in Q4_K format
; ============================================================================
Sovereign_MoE_Fused_Q4K_AVX512 PROC FRAME
    ; RCX = hidden_ptr (input/output)
    ; RDX = gate_up_weights (Q4_K)
    ; R8  = down_weights (Q4_K)
    ; R9  = hidden_size
    ; [RSP+40] = intermediate_size
    ; [RSP+48] = scales_gate
    ; [RSP+56] = scales_up
    ; [RSP+64] = scales_down
    
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 128
    .allocstack 128
    .endprolog
    
    mov rsi, rcx        ; hidden state
    mov rdi, rdx        ; gate_up weights
    mov rbx, r8         ; down weights
    mov r12, r9         ; hidden_size
    mov r13, [rsp+168]  ; intermediate_size
    mov r14, [rsp+176]  ; scales_gate
    mov r15, [rsp+184]  ; scales_up
    
    ; Allocate temp buffers on stack
    lea rax, [rsp+0]    ; gate_buf
    lea rcx, [rsp+32]   ; up_buf
    
    ; === Phase 1: gate_proj(hidden) and up_proj(hidden) ===
    ; Both are GEMV: [intermediate] = [hidden_size] x [hidden_size, intermediate]
    
    xor r8, r8          ; i = 0 (intermediate dim)
@gate_up_loop:
    cmp r8, r13
    jge @gate_up_done
    
    ; Compute gate[i] = dot(hidden, gate_weight[i])
    ; Compute up[i] = dot(hidden, up_weight[i])
    vxorps zmm0, zmm0, zmm0      ; gate_acc
    vxorps zmm1, zmm1, zmm1      ; up_acc
    
    mov r9, rsi         ; hidden ptr
    mov r10, rdi        ; gate_up weight ptr for this row
    add r10, r8, 18     ; Q4_K block size
    
    xor r11, r11        ; j = 0
@dot_loop:
    cmp r11, r12
    jge @dot_done
    
    ; Load 16 floats from hidden
    vmovups zmm2, [r9]
    
    ; Dequantize Q4_K and dot
    ; Simplified: assume weights are pre-dequantized for now
    vfmadd231ps zmm0, zmm2, [r10]        ; gate
    vfmadd231ps zmm1, zmm2, [r10+64]    ; up
    
    add r9, 64
    add r10, 128
    add r11, 16
    jmp @dot_loop
    
@dot_done:
    ; Horizontal sum
    vextractf64x4 ymm2, zmm0, 1
    vaddps ymm0, ymm0, ymm2
    vextractf128 xmm2, ymm0, 1
    vaddps xmm0, xmm0, xmm2
    vhaddps xmm1, xmm0, xmm0
    vhaddps xmm0, xmm1, xmm1
    vmovss dword ptr [rax+r8*4], xmm0              ; gate[i]
    
    vextractf64x4 ymm2, zmm1, 1
    vaddps ymm1, ymm1, ymm2
    vextractf128 xmm2, ymm1, 1
    vaddps xmm1, xmm1, xmm2
    vhaddps xmm0, xmm1, xmm1
    vhaddps xmm1, xmm0, xmm0
    vmovss dword ptr [rcx+r8*4], xmm1              ; up[i]
    
    inc r8
    jmp @gate_up_loop
    
@gate_up_done:
    
    ; === Phase 2: SiLU(gate) * up ===
    ; SiLU(x) = x * sigmoid(x)
    xor r8, r8
@activation_loop:
    cmp r8, r13
    jge @activation_done
    
    vmovss xmm0, dword ptr [rax+r8*4]      ; gate
    vmovss xmm1, dword ptr [rcx+r8*4]      ; up
    
    ; sigmoid
    vxorps xmm2, xmm2, xmm2
    vsubss xmm2, xmm2, xmm0      ; -gate
    ; exp(-gate) - use approximation
    vmovss xmm3, dword ptr [__one_f]
    vaddss xmm3, xmm3, xmm2      ; 1 + (-gate) approx
    vmovss xmm5, dword ptr [__one_f]
    vdivss xmm4, xmm5, xmm3      ; sigmoid
    
    vmulss xmm0, xmm0, xmm4      ; gate * sigmoid
    vmulss xmm0, xmm0, xmm1      ; * up
    
    vmovss dword ptr [rcx+r8*4], xmm0      ; store activated
    
    inc r8
    jmp @activation_loop
    
@activation_done:
    
    ; === Phase 3: down_proj(activated) ===
    ; GEMV: [hidden] = [intermediate] x [intermediate, hidden]
    
    xor r8, r8          ; i = 0 (hidden dim)
@down_loop:
    cmp r8, r12
    jge @down_done
    
    vxorps zmm0, zmm0, zmm0      ; acc
    
    mov r9, rcx         ; activated ptr
    mov r10, rbx        ; down weight ptr
    add r10, r8, 18     ; offset to this row
    
    xor r11, r11        ; j = 0
@down_dot_loop:
    cmp r11, r13
    jge @down_dot_done
    
    vmovss xmm3, dword ptr [r9+r11*4]   ; activated[j]
    vbroadcastss zmm1, xmm3              ; broadcast to zmm1
    vfmadd231ps zmm0, zmm1, [r10]    ; += activated[j] * weight[j]
    
    add r10, 64
    add r11, 16
    jmp @down_dot_loop
    
@down_dot_done:
    ; Horizontal sum
    vextractf64x4 ymm2, zmm0, 1
    vaddps ymm0, ymm0, ymm2
    vextractf128 xmm2, ymm0, 1
    vaddps xmm0, xmm0, xmm2
    vhaddps xmm1, xmm0, xmm0
    vhaddps xmm0, xmm1, xmm1
    
    ; Add to output (residual)
    vmovss xmm1, dword ptr [rsi+r8*4]
    vaddss xmm0, xmm0, xmm1
    vmovss dword ptr [rsi+r8*4], xmm0
    
    inc r8
    jmp @down_loop
    
@down_done:
    
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_MoE_Fused_Q4K_AVX512 ENDP

; Constants
__one_f real4 1.0
__zero_f real4 0.0

ENDIF

END
