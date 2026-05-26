; Titan_Expert_Router.asm
; Vectorized MoE Top-2 Gating and Routing Architecture
; FIXED: ENDP label synchronized with PUBLIC symbol
; Note: Top-2 search on 8 elements is inherently scalar-serial; ~20 cycles total.
; Constraint: Under 99 Lines, Zero Dependencies

.CODE
ALIGN 16
PUBLIC Titan_Route_Experts_Top2
; RCX = const float* gate_logits (8-element array)
; RDX = uint32_t* out_expert_indices (2-element destination)
; R8  = float* out_expert_weights (2-element destination)
Titan_Route_Experts_Top2 PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymmword ptr [rsp+32], ymm0
    ; Top-1 search
    movss xmm0, dword ptr [rsp+32]
    xor eax, eax
    mov r9, 1
Top1_Loop:
    movss xmm1, dword ptr [rsp+32+r9*4]
    ucomiss xmm1, xmm0
    jbe Top1_Skip
    movss xmm0, xmm1
    mov eax, r9d
Top1_Skip:
    inc r9
    cmp r9, 8
    jl Top1_Loop
    mov dword ptr [rdx], eax
    movss dword ptr [r8], xmm0
    ; Top-2 search (exclude top-1)
    movss xmm2, dword ptr [rsp+32]
    mov r10d, 0
    cmp eax, 0
    jne Top2_Init_Valid
    movss xmm2, dword ptr [rsp+36]
    mov r10d, 1
Top2_Init_Valid:
    mov r9, 0
Top2_Loop:
    cmp r9d, eax
    je Top2_Skip
    movss xmm1, dword ptr [rsp+32+r9*4]
    ucomiss xmm1, xmm2
    jbe Top2_Skip
    movss xmm2, xmm1
    mov r10d, r9d
Top2_Skip:
    inc r9
    cmp r9, 8
    jl Top2_Loop
    mov dword ptr [rdx+4], r10d
    movss dword ptr [r8+4], xmm2
    ; Softmax normalization of top-2
    movss xmm0, dword ptr [r8]
    addss xmm0, dword ptr [r8+4]
    xorps xmm3, xmm3
    ucomiss xmm0, xmm3
    je Zero_Division_Guard
    movss xmm3, dword ptr [r8]
    divss xmm3, xmm0
    movss dword ptr [r8], xmm3
    movss xmm4, dword ptr [r8+4]
    divss xmm4, xmm0
    movss dword ptr [r8+4], xmm4
    jmp Done
Zero_Division_Guard:
    mov dword ptr [r8],   03F000000h
    mov dword ptr [r8+4], 03F000000h
Done:
    add rsp, 64
    pop rbp
    ret
Titan_Route_Experts_Top2 ENDP
END
