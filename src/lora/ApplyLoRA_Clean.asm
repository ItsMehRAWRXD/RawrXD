; LoRA Optimized Kernel - Phase 20 (Clean Version)
; ApplyLoRA_Clean.asm
; ============================================================================
; High-performance LoRA inference kernel
; Target: < 10ms for rank=8, hidden_dim=768
; ============================================================================

; Constants
CACHE_LINE_SIZE     EQU 64
BEACON_RANK         EQU 8
BEACON_HIDDEN_DIM   EQU 12
BEACON_PTR_A        EQU 16
BEACON_PTR_B        EQU 24
BEACON_SCALE        EQU 32

.code

; ============================================================================
; Function: ApplyLoRA_Clean
; Purpose: Optimized LoRA application
; Input:  RCX = base_output pointer
;         RDX = input pointer
;         R8  = result pointer
;         R9  = beacon state pointer
;         R10 = token_count
; Output: Result in R8
; ============================================================================
ApplyLoRA_Clean PROC FRAME
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
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Load beacon parameters
    mov     r15, r9
    mov     r14d, dword ptr [r15 + BEACON_RANK]
    mov     r13d, dword ptr [r15 + BEACON_HIDDEN_DIM]
    
    ; Load matrix pointers
    mov     r12, qword ptr [r15 + BEACON_PTR_A]
    mov     r11, qword ptr [r15 + BEACON_PTR_B]
    
    ; Load scale factor
    vbroadcastss ymm15, dword ptr [r15 + BEACON_SCALE]
    
    ; Initialize result with base_output
    mov     rsi, rcx
    mov     rdi, r8
    mov     rcx, r10
    imul    rcx, r13
    rep movsd
    
    ; Restore pointers
    mov     r8, r12
    mov     r9, r11
    mov     r10, rdx
    mov     r11, r8
    
    ; Main computation loop
    mov     r12d, r13d
    
row_loop:
    cmp     r12d, 0
    jle     done
    
    ; Initialize accumulators
    vxorps  ymm0, ymm0, ymm0
    vxorps  ymm1, ymm1, ymm1
    vxorps  ymm2, ymm2, ymm2
    vxorps  ymm3, ymm3, ymm3
    
    ; Inner loop over rank
    mov     ecx, r14d
    xor     edx, edx
    
col_loop:
    cmp     ecx, 4
    jl      process_remainder
    
    ; Unrolled rank loop
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
    jmp     col_loop
    
process_remainder:
    test    ecx, ecx
    jz      compute_output
    vbroadcastss ymm4, dword ptr [r10 + rdx*4]
    vmovups      ymm5, [r8 + rdx*4]
    vfmadd231ps  ymm0, ymm5, ymm4
    inc     edx
    dec     ecx
    jmp     process_remainder
    
compute_output:
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
    imul    eax, 4
    add     r8,  rax
    add     r9,  rax
    add     r11, 32
    dec     r12d
    jmp     row_loop
    
done:
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
ApplyLoRA_Clean ENDP

END
