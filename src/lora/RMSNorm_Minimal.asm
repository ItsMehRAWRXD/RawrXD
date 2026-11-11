; ==============================================================================
; RMSNorm_Minimal.asm - Minimal test version
; ==============================================================================

.code

RMSNorm_Minimal PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Extract parameters
    mov     r10, [rsp+40]          ; r10 = dim
    test    r10, r10
    jz      ExitEarly
    
    ; Simple loop that just counts
    xor     rax, rax               ; rax = loop index counter
    
SumLoop:
    add     rax, 1
    cmp     rax, r10
    jl      SumLoop
    
    ; Store dummy result
    mov     dword ptr [r8], 12345678h
    
ExitEarly:
    mov     rsp, rbp
    pop     rbp
    ret
RMSNorm_Minimal ENDP

END