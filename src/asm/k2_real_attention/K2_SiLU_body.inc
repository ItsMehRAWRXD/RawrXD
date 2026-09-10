; K2_SiLU_body.inc — real SiLU; x spilled across Exp (xmm0-5 volatile).
PUBLIC XR_SiLU_F32
XR_SiLU_F32 PROC
    push    rbx
    push    r12
    sub     rsp, 28h
    mov     rbx, rcx
    mov     r12, rdx
@@:
    test    r12, r12
    jz      @F
    vmovss  xmm0, DWORD PTR [rbx]
    vmovss  DWORD PTR [rsp+20h], xmm0
    vxorps  xmm1, xmm1, xmm1
    vsubss  xmm0, xmm1, xmm0
    call    XR_ExpF32
    vmovss  xmm1, DWORD PTR [rsp+20h]
    vaddss  xmm0, xmm0, DWORD PTR c_one
    vdivss  xmm1, xmm1, xmm0
    vmovss  DWORD PTR [rbx], xmm1
    add     rbx, 4
    dec     r12
    jmp     @B
@@:
    xor     eax, eax
    add     rsp, 28h
    pop     r12
    pop     rbx
    ret
XR_SiLU_F32 ENDP
