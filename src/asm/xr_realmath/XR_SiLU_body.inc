; XR_SiLU_body.inc — in-place SiLU; reloads x after Exp (Win64 xmm0-5 volatile)
PUBLIC XR_SiLU_F32
XR_SiLU_F32 PROC
    push    rbx
    push    r12
    sub     rsp, 28h
    mov     rbx, rcx
    mov     r12, rdx
@@silu_loop:
    test    r12, r12
    jz      @@silu_done
    vmovss  xmm4, DWORD PTR [rbx]
    vxorps  xmm0, xmm0, xmm0
    vsubss  xmm0, xmm0, xmm4
    call    XR_ExpF32
    vmovss  xmm4, DWORD PTR [rbx]
    vaddss  xmm0, xmm0, DWORD PTR c_one
    vdivss  xmm4, xmm4, xmm0
    vmovss  DWORD PTR [rbx], xmm4
    add     rbx, 4
    dec     r12
    jmp     @@silu_loop
@@silu_done:
    xor     eax, eax
    add     rsp, 28h
    pop     r12
    pop     rbx
    ret
XR_SiLU_F32 ENDP
