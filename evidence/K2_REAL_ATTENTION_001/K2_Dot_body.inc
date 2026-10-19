; K2_Dot_body.inc — scalar F32 dot. body≈12.
PUBLIC XR_Dot_F32
XR_Dot_F32 PROC
    vxorps  xmm0, xmm0, xmm0
    xor     rax, rax
@@:
    cmp     rax, r8
    jae     @F
    vmovss  xmm1, DWORD PTR [rcx+rax*4]
    vmulss  xmm1, xmm1, DWORD PTR [rdx+rax*4]
    vaddss  xmm0, xmm0, xmm1
    inc     rax
    jmp     @B
@@:
    ret
XR_Dot_F32 ENDP
