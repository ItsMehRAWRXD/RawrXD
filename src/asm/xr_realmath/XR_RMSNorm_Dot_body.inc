; XR_RMSNorm_Dot_body.inc — RMSNorm (eps=1e-5) + Dot
PUBLIC XR_RMSNorm_F32
PUBLIC XR_Dot_F32
XR_RMSNorm_F32 PROC
    push    rbx
    push    r12
    push    r13
    mov     r12, rcx
    mov     rbx, rdx
    mov     r13, r8
    test    r13, r13
    jz      @@rn_bad
    vxorps  xmm0, xmm0, xmm0
    xor     rax, rax
@@rn_sum:
    cmp     rax, r13
    jae     @@rn_scale
    vmovss  xmm1, DWORD PTR [r12+rax*4]
    vmulss  xmm1, xmm1, xmm1
    vaddss  xmm0, xmm0, xmm1
    inc     rax
    jmp     @@rn_sum
@@rn_scale:
    vcvtsi2ss xmm1, xmm1, r13d
    vdivss  xmm0, xmm0, xmm1
    vaddss  xmm0, xmm0, DWORD PTR c_rms_eps
    vsqrtss xmm0, xmm0, xmm0
    vmovss  xmm1, DWORD PTR c_one
    vdivss  xmm0, xmm1, xmm0
    xor     rax, rax
@@rn_apply:
    cmp     rax, r13
    jae     @@rn_ok
    vmovss  xmm1, DWORD PTR [r12+rax*4]
    vmulss  xmm1, xmm1, xmm0
    vmulss  xmm1, xmm1, DWORD PTR [rbx+rax*4]
    vmovss  DWORD PTR [r12+rax*4], xmm1
    inc     rax
    jmp     @@rn_apply
@@rn_ok:
    xor     eax, eax
    jmp     @@rn_exit
@@rn_bad:
    mov     eax, 1
@@rn_exit:
    pop     r13
    pop     r12
    pop     rbx
    ret
XR_RMSNorm_F32 ENDP

XR_Dot_F32 PROC
    vxorps  xmm0, xmm0, xmm0
    xor     rax, rax
@@dot_loop:
    cmp     rax, r8
    jae     @@dot_done
    vmovss  xmm1, DWORD PTR [rcx+rax*4]
    vmulss  xmm1, xmm1, DWORD PTR [rdx+rax*4]
    vaddss  xmm0, xmm0, xmm1
    inc     rax
    jmp     @@dot_loop
@@dot_done:
    ret
XR_Dot_F32 ENDP
