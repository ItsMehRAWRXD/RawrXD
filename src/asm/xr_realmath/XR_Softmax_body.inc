; XR_Softmax_body.inc — stable SoftMax; max/sum spilled across Exp
PUBLIC XR_Softmax_F32
XR_Softmax_F32 PROC
    push    rbx
    push    r12
    push    r13
    sub     rsp, 30h
    mov     r12, rcx
    mov     r13, rdx
    test    r13, r13
    jz      @@sm_bad
    vmovss  xmm3, DWORD PTR [r12]
    mov     rbx, 1
@@sm_max:
    cmp     rbx, r13
    jae     @@sm_exp_begin
    vmaxss  xmm3, xmm3, DWORD PTR [r12+rbx*4]
    inc     rbx
    jmp     @@sm_max
@@sm_exp_begin:
    vmovss  DWORD PTR [rsp+28h], xmm3
    vxorps  xmm4, xmm4, xmm4
    vmovss  DWORD PTR [rsp+20h], xmm4
    xor     rbx, rbx
@@sm_exp_loop:
    cmp     rbx, r13
    jae     @@sm_norm_begin
    vmovss  xmm0, DWORD PTR [r12+rbx*4]
    vsubss  xmm0, xmm0, DWORD PTR [rsp+28h]
    call    XR_ExpF32
    vmovss  DWORD PTR [r12+rbx*4], xmm0
    vaddss  xmm0, xmm0, DWORD PTR [rsp+20h]
    vmovss  DWORD PTR [rsp+20h], xmm0
    inc     rbx
    jmp     @@sm_exp_loop
@@sm_norm_begin:
    xor     rbx, rbx
@@sm_norm_loop:
    cmp     rbx, r13
    jae     @@sm_ok
    vmovss  xmm0, DWORD PTR [r12+rbx*4]
    vdivss  xmm0, xmm0, DWORD PTR [rsp+20h]
    vmovss  DWORD PTR [r12+rbx*4], xmm0
    inc     rbx
    jmp     @@sm_norm_loop
@@sm_ok:
    xor     eax, eax
    jmp     @@sm_exit
@@sm_bad:
    mov     eax, 1
@@sm_exit:
    add     rsp, 30h
    pop     r13
    pop     r12
    pop     rbx
    ret
XR_Softmax_F32 ENDP
