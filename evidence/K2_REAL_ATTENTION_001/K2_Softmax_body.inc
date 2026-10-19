; K2_Softmax_body.inc — max-stable SoftMax; max/sum spilled across Exp.
PUBLIC XR_Softmax_F32
XR_Softmax_F32 PROC
    push    rbx
    push    r12
    push    r13
    sub     rsp, 30h
    mov     r12, rcx
    mov     r13, rdx
    test    r13, r13
    jz      sm_bad
    vmovss  xmm0, DWORD PTR [r12]
    mov     rbx, 1
@@:
    cmp     rbx, r13
    jae     @F
    vmaxss  xmm0, xmm0, DWORD PTR [r12+rbx*4]
    inc     rbx
    jmp     @B
@@:
    vmovss  DWORD PTR [rsp+28h], xmm0
    vxorps  xmm0, xmm0, xmm0
    vmovss  DWORD PTR [rsp+20h], xmm0
    xor     rbx, rbx
@@:
    cmp     rbx, r13
    jae     @F
    vmovss  xmm0, DWORD PTR [r12+rbx*4]
    vsubss  xmm0, xmm0, DWORD PTR [rsp+28h]
    call    XR_ExpF32
    vmovss  DWORD PTR [r12+rbx*4], xmm0
    vaddss  xmm0, xmm0, DWORD PTR [rsp+20h]
    vmovss  DWORD PTR [rsp+20h], xmm0
    inc     rbx
    jmp     @B
@@:
    xor     rbx, rbx
@@:
    cmp     rbx, r13
    jae     @F
    vmovss  xmm0, DWORD PTR [r12+rbx*4]
    vdivss  xmm0, xmm0, DWORD PTR [rsp+20h]
    vmovss  DWORD PTR [r12+rbx*4], xmm0
    inc     rbx
    jmp     @B
@@:
    xor     eax, eax
    jmp     sm_exit
sm_bad:
    mov     eax, 1
sm_exit:
    add     rsp, 30h
    pop     r13
    pop     r12
    pop     rbx
    ret
XR_Softmax_F32 ENDP
