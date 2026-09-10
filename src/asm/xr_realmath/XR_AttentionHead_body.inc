; XR_AttentionHead_body.inc — Q·K/√d, SoftMax, Σ softmax·V
PUBLIC XR_AttentionHead_F32
XR_AttentionHead_F32 PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40h
    test    rcx, rcx
    jz      @@ah_bad
    mov     r13, [rcx+ATTN_Q]
    mov     r14, [rcx+ATTN_K]
    mov     rsi, [rcx+ATTN_V]
    mov     rbx, [rcx+ATTN_SCORES]
    mov     rdi, [rcx+ATTN_OUT]
    mov     rax, [rcx+ATTN_SEQ_LEN]
    mov     r15, [rcx+ATTN_HEAD_DIM]
    test    r13, r13
    jz      @@ah_bad
    test    r14, r14
    jz      @@ah_bad
    test    rsi, rsi
    jz      @@ah_bad
    test    rbx, rbx
    jz      @@ah_bad
    test    rdi, rdi
    jz      @@ah_bad
    test    rax, rax
    jz      @@ah_bad
    test    r15, r15
    jz      @@ah_bad
    mov     [rsp+38h], rax
    vcvtsi2ss xmm0, xmm0, r15d
    vsqrtss xmm0, xmm0, xmm0
    vmovss  xmm1, DWORD PTR c_one
    vdivss  xmm0, xmm1, xmm0
    vmovss  DWORD PTR [rsp+30h], xmm0
    xor     r12, r12
@@ah_scores:
    cmp     r12, [rsp+38h]
    jae     @@ah_softmax
    mov     rcx, r13
    mov     rax, r12
    imul    rax, r15
    lea     rdx, [r14+rax*4]
    mov     r8, r15
    call    XR_Dot_F32
    vmulss  xmm0, xmm0, DWORD PTR [rsp+30h]
    vmovss  DWORD PTR [rbx+r12*4], xmm0
    inc     r12
    jmp     @@ah_scores
@@ah_softmax:
    mov     rcx, rbx
    mov     rdx, [rsp+38h]
    call    XR_Softmax_F32
    test    eax, eax
    jnz     @@ah_bad
    xor     r12, r12
@@ah_out_j:
    cmp     r12, r15
    jae     @@ah_ok
    vxorps  xmm0, xmm0, xmm0
    xor     r11, r11
@@ah_out_p:
    cmp     r11, [rsp+38h]
    jae     @@ah_store
    mov     rax, r11
    imul    rax, r15
    add     rax, r12
    vmovss  xmm1, DWORD PTR [rsi+rax*4]
    vmulss  xmm1, xmm1, DWORD PTR [rbx+r11*4]
    vaddss  xmm0, xmm0, xmm1
    inc     r11
    jmp     @@ah_out_p
@@ah_store:
    vmovss  DWORD PTR [rdi+r12*4], xmm0
    inc     r12
    jmp     @@ah_out_j
@@ah_ok:
    xor     eax, eax
    jmp     @@ah_exit
@@ah_bad:
    mov     eax, 1
@@ah_exit:
    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
XR_AttentionHead_F32 ENDP
