; K2_SwiGLU_body.inc — dst[i]=SiLU(gate[i])*up[i]; index spilled across SiLU.
PUBLIC XR_SwiGLU_F32
XR_SwiGLU_F32 PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 38h
    mov     rbx, rcx
    mov     rsi, rdx
    mov     rdi, r8
    mov     r12, r9
    test    r12, r12
    jz      sw_ok
    xor     r13, r13
@@:
    cmp     r13, r12
    jae     @F
    vmovss  xmm0, DWORD PTR [rbx+r13*4]
    vmovss  DWORD PTR [rsp+30h], xmm0
    mov     qword PTR [rsp+28h], r13
    lea     rcx, [rsp+30h]
    mov     rdx, 1
    call    XR_SiLU_F32
    mov     r13, qword PTR [rsp+28h]
    vmovss  xmm0, DWORD PTR [rsp+30h]
    vmulss  xmm0, xmm0, DWORD PTR [rsi+r13*4]
    vmovss  DWORD PTR [rdi+r13*4], xmm0
    inc     r13
    jmp     @B
@@:
sw_ok:
    xor     eax, eax
    add     rsp, 38h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
XR_SwiGLU_F32 ENDP
