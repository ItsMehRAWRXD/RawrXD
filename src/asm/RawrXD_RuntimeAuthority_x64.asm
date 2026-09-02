; RawrXD_RuntimeAuthority_x64.asm — keyed chained MAC runtime ledger (no CRT/heap)
option casemap:none
include RawrXD_RuntimeAuthority_x64.inc
.code
PUBLIC RawrXD_RA_Init
PUBLIC RawrXD_RA_Append
PUBLIC RawrXD_RA_Verify

RA_MixQword PROC
    xor     rax, rdx
    add     rax, r8
    mov     r9, rax
    rol     rax, 13
    xor     rax, r9
    mov     r10, rax
    rol     rax, 31
    add     rax, r10
    mov     r9, 09E3779B97F4A7C15h
    xor     rax, r9
    rol     rax, 17
    mov     r9, rax
    shr     r9, 29
    xor     rax, r9
    mov     r9, 0BF58476D1CE4E5B9h
    imul    rax, r9
    mov     r9, rax
    shr     r9, 32
    xor     rax, r9
    ret
RA_MixQword ENDP

RawrXD_RA_Init PROC
    test    rcx, rcx
    jz      rai_fail
    test    rdx, rdx
    jz      rai_fail
    test    r8, r8
    jz      rai_fail
    mov     rax, qword ptr [rsp+40]
    mov     qword ptr [rcx+RA_STATE_BASE], rdx
    mov     qword ptr [rcx+RA_STATE_CAPACITY], r8
    xor     edx, edx
    mov     qword ptr [rcx+RA_STATE_HEAD], rdx
    mov     qword ptr [rcx+RA_STATE_SEQUENCE], rdx
    mov     qword ptr [rcx+RA_STATE_PREV_TAG], rdx
    mov     qword ptr [rcx+RA_STATE_DROPPED], rdx
    mov     qword ptr [rcx+RA_STATE_KEY0], r9
    mov     qword ptr [rcx+RA_STATE_KEY1], rax
    mov     rax, RA_AUTH_MAGIC
    mov     qword ptr [rcx+RA_STATE_MAGIC], rax
    mov     rax, RA_AUTH_VERSION
    mov     qword ptr [rcx+RA_STATE_VERSION], rax
    mov     eax, 1
    ret
rai_fail:
    xor     eax, eax
    ret
RawrXD_RA_Init ENDP

RawrXD_RA_Append PROC
    mov     r10, qword ptr [rsp+40]
    mov     r11, qword ptr [rsp+48]
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rsi, rcx
    mov     r12d, edx
    mov     r13d, r8d
    mov     r14, r9
    mov     r15, r10
    mov     rbx, r11
    test    rsi, rsi
    jz      raa_fail
    mov     rax, qword ptr [rsi+RA_STATE_MAGIC]
    mov     rcx, RA_AUTH_MAGIC
    cmp     rax, rcx
    jne     raa_fail
    mov     rdi, qword ptr [rsi+RA_STATE_BASE]
    test    rdi, rdi
    jz      raa_drop
    mov     rcx, qword ptr [rsi+RA_STATE_CAPACITY]
    test    rcx, rcx
    jz      raa_drop
    mov     rax, qword ptr [rsi+RA_STATE_HEAD]
    xor     edx, edx
    div     rcx
    shl     rdx, 6
    add     rdi, rdx
    mov     rax, qword ptr [rsi+RA_STATE_HEAD]
    inc     rax
    mov     qword ptr [rsi+RA_STATE_HEAD], rax
    mov     rax, qword ptr [rsi+RA_STATE_SEQUENCE]
    inc     rax
    mov     qword ptr [rsi+RA_STATE_SEQUENCE], rax
    mov     qword ptr [rdi+RA_REC_SEQUENCE], rax
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     qword ptr [rdi+RA_REC_TSC], rax
    mov     dword ptr [rdi+RA_REC_KIND], r12d
    mov     dword ptr [rdi+RA_REC_STAGE], r13d
    mov     qword ptr [rdi+RA_REC_ARG0], r14
    mov     qword ptr [rdi+RA_REC_ARG1], r15
    mov     qword ptr [rdi+RA_REC_ARG2], rbx
    mov     rax, qword ptr [rsi+RA_STATE_PREV_TAG]
    mov     qword ptr [rdi+RA_REC_PREV_TAG], rax
    mov     rax, qword ptr [rsi+RA_STATE_KEY0]
    xor     rax, qword ptr [rsi+RA_STATE_KEY1]
    xor     rax, qword ptr [rsi+RA_STATE_PREV_TAG]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    mov     rdx, qword ptr [rdi+00h]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+08h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+10h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+18h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+20h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+28h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+30h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    xor     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, 524158445F415554h
    mov     r8, 0D6E8FEB86659FD93h
    call    RA_MixQword
    test    rax, rax
    jnz     short raa_tag_nonzero
    mov     rax, 1
raa_tag_nonzero:
    mov     qword ptr [rdi+RA_REC_TAG], rax
    mfence
    mov     qword ptr [rsi+RA_STATE_PREV_TAG], rax
    jmp     short raa_exit
raa_drop:
    mov     rax, qword ptr [rsi+RA_STATE_DROPPED]
    inc     rax
    mov     qword ptr [rsi+RA_STATE_DROPPED], rax
raa_fail:
    xor     eax, eax
raa_exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RawrXD_RA_Append ENDP

RawrXD_RA_Verify PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h
    mov     rsi, rcx
    mov     rdi, rdx
    mov     r12, r8
    mov     r13, r9
    test    rsi, rsi
    jz      rav_fail
    test    rdi, rdi
    jz      rav_fail
    test    r12, r12
    jz      rav_empty
rav_loop:
    cmp     qword ptr [rdi+RA_REC_PREV_TAG], r13
    jne     rav_fail
    mov     rax, qword ptr [rsi+RA_STATE_KEY0]
    xor     rax, qword ptr [rsi+RA_STATE_KEY1]
    xor     rax, r13
    mov     rdx, qword ptr [rdi+00h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+08h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+10h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+18h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+20h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+28h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, qword ptr [rdi+30h]
    mov     r8, qword ptr [rsi+RA_STATE_KEY0]
    xor     r8, qword ptr [rsi+RA_STATE_KEY1]
    call    RA_MixQword
    mov     rdx, 524158445F415554h
    mov     r8, 0D6E8FEB86659FD93h
    call    RA_MixQword
    test    rax, rax
    jnz     short rav_tag_nonzero
    mov     rax, 1
rav_tag_nonzero:
    cmp     rax, qword ptr [rdi+RA_REC_TAG]
    jne     rav_fail
    mov     r13, rax
    add     rdi, RA_REC_SIZE
    dec     r12
    jnz     rav_loop
    mov     rax, r13
    jmp     short rav_exit
rav_empty:
    mov     rax, r13
    jmp     short rav_exit
rav_fail:
    xor     eax, eax
rav_exit:
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RawrXD_RA_Verify ENDP
END
