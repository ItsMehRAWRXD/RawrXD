; P1_ProductRuntimeAuthority_Smoke_x64.asm — v002 contract smoke
; Exit 0 = PASS, 1 = fail-closed broken, 2 = user prompt path broken

option casemap:none

include P1_ProductRuntimeAuthority_x64.inc

EXTERN P1PRA_Initialize:PROC
EXTERN P1PRA_BeginUserPrompt:PROC
EXTERN P1PRA_Finalize:PROC

.data?
ALIGN 8
SmokeState BYTE P1PRA_STATE_SIZE DUP(?)

.data
ALIGN 1
TestPrompt db "test", 0

.code

PUBLIC P1_SmokeEntry

P1_SmokeEntry PROC
    sub     rsp, 28h

    lea     rcx, SmokeState
    call    P1PRA_Initialize

    lea     rcx, SmokeState
    call    P1PRA_Finalize
    test    rax, rax
    jz      short fail_closed

    lea     rcx, SmokeState
    lea     rdx, TestPrompt
    mov     r8, 4
    call    P1PRA_BeginUserPrompt
    test    rax, rax
    jz      short fail_prompt

    lea     rcx, SmokeState
    call    P1PRA_Finalize
    test    rax, rax
    jz      short fail_prompt_finalize

    xor     eax, eax
    add     rsp, 28h
    ret

fail_closed:
    mov     eax, 1
    add     rsp, 28h
    ret

fail_prompt:
    mov     eax, 2
    add     rsp, 28h
    ret

fail_prompt_finalize:
    mov     eax, 3
    add     rsp, 28h
    ret

P1_SmokeEntry ENDP

END
