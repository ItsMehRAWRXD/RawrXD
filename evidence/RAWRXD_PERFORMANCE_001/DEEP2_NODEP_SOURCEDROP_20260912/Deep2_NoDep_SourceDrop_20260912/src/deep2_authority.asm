option casemap:none
include ..\include\deep2_nodep.inc
PUBLIC Deep2AttemptDecodeGrant
.code
; rcx=ctx. Grants decode authority only from successful observed runtime calls.
Deep2AttemptDecodeGrant PROC
    test rcx, rcx
    jz ag_fail
    mov rax, D2DEC_MAGIC
    cmp [rcx+D2_CTX_MAGIC], rax
    jne ag_fail
    mov rax, [rcx+D2_CTX_GENERATED]
    test rax, rax
    jz ag_fail
    cmp [rcx+D2_CTX_FORWARD_CALLS], rax
    jne ag_fail
    cmp [rcx+D2_CTX_SELECT_CALLS], rax
    jne ag_fail
    cmp [rcx+D2_CTX_COMMIT_CALLS], rax
    jne ag_fail
    cmp [rcx+D2_CTX_ADVANCE_CALLS], rax
    jne ag_fail
    cmp qword ptr [rcx+D2_CTX_FULL_FORWARD_OBS], 1
    jne ag_fail
    mov eax, dword ptr [rcx+D2_CTX_AUTHORITY]
    and eax, D2_AUTH_FULL_FORWARD or D2_AUTH_TOKEN_SELECTED or D2_AUTH_TOKEN_COMMITTED or D2_AUTH_STATE_ADVANCED
    cmp eax, D2_AUTH_FULL_FORWARD or D2_AUTH_TOKEN_SELECTED or D2_AUTH_TOKEN_COMMITTED or D2_AUTH_STATE_ADVANCED
    jne ag_fail
    or dword ptr [rcx+D2_CTX_AUTHORITY], D2_AUTH_FULL_DECODE
    mov dword ptr [rcx+D2_CTX_ERROR], D2_ERR_NONE
    mov eax, 1
    ret
ag_fail:
    xor eax, eax
    ret
Deep2AttemptDecodeGrant ENDP
END
