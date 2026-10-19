option casemap:none
include ..\include\deep2_nodep.inc
PUBLIC Deep2ForwardProbeFail
PUBLIC Deep2ForwardProbeClear
.code
; rcx=ctx, edx=stage, r8d=reason
Deep2ForwardProbeFail PROC
    test rcx, rcx
    jz fpf_fail
    mov [rcx+D2_CTX_FAIL_STAGE], edx
    mov [rcx+D2_CTX_FAIL_REASON], r8d
    xor eax, eax
    ret
fpf_fail:
    xor eax, eax
    ret
Deep2ForwardProbeFail ENDP

Deep2ForwardProbeClear PROC
    test rcx, rcx
    jz fpc_fail
    mov dword ptr [rcx+D2_CTX_FAIL_STAGE], D2_FW_NONE
    mov dword ptr [rcx+D2_CTX_FAIL_REASON], 0
    mov eax, 1
    ret
fpc_fail:
    xor eax, eax
    ret
Deep2ForwardProbeClear ENDP
END
