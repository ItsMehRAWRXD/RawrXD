option casemap:none
include nilw_accounting.inc
ExitProcess PROTO

.data
bad_input LABEL NILW_INPUT
    dq 1000000000000, 5000000000, 4000000000
    dq 800000000, 0, 799999999
    dq 12800000000, 128, 12800000000
    dq 100000000, 1000000000, 10, 128
    dq 1, 1250, 1, 0
    dd 1, 1, 0, 0, 0, 0
bad_result NILW_RESULT <>

.code
main PROC
    sub rsp,28h
    lea rcx,bad_input
    lea rdx,bad_result
    call NilwEvaluate
    cmp eax,NILW_E_INVALID
    jne short failed
    test bad_result.error_mask,NILW_ERR_IDENTITY_MISMATCH
    jz short failed
    cmp bad_result.gate_mask,0
    jne short failed
    xor ecx,ecx
    call ExitProcess
failed:
    mov ecx,1
    call ExitProcess
main ENDP
END
