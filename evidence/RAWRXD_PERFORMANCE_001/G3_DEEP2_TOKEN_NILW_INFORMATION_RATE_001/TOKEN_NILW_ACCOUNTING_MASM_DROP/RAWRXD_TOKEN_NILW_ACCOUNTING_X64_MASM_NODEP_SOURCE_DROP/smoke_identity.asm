option casemap:none
include nilw_accounting.inc
ExitProcess PROTO

.data
identity_input LABEL NILW_INPUT
    dq 1000000000000, 5000000000, 4000000000
    dq 800000000, 0, 800000000
    dq 12800000000, 128, 12800000000
    dq 100000000, 1000000000, 10, 128
    dq 1, 1250, 1, 0
    dd 1, 1, 0, 0, 0, 0
identity_result NILW_RESULT <>

.code
main PROC
    sub rsp,28h
    lea rcx,identity_input
    lea rdx,identity_result
    call NilwEvaluate
    test eax,eax
    jnz short failed
    cmp identity_result.gate_mask,000000000001FFFFh
    jne short failed
    cmp identity_result.token_nilw_num,800000000
    jne short failed
    mov rax,1000000000000
    cmp identity_result.token_nilw_den,rax
    jne short failed
    mov rax,3200000000
    cmp identity_result.calculated_reuse_bits,rax
    jne short failed
    xor ecx,ecx
    call ExitProcess
failed:
    mov ecx,1
    call ExitProcess
main ENDP
END
