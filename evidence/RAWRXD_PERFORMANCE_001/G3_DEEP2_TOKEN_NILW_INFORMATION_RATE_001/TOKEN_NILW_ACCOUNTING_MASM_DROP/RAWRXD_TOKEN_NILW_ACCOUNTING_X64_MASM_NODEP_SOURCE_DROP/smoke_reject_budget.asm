option casemap:none
include nilw_accounting.inc
ExitProcess PROTO

.data
budget_input LABEL NILW_INPUT
    dq 1000000000000, 5000000000, 4000000000
    dq 800000008, 0, 800000008
    dq 12800000128, 128, 12800000000
    dq 100000000, 1000000000, 10, 128
    dq 1, 1250, 1, 0
    dd 1, 1, 0, 0, 0, 0
budget_result NILW_RESULT <>

.code
main PROC
    sub rsp,28h
    lea rcx,budget_input
    lea rdx,budget_result
    call NilwEvaluate
    test eax,eax
    jnz short failed
    mov rax,budget_result.gate_mask
    test rax,NILW_G_NILW_LIMIT
    jnz short failed
    test rax,NILW_G_TOKEN_PAYLOAD_CAP
    jnz short failed
    test rax,NILW_G_MEAN_PAYLOAD_CAP
    jnz short failed
    test rax,NILW_G_INFORMATION_RATE
    jnz short failed
    test rax,NILW_G_SUSTAINABLE
    jnz short failed
    test rax,NILW_G_RUNTIME_AUTHORIZED
    jnz short failed
    xor ecx,ecx
    call ExitProcess
failed:
    mov ecx,1
    call ExitProcess
main ENDP
END
