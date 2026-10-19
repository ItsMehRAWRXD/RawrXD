option casemap:none
include nilw_accounting.inc
ExitProcess PROTO

.data
overhead_input LABEL NILW_INPUT
    dq 1000000000000, 5000000000, 4000000000
    dq 799000000, 1000000, 800000000
    dq 12800000000, 128, 12800000000
    dq 100000000, 1000000000, 10, 128
    dq 1, 1250, 1, 0
    dd 1, 1, 0, 0, 0, 0
overhead_result NILW_RESULT <>

.code
main PROC
    sub rsp,28h
    lea rcx,overhead_input
    lea rdx,overhead_result
    call NilwEvaluate
    test eax,eax
    jnz short failed
    cmp overhead_result.gate_mask,000000000001FFFFh
    jne short failed
    cmp overhead_result.calculated_payload_bits,800000000
    jne short failed
    cmp overhead_result.overhead_num,1000000
    jne short failed
    cmp overhead_result.new_information_num,799000000
    jne short failed
    xor ecx,ecx
    call ExitProcess
failed:
    mov ecx,1
    call ExitProcess
main ENDP
END
