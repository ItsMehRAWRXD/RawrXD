option casemap:none
include enterprise_gate.inc
ExitProcess PROTO :DWORD
.data
obs EnterpriseObserved <>
res EnterpriseGateResult <>
.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    mov obs.product_binary_loaded,1
    mov obs.product_entry_reached,1
    mov obs.real_model_bytes_observed,1
    mov obs.product_runtime_rc,100
    lea rcx,obs
    lea rdx,res
    call ent_evaluate_all
    cmp res.product_prereq_pass,0
    jne bad
    cmp res.enterprise_ready,0
    jne bad
    cmp res.first_fail_code,ENT_E_PRODUCT
    jne bad
    xor ecx,ecx
    call ExitProcess
bad:
    mov ecx,1
    call ExitProcess
main ENDP
END
