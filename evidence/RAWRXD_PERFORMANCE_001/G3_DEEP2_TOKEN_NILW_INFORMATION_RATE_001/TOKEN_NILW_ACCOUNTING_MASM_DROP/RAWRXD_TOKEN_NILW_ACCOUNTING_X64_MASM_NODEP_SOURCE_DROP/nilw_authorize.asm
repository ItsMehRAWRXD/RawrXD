option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwApplyAuthorityGates

NilwApplyAuthorityGates PROC
    mov rax,[rdx].NILW_RESULT.gate_mask
    cmp [rcx].NILW_INPUT.full_materialization,0
    jne short ag_material_done
    or rax,NILW_G_NO_FULL_MATERIALIZATION
ag_material_done:
    cmp [rcx].NILW_INPUT.reported_budget_overflow,0
    jne short ag_overflow_done
    or rax,NILW_G_NO_REPORTED_OVERFLOW
ag_overflow_done:
    cmp [rcx].NILW_INPUT.longrun_failures,0
    jne short ag_failures_done
    or rax,NILW_G_NO_LONGRUN_FAILURES
ag_failures_done:
    cmp [rcx].NILW_INPUT.live_runtime_witness_count,0
    je short ag_live_done
    or rax,NILW_G_LIVE_WITNESS
ag_live_done:
    cmp [rcx].NILW_INPUT.token_authority_agrees,1
    jne short ag_token_done
    or rax,NILW_G_TOKEN_AUTHORITY
ag_token_done:
    cmp [rcx].NILW_INPUT.decode_authority_agrees,1
    jne short ag_decode_done
    or rax,NILW_G_DECODE_AUTHORITY
ag_decode_done:
    cmp [rcx].NILW_INPUT.superseded_zero_path_used,0
    jne short ag_fallback_done
    or rax,NILW_G_NO_SUPERSEDED_FALLBACK
ag_fallback_done:
    mov r8,rax
    and r8,NILW_G_SUSTAINABLE_REQUIRED
    cmp r8,NILW_G_SUSTAINABLE_REQUIRED
    jne short ag_sustainable_done
    or rax,NILW_G_SUSTAINABLE
ag_sustainable_done:
    mov r8,rax
    and r8,NILW_G_RUNTIME_REQUIRED
    cmp r8,NILW_G_RUNTIME_REQUIRED
    jne short ag_authorized_done
    or rax,NILW_G_RUNTIME_AUTHORIZED
ag_authorized_done:
    mov [rdx].NILW_RESULT.gate_mask,rax
    xor eax,eax
    ret
NilwApplyAuthorityGates ENDP

END
