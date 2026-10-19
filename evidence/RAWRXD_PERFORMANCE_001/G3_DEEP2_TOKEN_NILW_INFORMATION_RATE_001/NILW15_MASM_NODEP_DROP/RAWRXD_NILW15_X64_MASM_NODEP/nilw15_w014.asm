option casemap:none
include nilw15.inc

.code
; rcx=witness* → CF=0 if W01..W14 all derived PASS
Nilw15DeriveWitnesses PROC FRAME
    push rsi
    .pushreg rsi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rsi, rcx
    call Nilw15FormNumerator
    jc dw_fail
    mov rcx, rsi
    call Nilw15DeriveRates
    jc dw_fail
    mov rax, qword ptr [rsi].Nilw15Witness.active_logical_weights
    test rax, rax
    jz dw_fail
    cmp rax, qword ptr [rsi].Nilw15Witness.total_logical_weights
    jae dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_ACTIVE_SUBSET*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.active_subset_measured, PROOF_PASS
    mov rax, qword ptr [rsi].Nilw15Witness.form
    cmp rax, NILW_FORM_A
    je p_a
    mov rax, qword ptr [rsi].Nilw15Witness.new_payload_bits
    jmp p_c
p_a: mov rax, qword ptr [rsi].Nilw15Witness.new_information_bits
p_c: test rax, rax
    jz dw_fail
    cmp rax, qword ptr [rsi].Nilw15Witness.payload_bits_fetched
    jne dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_NEW_PAYLOAD*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_FORM_SELECTION*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.reuse_events, 0
    je dw_fail
    cmp qword ptr [rsi].Nilw15Witness.reused_bits, 0
    je dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_REUSE*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.reuse_measured, PROOF_PASS
    mov rax, qword ptr [rsi].Nilw15Witness.payload_bits_fetched
    cmp rax, qword ptr [rsi].Nilw15Witness.component_bits_sum
    jne dw_fail
    cmp rax, qword ptr [rsi].Nilw15Witness.class_bits_sum
    jne dw_fail
    cmp qword ptr [rsi].Nilw15Witness.unaccounted_bits, 0
    jne dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_OVERHEAD*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_ACCOUNTING*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.overhead_accounted, PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.active_bpw_x1e6, 0
    je dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_ACTIVE_BPW*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.token_nilw_x1e9, TOKEN_NILW_LIMIT_X1E9
    ja dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_TOKEN_NILW*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.information_rate_bps, INFO_RATE_BPS_MAX
    ja dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_BANDWIDTH*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.generated_tokens, TOKENS_MIN
    jb dw_fail
    cmp qword ptr [rsi].Nilw15Witness.tps_x1000, TPS_X1000_MIN
    jb dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_TOKEN_RATE*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.mean_payload_bytes_token, PAYLOAD_BYTES_LIMIT
    ja dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_PAYLOAD_PER_TOKEN*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.full_model_materialization, 0
    jne dw_fail
    cmp qword ptr [rsi].Nilw15Witness.full_layer_materialization, 0
    jne dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_FULL_MATERIAL*8], PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.quality_baseline_value, 0
    je dw_fail
    mov rax, qword ptr [rsi].Nilw15Witness.quality_metric_value
    cmp rax, qword ptr [rsi].Nilw15Witness.quality_baseline_value
    jb dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_QUALITY*8], PROOF_PASS
    mov qword ptr [rsi].Nilw15Witness.quality_gate_pass, PROOF_PASS
    cmp qword ptr [rsi].Nilw15Witness.longrun_failures, 0
    jne dw_fail
    cmp qword ptr [rsi].Nilw15Witness.payload_budget_overflow, 0
    jne dw_fail
    cmp qword ptr [rsi].Nilw15Witness.stale_generation_faults, 0
    jne dw_fail
    mov qword ptr [rsi].Nilw15Witness.witness_state[WIT_LONGRUN*8], PROOF_PASS
    clc
    jmp dw_done
dw_fail:
    stc
dw_done:
    add rsp, 28h
    pop rsi
    ret
Nilw15DeriveWitnesses ENDP
END
