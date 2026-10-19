option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwValidateShape

NilwValidateShape PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    mov rsi,rcx
    mov rdi,rdx
    xor ebx,ebx

    cmp [rsi].NILW_INPUT.total_logical_weights,0
    jne short vs_total_ok
    or rbx,NILW_ERR_TOTAL_WEIGHTS_ZERO
vs_total_ok:
    cmp [rsi].NILW_INPUT.active_logical_weights,0
    jne short vs_active_nonzero
    or rbx,NILW_ERR_ACTIVE_WEIGHTS_ZERO
vs_active_nonzero:
    mov rax,[rsi].NILW_INPUT.active_logical_weights
    cmp rax,[rsi].NILW_INPUT.total_logical_weights
    jbe short vs_active_ok
    or rbx,NILW_ERR_ACTIVE_RANGE
vs_active_ok:
    cmp [rsi].NILW_INPUT.active_codec_bits,0
    jne short vs_codec_ok
    or rbx,NILW_ERR_CODEC_BITS_ZERO
vs_codec_ok:
    mov rax,[rsi].NILW_INPUT.new_codec_bits
    cmp rax,[rsi].NILW_INPUT.active_codec_bits
    jbe short vs_new_ok
    or rbx,NILW_ERR_NEW_GT_CODEC
vs_new_ok:
    cmp [rsi].NILW_INPUT.target_nilw_num,0
    je short vs_bad_nilw
    cmp [rsi].NILW_INPUT.target_nilw_den,0
    jne short vs_nilw_ok
vs_bad_nilw:
    or rbx,NILW_ERR_TARGET_NILW_ZERO
vs_nilw_ok:
    cmp [rsi].NILW_INPUT.payload_cap_bytes_per_token,0
    jne short vs_payload_ok
    or rbx,NILW_ERR_PAYLOAD_CAP_ZERO
vs_payload_ok:
    cmp [rsi].NILW_INPUT.information_rate_cap_bps,0
    jne short vs_rate_ok
    or rbx,NILW_ERR_RATE_CAP_ZERO
vs_rate_ok:
    cmp [rsi].NILW_INPUT.target_tps,0
    jne short vs_tps_ok
    or rbx,NILW_ERR_TARGET_TPS_ZERO
vs_tps_ok:
    cmp [rsi].NILW_INPUT.min_generated_tokens,0
    jne short vs_min_ok
    or rbx,NILW_ERR_MIN_TOKENS_ZERO
vs_min_ok:
    cmp [rsi].NILW_INPUT.run_generated_tokens,0
    jne short vs_tokens_ok
    or rbx,NILW_ERR_RUN_TOKENS_ZERO
vs_tokens_ok:
    cmp [rsi].NILW_INPUT.run_wall_ns,0
    jne short vs_wall_ok
    or rbx,NILW_ERR_WALL_NS_ZERO
vs_wall_ok:
    mov eax,[rsi].NILW_INPUT.token_authority_agrees
    or eax,[rsi].NILW_INPUT.decode_authority_agrees
    or eax,[rsi].NILW_INPUT.superseded_zero_path_used
    or eax,[rsi].NILW_INPUT.full_materialization
    or eax,[rsi].NILW_INPUT.reported_budget_overflow
    cmp eax,1
    jbe short vs_bools_ok
    or rbx,NILW_ERR_BOOLEAN_RANGE
vs_bools_ok:
    mov [rdi].NILW_RESULT.error_mask,rbx
    test rbx,rbx
    jz short vs_valid
    mov [rdi].NILW_RESULT.status,NILW_E_INVALID
    mov eax,NILW_E_INVALID
    jmp short vs_done
vs_valid:
    xor eax,eax
vs_done:
    pop rdi
    pop rsi
    pop rbx
    ret
NilwValidateShape ENDP

END
