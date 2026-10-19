option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwApplyPerformanceGates

NilwApplyPerformanceGates PROC FRAME
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push rbx
    .pushreg rbx
    sub rsp,20h
    .allocstack 20h
    .endprolog
    mov rsi,rcx
    mov rdi,rdx
    mov ebx,NILW_G_INPUT_VALID or NILW_G_IDENTITY

    mov rcx,[rsi].NILW_INPUT.observed_new_payload_bits
    mov rdx,[rsi].NILW_INPUT.target_nilw_den
    mov r8,[rsi].NILW_INPUT.total_logical_weights
    mov r9,[rsi].NILW_INPUT.target_nilw_num
    call NilwU128MulLE
    test eax,eax
    jz short pg_nilw_done
    or rbx,NILW_G_NILW_LIMIT
pg_nilw_done:
    mov rcx,[rsi].NILW_INPUT.observed_new_payload_bits
    mov edx,1
    mov r8,[rsi].NILW_INPUT.payload_cap_bytes_per_token
    mov r9d,8
    call NilwU128MulLE
    test eax,eax
    jz short pg_token_done
    or rbx,NILW_G_TOKEN_PAYLOAD_CAP
pg_token_done:
    mov rcx,[rsi].NILW_INPUT.run_new_payload_bytes
    mov edx,1
    mov r8,[rsi].NILW_INPUT.run_generated_tokens
    mov r9,[rsi].NILW_INPUT.payload_cap_bytes_per_token
    call NilwU128MulLE
    test eax,eax
    jz short pg_mean_done
    or rbx,NILW_G_MEAN_PAYLOAD_CAP
pg_mean_done:
    mov rcx,[rsi].NILW_INPUT.run_new_payload_bytes
    mov edx,1000000000
    mov r8,[rsi].NILW_INPUT.information_rate_cap_bps
    mov r9,[rsi].NILW_INPUT.run_wall_ns
    call NilwU128MulLE
    test eax,eax
    jz short pg_rate_done
    or rbx,NILW_G_INFORMATION_RATE
pg_rate_done:
    mov rcx,[rsi].NILW_INPUT.target_tps
    mov rdx,[rsi].NILW_INPUT.run_wall_ns
    mov r8,[rsi].NILW_INPUT.run_generated_tokens
    mov r9d,1000000000
    call NilwU128MulLE
    test eax,eax
    jz short pg_tps_done
    or rbx,NILW_G_TARGET_TPS
pg_tps_done:
    mov rax,[rsi].NILW_INPUT.run_generated_tokens
    cmp rax,[rsi].NILW_INPUT.min_generated_tokens
    jb short pg_min_done
    or rbx,NILW_G_MIN_TOKEN_WINDOW
pg_min_done:
    mov [rdi].NILW_RESULT.gate_mask,rbx
    xor eax,eax
    add rsp,20h
    pop rbx
    pop rdi
    pop rsi
    ret
NilwApplyPerformanceGates ENDP

END
