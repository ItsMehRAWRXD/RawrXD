option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwDeriveExact

NilwDeriveExact PROC FRAME
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

    mov rax,[rsi].NILW_INPUT.new_codec_bits
    add rax,[rsi].NILW_INPUT.overhead_bits
    jc short de_sum_overflow
    mov [rdi].NILW_RESULT.calculated_payload_bits,rax
    cmp rax,[rsi].NILW_INPUT.observed_new_payload_bits
    je short de_identity_ok
    or rbx,NILW_ERR_IDENTITY_MISMATCH
    jmp short de_identity_ok
de_sum_overflow:
    or rbx,NILW_ERR_PAYLOAD_SUM_OVERFLOW
de_identity_ok:
    mov rax,[rsi].NILW_INPUT.observed_new_payload_bits
    mov rcx,rax
    shr rcx,3
    and eax,7
    jz short de_ceil_ready
    inc rcx
de_ceil_ready:
    cmp [rsi].NILW_INPUT.run_new_payload_bytes,rcx
    jae short de_run_ok
    or rbx,NILW_ERR_RUN_PAYLOAD_TOO_SMALL
de_run_ok:
    mov [rdi].NILW_RESULT.error_mask,rbx
    test rbx,rbx
    jz short de_fill
    mov [rdi].NILW_RESULT.status,NILW_E_INVALID
    mov eax,NILW_E_INVALID
    jmp de_done

de_fill:
    mov rax,[rsi].NILW_INPUT.active_codec_bits
    sub rax,[rsi].NILW_INPUT.new_codec_bits
    mov [rdi].NILW_RESULT.calculated_reuse_bits,rax
    mov rax,[rsi].NILW_INPUT.active_codec_bits
    mov [rdi].NILW_RESULT.active_codec_bpw_num,rax
    mov rax,[rsi].NILW_INPUT.active_logical_weights
    mov [rdi].NILW_RESULT.active_codec_bpw_den,rax
    mov [rdi].NILW_RESULT.physicalization_num,rax
    mov rax,[rsi].NILW_INPUT.total_logical_weights
    mov [rdi].NILW_RESULT.physicalization_den,rax
    mov [rdi].NILW_RESULT.overhead_den,rax
    mov [rdi].NILW_RESULT.token_nilw_den,rax
    mov rax,[rsi].NILW_INPUT.new_codec_bits
    mov [rdi].NILW_RESULT.new_information_num,rax
    mov rax,[rsi].NILW_INPUT.active_codec_bits
    mov [rdi].NILW_RESULT.new_information_den,rax
    mov rax,[rsi].NILW_INPUT.overhead_bits
    mov [rdi].NILW_RESULT.overhead_num,rax
    mov rax,[rsi].NILW_INPUT.observed_new_payload_bits
    mov [rdi].NILW_RESULT.token_nilw_num,rax
    mov rax,[rsi].NILW_INPUT.run_new_payload_bytes
    mov [rdi].NILW_RESULT.mean_payload_bytes_num,rax
    mov [rdi].NILW_RESULT.information_rate_bytes_num,rax
    mov rax,[rsi].NILW_INPUT.run_generated_tokens
    mov [rdi].NILW_RESULT.mean_payload_tokens_den,rax
    mov [rdi].NILW_RESULT.generation_tps_tokens_num,rax
    mov rax,[rsi].NILW_INPUT.run_wall_ns
    mov [rdi].NILW_RESULT.information_rate_wall_ns_den,rax
    mov [rdi].NILW_RESULT.generation_tps_wall_ns_den,rax
    xor eax,eax
de_done:
    pop rdi
    pop rsi
    pop rbx
    ret
NilwDeriveExact ENDP

END
