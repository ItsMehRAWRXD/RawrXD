option casemap:none
include tokencode_tokenid_domain.inc
ExitProcess PROTO

.data?
raw    TokenIdRaw <>
result TokenIdResult <>

.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    mov raw.generation_id, 1
    mov raw.observation_epoch, 1
    mov raw.generated, 128
    mov raw.token_id_mode, TOKEN_ID_MODE_BOUNDED
    mov raw.vocab_base_id, 0
    mov raw.vocab_count, 500000
    mov raw.token_id_check_count, 128
    mov raw.min_observed_token_id, 0
    mov raw.max_observed_token_id, 499999
    mov raw.run_observed, 1
    lea rcx, raw
    lea rdx, result
    call TokenIdEvaluate
    cmp result.token_id_authorized, 1
    jne bad
    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
