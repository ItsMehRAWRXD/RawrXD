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
    mov raw.generation_id, 4
    mov raw.observation_epoch, 4
    mov raw.generated, 1
    mov raw.token_id_mode, TOKEN_ID_MODE_BOUNDED
    mov rax, 0FFFFFFFFFFFFFFF0h
    mov raw.vocab_base_id, rax
    mov raw.vocab_count, 100h
    mov raw.token_id_check_count, 1
    mov raw.min_observed_token_id, rax
    mov raw.max_observed_token_id, rax
    mov raw.run_observed, 1
    lea rcx, raw
    lea rdx, result
    call TokenIdEvaluate
    cmp result.arithmetic_fault, 1
    jne bad
    cmp result.token_id_authorized, 0
    jne bad
    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
