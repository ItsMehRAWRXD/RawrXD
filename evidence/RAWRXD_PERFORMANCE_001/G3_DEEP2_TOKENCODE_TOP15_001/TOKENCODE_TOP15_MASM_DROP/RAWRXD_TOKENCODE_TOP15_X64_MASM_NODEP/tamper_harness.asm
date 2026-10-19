option casemap:none
include tokencode15.inc
ExitProcess PROTO

.data?
raw    TokenCodeRaw <>
result TokenCodeResult <>

.code
main PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    ; Same as positive except tokencode_count=127 (short) to force TE04 FAIL.
    mov raw.generation_id, 92
    mov raw.observation_epoch, 92
    mov raw.generated, 128
    mov raw.encode_request_count, 128
    mov raw.tokencode_count, 127
    mov raw.token_input_count, 128
    mov raw.token_output_count, 128
    mov raw.vocab_size, 32000
    mov raw.min_token_id, 1
    mov raw.max_token_id, 31999
    mov raw.encode_commit_count, 128
    mov raw.first_position, 5000
    mov raw.last_position, 5127
    mov raw.position_observation_count, 128
    mov raw.decode_roundtrip_count, 128
    mov raw.output_bytes_expected, 512
    mov raw.output_bytes_written, 512
    mov raw.run_observed, 1

    lea rcx, raw
    lea rdx, result
    call TokenCodeEvaluate

    lea rax, result.witness_state
    cmp qword ptr [rax+TE04_TOKENCODE_CLOSURE*8], TE_FAIL
    jne bad
    cmp result.tokencode_authorized, 0
    jne bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
