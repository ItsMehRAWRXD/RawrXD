option casemap:none
include authoritative_decode.inc

ExitProcess PROTO

.data?
raw     RawDecodeRuntime <>
derived DerivedDecodeRuntime <>

.code
main PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov raw.product_open_attempts, 1
    mov raw.product_open_success, 1
    mov raw.session_enter_attempts, 1
    mov raw.session_enter_success, 1
    mov raw.decode_enter_count, 128
    mov raw.decode_exit_count, 128
    mov raw.requested_tokens, 128
    mov raw.generated_tokens, 128
    mov raw.layer_forward_calls, 4096
    mov raw.expected_layer_forwards, 4096
    mov raw.lmhead_calls, 128
    mov raw.logits_ready_count, 128
    mov raw.token_select_count, 128
    mov raw.token_commit_count, 128
    mov raw.first_step_id, 0
    mov raw.last_step_id, 127
    mov raw.step_observation_count, 128
    mov raw.host_forward_calls, 4096
    mov raw.declared_path, PATH_HOST
    mov raw.output_bytes, 1024
    mov raw.output_tokens_visible, 128

    lea rcx, raw
    lea rdx, derived
    call AuthoritativeDecodeEvaluate

    cmp derived.decode_authorized, 1
    jne bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
