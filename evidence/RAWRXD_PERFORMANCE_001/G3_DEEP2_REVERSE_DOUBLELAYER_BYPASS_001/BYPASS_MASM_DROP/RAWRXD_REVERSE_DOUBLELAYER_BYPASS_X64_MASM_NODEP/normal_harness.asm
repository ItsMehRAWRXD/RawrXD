option casemap:none
include reverse_doublelayer_bypass.inc
ExitProcess PROTO

.data?
raw    RDLRaw <>
result RDLResult <>

.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    mov raw.generation_id, 10
    mov raw.scheduler_epoch, 10
    mov raw.token_epoch, 10
    mov raw.decode_epoch, 10
    mov raw.working_set_epoch, 10
    mov raw.quality_epoch, 10
    mov raw.tensor_math_epoch, 10
    mov raw.scheduler_authorized, 1
    mov raw.token_authorized, 1
    mov raw.decode_authorized, 1
    mov raw.working_set_authorized, 1
    mov raw.quality_authorized, 1
    mov raw.tensor_math_authorized, 1
    mov raw.product_open, 1
    mov raw.session_enter, 1
    mov raw.generated_tokens, 128
    mov raw.token_commit_count, 128
    mov raw.decode_commit_count, 128
    lea rcx, raw
    lea rdx, result
    call ReverseDoubleLayerEvaluate
    cmp result.final_authority, 1
    jne bad
    cmp result.bypass_authorized, 0
    jne bad
    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
