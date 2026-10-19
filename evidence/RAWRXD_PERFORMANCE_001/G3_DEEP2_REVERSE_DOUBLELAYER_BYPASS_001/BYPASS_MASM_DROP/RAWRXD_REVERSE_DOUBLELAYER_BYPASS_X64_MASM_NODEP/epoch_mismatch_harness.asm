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
    mov raw.generation_id, 40
    mov raw.generated_tokens, 128
    mov raw.bypass_request, 1
    mov raw.bypass_epoch, 39
    mov raw.bypass_live_generation, 1
    mov raw.bypass_token_commit_count, 128
    mov raw.bypass_decode_commit_count, 128
    lea rcx, raw
    lea rdx, result
    call ReverseDoubleLayerEvaluate
    cmp result.bypass_generation_bound, 0
    jne bad
    cmp result.bypass_authorized, 0
    jne bad
    cmp result.final_authority, 0
    jne bad
    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
