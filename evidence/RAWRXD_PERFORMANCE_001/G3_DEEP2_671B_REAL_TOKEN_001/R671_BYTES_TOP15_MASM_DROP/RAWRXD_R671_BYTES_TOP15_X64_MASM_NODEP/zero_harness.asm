option casemap:none
include r671_bytes15.inc
ExitProcess PROTO

.data?
raw    R671BytesRaw <>
result R671BytesResult <>

.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    lea rcx, raw
    lea rdx, result
    call R671BytesEvaluate
    cmp result.bytes_authorized, 0
    jne bad
    cmp result.notrun_count, 0
    je bad
    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
