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

    lea rcx, raw
    lea rdx, result
    call TokenCodeEvaluate

    cmp result.tokencode_authorized, 0
    jne bad
    cmp result.notrun_witnesses, 0
    je bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
