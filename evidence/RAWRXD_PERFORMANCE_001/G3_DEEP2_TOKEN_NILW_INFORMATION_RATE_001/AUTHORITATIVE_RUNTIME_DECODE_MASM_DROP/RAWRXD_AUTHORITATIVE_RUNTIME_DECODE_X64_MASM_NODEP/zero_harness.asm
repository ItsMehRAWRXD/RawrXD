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

    lea rcx, raw
    lea rdx, derived
    call AuthoritativeDecodeEvaluate

    cmp derived.decode_authorized, 0
    jne bad
    cmp derived.notrun_witnesses, 0
    je bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
