option casemap:none
include authoritative_token.inc

ExitProcess PROTO

.data?
raw     RawTokenRuntime <>
derived DerivedTokenRuntime <>

.code
main PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog

    lea rcx, raw
    lea rdx, derived
    call AuthoritativeTokenEvaluate

    ; Zero witness must never authorize.
    cmp derived.authorized_pass, 0
    jne bad

    ; At least one witness must remain NOT_RUN.
    cmp derived.notrun_witnesses, 0
    je bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
