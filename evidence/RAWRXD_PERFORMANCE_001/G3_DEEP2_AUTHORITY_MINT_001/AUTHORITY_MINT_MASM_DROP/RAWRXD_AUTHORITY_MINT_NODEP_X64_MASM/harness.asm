option casemap:none
include AuthorityState.inc

ExitProcess PROTO
AuthorityContractTest PROTO

.code
main PROC
    sub rsp, 28h
    call AuthorityContractTest
    mov ecx, eax
    call ExitProcess
main ENDP
END
