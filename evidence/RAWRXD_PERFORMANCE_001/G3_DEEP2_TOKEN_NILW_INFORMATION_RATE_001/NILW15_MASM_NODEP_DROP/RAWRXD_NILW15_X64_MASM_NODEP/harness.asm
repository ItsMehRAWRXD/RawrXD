option casemap:none
include nilw15.inc

ExitProcess PROTO :DWORD
GetStdHandle PROTO :DWORD
WriteFile PROTO :QWORD, :QWORD, :DWORD, :QWORD, :QWORD

STD_OUTPUT_HANDLE equ -11

.data
msg db "RAWRXD_NILW15_X64_MASM_NODEP",13,10
    db "ZERO_WITNESS=1",13,10
    db "NOT_RUN_NE_PASS=1",13,10
    db "AUTHORIZED_PASS=0",13,10
msg_len equ ($ - msg)

.data?
witness Nilw15Witness <>
result  Nilw15Result <>
written DWORD ?

.code
main PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog

    ; Zero BSS => all proof states NOT_RUN.
    lea rcx, witness
    lea rdx, result
    call Nilw15Evaluate

    ; Fail if zero witness ever authorizes.
    cmp result.authorized_pass, 0
    jne bad

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle

    mov rcx, rax
    lea rdx, msg
    mov r8d, msg_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile

    xor ecx, ecx
    call ExitProcess

bad:
    mov ecx, 1
    call ExitProcess
main ENDP

END
