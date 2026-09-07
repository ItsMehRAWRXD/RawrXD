; Deep2R1_Scan.asm — walk 16-byte name/role table
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
EXTERN StrEqA:PROC
PUBLIC ScanRoleTable

.code
; RCX=name RDX=table R8=Deep2R1TensorRoleDecode*
ScanRoleTable PROC
    push r12
    push r13
    push r14
    sub rsp, 20h
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
ScanLoop:
    mov rdx, qword ptr [r13]
    test rdx, rdx
    jz short ScanNo
    mov rcx, r12
    call StrEqA
    test eax, eax
    jnz short ScanYes
    add r13, 16
    jmp short ScanLoop
ScanYes:
    mov eax, dword ptr [r13 + 8]
    mov dword ptr [r14 + R1D_ROLE], eax
    mov eax, dword ptr [r13 + 12]
    mov dword ptr [r14 + R1D_FLAGS], eax
    mov eax, 1
    jmp short ScanDone
ScanNo:
    xor eax, eax
ScanDone:
    add rsp, 20h
    pop r14
    pop r13
    pop r12
    ret
ScanRoleTable ENDP
END
