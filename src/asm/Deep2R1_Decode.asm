; Deep2R1_Decode.asm — global + blk.<layer>.<suffix> name decode
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
EXTERN ScanRoleTable:PROC
EXTERN GlobalRoleTable:BYTE
EXTERN MlaRoleTable:BYTE
EXTERN MoeRoleTable:BYTE
PUBLIC Deep2R1_DecodeTensorName

.code
Deep2R1_DecodeTensorName PROC PUBLIC
    push r12
    push r13
    push r14
    sub rsp, 20h
    mov r12, rcx
    mov r13, rdx
    xor eax, eax
    test r12, r12
    jz R1D_Fail
    test r13, r13
    jz R1D_Fail
    mov dword ptr [r13 + R1D_ROLE], R1_ROLE_UNKNOWN
    mov dword ptr [r13 + R1D_LAYER], R1_LAYER_NONE
    mov dword ptr [r13 + R1D_EXPERT], R1_EXPERT_NONE
    mov dword ptr [r13 + R1D_FLAGS], 0
    mov rcx, r12
    lea rdx, GlobalRoleTable
    mov r8, r13
    call ScanRoleTable
    test eax, eax
    jnz R1D_Ok
    cmp byte ptr [r12], 'b'
    jne R1D_Fail
    cmp byte ptr [r12+1], 'l'
    jne R1D_Fail
    cmp byte ptr [r12+2], 'k'
    jne R1D_Fail
    cmp byte ptr [r12+3], '.'
    jne R1D_Fail
    lea r14, [r12+4]
    xor eax, eax
    xor r10d, r10d
R1D_Parse:
    movzx r11d, byte ptr [r14]
    cmp r11b, '0'
    jb short R1D_EndL
    cmp r11b, '9'
    ja short R1D_EndL
    imul eax, eax, 10
    sub r11d, '0'
    add eax, r11d
    cmp eax, 4095
    ja R1D_Fail
    inc r14
    inc r10d
    jmp short R1D_Parse
R1D_EndL:
    test r10d, r10d
    jz R1D_Fail
    cmp byte ptr [r14], '.'
    jne R1D_Fail
    inc r14
    mov dword ptr [r13 + R1D_LAYER], eax
    mov rcx, r14
    lea rdx, MlaRoleTable
    mov r8, r13
    call ScanRoleTable
    test eax, eax
    jnz short R1D_Ok
    mov rcx, r14
    lea rdx, MoeRoleTable
    mov r8, r13
    call ScanRoleTable
    test eax, eax
    jnz short R1D_Ok
R1D_Fail:
    xor eax, eax
    jmp short R1D_Done
R1D_Ok:
    mov eax, 1
R1D_Done:
    add rsp, 20h
    pop r14
    pop r13
    pop r12
    ret
Deep2R1_DecodeTensorName ENDP
END
