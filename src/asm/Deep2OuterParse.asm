; Deep2OuterParse.asm — locate -of- and parse total + .gguf
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN Deep2Outer_ParseIndexLeft:PROC
PUBLIC Deep2Outer_ParseSplitName

.code
Deep2Outer_ParseSplitName PROC PUBLIC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    xor eax, eax
    test rcx, rcx
    jz P_Done
    test rdx, rdx
    jz P_Done
    test r8, r8
    jz P_Done
    mov dword ptr [rdx], 0
    mov dword ptr [r8], 0
    mov rsi, rcx
    mov rbx, rdx
    mov rdi, r8
P_Find:
    mov al, byte ptr [rsi]
    test al, al
    jz P_Fail
    cmp al, '-'
    jne P_Next
    mov al, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'o'
    jne P_Next
    mov al, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'f'
    jne P_Next
    cmp byte ptr [rsi+3], '-'
    je P_Hit
P_Next:
    inc rsi
    jmp P_Find
P_Hit:
    lea r9, [rsi+4]
    xor eax, eax
    xor r10d, r10d
P_Tot:
    movzx r11d, byte ptr [r9]
    cmp r11b, '0'
    jb P_TotEnd
    cmp r11b, '9'
    ja P_TotEnd
    imul eax, eax, 10
    sub r11d, '0'
    add eax, r11d
    inc r9
    inc r10d
    cmp eax, 4095
    ja P_Fail
    jmp P_Tot
P_TotEnd:
    test r10d, r10d
    jz P_Fail
    test eax, eax
    jz P_Fail
    mov dword ptr [rdi], eax
    cmp byte ptr [r9], '.'
    jne P_Fail
    mov al, byte ptr [r9+1]
    or al, 20h
    cmp al, 'g'
    jne P_Fail
    mov al, byte ptr [r9+2]
    or al, 20h
    cmp al, 'g'
    jne P_Fail
    mov al, byte ptr [r9+3]
    or al, 20h
    cmp al, 'u'
    jne P_Fail
    mov al, byte ptr [r9+4]
    or al, 20h
    cmp al, 'f'
    jne P_Fail
    cmp byte ptr [r9+5], 0
    jne P_Fail
    mov rcx, rsi
    mov rdx, rbx
    call Deep2Outer_ParseIndexLeft
    jmp P_Done
P_Fail:
    xor eax, eax
P_Done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2Outer_ParseSplitName ENDP
END
