; Deep2OuterPrintIO.asm — GetStdHandle/WriteFile zstring
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
PUBLIC OuterWriteZ

.code
OuterWriteZ PROC
    push rsi
    sub rsp, 30h
    mov rsi, rcx
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    cmp rax, INVALID_HANDLE_VALUE
    je WZ_Done
    test rsi, rsi
    jz WZ_Done
    mov rcx, rax
    xor eax, eax
WZ_Len:
    cmp byte ptr [rsi+rax], 0
    je WZ_Go
    inc eax
    jmp WZ_Len
WZ_Go:
    mov rdx, rsi
    mov r8d, eax
    lea r9, [rsp+28h]
    mov qword ptr [rsp+20h], 0
    call WriteFile
WZ_Done:
    add rsp, 30h
    pop rsi
    ret
OuterWriteZ ENDP
END
