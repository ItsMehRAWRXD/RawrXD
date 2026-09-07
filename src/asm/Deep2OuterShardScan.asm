; Deep2OuterShardScan.asm — FindFirst/Next *.gguf, generic -of- names only
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN FindFirstFileA:PROC
EXTERN FindNextFileA:PROC
EXTERN FindClose:PROC
EXTERN OuterZero:PROC
EXTERN OuterMakeGlob:PROC
EXTERN OuterJoinPath:PROC
EXTERN Deep2Outer_ParseSplitName:PROC
EXTERN OuterApplyShard:PROC
PUBLIC Deep2Outer_ScanDirectory

.code
Deep2Outer_ScanDirectory PROC PUBLIC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 6A0h
    mov r12, rcx
    mov r13d, edx
    mov rbx, r8
    xor eax, eax
    test r12, r12
    jz SC_Done
    test rbx, rbx
    jz SC_Done
    mov rcx, rbx
    mov edx, OS_SIZE
    call OuterZero
    mov dword ptr [rbx + OS_EXPECTED], r13d
    lea rdx, [rsp+40h]
    mov rcx, r12
    call OuterMakeGlob
    lea rcx, [rsp+40h]
    lea rdx, [rsp+180h]
    call FindFirstFileA
    cmp rax, INVALID_HANDLE_VALUE
    je SC_Done
    mov rsi, rax
SC_Loop:
    lea rcx, [rsp+180h + WIN32_FIND_NAME]
    lea rdx, [rsp+38h]
    lea r8, [rsp+3Ch]
    call Deep2Outer_ParseSplitName
    test eax, eax
    jz SC_Next
    lea r8, [rsp+400h]
    mov rcx, r12
    lea rdx, [rsp+180h + WIN32_FIND_NAME]
    call OuterJoinPath
    mov rcx, rbx
    mov edx, dword ptr [rsp+38h]
    mov r8d, dword ptr [rsp+3Ch]
    lea r9, [rsp+400h]
    call OuterApplyShard
SC_Next:
    mov rcx, rsi
    lea rdx, [rsp+180h]
    call FindNextFileA
    test eax, eax
    jnz SC_Loop
    mov rcx, rsi
    call FindClose
    mov eax, 1
SC_Done:
    add rsp, 6A0h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2Outer_ScanDirectory ENDP
END
