; Deep2OuterHost.asm — manifest probe; optional engine ABI when vtable live
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN QueryPerformanceCounter:PROC
EXTERN GetFileAttributesA:PROC
EXTERN Deep2Outer_ResolvePath:PROC
EXTERN Deep2Outer_ScanDirectory:PROC
EXTERN OuterFinalizeScan:PROC
EXTERN OuterScanFlags:PROC
EXTERN OuterZero:PROC
EXTERN OuterPrintFlags:PROC
EXTERN Deep2Outer_WriteEvidence:PROC
EXTERN OuterCallEngine:PROC
PUBLIC Deep2Outer_RunProbe

.code
Deep2Outer_RunProbe PROC PUBLIC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 4B0h
    mov ebx, ecx
    mov r12, rdx
    mov rsi, r8
    xor r13d, r13d
    xor eax, eax
    test rsi, rsi
    jz HP_Done
    mov rcx, rsi
    mov edx, OH_SIZE
    call OuterZero
    lea rcx, [rsp+40h]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+40h]
    mov qword ptr [rsi + OH_QPC_T0], rax
    cmp ebx, OUT_KIND_DEEPSEEK
    mov edi, OUT_EXPECT_K2
    jne HP_Exp
    mov edi, OUT_EXPECT_DS
HP_Exp:
    mov dword ptr [rsi + OH_EXPECTED], edi
    mov ecx, ebx
    lea rdx, [rsp+80h]
    mov r8d, 400
    call Deep2Outer_ResolvePath
    test eax, eax
    jz HP_Eng
    or dword ptr [rsi + OH_FLAGS], OUT_F_PATH
    lea rcx, [rsp+80h]
    call GetFileAttributesA
    cmp eax, INVALID_FILE_ATTRIBUTES
    je HP_Eng
    test eax, FILE_ATTRIBUTE_DIRECTORY
    jz HP_Eng
    or dword ptr [rsi + OH_FLAGS], OUT_F_DIR
    lea rcx, [rsp+80h]
    mov edx, edi
    lea r8, [rsp+280h]
    call Deep2Outer_ScanDirectory
    lea rcx, [rsp+280h]
    call OuterFinalizeScan
    lea rcx, [rsp+280h]
    call OuterScanFlags
    or dword ptr [rsi + OH_FLAGS], eax
    mov eax, dword ptr [rsp+280h + OS_FOUND]
    mov dword ptr [rsi + OH_SHARDS], eax
HP_Eng:
    test r12, r12
    jz HP_Time
    mov eax, dword ptr [rsi + OH_FLAGS]
    and eax, OUT_F_ALL
    cmp eax, OUT_F_ALL
    jne HP_Time
    mov rcx, r12
    lea rdx, [rsp+80h]
    mov r8, rsi
    call OuterCallEngine
    mov r13d, eax
HP_Time:
    lea rcx, [rsp+48h]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+48h]
    sub rax, qword ptr [rsi + OH_QPC_T0]
    mov qword ptr [rsi + OH_QPC], rax
    mov ecx, dword ptr [rsi + OH_FLAGS]
    call OuterPrintFlags
    mov rcx, rsi
    call Deep2Outer_WriteEvidence
    mov eax, dword ptr [rsi + OH_FLAGS]
    and eax, OUT_F_ALL
    cmp eax, OUT_F_ALL
    jne HP_Fail
    test r12, r12
    jz HP_Ok
    test r13d, r13d
    jz HP_Fail
HP_Ok:
    mov eax, 1
    jmp HP_Done
HP_Fail:
    xor eax, eax
HP_Done:
    add rsp, 4B0h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2Outer_RunProbe ENDP
END
