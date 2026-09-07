; Deep2OuterCallEngine.asm — invoke open/generate/close when vtable live
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN QueryPerformanceCounter:PROC
PUBLIC OuterCallEngine

.data
def_prompt db "hello",0

.code
; RCX=api RDX=dir R8=hostRec  EAX=1 if OUT_E_ALL
OuterCallEngine PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 40h
    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    xor eax, eax
    test rbx, rbx
    jz CE_Done
    test rsi, rsi
    jz CE_Done
    test rdi, rdi
    jz CE_Done
    mov rax, qword ptr [rbx + OE_OPEN]
    test rax, rax
    jz CE_Done
    mov r12, qword ptr [rbx + OE_GENERATE]
    test r12, r12
    jz CE_Done
    mov r13, qword ptr [rbx + OE_CLOSE]
    test r13, r13
    jz CE_Done
    or dword ptr [rdi + OH_ENG_FLAGS], OUT_E_OPEN_ENTERED
    lea rcx, [rsp+30h]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+30h]
    mov qword ptr [rdi + OH_QPC_OPEN], rax
    mov qword ptr [rsp+38h], 0
    mov rcx, rsi
    lea rdx, [rsp+38h]
    call qword ptr [rbx + OE_OPEN]
    test eax, eax
    jz CE_Close
    cmp qword ptr [rsp+38h], 0
    je CE_Close
    or dword ptr [rdi + OH_ENG_FLAGS], OUT_E_OPEN_HANDLE
    or dword ptr [rdi + OH_ENG_FLAGS], OUT_E_GEN_ENTERED
    lea rcx, [rsp+30h]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+30h]
    mov qword ptr [rdi + OH_QPC_FIRST], rax
    mov rcx, qword ptr [rsp+38h]
    lea rdx, def_prompt
    mov r8d, 2
    call r12
    test eax, eax
    jz CE_Close
    or dword ptr [rdi + OH_ENG_FLAGS], OUT_E_GEN_OK
CE_Close:
    lea rcx, [rsp+30h]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+30h]
    mov qword ptr [rdi + OH_QPC_END], rax
    mov rcx, qword ptr [rsp+38h]
    test rcx, rcx
    jz CE_Flags
    or dword ptr [rdi + OH_ENG_FLAGS], OUT_E_CLOSE_ENTERED
    call r13
CE_Flags:
    mov eax, dword ptr [rdi + OH_ENG_FLAGS]
    and eax, OUT_E_ALL
    cmp eax, OUT_E_ALL
    je CE_Ok
    xor eax, eax
    jmp CE_Done
CE_Ok:
    mov eax, 1
CE_Done:
    add rsp, 40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OuterCallEngine ENDP
END
