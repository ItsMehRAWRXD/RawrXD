; Deep2OuterSmoke.asm — argv 1=K2/13  2=DeepSeek/11  (no generation claim)
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN GetCommandLineA:PROC
EXTERN ExitProcess:PROC
EXTERN Deep2Outer_RunProbe:PROC

.data
ALIGN 16
hostrec db OH_SIZE dup(0)

.code
ParseKind PROC
    sub rsp, 28h
    call GetCommandLineA
    mov rcx, rax
    test rcx, rcx
    jz PK_One
PK_Skip:
    mov al, byte ptr [rcx]
    test al, al
    jz PK_One
    cmp al, ' '
    je PK_Sp
    inc rcx
    jmp PK_Skip
PK_Sp:
    inc rcx
    cmp byte ptr [rcx], ' '
    je PK_Sp
    cmp byte ptr [rcx], '2'
    je PK_Two
PK_One:
    mov eax, OUT_KIND_K2
    add rsp, 28h
    ret
PK_Two:
    mov eax, OUT_KIND_DEEPSEEK
    add rsp, 28h
    ret
ParseKind ENDP

mainCRTStartup PROC
    sub rsp, 28h
    call ParseKind
    mov ecx, eax
    xor edx, edx
    lea r8, hostrec
    call Deep2Outer_RunProbe
    test eax, eax
    jz SM_Fail
    xor ecx, ecx
    call ExitProcess
SM_Fail:
    mov ecx, 1
    call ExitProcess
mainCRTStartup ENDP
END
