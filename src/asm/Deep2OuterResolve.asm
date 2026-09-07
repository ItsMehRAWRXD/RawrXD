; Deep2OuterResolve.asm — env first, then locked model directories
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN Deep2Outer_GetEnvPath:PROC
EXTERN OuterCopyZ:PROC
PUBLIC Deep2Outer_ResolvePath

.data
def_k2 db "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M",0
def_ds db "F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE",0

.code
; ECX=kind RDX=dst R8D=dstBytes  EAX=1 non-empty
Deep2Outer_ResolvePath PROC PUBLIC
    push rbx
    push rsi
    sub rsp, 28h
    mov ebx, ecx
    mov rsi, rdx
    call Deep2Outer_GetEnvPath
    test eax, eax
    jnz RP_Ok
    cmp ebx, OUT_KIND_DEEPSEEK
    je RP_Ds
    lea rdx, def_k2
    jmp RP_Copy
RP_Ds:
    lea rdx, def_ds
RP_Copy:
    mov rcx, rsi
    call OuterCopyZ
    cmp byte ptr [rsi], 0
    je RP_Fail
RP_Ok:
    mov eax, 1
    jmp RP_Done
RP_Fail:
    xor eax, eax
RP_Done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
Deep2Outer_ResolvePath ENDP
END
