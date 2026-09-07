; Deep2OuterEnv.asm — DEEP2_K2_SHARD_DIR / DEEP2_DEEPSEEK_MODEL
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN GetEnvironmentVariableA:PROC
PUBLIC Deep2Outer_GetEnvPath

.data
env_k2  db "DEEP2_K2_SHARD_DIR",0
env_ds  db "DEEP2_DEEPSEEK_MODEL",0

.code
; ECX=kind RDX=dst R8D=dstBytes  EAX=1 present
Deep2Outer_GetEnvPath PROC PUBLIC
    push rbx
    push rsi
    sub rsp, 28h
    xor eax, eax
    mov rsi, rdx
    mov ebx, r8d
    test rsi, rsi
    jz ENV_Done
    test ebx, ebx
    jz ENV_Done
    mov byte ptr [rsi], 0
    cmp ecx, OUT_KIND_DEEPSEEK
    je ENV_Ds
    lea rcx, env_k2
    jmp ENV_Call
ENV_Ds:
    lea rcx, env_ds
ENV_Call:
    mov rdx, rsi
    mov r8d, ebx
    call GetEnvironmentVariableA
    test eax, eax
    jz ENV_Fail
    cmp eax, ebx
    jae ENV_Fail
    mov eax, 1
    jmp ENV_Done
ENV_Fail:
    xor eax, eax
    mov byte ptr [rsi], 0
ENV_Done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
Deep2Outer_GetEnvPath ENDP
END
