; agent_watch.asm
; Polls heartbeat + STATUS and reports lifecycle-aware health.

option casemap:none

EXTERN IPC_Init : PROC
EXTERN IPC_Shutdown : PROC
EXTERN IPC_ReadHeartbeat : PROC
EXTERN IPC_SendCommand : PROC
EXTERN IPC_ReadResponse : PROC

EXTERN GetStdHandle : PROC
EXTERN WriteFile : PROC
EXTERN Sleep : PROC
EXTERN ExitProcess : PROC

STD_OUTPUT_HANDLE      EQU -11
STALL_THRESHOLD        EQU 5
CMD_STATUS_ID          EQU 1002h
CMD_STATUS_TYPE        EQU 1002h

.data
msgInitFail            db "[agent_watch] IPC_Init failed",13,10,0
msgStart               db "[agent_watch] monitoring heartbeat...",13,10,0
msgAlive               db "[agent_watch] ALIVE",13,10,0
msgBusy                db "[agent_watch] BUSY",13,10,0
msgLoading             db "[agent_watch] LOADING",13,10,0
msgReady               db "[agent_watch] READY",13,10,0
msgStall               db "[agent_watch] STALLED",13,10,0
msgDead                db "[agent_watch] orchestrator appears stalled",13,10,0

tokActive              db '"state":"INFERENCE_ACTIVE"',0
tokLoading             db '"state":"LOADING"',0
tokReady               db '"state":"READY"',0
tokUnloaded            db '"state":"UNLOADED"',0

.data?
g_hStdOut              dq ?
g_BytesWritten         dq ?
respBuf                db 512 dup(?)

.code

StrLen PROC
    xor eax, eax
str_len_loop:
    cmp byte ptr [rcx+rax], 0
    je str_len_done
    inc eax
    jmp str_len_loop
str_len_done:
    ret
StrLen ENDP

WriteZ PROC
    push rbx
    sub rsp, 28h
    mov rbx, rcx
    call StrLen
    mov r8d, eax
    mov rcx, [g_hStdOut]
    mov rdx, rbx
    lea r9, [g_BytesWritten]
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 28h
    pop rbx
    ret
WriteZ ENDP

ContainsToken PROC
    ; RCX = haystack (ASCIIZ), RDX = token (ASCIIZ), EAX = 1 if found
    push rbx
    push rsi
    push rdi

    mov rbx, rcx

token_outer:
    mov al, byte ptr [rbx]
    test al, al
    jz token_not_found

    mov rdi, rbx
    mov rsi, rdx

token_inner:
    mov al, byte ptr [rsi]
    test al, al
    jz token_found

    mov cl, byte ptr [rdi]
    test cl, cl
    jz token_advance
    cmp cl, al
    jne token_advance

    inc rdi
    inc rsi
    jmp token_inner

token_advance:
    inc rbx
    jmp token_outer

token_found:
    mov eax, 1
    jmp token_done

token_not_found:
    xor eax, eax

token_done:
    pop rdi
    pop rsi
    pop rbx
    ret
ContainsToken ENDP

PollState PROC
    ; EAX state code: 0 unknown, 1 loading, 2 ready, 3 active, 4 unloaded
    sub rsp, 20h

    mov ecx, CMD_STATUS_ID
    mov edx, CMD_STATUS_TYPE
    xor r8, r8
    xor r9d, r9d
    call IPC_SendCommand
    cmp eax, 0
    jne poll_unknown

    lea rcx, respBuf
    mov edx, 512
    call IPC_ReadResponse
    cmp eax, 0
    jne poll_unknown

    lea rcx, respBuf
    lea rdx, tokActive
    call ContainsToken
    test eax, eax
    jnz poll_active

    lea rcx, respBuf
    lea rdx, tokLoading
    call ContainsToken
    test eax, eax
    jnz poll_loading

    lea rcx, respBuf
    lea rdx, tokReady
    call ContainsToken
    test eax, eax
    jnz poll_ready

    lea rcx, respBuf
    lea rdx, tokUnloaded
    call ContainsToken
    test eax, eax
    jnz poll_unloaded

poll_unknown:
    xor eax, eax
    jmp poll_done

poll_loading:
    mov eax, 1
    jmp poll_done

poll_ready:
    mov eax, 2
    jmp poll_done

poll_active:
    mov eax, 3
    jmp poll_done

poll_unloaded:
    mov eax, 4

poll_done:
    add rsp, 20h
    ret
PollState ENDP

main PROC
    push rbx
    push rsi
    sub rsp, 28h

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [g_hStdOut], rax

    call IPC_Init
    test eax, eax
    jnz watch_start

    lea rcx, msgInitFail
    call WriteZ
    mov ecx, 2
    call ExitProcess

watch_start:
    lea rcx, msgStart
    call WriteZ

    call IPC_ReadHeartbeat
    mov rsi, rax
    xor ebx, ebx

watch_loop:
    mov ecx, 1000
    call Sleep

    call IPC_ReadHeartbeat
    cmp rax, rsi
    jne watch_alive

    ; Heartbeat unchanged: use STATUS polling before declaring stall.
    call PollState
    cmp eax, 3
    je watch_busy
    cmp eax, 1
    je watch_loading
    cmp eax, 2
    je watch_ready
    cmp eax, 4
    je watch_alive

    inc ebx
    lea rcx, msgStall
    call WriteZ
    cmp ebx, STALL_THRESHOLD
    jg watch_dead
    jmp watch_loop

watch_alive:
    mov rsi, rax
    xor ebx, ebx
    call PollState
    cmp eax, 3
    je watch_busy
    cmp eax, 1
    je watch_loading
    cmp eax, 2
    je watch_ready
    lea rcx, msgAlive
    call WriteZ
    jmp watch_loop

watch_busy:
    lea rcx, msgBusy
    call WriteZ
    jmp watch_loop

watch_loading:
    lea rcx, msgLoading
    call WriteZ
    jmp watch_loop

watch_ready:
    lea rcx, msgReady
    call WriteZ
    jmp watch_loop

watch_dead:
    lea rcx, msgDead
    call WriteZ
    call IPC_Shutdown
    mov ecx, 3
    call ExitProcess

    add rsp, 28h
    pop rsi
    pop rbx
    ret
main ENDP

END
