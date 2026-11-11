; agent_control.asm
; Sends CMD_STATUS through shared IPC and prints response.

option casemap:none

EXTERN IPC_Init : PROC
EXTERN IPC_Shutdown : PROC
EXTERN IPC_SendCommand : PROC
EXTERN IPC_ReadResponse : PROC

EXTERN GetStdHandle : PROC
EXTERN WriteFile : PROC
EXTERN ExitProcess : PROC

STD_OUTPUT_HANDLE      EQU -11
CMD_STATUS_TYPE        EQU 1002h
CMD_STATUS_ID          EQU 1002h

.data
msgInitFail            db "[agent_control] IPC_Init failed",13,10,0
msgStatusPrefix        db "RESP_STATUS=0x",0
msgPayloadPrefix       db "RESP_PAYLOAD=",0
msgNewline             db 13,10,0

.data?
g_hStdOut              dq ?
g_BytesWritten         dq ?
respBuf                db 4096 dup(?)
hexBuf                 db 9 dup(?)

.code

StrLen PROC
    ; RCX = ASCIIZ pointer, EAX = length
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
    ; RCX = ASCIIZ pointer
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

Hex32 PROC
    ; ECX=value, RDX=output buffer (9 bytes min)
    push rbx
    mov ebx, ecx
    mov r8, rdx
    mov r9d, 8
hex32_loop:
    mov eax, ebx
    shr eax, 28
    and eax, 0Fh
    cmp eax, 9
    jbe hex32_digit
    add eax, 7
hex32_digit:
    add eax, '0'
    mov byte ptr [r8], al
    inc r8
    shl ebx, 4
    dec r9d
    jnz hex32_loop
    mov byte ptr [r8], 0
    pop rbx
    ret
Hex32 ENDP

main PROC
    sub rsp, 28h

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [g_hStdOut], rax

    call IPC_Init
    test eax, eax
    jnz control_send

    lea rcx, msgInitFail
    call WriteZ
    mov ecx, 2
    call ExitProcess

control_send:
    mov ecx, CMD_STATUS_ID
    mov edx, CMD_STATUS_TYPE
    xor r8, r8
    xor r9d, r9d
    call IPC_SendCommand

    lea rcx, respBuf
    mov edx, 4096
    call IPC_ReadResponse
    mov ebx, eax
    mov esi, edx

    lea rcx, msgStatusPrefix
    call WriteZ
    mov ecx, ebx
    lea rdx, hexBuf
    call Hex32
    lea rcx, hexBuf
    call WriteZ
    lea rcx, msgNewline
    call WriteZ

    cmp esi, 0
    jle control_done

    lea rcx, msgPayloadPrefix
    call WriteZ
    lea rcx, respBuf
    call WriteZ
    lea rcx, msgNewline
    call WriteZ

control_done:
    call IPC_Shutdown
    mov ecx, ebx
    call ExitProcess

    add rsp, 28h
    ret
main ENDP

END
