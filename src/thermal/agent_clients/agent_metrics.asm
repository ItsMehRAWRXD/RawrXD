; agent_metrics.asm
; Requests telemetry metrics and writes metrics.json.

option casemap:none

EXTERN IPC_Init : PROC
EXTERN IPC_Shutdown : PROC
EXTERN IPC_SendCommand : PROC
EXTERN IPC_ReadResponse : PROC

EXTERN CreateFileA : PROC
EXTERN WriteFile : PROC
EXTERN CloseHandle : PROC
EXTERN ExitProcess : PROC
EXTERN GetStdHandle : PROC

GENERIC_WRITE          EQU 40000000h
CREATE_ALWAYS          EQU 2
FILE_ATTRIBUTE_NORMAL  EQU 80h
STD_OUTPUT_HANDLE      EQU -11

CMD_METRICS_ID         EQU 7000h
CMD_METRICS_TYPE       EQU 7000h
MODEL_STATE_UNLOADED   EQU 0
MODEL_STATE_LOADING    EQU 1
MODEL_STATE_READY      EQU 2
MODEL_STATE_ACTIVE     EQU 3

.data
szMetricsFile          db "metrics.json",0
msgInitFail            db "[agent_metrics] IPC_Init failed",13,10,0
msgWriteFail           db "[agent_metrics] failed to write metrics.json",13,10,0
msgDone                db "[agent_metrics] wrote metrics.json",13,10,0
jsonPrefixUnloaded     db '{"protocol":1,"state":"UNLOADED","model_loaded":false,"inference_active":false,"heartbeat_hex":"0x',0
jsonPrefixLoading      db '{"protocol":1,"state":"LOADING","model_loaded":false,"inference_active":false,"heartbeat_hex":"0x',0
jsonPrefixReady        db '{"protocol":1,"state":"READY","model_loaded":true,"inference_active":false,"heartbeat_hex":"0x',0
jsonPrefixActive       db '{"protocol":1,"state":"INFERENCE_ACTIVE","model_loaded":true,"inference_active":true,"heartbeat_hex":"0x',0
jsonPrefixUnknown      db '{"protocol":1,"state":"UNKNOWN","model_loaded":false,"inference_active":false,"heartbeat_hex":"0x',0
jsonMidErr             db '","last_error":"0x',0
jsonSuffix             db '"}',13,10,0

.data?
g_hStdOut              dq ?
g_BytesWritten         dq ?
outBuf                 db 4096 dup(?)
jsonBuf                db 512 dup(?)
hex64Buf               db 17 dup(?)
hex32Buf               db 9 dup(?)

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

AppendStr PROC
    ; RCX = source ASCIIZ, RDX = destination, returns RAX=end pointer
    push rsi
    push rdi
    push rbx

    mov rbx, rcx
    mov rcx, rbx
    call StrLen

    mov rsi, rbx
    mov rdi, rdx
    mov ecx, eax
    rep movsb
    mov byte ptr [rdi], 0
    mov rax, rdi

    pop rbx
    pop rdi
    pop rsi
    ret
AppendStr ENDP

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

Hex64 PROC
    ; RCX=value, RDX=output buffer (17 bytes min)
    push rbx
    mov rbx, rcx
    mov r8, rdx
    mov r9d, 16
hex64_loop:
    mov rax, rbx
    shr rax, 60
    and eax, 0Fh
    cmp eax, 9
    jbe hex64_digit
    add eax, 7
hex64_digit:
    add eax, '0'
    mov byte ptr [r8], al
    inc r8
    shl rbx, 4
    dec r9d
    jnz hex64_loop
    mov byte ptr [r8], 0
    pop rbx
    ret
Hex64 ENDP

main PROC
    push rbx
    sub rsp, 40h

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [g_hStdOut], rax

    call IPC_Init
    test eax, eax
    jnz metrics_send

    lea rcx, msgInitFail
    call WriteZ
    mov ecx, 2
    call ExitProcess

metrics_send:
    mov ecx, CMD_METRICS_ID
    mov edx, CMD_METRICS_TYPE
    xor r8, r8
    xor r9d, r9d
    call IPC_SendCommand

    lea rcx, outBuf
    mov edx, 4096
    call IPC_ReadResponse
    mov ebx, eax
    mov esi, edx

    cmp ebx, 0
    jne metrics_fail

    ; Build JSON output. If response is a JSON object already, write as-is.
    cmp esi, 2
    jl metrics_wrap
    cmp byte ptr [outBuf], '{'
    jne metrics_wrap

    lea rcx, szMetricsFile
    mov edx, GENERIC_WRITE
    xor r8d, r8d
    xor r9d, r9d
    mov dword ptr [rsp+20h], CREATE_ALWAYS
    mov dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, -1
    je metrics_fail

    mov rcx, rax
    lea rdx, outBuf
    mov r8d, esi
    lea r9, [g_BytesWritten]
    mov qword ptr [rsp+20h], 0
    call WriteFile
    call CloseHandle
    jmp metrics_done

metrics_wrap:
    ; Expected telemetry payload layout:
    ; [0..3]=state, [4..7]=last_error, [8..11]=last_win32,
    ; [12..15]=load_ms, [16..23]=heartbeat.
    cmp esi, 24
    jl metrics_fail

    mov eax, dword ptr [outBuf]
    cmp eax, MODEL_STATE_UNLOADED
    je metrics_prefix_unloaded
    cmp eax, MODEL_STATE_LOADING
    je metrics_prefix_loading
    cmp eax, MODEL_STATE_READY
    je metrics_prefix_ready
    cmp eax, MODEL_STATE_ACTIVE
    je metrics_prefix_active
    lea rcx, jsonPrefixUnknown
    jmp metrics_prefix_set

metrics_prefix_unloaded:
    lea rcx, jsonPrefixUnloaded
    jmp metrics_prefix_set
metrics_prefix_loading:
    lea rcx, jsonPrefixLoading
    jmp metrics_prefix_set
metrics_prefix_ready:
    lea rcx, jsonPrefixReady
    jmp metrics_prefix_set
metrics_prefix_active:
    lea rcx, jsonPrefixActive

metrics_prefix_set:
    lea rdx, jsonBuf
    call AppendStr
    mov rdi, rax

    mov rcx, qword ptr [outBuf+16]
    lea rdx, hex64Buf
    call Hex64

    lea rcx, hex64Buf
    mov rdx, rdi
    call AppendStr
    mov rdi, rax

    lea rcx, jsonMidErr
    mov rdx, rdi
    call AppendStr
    mov rdi, rax

    mov ecx, dword ptr [outBuf+4]
    lea rdx, hex32Buf
    call Hex32

    lea rcx, hex32Buf
    mov rdx, rdi
    call AppendStr
    mov rdi, rax

    lea rcx, jsonSuffix
    mov rdx, rdi
    call AppendStr

    lea rcx, szMetricsFile
    mov edx, GENERIC_WRITE
    xor r8d, r8d
    xor r9d, r9d
    mov dword ptr [rsp+20h], CREATE_ALWAYS
    mov dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, -1
    je metrics_fail

    mov rbx, rax
    lea rcx, jsonBuf
    call StrLen

    mov rcx, rbx
    lea rdx, jsonBuf
    mov r8d, eax
    lea r9, [g_BytesWritten]
    mov qword ptr [rsp+20h], 0
    call WriteFile

    mov rcx, rbx
    call CloseHandle

metrics_done:
    lea rcx, msgDone
    call WriteZ
    call IPC_Shutdown
    xor ecx, ecx
    call ExitProcess

metrics_fail:
    lea rcx, msgWriteFail
    call WriteZ
    call IPC_Shutdown
    mov ecx, 4
    call ExitProcess

    add rsp, 40h
    pop rbx
    ret
main ENDP

END
