; agent_ipc.asm
; Shared MMF/event IPC layer for sovereign agents.

option casemap:none

EXTERN OpenFileMappingA : PROC
EXTERN MapViewOfFile : PROC
EXTERN UnmapViewOfFile : PROC
EXTERN OpenEventA : PROC
EXTERN SetEvent : PROC
EXTERN WaitForSingleObject : PROC
EXTERN CloseHandle : PROC

FILE_MAP_ALL_ACCESS      EQU 0F001Fh
EVENT_MODIFY_STATE       EQU 0002h
SYNCHRONIZE              EQU 00100000h
EVENT_OPEN_RIGHTS        EQU (EVENT_MODIFY_STATE OR SYNCHRONIZE)
WAIT_TIMEOUT_MS          EQU 3000
IPC_PROTOCOL_VERSION     EQU 1
IPC_CMDPAYLOAD_MAX       EQU 0FFFh
IPC_RESPPAYLOAD_MAX      EQU 0EFD8h

IPC_STATE                EQU 0
IPC_CMDID                EQU 4
IPC_CMDTYPE              EQU 8
IPC_PAYLEN               EQU 12
IPC_RESPSTATUS           EQU 16
IPC_RESPLEN              EQU 20
IPC_CMDPAYLOAD           EQU 18h
IPC_RESPBUF              EQU 1018h
IPC_HEARTBEAT            EQU 0FFF8h

.data
szMapName      db "SOVEREIGN_BEACON_V1",0
szCmdEvent     db "SOVEREIGN_CMD_EVENT",0
szRespEvent    db "SOVEREIGN_RESP_EVENT",0

.data?
PUBLIC g_hMap
PUBLIC g_hCmdEvt
PUBLIC g_hRespEvt
PUBLIC g_pView

g_hMap         dq ?
g_hCmdEvt      dq ?
g_hRespEvt     dq ?
g_pView        dq ?

.code

PUBLIC IPC_Init
IPC_Init PROC
    sub rsp, 40h

    ; Open shared memory mapping.
    mov ecx, FILE_MAP_ALL_ACCESS
    xor edx, edx
    lea r8, szMapName
    call OpenFileMappingA
    mov [g_hMap], rax
    test rax, rax
    jz ipc_init_fail

    ; Map full view.
    mov rcx, rax
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    call MapViewOfFile
    mov [g_pView], rax
    test rax, rax
    jz ipc_init_fail

    ; Open command event.
    mov ecx, EVENT_OPEN_RIGHTS
    xor edx, edx
    lea r8, szCmdEvent
    call OpenEventA
    mov [g_hCmdEvt], rax
    test rax, rax
    jz ipc_init_fail

    ; Open response event.
    mov ecx, EVENT_OPEN_RIGHTS
    xor edx, edx
    lea r8, szRespEvent
    call OpenEventA
    mov [g_hRespEvt], rax
    test rax, rax
    jz ipc_init_fail

    mov eax, 1
    add rsp, 40h
    ret

ipc_init_fail:
    call IPC_Shutdown
    xor eax, eax
    add rsp, 40h
    ret
IPC_Init ENDP

PUBLIC IPC_Shutdown
IPC_Shutdown PROC
    sub rsp, 20h

    mov rcx, [g_pView]
    test rcx, rcx
    jz ipc_no_view
    call UnmapViewOfFile
    mov qword ptr [g_pView], 0

ipc_no_view:
    mov rcx, [g_hCmdEvt]
    test rcx, rcx
    jz ipc_no_cmd_evt
    call CloseHandle
    mov qword ptr [g_hCmdEvt], 0

ipc_no_cmd_evt:
    mov rcx, [g_hRespEvt]
    test rcx, rcx
    jz ipc_no_resp_evt
    call CloseHandle
    mov qword ptr [g_hRespEvt], 0

ipc_no_resp_evt:
    mov rcx, [g_hMap]
    test rcx, rcx
    jz ipc_shutdown_done
    call CloseHandle
    mov qword ptr [g_hMap], 0

ipc_shutdown_done:
    add rsp, 20h
    ret
IPC_Shutdown ENDP

; RCX=CmdID, RDX=CmdType, R8=PayloadPtr(optional), R9=PayloadLen
; Return EAX = WaitForSingleObject result (WAIT_OBJECT_0 on success).
PUBLIC IPC_SendCommand
IPC_SendCommand PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h

    mov r10d, ecx
    mov r11d, edx
    mov edx, r9d

    test edx, edx
    jns ipc_send_len_nonneg
    xor edx, edx
ipc_send_len_nonneg:
    cmp edx, IPC_CMDPAYLOAD_MAX
    jbe ipc_send_len_ok
    mov edx, IPC_CMDPAYLOAD_MAX
ipc_send_len_ok:

    mov rbx, [g_pView]
    test rbx, rbx
    jz ipc_send_fail

    mov byte ptr [rbx+IPC_STATE], 1
    mov dword ptr [rbx+IPC_CMDID], r10d
    mov dword ptr [rbx+IPC_CMDTYPE], r11d
    mov dword ptr [rbx+IPC_PAYLEN], edx

    lea rdi, [rbx+IPC_CMDPAYLOAD]
    test r8, r8
    jz ipc_send_zero
    test edx, edx
    jle ipc_send_zero

    mov rsi, r8
    mov ecx, edx
    rep movsb

ipc_send_zero:
    mov byte ptr [rdi], 0

    mov rcx, [g_hCmdEvt]
    call SetEvent

    mov rcx, [g_hRespEvt]
    mov edx, WAIT_TIMEOUT_MS
    call WaitForSingleObject
    jmp ipc_send_done

ipc_send_fail:
    mov eax, 0FFFFFFFFh

ipc_send_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
IPC_SendCommand ENDP

; RCX=OutBuf(optional), RDX=OutBufCapacity
; Return EAX=RespStatus, EDX=RespLen
PUBLIC IPC_ReadResponse
IPC_ReadResponse PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h

    mov r8, rcx
    mov r9d, edx

    mov rbx, [g_pView]
    test rbx, rbx
    jz ipc_read_fail

    mov eax, dword ptr [rbx+IPC_RESPSTATUS]
    mov r10d, dword ptr [rbx+IPC_RESPLEN]

    test r10d, r10d
    jns ipc_read_len_nonneg
    xor r10d, r10d
ipc_read_len_nonneg:
    cmp r10d, IPC_RESPPAYLOAD_MAX
    jbe ipc_read_len_ok
    mov r10d, IPC_RESPPAYLOAD_MAX
ipc_read_len_ok:

    test r8, r8
    jz ipc_read_done
    test r9d, r9d
    jle ipc_read_done

    mov ecx, r9d
    dec ecx
    jle ipc_read_terminate_only

    mov edx, r10d
    cmp edx, ecx
    cmova edx, ecx

    lea rsi, [rbx+IPC_RESPBUF]
    mov rdi, r8
    mov ecx, edx
    rep movsb
    mov byte ptr [rdi], 0
    jmp ipc_read_done

ipc_read_terminate_only:
    mov byte ptr [r8], 0
    jmp ipc_read_done

ipc_read_fail:
    mov eax, 0FFFFFFFFh
    xor r10d, r10d

ipc_read_done:
    mov edx, r10d
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
IPC_ReadResponse ENDP

; Return RAX = heartbeat counter (QWORD)
PUBLIC IPC_ReadHeartbeat
IPC_ReadHeartbeat PROC
    mov rax, [g_pView]
    test rax, rax
    jz ipc_hb_zero
    mov rax, qword ptr [rax+IPC_HEARTBEAT]
    ret
ipc_hb_zero:
    xor rax, rax
    ret
IPC_ReadHeartbeat ENDP

END
