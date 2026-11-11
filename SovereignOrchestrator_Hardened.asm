; ================================================================
; SovereignOrchestrator_Hardened.asm
; Pure x64 MASM | Zero-dependency beacon orchestrator
; Single-instance mutex + integrity cookie + watchdog heartbeat
; ================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

; ----------------------------------------------------------------
; IMPORTS
; ----------------------------------------------------------------
EXTRN CreateFileMappingA:PROC
EXTRN MapViewOfFile:PROC
EXTRN UnmapViewOfFile:PROC
EXTRN CreateEventA:PROC
EXTRN SetEvent:PROC
EXTRN WaitForSingleObject:PROC
EXTRN CreateMutexA:PROC
EXTRN GetLastError:PROC
EXTRN GetTickCount64:PROC
EXTRN ReleaseMutex:PROC
EXTRN ProcessIdToSessionId:PROC
EXTRN GetCurrentProcessId:PROC
EXTRN GetStdHandle:PROC
EXTRN WriteFile:PROC
EXTRN ExitProcess:PROC
EXTRN CreateThread:PROC
EXTRN CloseHandle:PROC

; ----------------------------------------------------------------
; External Sovereign pipeline symbols
; ----------------------------------------------------------------
EXTRN SOVEREIGN_LOAD_MODEL:PROC
EXTRN SOVEREIGN_UNLOAD_MODEL:PROC
EXTRN STREAMER_INIT:PROC
EXTRN STREAMER_PUSH_TOKEN:PROC
EXTRN STREAMER_FLUSH:PROC
EXTRN InferenceWorkerThread:PROC
EXTRN DequeueAsyncResponse:PROC
EXTRN g_RingHead:QWORD
EXTRN g_RingTail:QWORD
EXTRN g_RingDropped:QWORD
EXTRN g_RingBackpressure:QWORD
EXTRN g_StreamerEnabled:DWORD

; ----------------------------------------------------------------
; Constants
; ----------------------------------------------------------------
SHMEM_SIZE            EQU 65536
PAGE_READWRITE        EQU 04h
FILE_MAP_ALL_ACCESS   EQU 0F001Fh
WAIT_OBJECT_0         EQU 0
WAIT_TIMEOUT          EQU 102h

BEACON_READY          EQU 01h
BEACON_PROCESSING     EQU 02h
BEACON_COMPLETE       EQU 04h
BEACON_SHUTDOWN       EQU 0FFh

; Legacy command values (kept for backward compatibility)
CMD_LOAD_MODEL_LEGACY EQU 10h
CMD_INFERENCE_LEGACY  EQU 20h
CMD_STATUS_LEGACY     EQU 30h
CMD_HOTPATCH_LEGACY   EQU 40h
CMD_TELEMETRY_LEGACY  EQU 50h

; Command ID families
CMD_PING              EQU 1000h
CMD_GET_VERSION       EQU 1001h
CMD_GET_STATUS        EQU 1002h
CMD_SHUTDOWN          EQU 1003h
CMD_RELOAD_CONFIG     EQU 1004h
CMD_GET_HEARTBEAT     EQU 1005h

CMD_LOAD_MODEL        EQU 2000h
CMD_UNLOAD_MODEL      EQU 2001h
CMD_LIST_MODELS       EQU 2002h
CMD_GET_MODEL_INFO    EQU 2003h
CMD_VERIFY_GGUF       EQU 2004h
CMD_PATCH_METADATA    EQU 2005h

CMD_BEGIN_SESSION     EQU 3000h
CMD_END_SESSION       EQU 3001h
CMD_TOKENIZE          EQU 3002h
CMD_INFER             EQU 3003h
CMD_NEXT_TOKEN        EQU 3004h
CMD_CANCEL_INFER      EQU 3005h

CMD_STREAM_START      EQU 4000h
CMD_STREAM_STOP       EQU 4001h
CMD_STREAM_PAUSE      EQU 4002h
CMD_STREAM_RESUME     EQU 4003h
CMD_STREAM_STATUS     EQU 4004h

CMD_CACHE_STATUS      EQU 5000h
CMD_CACHE_EVICT       EQU 5001h
CMD_CACHE_PIN         EQU 5002h
CMD_CACHE_UNPIN       EQU 5003h
CMD_CACHE_FLUSH       EQU 5004h

CMD_NVME_STATUS       EQU 6000h
CMD_NVME_PREFETCH     EQU 6001h
CMD_NVME_CANCEL       EQU 6002h
CMD_NVME_BURST        EQU 6003h
CMD_NVME_THERMAL      EQU 6004h

CMD_GET_METRICS       EQU 7000h
CMD_GET_MEMORY        EQU 7001h
CMD_GET_VRAM          EQU 7002h
CMD_GET_IO            EQU 7003h
CMD_GET_THREADS       EQU 7004h

CMD_AGENT_REGISTER    EQU 8000h
CMD_AGENT_UNREGISTER  EQU 8001h
CMD_AGENT_LIST        EQU 8002h
CMD_AGENT_HEALTH      EQU 8003h
CMD_AGENT_BROADCAST   EQU 8004h

OFF_STATE             EQU 00h
OFF_CMD_ID            EQU 04h
OFF_CMD_TYPE          EQU 08h
OFF_PAYLOAD_LEN       EQU 0Ch
OFF_RESP_STATUS       EQU 10h
OFF_RESP_LEN          EQU 14h
OFF_CMD_PAYLOAD       EQU 18h
OFF_RESP_PAYLOAD      EQU 1018h
OFF_MAGIC_COOKIE      EQU 0FFF0h
OFF_HEARTBEAT         EQU 0FFF8h
OFF_MODEL_STATE       EQU 2030h
OFF_RING_HEAD         EQU 2040h
OFF_RING_TAIL         EQU 2048h
OFF_RING_DROPPED      EQU 2050h
OFF_RING_BACKPRESSURE EQU 2058h
OFF_RING_FILL_LEVEL   EQU 2060h
OFF_RING_CAPACITY     EQU 2064h
OFF_RING_LAST_CMD_ID  EQU 2068h
OFF_RING_LAST_STATUS  EQU 206Ch
OFF_RING_LAST_PLEN    EQU 2070h
OFF_RING_LAST_FLAGS   EQU 2074h
OFF_RING_LAST_TS      EQU 2078h
OFF_RING_LAST_PAYLOAD0 EQU 2080h
OFF_RING_LAST_PAYLOAD1 EQU 2088h
OFF_SHUTDOWN_SENTINEL EQU 2090h
CMD_PAYLOAD_MAX       EQU 0FFFh
RESP_PAYLOAD_MAX      EQU 0EFD8h

MAGIC_COOKIE_VAL      EQU 0CAFEBABEDEADBEEFH
SHUTDOWN_SENTINEL_CLEAN EQU 00000000DEADBEEFH

RESP_OK               EQU 0
RESP_UNKNOWN_CMD      EQU 1
RESP_INVALID_PAYLOAD  EQU 2
RESP_TIMEOUT          EQU 3
RESP_INTERNAL_ERROR   EQU 4
RESP_NOT_READY        EQU 5
RESP_MODEL_NOT_LOADED EQU 6
RESP_BUSY             EQU 7
RESP_CANCELLED        EQU 8

MODEL_STATE_UNLOADED         EQU 0
MODEL_STATE_LOADING          EQU 1
MODEL_STATE_READY            EQU 2
MODEL_STATE_INFERENCE_ACTIVE EQU 3
MODEL_STATE_CANCEL_PENDING   EQU 4

; Async SPSC ring metrics
ASYNC_RING_SIZE       EQU 64
ASYNC_RING_MASK       EQU (ASYNC_RING_SIZE - 1)
ASYNC_PAYLOAD_BYTES   EQU 256

ERR_OK                EQU RESP_OK
ERR_UNKNOWN_CMD       EQU RESP_UNKNOWN_CMD
ERR_TIMEOUT           EQU RESP_TIMEOUT
ERR_MUTEX_COLLISION   EQU 0E0000005h
ERR_LOAD_FAIL         EQU RESP_INTERNAL_ERROR
ERR_AUDIT_FAIL        EQU 0E0000006h

; Shared with worker object for dequeue copy target
RESPONSE_SLOT STRUCT
    CmdId           DD ?
    Status          DD ?
    PayloadLen      DD ?
    Flags           DD ?
    TimestampQpc    DQ ?
    Payload         DB ASYNC_PAYLOAD_BYTES DUP(?)
RESPONSE_SLOT ENDS

; ----------------------------------------------------------------
; Data
; ----------------------------------------------------------------
.DATA
ALIGN 8

g_MutexName           DB "SOVEREIGN_ORCH_MUTEX",0
g_ShMemName           DB "SOVEREIGN_BEACON_V1",0
g_CmdEventName        DB "SOVEREIGN_CMD_EVENT",0
g_RespEventName       DB "SOVEREIGN_RESP_EVENT",0
g_InferEventName      DB "SOVEREIGN_INFER_EVENT",0
g_CancelEventName     DB "SOVEREIGN_CANCEL_EVENT",0

g_Banner              DB "[ORCH] SovereignOrchestrator Hardened",13,10,0
g_MsgMutexFail        DB "[FATAL] Existing instance detected.",13,10,0
g_MsgListen           DB "[ORCH] Listening on beacon.",13,10,0
g_MsgShutdown         DB "[ORCH] Shutdown signal received.",13,10,0
g_MsgTimeout          DB "[WARN] Watchdog timeout.",13,10,0
g_MsgCorrupt          DB "[WARN] Cookie mismatch; resetting header.",13,10,0
g_MsgDirtyReset       DB "[WARN] DIRTY_RESET_DETECTED; forcing beacon reset.",13,10,0
g_MsgStatusDisp       DB "[CMD] STATUS dispatched",13,10,0
g_MsgRespLenBad       DB "[WARN] Response length out of bounds; payload dropped.",13,10,0
g_MsgDiagHdr          DB "[DIAG] Initialization Banner",13,10,0
g_MsgDiagPid          DB "[DIAG] PID=",0
g_MsgDiagShMem        DB "[DIAG] hShMem=",0
g_MsgDiagCmdEvt       DB "[DIAG] hCmdEvent=",0
g_MsgDiagRespEvt      DB "[DIAG] hRespEvent=",0
g_MsgDiagBase         DB "[DIAG] pShMem=",0
g_MsgDiagUptime       DB "[DIAG] uptime_ms=",0
g_MsgDiagLastErr      DB "[DIAG] last_error=",0
g_MsgDiagBad          DB "[CRITICAL] Handle invalid; refusing to enter dispatch loop.",13,10,0
g_MsgDiagLastErrBad   DB "[CRITICAL] Startup LastError nonzero; refusing to enter dispatch loop.",13,10,0
g_RespPing            DB '{"pong":true}',0
g_RespVersion         DB '{"status":"ok","mode":"sovereign","ver":"1.1","protocol":1}',0

g_RespStateUnloaded   DB '{"status":"ok","mode":"sovereign","ver":"1.1","protocol":1,"state":"UNLOADED","inference_active":false}',0
g_RespStateLoading    DB '{"status":"ok","mode":"sovereign","ver":"1.1","protocol":1,"state":"LOADING","inference_active":false}',0
g_RespStateReady      DB '{"status":"ok","mode":"sovereign","ver":"1.1","protocol":1,"state":"READY","inference_active":false}',0
g_RespStateActive     DB '{"status":"ok","mode":"sovereign","ver":"1.1","protocol":1,"state":"INFERENCE_ACTIVE","inference_active":true}',0
g_RespLoad            DB '{"status":"loading","stage":"mmap"}',0
g_RespReady           DB '{"status":"ready","protocol":1}',0
g_RespUnloaded        DB '{"status":"unloaded"}',0
g_RespInferDone       DB '{"status":"inference_complete"}',0
g_RespStreamReady     DB '{"status":"ok","stream_state":"ready"}',0
g_RespStreamActive    DB '{"status":"ok","stream_state":"active"}',0

PUBLIC g_hMutex
PUBLIC g_hShMem
PUBLIC g_pShMem
PUBLIC g_hCmdEvent
PUBLIC g_hRespEvent
PUBLIC g_hInferenceTrigger
PUBLIC g_hCancelEvent
PUBLIC g_hInferenceThread
PUBLIC g_StdOut
PUBLIC g_PID
PUBLIC g_SessionId
PUBLIC g_Running
PUBLIC g_ModelState
PUBLIC g_LastLoadResult
PUBLIC g_LastLoadWin32Error
g_LastLoadResult      DD 0
g_LastLoadWin32Error  DD 0
g_LastLoadDurationMs  DD 0
g_ModelState          DD MODEL_STATE_UNLOADED
g_LoadStartTick       DQ 0
g_HexOut              DB "0x0000000000000000",13,10,0
g_ExitCode            DD 0

CoreTable             DQ OFFSET HandlePing
                      DQ OFFSET HandleGetVersion
                      DQ OFFSET HandleStatus
                      DQ OFFSET HandleShutdownCmd
                      DQ OFFSET HandleReloadConfig
                      DQ OFFSET HandleTelemetry

ModelTable            DQ OFFSET HandleLoadModel
                      DQ OFFSET HandleUnloadModel
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady

InferTable            DQ OFFSET HandleBeginSession
                      DQ OFFSET HandleEndSession
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleInference
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleCancelInfer

StreamTable           DQ OFFSET HandleStreamStart
                      DQ OFFSET HandleStreamStop
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleStreamStatus

CacheTable            DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady

NvmeTable             DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady

TelemetryTable        DQ OFFSET HandleTelemetry
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady

AgentTable            DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady
                      DQ OFFSET HandleNotReady

; ----------------------------------------------------------------
; BSS
; ----------------------------------------------------------------
.DATA?
ALIGN 16

g_hMutex              DQ ?
g_hShMem              DQ ?
g_pShMem              DQ ?
g_hCmdEvent           DQ ?
g_hRespEvent          DQ ?
g_hInferenceTrigger   DQ ?
g_hCancelEvent        DQ ?
g_hInferenceThread    DQ ?
g_StdOut              DQ ?
g_PID                 DD ?
g_SessionId           DD ?
g_Running             DB ?
g_LastAsyncSlot       RESPONSE_SLOT <>

; ----------------------------------------------------------------
; Code
; ----------------------------------------------------------------
.CODE

main PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40h
    .allocstack 40h
    .endprolog

    mov dword ptr [g_ExitCode], 0

    ; stdout
    mov rcx, -11
    call GetStdHandle
    mov [g_StdOut], rax

    ; pid / session
    call GetCurrentProcessId
    mov [g_PID], eax
    mov ecx, eax
    lea rdx, [g_SessionId]
    call ProcessIdToSessionId

    lea rcx, [g_Banner]
    call PrintString

    ; single-instance mutex
    xor rcx, rcx
    xor edx, edx
    lea r8, [g_MutexName]
    call CreateMutexA
    mov [g_hMutex], rax
    test rax, rax
    jz main_fatal

    call GetLastError
    cmp eax, 183
    jne mutex_ok
    lea rcx, [g_MsgMutexFail]
    call PrintString
    mov ecx, ERR_MUTEX_COLLISION
    call ExitProcess

mutex_ok:
    call BeaconInit
    test al, al
    jz main_fatal

    call System_Audit
    test al, al
    jz main_fatal

    lea rcx, [g_MsgListen]
    call PrintString

    mov byte ptr [g_Running], 1
    call DispatchLoop

main_exit:
    call BeaconCleanup
    mov rcx, [g_hMutex]
    test rcx, rcx
    jz no_release
    call ReleaseMutex
no_release:
    mov ecx, dword ptr [g_ExitCode]
    call ExitProcess

main_fatal:
    mov eax, dword ptr [g_ExitCode]
    test eax, eax
    jnz main_fatal_msg
    mov dword ptr [g_ExitCode], ERR_AUDIT_FAIL
main_fatal_msg:
    lea rcx, [g_MsgShutdown]
    call PrintString
    jmp main_exit
main ENDP

System_Audit PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    call PrintBanner
    test al, al
    jz audit_fail

    ; Print startup LastError for immediate triage.
    call GetLastError
    mov dword ptr [rsp+18h], eax
    mov edx, eax
    lea rcx, [g_MsgDiagLastErr]
    call PrintHandleLine
    mov eax, dword ptr [rsp+18h]

    ; Only ERROR_SUCCESS and ERROR_ALREADY_EXISTS are tolerated.
    test eax, eax
    jz audit_uptime
    cmp eax, 183
    je audit_uptime

    lea rcx, [g_MsgDiagLastErrBad]
    call PrintString
    jmp audit_fail

audit_uptime:
    call GetTickCount64
    mov rdx, rax
    lea rcx, [g_MsgDiagUptime]
    call PrintHandleLine

    mov al, 1
    leave
    ret

audit_fail:
    mov dword ptr [g_ExitCode], ERR_AUDIT_FAIL
    xor al, al
    leave
    ret
System_Audit ENDP

PrintBanner PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    lea rcx, [g_MsgDiagHdr]
    call PrintString

    lea rcx, [g_MsgDiagPid]
    mov edx, dword ptr [g_PID]
    call PrintHandleLine

    mov rdx, qword ptr [g_hShMem]
    test rdx, rdx
    jz diag_fail
    lea rcx, [g_MsgDiagShMem]
    call PrintHandleLine

    mov rdx, qword ptr [g_hCmdEvent]
    test rdx, rdx
    jz diag_fail
    lea rcx, [g_MsgDiagCmdEvt]
    call PrintHandleLine

    mov rdx, qword ptr [g_hRespEvent]
    test rdx, rdx
    jz diag_fail
    lea rcx, [g_MsgDiagRespEvt]
    call PrintHandleLine

    mov rdx, qword ptr [g_pShMem]
    test rdx, rdx
    jz diag_fail
    lea rcx, [g_MsgDiagBase]
    call PrintHandleLine

    mov al, 1
    leave
    ret

diag_fail:
    lea rcx, [g_MsgDiagBad]
    call PrintString
    xor al, al
    leave
    ret
PrintBanner ENDP

PrintHandleLine PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    ; RCX = label, RDX = value
    mov qword ptr [rsp+20h], rdx
    call PrintString
    mov rdx, qword ptr [rsp+20h]
    call PrintQwordHex

    leave
    ret
PrintHandleLine ENDP

PrintQwordHex PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; RDX = value
    mov rax, rdx
    lea r8, [g_HexOut + 2]
    mov r9d, 16

printhex_loop:
    mov rcx, rax
    shr rcx, 60
    and ecx, 0Fh
    cmp ecx, 9
    jbe printhex_digit
    add ecx, 7
printhex_digit:
    add ecx, '0'
    mov byte ptr [r8], cl
    inc r8
    shl rax, 4
    dec r9d
    jnz printhex_loop

    lea rcx, [g_HexOut]
    call PrintString

    leave
    ret
PrintQwordHex ENDP

BeaconInit PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40h
    .allocstack 40h
    .endprolog

    ; CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHMEM_SIZE, g_ShMemName)
    ; RCX=hFile, RDX=lpFileMappingAttributes, R8=flProtect, R9=dwMaximumSizeHigh
    ; [rsp+20h]=dwMaximumSizeLow, [rsp+28h]=lpName
    mov rcx, -1
    xor rdx, rdx
    mov r8d, PAGE_READWRITE
    xor r9d, r9d
    mov dword ptr [rsp+20h], SHMEM_SIZE
    lea rax, [g_ShMemName]
    mov qword ptr [rsp+28h], rax
    call CreateFileMappingA
    mov [g_hShMem], rax
    test rax, rax
    jz beacon_fail
    call GetLastError
    mov dword ptr [rbp - 4], eax

    ; MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0)
    mov rcx, [g_hShMem]
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    call MapViewOfFile
    mov [g_pShMem], rax
    test rax, rax
    jz beacon_fail

    mov rbx, [g_pShMem]
    cmp dword ptr [rbp - 4], 183
    jne beacon_sanitize_done

    mov rax, qword ptr [rbx + OFF_RING_HEAD]
    mov rdx, qword ptr [rbx + OFF_RING_TAIL]
    or rax, rdx
    jnz beacon_force_reset

    mov rax, qword ptr [rbx + OFF_SHUTDOWN_SENTINEL]
    mov rdx, SHUTDOWN_SENTINEL_CLEAN
    cmp rax, rdx
    je beacon_clear_sentinel

beacon_force_reset:
    lea rcx, [g_MsgDirtyReset]
    call PrintString
    call ResetBeaconHeader

beacon_clear_sentinel:
    mov rbx, [g_pShMem]
    mov qword ptr [rbx + OFF_SHUTDOWN_SENTINEL], 0

beacon_sanitize_done:

    ; Create command and response events
    xor rcx, rcx
    xor edx, edx
    xor r8d, r8d
    lea r9, [g_CmdEventName]
    call CreateEventA
    mov [g_hCmdEvent], rax
    test rax, rax
    jz beacon_fail

    xor rcx, rcx
    xor edx, edx
    xor r8d, r8d
    lea r9, [g_RespEventName]
    call CreateEventA
    mov [g_hRespEvent], rax
    test rax, rax
    jz beacon_fail

    ; Create inference trigger event (manual reset, initially nonsignaled)
    xor rcx, rcx
    mov edx, 1
    xor r8d, r8d
    lea r9, [g_InferEventName]
    call CreateEventA
    mov [g_hInferenceTrigger], rax
    test rax, rax
    jz beacon_fail

    ; Create cancellation event (manual reset, initially nonsignaled)
    xor rcx, rcx
    mov edx, 1
    xor r8d, r8d
    lea r9, [g_CancelEventName]
    call CreateEventA
    mov [g_hCancelEvent], rax
    test rax, rax
    jz beacon_fail

    ; Set running flag before worker starts to avoid startup race where
    ; worker sees 0 and exits immediately.
    mov byte ptr [g_Running], 1

    ; Create inference worker thread
    xor rcx, rcx
    xor rdx, rdx
    lea r8, [InferenceWorkerThread]
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    mov qword ptr [rsp+28h], 0
    call CreateThread
    mov [g_hInferenceThread], rax
    test rax, rax
    jz beacon_fail

    ; initialize header + cookie
    mov rbx, [g_pShMem]
    xor eax, eax
    mov [rbx + OFF_STATE], eax
    mov [rbx + OFF_CMD_ID], eax
    mov [rbx + OFF_CMD_TYPE], eax
    mov [rbx + OFF_PAYLOAD_LEN], eax
    mov [rbx + OFF_RESP_STATUS], eax
    mov [rbx + OFF_RESP_LEN], eax
    mov qword ptr [rbx + OFF_RING_HEAD], 0
    mov qword ptr [rbx + OFF_RING_TAIL], 0
    mov qword ptr [rbx + OFF_RING_DROPPED], 0
    mov qword ptr [rbx + OFF_RING_BACKPRESSURE], 0
    mov dword ptr [rbx + OFF_RING_FILL_LEVEL], 0
    mov dword ptr [rbx + OFF_RING_CAPACITY], ASYNC_RING_SIZE
    mov dword ptr [rbx + OFF_RING_LAST_CMD_ID], 0
    mov dword ptr [rbx + OFF_RING_LAST_STATUS], 0
    mov dword ptr [rbx + OFF_RING_LAST_PLEN], 0
    mov dword ptr [rbx + OFF_RING_LAST_FLAGS], 0
    mov qword ptr [rbx + OFF_RING_LAST_TS], 0
    mov qword ptr [rbx + OFF_RING_LAST_PAYLOAD0], 0
    mov dword ptr [rbx + OFF_RING_LAST_PAYLOAD1], 0
    mov qword ptr [rbx + OFF_SHUTDOWN_SENTINEL], 0
    mov rax, MAGIC_COOKIE_VAL
    mov [rbx + OFF_MAGIC_COOKIE], rax
    mov qword ptr [rbx + OFF_HEARTBEAT], 0

    mov al, 1
    leave
    ret

beacon_fail:
    xor al, al
    leave
    ret
BeaconInit ENDP

BeaconCleanup PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; Signal worker thread to stop
    mov byte ptr [g_Running], 0
    
    ; Signal events to wake worker if blocked
    mov rcx, [g_hInferenceTrigger]
    test rcx, rcx
    jz cleanup_skip_trigger_signal
    call SetEvent
cleanup_skip_trigger_signal:
    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz cleanup_skip_cancel_signal
    call SetEvent
cleanup_skip_cancel_signal:
    
    ; Wait for worker thread to exit (give it 1 second)
    mov rcx, [g_hInferenceThread]
    test rcx, rcx
    jz cleanup_skip_thread_wait
    mov rdx, 1000
    call WaitForSingleObject
    
    ; Close thread handle
    mov rcx, [g_hInferenceThread]
    test rcx, rcx
    jz cleanup_skip_thread_close
    call CloseHandle
cleanup_skip_thread_close:
    mov qword ptr [g_hInferenceThread], 0
cleanup_skip_thread_wait:
    ; Scrub shared ring state after the worker has exited so the next run
    ; does not inherit stale head/tail/drop counters.
    call ResetBeaconHeader
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz cleanup_skip_clean_sentinel
    mov rax, SHUTDOWN_SENTINEL_CLEAN
    mov qword ptr [rbx + OFF_SHUTDOWN_SENTINEL], rax
cleanup_skip_clean_sentinel:

    ; Close inference trigger event
    mov rcx, [g_hInferenceTrigger]
    test rcx, rcx
    jz cleanup_skip_infer_event
    call CloseHandle
cleanup_skip_infer_event:
    mov qword ptr [g_hInferenceTrigger], 0
    ; Close cancellation event
    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz cleanup_skip_cancel_event
    call CloseHandle
cleanup_skip_cancel_event:
    mov qword ptr [g_hCancelEvent], 0
    ; Close command event
    mov rcx, [g_hCmdEvent]
    test rcx, rcx
    jz cleanup_skip_cmd_event
    call CloseHandle
cleanup_skip_cmd_event:
    mov qword ptr [g_hCmdEvent], 0
    ; Close response event
    mov rcx, [g_hRespEvent]
    test rcx, rcx
    jz cleanup_skip_resp_event
    call CloseHandle
cleanup_skip_resp_event:
    mov qword ptr [g_hRespEvent], 0
    ; Close mutex
    mov rcx, [g_hMutex]
    test rcx, rcx
    jz cleanup_skip_mutex
    call CloseHandle
cleanup_skip_mutex:
    ; Unmap shared memory
    mov rcx, [g_pShMem]
    test rcx, rcx
    jz cleanup_skip_unmap
    call UnmapViewOfFile
cleanup_skip_unmap:
    mov qword ptr [g_pShMem], 0
    ; Close file mapping handle
    mov rcx, [g_hShMem]
    test rcx, rcx
    jz cleanup_done
    call CloseHandle
    mov qword ptr [g_hShMem], 0

cleanup_done:
    leave
    ret
BeaconCleanup ENDP

DispatchLoop PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

dispatch_loop_top:
    cmp byte ptr [g_Running], 0
    je dispatch_done

    ; Opportunistically drain one async worker completion entry.
    ; Command response lane remains single-owner; this is observability-only.
    lea rcx, [g_LastAsyncSlot]
    call DequeueAsyncResponse

    ; Publish passive ring metrics for sidecar readers (no command lane use).
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz dispatch_wait_cmd

    mov rax, [g_RingHead]
    mov [rbx + OFF_RING_HEAD], rax
    mov rax, [g_RingTail]
    mov [rbx + OFF_RING_TAIL], rax
    mov rax, [g_RingDropped]
    mov [rbx + OFF_RING_DROPPED], rax
    mov rax, [g_RingBackpressure]
    mov [rbx + OFF_RING_BACKPRESSURE], rax

    mov rax, [g_RingTail]
    mov rdx, [g_RingHead]
    sub rax, rdx
    and eax, ASYNC_RING_MASK
    mov dword ptr [rbx + OFF_RING_FILL_LEVEL], eax
    mov dword ptr [rbx + OFF_RING_CAPACITY], ASYNC_RING_SIZE

    mov eax, dword ptr [g_LastAsyncSlot.CmdId]
    mov dword ptr [rbx + OFF_RING_LAST_CMD_ID], eax
    mov eax, dword ptr [g_LastAsyncSlot.Status]
    mov dword ptr [rbx + OFF_RING_LAST_STATUS], eax
    mov eax, dword ptr [g_LastAsyncSlot.PayloadLen]
    mov dword ptr [rbx + OFF_RING_LAST_PLEN], eax
    mov eax, dword ptr [g_LastAsyncSlot.Flags]
    mov dword ptr [rbx + OFF_RING_LAST_FLAGS], eax
    mov rax, qword ptr [g_LastAsyncSlot.TimestampQpc]
    mov qword ptr [rbx + OFF_RING_LAST_TS], rax
    mov rax, qword ptr [g_LastAsyncSlot.Payload]
    mov qword ptr [rbx + OFF_RING_LAST_PAYLOAD0], rax
    mov eax, dword ptr [g_LastAsyncSlot.Payload + 8]
    mov dword ptr [rbx + OFF_RING_LAST_PAYLOAD1], eax

dispatch_wait_cmd:

    mov rcx, [g_hCmdEvent]
    mov edx, 5000
    call WaitForSingleObject

    cmp eax, WAIT_TIMEOUT
    je dispatch_timeout
    cmp eax, WAIT_OBJECT_0
    jne dispatch_loop_top

    ; integrity check
    mov rbx, [g_pShMem]
    mov rax, [rbx + OFF_MAGIC_COOKIE]
    mov rdx, MAGIC_COOKIE_VAL
    cmp rax, rdx
    je cookie_ok
    lea rcx, [g_MsgCorrupt]
    call PrintString
    call ResetBeaconHeader
    jmp dispatch_loop_top

cookie_ok:
    movzx eax, byte ptr [rbx + OFF_STATE]
    cmp al, BEACON_SHUTDOWN
    je dispatch_shutdown
    cmp al, BEACON_READY
    jne dispatch_loop_top

    mov dword ptr [rbx + OFF_STATE], BEACON_PROCESSING
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INTERNAL_ERROR
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    mov byte ptr [rbx + OFF_RESP_PAYLOAD], 0

    call MasterDispatch

    mov eax, dword ptr [rbx + OFF_RESP_LEN]
    cmp eax, RESP_PAYLOAD_MAX
    jbe dispatch_complete

    lea rcx, [g_MsgRespLenBad]
    call PrintString
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INTERNAL_ERROR
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    mov byte ptr [rbx + OFF_RESP_PAYLOAD], 0
    jmp dispatch_complete

dispatch_timeout:
    lea rcx, [g_MsgTimeout]
    call PrintString
    mov rbx, [g_pShMem]
    lock inc qword ptr [rbx + OFF_HEARTBEAT]
    jmp dispatch_loop_top

dispatch_complete:
    mov rbx, [g_pShMem]
    mov rax, MAGIC_COOKIE_VAL
    mov [rbx + OFF_MAGIC_COOKIE], rax
    mov dword ptr [rbx + OFF_STATE], BEACON_COMPLETE
    mov rcx, [g_hRespEvent]
    call SetEvent
    jmp dispatch_loop_top

dispatch_shutdown:
    lea rcx, [g_MsgShutdown]
    call PrintString
    mov byte ptr [g_Running], 0

dispatch_done:
    leave
    ret
DispatchLoop ENDP

; ----------------------------------------------------------------
; Master dispatch with range groups + O(1) table jumps.
; ----------------------------------------------------------------
MasterDispatch PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, [rbx + OFF_CMD_TYPE]
    test eax, eax
    jnz md_have_cmd
    mov eax, [rbx + OFF_CMD_ID]

md_have_cmd:
    ; Legacy mapping support
    cmp eax, CMD_STATUS_LEGACY
    je md_legacy_status
    cmp eax, CMD_LOAD_MODEL_LEGACY
    je md_legacy_load
    cmp eax, CMD_INFERENCE_LEGACY
    je md_legacy_infer
    cmp eax, CMD_HOTPATCH_LEGACY
    je md_legacy_hotpatch
    cmp eax, CMD_TELEMETRY_LEGACY
    je md_legacy_metrics
    jmp md_dispatch_ranges

md_legacy_status:
    mov eax, CMD_GET_STATUS
    jmp md_dispatch_ranges
md_legacy_load:
    mov eax, CMD_LOAD_MODEL
    jmp md_dispatch_ranges
md_legacy_infer:
    mov eax, CMD_INFER
    jmp md_dispatch_ranges
md_legacy_hotpatch:
    mov eax, CMD_RELOAD_CONFIG
    jmp md_dispatch_ranges
md_legacy_metrics:
    mov eax, CMD_GET_METRICS

md_dispatch_ranges:
    cmp eax, 1000h
    jb md_invalid
    cmp eax, 2000h
    jb md_core
    cmp eax, 3000h
    jb md_model
    cmp eax, 4000h
    jb md_infer
    cmp eax, 5000h
    jb md_stream
    cmp eax, 6000h
    jb md_cache
    cmp eax, 7000h
    jb md_nvme
    cmp eax, 8000h
    jb md_telemetry
    cmp eax, 9000h
    jb md_agent
    jmp md_invalid

md_core:
    sub eax, 1000h
    cmp eax, 5
    ja md_invalid
    lea r10, [CoreTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_model:
    sub eax, 2000h
    cmp eax, 5
    ja md_invalid
    lea r10, [ModelTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_infer:
    sub eax, 3000h
    cmp eax, 5
    ja md_invalid
    lea r10, [InferTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_stream:
    sub eax, 4000h
    cmp eax, 4
    ja md_invalid
    lea r10, [StreamTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_cache:
    sub eax, 5000h
    cmp eax, 4
    ja md_invalid
    lea r10, [CacheTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_nvme:
    sub eax, 6000h
    cmp eax, 4
    ja md_invalid
    lea r10, [NvmeTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_telemetry:
    sub eax, 7000h
    cmp eax, 4
    ja md_invalid
    lea r10, [TelemetryTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_agent:
    sub eax, 8000h
    cmp eax, 4
    ja md_invalid
    lea r10, [AgentTable]
    call qword ptr [r10 + rax*8]
    jmp md_done

md_invalid:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_UNKNOWN_CMD
    mov dword ptr [rbx + OFF_RESP_LEN], 0
md_done:
    leave
    ret
MasterDispatch ENDP

ResetBeaconHeader PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    xor eax, eax
    mov [rbx + OFF_STATE], eax
    mov [rbx + OFF_CMD_ID], eax
    mov [rbx + OFF_CMD_TYPE], eax
    mov [rbx + OFF_PAYLOAD_LEN], eax
    mov [rbx + OFF_RESP_STATUS], eax
    mov [rbx + OFF_RESP_LEN], eax
    mov qword ptr [rbx + OFF_RING_HEAD], 0
    mov qword ptr [rbx + OFF_RING_TAIL], 0
    mov qword ptr [rbx + OFF_RING_DROPPED], 0
    mov qword ptr [rbx + OFF_RING_BACKPRESSURE], 0
    mov dword ptr [rbx + OFF_RING_FILL_LEVEL], 0
    mov dword ptr [rbx + OFF_RING_CAPACITY], ASYNC_RING_SIZE
    mov dword ptr [rbx + OFF_RING_LAST_CMD_ID], 0
    mov dword ptr [rbx + OFF_RING_LAST_STATUS], 0
    mov dword ptr [rbx + OFF_RING_LAST_PLEN], 0
    mov dword ptr [rbx + OFF_RING_LAST_FLAGS], 0
    mov qword ptr [rbx + OFF_RING_LAST_TS], 0
    mov qword ptr [rbx + OFF_RING_LAST_PAYLOAD0], 0
    mov dword ptr [rbx + OFF_RING_LAST_PAYLOAD1], 0
    mov qword ptr [rbx + OFF_SHUTDOWN_SENTINEL], 0
    mov rax, MAGIC_COOKIE_VAL
    mov [rbx + OFF_MAGIC_COOKIE], rax

    leave
    ret
ResetBeaconHeader ENDP

; ----------------------------------------------------------------
; HandleLoadModel
;   RCX to loader = path at OFF_CMD_PAYLOAD
;   success: resp_status = ERR_OK
;   fail:    resp_status = ERR_LOAD_FAIL
; ----------------------------------------------------------------
HandleLoadModel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]

    ; Valid in UNLOADED only.
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_UNLOADED
    jne handle_load_busy

    mov r8d, dword ptr [rbx + OFF_PAYLOAD_LEN]
    test r8d, r8d
    jle handle_load_bad_payload
    cmp r8d, CMD_PAYLOAD_MAX
    ja handle_load_bad_payload
    mov byte ptr [rbx + OFF_CMD_PAYLOAD + r8], 0

    mov dword ptr [g_ModelState], MODEL_STATE_LOADING
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_LOADING
    call GetTickCount64
    mov qword ptr [g_LoadStartTick], rax
    lea rcx, [rbx + OFF_CMD_PAYLOAD]

    call SOVEREIGN_LOAD_MODEL
    test rax, rax
    jz handle_load_fail

    call STREAMER_INIT
    test rax, rax
    jz handle_load_fail

    mov dword ptr [g_ModelState], MODEL_STATE_READY
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_READY
    call GetTickCount64
    mov rdx, qword ptr [g_LoadStartTick]
    sub rax, rdx
    mov dword ptr [g_LastLoadDurationMs], eax
    mov dword ptr [g_LastLoadResult], 0
    mov dword ptr [g_LastLoadWin32Error], 0
    mov dword ptr [rbx + OFF_RESP_STATUS], ERR_OK
    lea rsi, [g_RespReady]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    jmp handle_load_done

handle_load_busy:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    jmp handle_load_done

handle_load_bad_payload:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INVALID_PAYLOAD
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    jmp handle_load_done

handle_load_fail:
    mov dword ptr [g_ModelState], MODEL_STATE_UNLOADED
    mov dword ptr [g_LastLoadResult], ERR_LOAD_FAIL
    call GetLastError
    mov dword ptr [g_LastLoadWin32Error], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], ERR_LOAD_FAIL
    mov eax, dword ptr [g_LastLoadResult]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD], eax
    mov eax, dword ptr [g_LastLoadWin32Error]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 4], eax
    mov dword ptr [rbx + OFF_RESP_LEN], 8

handle_load_done:
    leave
    ret
HandleLoadModel ENDP

HandlePing PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    lea rsi, [g_RespPing]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    leave
    ret
HandlePing ENDP

HandleGetVersion PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    lea rsi, [g_RespVersion]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    leave
    ret
HandleGetVersion ENDP

HandleShutdownCmd PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov byte ptr [g_Running], 0
    mov rbx, [g_pShMem]
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleShutdownCmd ENDP

HandleReloadConfig PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    call HandleHotpatch
    leave
    ret
HandleReloadConfig ENDP

HandleUnloadModel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_UNLOADED
    je unload_not_loaded
    cmp eax, MODEL_STATE_LOADING
    je unload_busy
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    je unload_busy
    cmp eax, MODEL_STATE_CANCEL_PENDING
    je unload_busy

    ; Track A integration safety: state-only unload transition.
    ; Strict loader teardown will be re-enabled in parser-hardening track.
    mov dword ptr [g_ModelState], MODEL_STATE_UNLOADED
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_UNLOADED
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    lea rsi, [g_RespUnloaded]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    leave
    ret

unload_busy:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

unload_not_loaded:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_MODEL_NOT_LOADED
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleUnloadModel ENDP

HandleBeginSession PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_READY
    je begin_ok
    cmp eax, MODEL_STATE_UNLOADED
    je begin_not_loaded
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

begin_ok:
    ; Atomic transition: READY -> INFERENCE_ACTIVE
    mov eax, MODEL_STATE_READY
    mov edx, MODEL_STATE_INFERENCE_ACTIVE
    lock cmpxchg [g_ModelState], edx
    jne begin_race_lost
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    lea rsi, [g_RespReady]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    leave
    ret

begin_race_lost:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

begin_not_loaded:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_MODEL_NOT_LOADED
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleBeginSession ENDP

HandleEndSession PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    jne end_not_ready
    mov dword ptr [g_ModelState], MODEL_STATE_READY
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

end_not_ready:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_NOT_READY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleEndSession ENDP

HandleCancelInfer PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    jne cancel_not_ready
    
    ; Signal cancellation event to wake worker thread
    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz cancel_no_event
    call SetEvent
    
cancel_no_event:
    ; Set state to CANCEL_PENDING (worker will reset to READY)
    mov dword ptr [g_ModelState], MODEL_STATE_CANCEL_PENDING
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_CANCEL_PENDING
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

cancel_not_ready:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_NOT_READY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleCancelInfer ENDP

HandleNotReady PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_NOT_READY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleNotReady ENDP

; ----------------------------------------------------------------
; HandleInference - Non-Blocking Handoff Pattern
;   1. Gate: Check if system is in READY state
;   2. Transition: Update state to INFERENCE_ACTIVE
;   3. Signal: Notify background worker thread
;   4. Return: Immediate RESP_OK (handoff complete)
;
; Payload format: Null-terminated prompt at OFF_CMD_PAYLOAD
; Worker thread consumes prompt and writes tokens to OFF_RESP_PAYLOAD
; ----------------------------------------------------------------
HandleInference PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]

    ; 1. Gate: Check if READY
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_READY
    jne infer_check_other_states
    jmp infer_proceed

infer_check_other_states:
    cmp eax, MODEL_STATE_UNLOADED
    je infer_model_not_loaded
    cmp eax, MODEL_STATE_LOADING
    je infer_not_ready
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    je infer_busy
    jmp infer_model_not_loaded

infer_proceed:
    ; 2. Validate input buffer has data
    mov r8d, dword ptr [rbx + OFF_PAYLOAD_LEN]
    test r8d, r8d
    jle infer_invalid_input
    cmp r8d, CMD_PAYLOAD_MAX
    ja infer_invalid_input

    ; Ensure null-termination of prompt
    mov byte ptr [rbx + OFF_CMD_PAYLOAD + r8], 0

    ; 3. Atomic transition to INFERENCE_ACTIVE
    ; lock cmpxchg: if state == READY, set to INFERENCE_ACTIVE
    mov eax, MODEL_STATE_READY
    mov edx, MODEL_STATE_INFERENCE_ACTIVE
    lock cmpxchg [g_ModelState], edx
    jne infer_race_lost
    
    ; Mirror state to MMF for external polling
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_INFERENCE_ACTIVE

    ; 4. Signal the background worker thread
    ; Worker thread waits on g_hInferenceTrigger
    ; Worker reads prompt from OFF_CMD_PAYLOAD
    ; Worker writes tokens to OFF_RESP_PAYLOAD
    ; Worker resets state to READY on completion
    mov rcx, [g_hInferenceTrigger]
    test rcx, rcx
    jz infer_signal_fail
    call SetEvent
    test rax, rax
    jz infer_signal_fail

    ; 5. Immediate Response - handoff complete
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    lea rsi, [g_RespReady]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    leave
    ret

infer_race_lost:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

infer_signal_fail:
    ; Failed to signal worker - rollback state
    mov dword ptr [g_ModelState], MODEL_STATE_READY
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INTERNAL_ERROR
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

infer_busy:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_BUSY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

infer_model_not_loaded:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_MODEL_NOT_LOADED
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

infer_not_ready:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_NOT_READY
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret

infer_invalid_input:
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INVALID_PAYLOAD
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    leave
    ret
HandleInference ENDP

HandleStatus PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    lea rcx, [g_MsgStatusDisp]
    call PrintString

    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_UNLOADED
    je status_unloaded
    cmp eax, MODEL_STATE_LOADING
    je status_loading
    cmp eax, MODEL_STATE_READY
    je status_ready
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    je status_active
    jmp status_ready

status_unloaded:
    lea rsi, [g_RespStateUnloaded]
    jmp status_copy
status_loading:
    lea rsi, [g_RespStateLoading]
    jmp status_copy
status_ready:
    lea rsi, [g_RespStateReady]
    jmp status_copy
status_active:
    lea rsi, [g_RespStateActive]

status_copy:
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], ERR_OK

    leave
    ret
HandleStatus ENDP

HandleHotpatch PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov dword ptr [rbx + OFF_RESP_STATUS], ERR_OK
    mov dword ptr [rbx + OFF_RESP_LEN], 0

    leave
    ret
HandleHotpatch ENDP

HandleTelemetry PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_ModelState]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD], eax
    mov eax, dword ptr [g_LastLoadResult]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 4], eax
    mov eax, dword ptr [g_LastLoadWin32Error]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 8], eax
    mov eax, dword ptr [g_LastLoadDurationMs]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 12], eax
    mov rax, [rbx + OFF_HEARTBEAT]
    mov [rbx + OFF_RESP_PAYLOAD + 16], rax

    ; Ring observability block
    mov rax, [g_RingHead]
    mov [rbx + OFF_RESP_PAYLOAD + 24], rax
    mov rax, [g_RingTail]
    mov [rbx + OFF_RESP_PAYLOAD + 32], rax

    ; fill_level = (tail - head) & ASYNC_RING_MASK
    mov rax, [g_RingTail]
    mov rdx, [g_RingHead]
    mov rcx, rax
    sub rcx, rdx
    and ecx, ASYNC_RING_MASK
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 40], ecx
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 44], ASYNC_RING_SIZE

    mov rax, [g_RingBackpressure]
    mov [rbx + OFF_RESP_PAYLOAD + 48], rax
    mov rax, [g_RingDropped]
    mov [rbx + OFF_RESP_PAYLOAD + 56], rax

    ; Last dequeued async completion snapshot.
    mov eax, dword ptr [g_LastAsyncSlot.CmdId]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 64], eax
    mov eax, dword ptr [g_LastAsyncSlot.Status]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 68], eax
    mov eax, dword ptr [g_LastAsyncSlot.PayloadLen]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 72], eax
    mov eax, dword ptr [g_LastAsyncSlot.Flags]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 76], eax
    mov rax, qword ptr [g_LastAsyncSlot.TimestampQpc]
    mov qword ptr [rbx + OFF_RESP_PAYLOAD + 80], rax
    mov rax, qword ptr [g_LastAsyncSlot.Payload]
    mov qword ptr [rbx + OFF_RESP_PAYLOAD + 88], rax
    mov eax, dword ptr [g_LastAsyncSlot.Payload + 8]
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 96], eax

    ; utilization_pct = (fill_level * 100) / ASYNC_RING_SIZE
    mov eax, dword ptr [rbx + OFF_RESP_PAYLOAD + 40]
    imul eax, 100
    xor edx, edx
    mov ecx, ASYNC_RING_SIZE
    div ecx
    mov dword ptr [rbx + OFF_RESP_PAYLOAD + 100], eax

    mov dword ptr [rbx + OFF_RESP_LEN], 104
    mov dword ptr [rbx + OFF_RESP_STATUS], ERR_OK

    leave
    ret
HandleTelemetry ENDP

HandleStreamStart PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov dword ptr [g_StreamerEnabled], 1
    lea rsi, [g_RespStreamActive]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK

    leave
    ret
HandleStreamStart ENDP

HandleStreamStop PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov dword ptr [g_StreamerEnabled], 0
    lea rsi, [g_RespStreamReady]
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK

    leave
    ret
HandleStreamStop ENDP

HandleStreamStatus PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, [g_pShMem]
    mov eax, dword ptr [g_StreamerEnabled]
    cmp eax, 0
    jne stream_active

    lea rsi, [g_RespStreamReady]
    jmp stream_copy

stream_active:
    lea rsi, [g_RespStreamActive]

stream_copy:
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    call CopyZ
    mov [rbx + OFF_RESP_LEN], eax
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK

    leave
    ret
HandleStreamStatus ENDP

; ----------------------------------------------------------------
; CopyZ: copy ASCIIZ from RSI -> RDI, return EAX = bytes copied (without NUL)
; ----------------------------------------------------------------
CopyZ PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    xor eax, eax
copyz_loop:
    mov dl, byte ptr [rsi]
    mov byte ptr [rdi], dl
    inc rsi
    inc rdi
    test dl, dl
    jz copyz_done
    inc eax
    jmp copyz_loop

copyz_done:
    leave
    ret
CopyZ ENDP

; ----------------------------------------------------------------
; PrintString: RCX = ASCIIZ
; ----------------------------------------------------------------
PrintString PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40h
    .allocstack 40h
    .endprolog

    mov rsi, rcx
    xor ecx, ecx
print_len_loop:
    cmp byte ptr [rsi + rcx], 0
    je print_do
    inc rcx
    jmp print_len_loop

print_do:
    mov qword ptr [rsp+20h], 0
    lea r9, [rsp+28h]
    mov r8, rcx
    mov rdx, rsi
    mov rcx, [g_StdOut]
    call WriteFile

    leave
    ret
PrintString ENDP

; ----------------------------------------------------------------
; Stubs required by Sovereign_Model_Streamer.asm when full Ghost engine
; symbols are not yet linked in this target.
; ----------------------------------------------------------------
PUBLIC PUSH_GHOST_PREDICTION
PUSH_GHOST_PREDICTION PROC
    ret
PUSH_GHOST_PREDICTION ENDP

PUBLIC FLUSH_GHOST_BUFFER
FLUSH_GHOST_BUFFER PROC
    ret
FLUSH_GHOST_BUFFER ENDP

PUBLIC GHOST_HEARTBEAT
GHOST_HEARTBEAT PROC
    ret
GHOST_HEARTBEAT ENDP

PUBLIC SOVEREIGN_TELEMETRY_SIGN
SOVEREIGN_TELEMETRY_SIGN PROC
    ; RCX=buf, RDX=len, R8=sigOut -> return fake sig length 0
    xor eax, eax
    ret
SOVEREIGN_TELEMETRY_SIGN ENDP

END
