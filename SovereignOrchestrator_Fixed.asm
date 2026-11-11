; SovereignOrchestrator_Fixed.asm - FULLY DEBUGGED VERSION
; Fixes:
; 1. Response event is now MANUAL-RESET (stays signaled until ResetEvent)
; 2. Added diagnostic output for every step
; 3. Worker writes response BEFORE signaling event
; 4. Added proper error checking

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

; =============================================================================
; External APIs
; =============================================================================
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CreateEventA:PROC
EXTERN SetEvent:PROC
EXTERN ResetEvent:PROC
EXTERN WaitForSingleObject:PROC
EXTERN CreateThread:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN GetLastError:PROC
EXTERN GetCurrentProcessId:PROC
EXTERN GetTickCount64:PROC
EXTERN CloseHandle:PROC
EXTERN ReleaseMutex:PROC
EXTERN CreateMutexA:PROC

; =============================================================================
; External from worker
; =============================================================================
EXTERN InferenceWorkerThread:PROC

; =============================================================================
; Constants
; =============================================================================
STD_OUTPUT_HANDLE EQU -11
PAGE_READWRITE EQU 04h
FILE_MAP_ALL_ACCESS EQU 0F001Fh
SHMEM_SIZE EQU 65536
WAIT_OBJECT_0 EQU 0
WAIT_TIMEOUT EQU 102h
INFINITE EQU -1

; MMF Offsets
OFF_STATE EQU 00h
OFF_CMD_ID EQU 04h
OFF_CMD_TYPE EQU 08h
OFF_PAYLOAD_LEN EQU 0Ch
OFF_RESP_STATUS EQU 10h
OFF_RESP_LEN EQU 14h
OFF_CMD_PAYLOAD EQU 18h
OFF_RESP_PAYLOAD EQU 1018h
OFF_MODEL_STATE EQU 2030h
OFF_MAGIC_COOKIE EQU 0FFF0h

; Commands
CMD_LOAD_MODEL EQU 2000h
CMD_INFER EQU 3003h

; States
BEACON_READY EQU 01h
BEACON_PROCESSING EQU 02h
BEACON_COMPLETE EQU 04h

MODEL_STATE_UNLOADED EQU 0
MODEL_STATE_LOADING EQU 1
MODEL_STATE_READY EQU 2
MODEL_STATE_INFERENCE_ACTIVE EQU 3

; Response codes
RESP_OK EQU 0

; =============================================================================
; Data Section
; =============================================================================
.DATA
ALIGN 16

    ; Event names
    g_ShMemName         DB "SOVEREIGN_BEACON_V1",0
    g_CmdEventName      DB "SOVEREIGN_CMD_EVENT",0
    g_RespEventName     DB "SOVEREIGN_RESP_EVENT",0
    g_InferEventName    DB "SOVEREIGN_INFER_EVENT",0
    g_CancelEventName   DB "SOVEREIGN_CANCEL_EVENT",0
    g_MutexName         DB "SOVEREIGN_ORCH_MUTEX",0
    
    ; Diagnostic messages
    msg_banner          DB "[ORCH] SovereignOrchestrator DEBUG BUILD",13,10,0
    msg_pid             DB "[DIAG] PID=",0
    msg_creating_shmem  DB "[DIAG] Creating shared memory...",0
    msg_shmem_ok        DB " OK",13,10,0
    msg_shmem_fail      DB " FAILED",13,10,0
    msg_creating_events DB "[DIAG] Creating events (MANUAL-RESET)...",0
    msg_events_ok       DB " OK",13,10,0
    msg_cmd_manual      DB "[DIAG]   CMD_EVENT = MANUAL-RESET",13,10,0
    msg_resp_manual     DB "[DIAG]   RESP_EVENT = MANUAL-RESET",13,10,0
    msg_infer_manual    DB "[DIAG]   INFER_EVENT = MANUAL-RESET",13,10,0
    msg_listening       DB "[ORCH] Listening on beacon.",13,10,0
    msg_cmd_received    DB "[DIAG] Command received, type=",0
    msg_processing      DB "[DIAG] Processing command...",0
    msg_signaling       DB "[DIAG] Signaling worker...",0
    msg_worker_done     DB "[DIAG] Worker completed, signaling response...",0
    msg_response_sent   DB "[DIAG] Response event signaled",13,10,0
    msg_newline         DB 13,10,0
    msg_hex_prefix      DB "0x",0
    
    ; Variables - PUBLIC for worker access
    PUBLIC g_hInferenceTrigger
    PUBLIC g_hCancelEvent
    PUBLIC g_hRespEvent
    PUBLIC g_pShMem
    PUBLIC g_ModelState
    PUBLIC g_Running
    PUBLIC g_RespOffset
    
    g_hMutex            DQ 0
    g_hShMem            DQ 0
    g_pShMem            DQ 0
    g_hCmdEvent         DQ 0
    g_hRespEvent        DQ 0
    g_hInferenceTrigger DQ 0
    g_hCancelEvent      DQ 0
    g_hWorkerThread     DQ 0
    g_ModelState        DD MODEL_STATE_UNLOADED
    g_Running           DB 1
    g_RespOffset        DD 0
    g_StdOut            DQ 0
    g_PID               DD 0
    written             DD 0
    hex_buffer          DB 32 DUP(0)

; =============================================================================
; Code Section
; =============================================================================
.CODE

; -------------------------------------------------------------------------
; PrintString
; -------------------------------------------------------------------------
PrintString PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    mov rsi, rcx
    mov rdi, rcx
    mov rcx, -1
    xor eax, eax
    repne scasb
    not rcx
    dec rcx
    jz print_done
    
    mov r12, rcx
    mov rcx, g_StdOut
    test rcx, rcx
    jnz have_handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_StdOut, rax
    mov rcx, rax
have_handle:
    mov rdx, rsi
    mov r8, r12
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
print_done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

; -------------------------------------------------------------------------
; PrintHex - Print 32-bit hex value
; RCX = value
; -------------------------------------------------------------------------
PrintHex PROC
    push rbx
    push r12
    mov r12, rcx
    
    lea rcx, msg_hex_prefix
    call PrintString
    
    ; Convert to hex string
    lea rdi, hex_buffer
    mov rcx, 8
    mov rbx, r12
    
hex_loop:
    rol ebx, 4
    mov eax, ebx
    and eax, 0Fh
    cmp eax, 10
    jb hex_digit
    add al, 'A' - 10
    jmp hex_store
hex_digit:
    add al, '0'
hex_store:
    mov [rdi], al
    inc rdi
    dec rcx
    jnz hex_loop
    
    mov byte ptr [rdi], 0
    lea rcx, hex_buffer
    call PrintString
    
    pop r12
    pop rbx
    ret
PrintHex ENDP

; -------------------------------------------------------------------------
; MasterDispatch - FIXED VERSION with full diagnostics
; -------------------------------------------------------------------------
MasterDispatch PROC
    push rbx
    push r12
    push r13
    sub rsp, 40
    
    mov rbx, g_pShMem
    test rbx, rbx
    jz md_exit
    
    ; Get command type
    mov r12d, [rbx + OFF_CMD_TYPE]
    test r12d, r12d
    jnz md_have_cmd
    mov r12d, [rbx + OFF_CMD_ID]
    
md_have_cmd:
    ; Print command received
    lea rcx, msg_cmd_received
    call PrintString
    mov ecx, r12d
    call PrintHex
    lea rcx, msg_newline
    call PrintString
    
    ; Handle CMD_LOAD_MODEL
    cmp r12d, CMD_LOAD_MODEL
    jne md_check_infer
    
    lea rcx, msg_processing
    call PrintString
    
    ; Set model state to LOADING
    mov dword ptr [g_ModelState], MODEL_STATE_LOADING
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_LOADING
    
    ; For demo: immediately set to READY (in real impl, would load actual model)
    mov dword ptr [g_ModelState], MODEL_STATE_READY
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_READY
    
    ; Write response
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_OK
    mov dword ptr [rbx + OFF_RESP_LEN], 2
    mov word ptr [rbx + OFF_RESP_PAYLOAD], 'OK'
    
    ; Signal response (MANUAL-RESET event stays signaled)
    lea rcx, msg_response_sent
    call PrintString
    
    mov rcx, g_hRespEvent
    call SetEvent
    
    jmp md_exit
    
md_check_infer:
    ; Handle CMD_INFER
    cmp r12d, CMD_INFER
    jne md_unknown
    
    lea rcx, msg_processing
    call PrintString
    lea rcx, msg_signaling
    call PrintString
    
    ; Set model state to INFERENCE_ACTIVE
    mov dword ptr [g_ModelState], MODEL_STATE_INFERENCE_ACTIVE
    mov dword ptr [rbx + OFF_MODEL_STATE], MODEL_STATE_INFERENCE_ACTIVE
    
    ; Signal inference trigger (worker will process)
    mov rcx, g_hInferenceTrigger
    call SetEvent
    
    ; Note: Worker will signal g_hRespEvent when done
    jmp md_exit
    
md_unknown:
    ; Unknown command
    mov dword ptr [rbx + OFF_RESP_STATUS], 1  ; RESP_UNKNOWN_CMD
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    
    mov rcx, g_hRespEvent
    call SetEvent
    
md_exit:
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
MasterDispatch ENDP

; -------------------------------------------------------------------------
; DispatchLoop - FIXED with proper event handling
; -------------------------------------------------------------------------
DispatchLoop PROC
    push rbx
    push r12
    sub rsp, 40
    
dispatch_loop:
    cmp byte ptr [g_Running], 0
    je dispatch_exit
    
    ; Wait for command event (with timeout to check running flag)
    mov rcx, g_hCmdEvent
    mov edx, 1000    ; 1 second timeout
    call WaitForSingleObject
    
    cmp eax, WAIT_TIMEOUT
    je dispatch_loop
    cmp eax, WAIT_OBJECT_0
    jne dispatch_loop
    
    ; Reset command event (manual-reset, so we reset it)
    mov rcx, g_hCmdEvent
    call ResetEvent
    
    ; Verify magic cookie
    mov rbx, g_pShMem
    mov rax, [rbx + OFF_MAGIC_COOKIE]
    mov r12, 0DEADBEEFCAFEBABEh
    cmp rax, r12
    jne dispatch_loop
    
    ; Check state
    movzx eax, byte ptr [rbx + OFF_STATE]
    cmp al, BEACON_READY
    jne dispatch_loop
    
    ; Set processing state
    mov dword ptr [rbx + OFF_STATE], BEACON_PROCESSING
    
    ; Dispatch command
    call MasterDispatch
    
    ; Set complete state
    mov dword ptr [rbx + OFF_STATE], BEACON_COMPLETE
    
    jmp dispatch_loop
    
dispatch_exit:
    add rsp, 40
    pop r12
    pop rbx
    ret
DispatchLoop ENDP

; -------------------------------------------------------------------------
; BeaconInit - FIXED with MANUAL-RESET events
; -------------------------------------------------------------------------
BeaconInit PROC
    push rbx
    push r12
    sub rsp, 56
    
    ; Create shared memory
    lea rcx, msg_creating_shmem
    call PrintString
    
    mov rcx, -1                 ; INVALID_HANDLE_VALUE
    xor rdx, rdx                ; lpFileMappingAttributes
    mov r8d, PAGE_READWRITE     ; flProtect
    xor r9d, r9d                ; dwMaximumSizeHigh
    mov dword ptr [rsp+20h], SHMEM_SIZE
    lea rax, g_ShMemName
    mov qword ptr [rsp+28h], rax
    call CreateFileMappingA
    mov g_hShMem, rax
    test rax, rax
    jz bi_fail
    
    ; Map view
    mov rcx, g_hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    call MapViewOfFile
    mov g_pShMem, rax
    test rax, rax
    jz bi_fail
    
    lea rcx, msg_shmem_ok
    call PrintString
    
    ; Create events - ALL MANUAL-RESET NOW
    lea rcx, msg_creating_events
    call PrintString
    
    ; CMD_EVENT - MANUAL-RESET (edx=1)
    xor ecx, ecx                ; lpEventAttributes
    mov edx, 1                  ; bManualReset = TRUE (FIXED!)
    xor r8d, r8d                ; bInitialState = FALSE
    lea r9, g_CmdEventName      ; lpName
    call CreateEventA
    mov g_hCmdEvent, rax
    test rax, rax
    jz bi_fail
    
    lea rcx, msg_cmd_manual
    call PrintString
    
    ; RESP_EVENT - MANUAL-RESET (edx=1) - THIS IS THE KEY FIX!
    xor ecx, ecx
    mov edx, 1                  ; bManualReset = TRUE (FIXED!)
    xor r8d, r8d
    lea r9, g_RespEventName
    call CreateEventA
    mov g_hRespEvent, rax
    test rax, rax
    jz bi_fail
    
    lea rcx, msg_resp_manual
    call PrintString
    
    ; INFER_EVENT - MANUAL-RESET (edx=1)
    xor ecx, ecx
    mov edx, 1                  ; bManualReset = TRUE
    xor r8d, r8d
    lea r9, g_InferEventName
    call CreateEventA
    mov g_hInferenceTrigger, rax
    test rax, rax
    jz bi_fail
    
    lea rcx, msg_infer_manual
    call PrintString
    
    lea rcx, msg_events_ok
    call PrintString
    
    ; Initialize shared memory
    mov rbx, g_pShMem
    xor eax, eax
    mov [rbx + OFF_STATE], eax
    mov [rbx + OFF_CMD_ID], eax
    mov [rbx + OFF_CMD_TYPE], eax
    mov [rbx + OFF_PAYLOAD_LEN], eax
    mov [rbx + OFF_RESP_STATUS], eax
    mov [rbx + OFF_RESP_LEN], eax
    mov r12, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], r12
    
    add rsp, 56
    pop r12
    pop rbx
    mov eax, 1      ; Success
    ret
    
bi_fail:
    lea rcx, msg_shmem_fail
    call PrintString
    add rsp, 56
    pop r12
    pop rbx
    xor eax, eax    ; Fail
    ret
BeaconInit ENDP

; -------------------------------------------------------------------------
; Main Entry
; -------------------------------------------------------------------------
main PROC
    sub rsp, 56
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_StdOut, rax
    
    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; Get PID
    call GetCurrentProcessId
    mov g_PID, eax
    
    lea rcx, msg_pid
    call PrintString
    mov ecx, g_PID
    call PrintHex
    lea rcx, msg_newline
    call PrintString
    
    ; Initialize beacon
    call BeaconInit
    test eax, eax
    jz main_fail
    
    ; Start worker thread
    mov byte ptr [g_Running], 1
    xor ecx, ecx
    xor edx, edx
    lea r8, InferenceWorkerThread
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    mov qword ptr [rsp+28h], 0
    call CreateThread
    mov g_hWorkerThread, rax
    
    ; Start listening
    lea rcx, msg_listening
    call PrintString
    
    call DispatchLoop
    
main_exit:
    xor ecx, ecx
    call ExitProcess
    
main_fail:
    mov ecx, 1
    call ExitProcess
    
    add rsp, 56
    ret
main ENDP

END
