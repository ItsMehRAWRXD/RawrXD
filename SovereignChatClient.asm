; SovereignChatClient.asm
; Communicates with running SovereignOrchestrator via shared memory
; Proves end-to-end inference produces readable text

OPTION CASEMAP:NONE

; ----------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------
STD_OUTPUT_HANDLE EQU -11
FILE_MAP_ALL_ACCESS EQU 0F001Fh
WAIT_OBJECT_0 EQU 0
WAIT_TIMEOUT EQU 102h

; Offsets into shared memory beacon (from SovereignOrchestrator_Hardened.asm)
OFF_STATE EQU 00h
OFF_CMD_ID EQU 04h
OFF_CMD_TYPE EQU 08h
OFF_PAYLOAD_LEN EQU 0Ch
OFF_RESP_STATUS EQU 10h
OFF_RESP_LEN EQU 14h
OFF_CMD_PAYLOAD EQU 18h
OFF_RESP_PAYLOAD EQU 1018h
OFF_MAGIC_COOKIE EQU 0FFF0h

; Command types
CMD_INFER EQU 3003h

; Beacon states
BEACON_READY EQU 01h
BEACON_PROCESSING EQU 02h
BEACON_COMPLETE EQU 04h

; Response status
RESP_OK EQU 0

; ----------------------------------------------------------------
; CODE
; ----------------------------------------------------------------
.CODE

; External Windows APIs
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN OpenFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN OpenEventA:PROC
EXTERN WaitForSingleObject:PROC
EXTERN SetEvent:PROC
EXTERN CloseHandle:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC

; ----------------------------------------------------------------
; ENTRY POINT
; ----------------------------------------------------------------
main PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 80
    .allocstack 80
    .endprolog

    ; Print banner
    lea rcx, banner1
    call PrintString
    lea rcx, banner2
    call PrintString
    lea rcx, banner3
    call PrintString
    lea rcx, newline
    call PrintString

    ; Open shared memory
    lea rcx, msg_open_shmem
    call PrintString
    
    mov ecx, FILE_MAP_ALL_ACCESS
    xor edx, edx
    lea r8, shmem_name
    call OpenFileMappingA
    mov hShMem, rax
    test rax, rax
    jz open_shmem_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Map view
    lea rcx, msg_map_view
    call PrintString
    
    mov rcx, hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    mov pShMem, rax
    test rax, rax
    jz map_view_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Open events
    lea rcx, msg_open_events
    call PrintString
    
    mov ecx, 00100000h              ; SYNCHRONIZE
    xor edx, edx
    lea r8, cmd_event_name
    call OpenEventA
    mov hCmdEvent, rax
    test rax, rax
    jz open_event_fail
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, resp_event_name
    call OpenEventA
    mov hRespEvent, rax
    test rax, rax
    jz open_event_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Send inference command
    lea rcx, msg_send_cmd
    call PrintString
    
    mov rbx, pShMem
    
    ; Set magic cookie
    mov rax, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], rax
    
    ; Set command type to CMD_INFER
    mov dword ptr [rbx + OFF_CMD_TYPE], CMD_INFER
    
    ; Set payload (simple test prompt)
    lea rsi, test_prompt
    lea rdi, [rbx + OFF_CMD_PAYLOAD]
    mov rcx, test_prompt_len
    rep movsb
    mov dword ptr [rbx + OFF_PAYLOAD_LEN], test_prompt_len
    
    ; Set state to READY
    mov dword ptr [rbx + OFF_STATE], BEACON_READY
    
    ; Signal command event
    mov rcx, hCmdEvent
    call SetEvent
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Wait for response
    lea rcx, msg_wait_resp
    call PrintString
    
    mov rcx, hRespEvent
    mov edx, 30000                  ; 30 second timeout
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne wait_timeout
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Check response
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_STATUS]
    cmp eax, RESP_OK
    jne resp_error
    
    ; Print response
    lea rcx, msg_response
    call PrintString
    lea rcx, [rbx + OFF_RESP_PAYLOAD]
    call PrintString
    lea rcx, newline
    call PrintString
    jmp cleanup

open_shmem_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_shmem
    call PrintString
    jmp exit_error

map_view_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_map
    call PrintString
    jmp cleanup

open_event_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_event
    call PrintString
    jmp cleanup

wait_timeout:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_timeout
    call PrintString
    jmp cleanup

resp_error:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_resp
    call PrintString
    jmp cleanup

cleanup:
    ; Unmap shared memory
    mov rcx, pShMem
    test rcx, rcx
    jz skip_unmap
    call UnmapViewOfFile
skip_unmap:

    ; Close handles
    mov rcx, hShMem
    test rcx, rcx
    jz skip_close_shmem
    call CloseHandle
skip_close_shmem:

    mov rcx, hCmdEvent
    test rcx, rcx
    jz skip_close_cmd
    call CloseHandle
skip_close_cmd:

    mov rcx, hRespEvent
    test rcx, rcx
    jz skip_close_resp
    call CloseHandle
skip_close_resp:

exit_error:
    xor ecx, ecx
    call ExitProcess

main ENDP

; ----------------------------------------------------------------
; PrintString - Write null-terminated string to console
; RCX = string pointer
; ----------------------------------------------------------------
PrintString PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 64
    .allocstack 64
    .endprolog

    mov rsi, rcx                    ; Save string pointer

    ; Calculate string length
    mov rdi, rsi
    mov rcx, -1
    xor eax, eax
    repne scasb
    not rcx
    dec rcx                         ; RCX = length
    jz print_done                   ; Empty string

    ; Get stdout handle
    mov r12, rcx                    ; Save length
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle

    ; Write to console
    mov rcx, rax                    ; Handle
    mov rdx, rsi                    ; Buffer
    mov r8, r12                     ; Length
    lea r9, written                 ; Bytes written
    mov qword ptr [rsp+32], 0       ; Reserved
    call WriteConsoleA

print_done:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

; ----------------------------------------------------------------
; DATA
; ----------------------------------------------------------------
.DATA

    ; Banner
    banner1     DB "========================================", 13, 10, 0
    banner2     DB "  SOVEREIGN CHAT CLIENT", 13, 10, 0
    banner3     DB "========================================", 13, 10, 0
    newline     DB 13, 10, 0
    
    ; Messages
    msg_open_shmem   DB "Opening shared memory... ", 0
    msg_map_view     DB "Mapping view... ", 0
    msg_open_events  DB "Opening events... ", 0
    msg_send_cmd     DB "Sending inference command... ", 0
    msg_wait_resp    DB "Waiting for response... ", 0
    msg_response     DB "Response: ", 0
    
    msg_ok           DB "OK", 0
    msg_fail         DB "FAILED", 0
    
    msg_err_shmem    DB "Cannot open shared memory. Is orchestrator running?", 13, 10, 0
    msg_err_map      DB "Cannot map view", 13, 10, 0
    msg_err_event    DB "Cannot open events", 13, 10, 0
    msg_err_timeout  DB "Timeout waiting for response", 13, 10, 0
    msg_err_resp     DB "Response error", 13, 10, 0
    
    ; Names
    shmem_name       DB "SOVEREIGN_BEACON_V1", 0
    cmd_event_name   DB "SOVEREIGN_CMD_EVENT", 0
    resp_event_name  DB "SOVEREIGN_RESP_EVENT", 0
    
    ; Test prompt
    test_prompt      DB '{"action":"generate","prompt":"Hello","max_tokens":20}', 0
    test_prompt_len  EQU $ - test_prompt - 1
    
    ; Variables
    hShMem           DQ 0
    pShMem           DQ 0
    hCmdEvent        DQ 0
    hRespEvent       DQ 0
    written          DD 0

END
