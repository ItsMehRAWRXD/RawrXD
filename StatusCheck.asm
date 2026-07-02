; StatusCheck.asm - Simple status check via shared memory
; Tests if orchestrator responds to CMD_GET_STATUS

OPTION CASEMAP:NONE

STD_OUTPUT_HANDLE EQU -11
FILE_MAP_ALL_ACCESS EQU 0F001Fh
WAIT_OBJECT_0 EQU 0

; Offsets
OFF_STATE EQU 00h
OFF_CMD_TYPE EQU 08h
OFF_PAYLOAD_LEN EQU 0Ch
OFF_RESP_STATUS EQU 10h
OFF_RESP_LEN EQU 14h
OFF_RESP_PAYLOAD EQU 1018h
OFF_MAGIC_COOKIE EQU 0FFF0h

; Commands
CMD_GET_STATUS EQU 1002h
BEACON_READY EQU 01h
BEACON_COMPLETE EQU 04h

.CODE

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
    lea rcx, banner
    call PrintString
    lea rcx, newline
    call PrintString

    ; Open shared memory
    lea rcx, msg_open
    call PrintString
    
    mov ecx, FILE_MAP_ALL_ACCESS
    xor edx, edx
    lea r8, shmem_name
    call OpenFileMappingA
    mov hShMem, rax
    test rax, rax
    jz open_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Map view
    lea rcx, msg_map
    call PrintString
    
    mov rcx, hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    mov pShMem, rax
    test rax, rax
    jz map_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Open events
    lea rcx, msg_events
    call PrintString
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, cmd_event_name
    call OpenEventA
    mov hCmdEvent, rax
    test rax, rax
    jz event_fail
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, resp_event_name
    call OpenEventA
    mov hRespEvent, rax
    test rax, rax
    jz event_fail
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Send STATUS command
    lea rcx, msg_status
    call PrintString
    
    mov rbx, pShMem
    
    ; Set magic cookie
    mov rax, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], rax
    
    ; Set command type
    mov dword ptr [rbx + OFF_CMD_TYPE], CMD_GET_STATUS
    mov dword ptr [rbx + OFF_PAYLOAD_LEN], 0
    
    ; Set state to READY
    mov dword ptr [rbx + OFF_STATE], BEACON_READY
    
    ; Signal command
    mov rcx, hCmdEvent
    call SetEvent
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Wait for response
    lea rcx, msg_wait
    call PrintString
    
    mov rcx, hRespEvent
    mov edx, 5000
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne timeout
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Check response
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_STATUS]
    test eax, eax
    jnz resp_error
    
    lea rcx, msg_success
    call PrintString
    lea rcx, newline
    call PrintString
    
    ; Print response data
    mov eax, [rbx + OFF_RESP_LEN]
    test eax, eax
    jz no_data
    
    lea rcx, msg_data
    call PrintString
    lea rcx, [rbx + OFF_RESP_PAYLOAD]
    call PrintString
    lea rcx, newline
    call PrintString

no_data:
    jmp cleanup

open_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_open
    call PrintString
    jmp exit_error

map_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_map
    call PrintString
    jmp cleanup

event_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_event
    call PrintString
    jmp cleanup

timeout:
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
    mov rcx, pShMem
    test rcx, rcx
    jz skip_unmap
    call UnmapViewOfFile
skip_unmap:

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

    mov rsi, rcx
    mov rdi, rcx
    mov rcx, -1
    xor eax, eax
    repne scasb
    not rcx
    dec rcx
    jz print_done

    mov r12, rcx
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle

    mov rcx, rax
    mov rdx, rsi
    mov r8, r12
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteConsoleA

print_done:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

.DATA

    banner      DB "Status Check Test", 13, 10
                DB "=================", 13, 10, 0
    newline     DB 13, 10, 0
    
    msg_open    DB "Opening shared memory... ", 0
    msg_map     DB "Mapping view... ", 0
    msg_events  DB "Opening events... ", 0
    msg_status  DB "Sending STATUS command... ", 0
    msg_wait    DB "Waiting for response... ", 0
    msg_success DB "Status check successful!", 0
    msg_data    DB "Response: ", 0
    
    msg_ok      DB "OK", 0
    msg_fail    DB "FAILED", 0
    
    msg_err_open    DB "Cannot open shared memory", 13, 10, 0
    msg_err_map     DB "Cannot map view", 13, 10, 0
    msg_err_event   DB "Cannot open events", 13, 10, 0
    msg_err_timeout DB "Timeout waiting for response", 13, 10, 0
    msg_err_resp    DB "Response error", 13, 10, 0
    
    shmem_name      DB "SOVEREIGN_BEACON_V1", 0
    cmd_event_name  DB "SOVEREIGN_CMD_EVENT", 0
    resp_event_name DB "SOVEREIGN_RESP_EVENT", 0
    
    hShMem          DQ 0
    pShMem          DQ 0
    hCmdEvent       DQ 0
    hRespEvent      DQ 0
    written         DD 0

END
