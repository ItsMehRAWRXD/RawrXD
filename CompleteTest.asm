; CompleteTest.asm - Load model then do inference
; Tests full end-to-end flow

OPTION CASEMAP:NONE

STD_OUTPUT_HANDLE EQU -11
FILE_MAP_ALL_ACCESS EQU 0F001Fh
WAIT_OBJECT_0 EQU 0
INFINITE EQU -1

; Offsets
OFF_STATE EQU 00h
OFF_CMD_TYPE EQU 08h
OFF_PAYLOAD_LEN EQU 0Ch
OFF_RESP_STATUS EQU 10h
OFF_RESP_LEN EQU 14h
OFF_CMD_PAYLOAD EQU 18h
OFF_RESP_PAYLOAD EQU 1018h
OFF_MAGIC_COOKIE EQU 0FFF0h
OFF_MODEL_STATE EQU 2030h

; Commands
CMD_LOAD_MODEL EQU 2000h
CMD_INFER EQU 3003h
BEACON_READY EQU 01h
BEACON_COMPLETE EQU 04h
RESP_OK EQU 0

MODEL_STATE_READY EQU 2

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
EXTERN ResetEvent:PROC
EXTERN CloseHandle:PROC
EXTERN Sleep:PROC

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

    ; ================================================================
    ; STEP 1: Load Model
    ; ================================================================
    lea rcx, msg_load
    call PrintString
    
    mov rbx, pShMem
    mov rax, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], rax
    mov dword ptr [rbx + OFF_CMD_TYPE], CMD_LOAD_MODEL
    mov dword ptr [rbx + OFF_STATE], BEACON_READY
    
    ; Copy model path to payload
    lea rsi, model_path
    lea rdi, [rbx + OFF_CMD_PAYLOAD]
    mov rcx, model_path_len
    rep movsb
    mov dword ptr [rbx + OFF_PAYLOAD_LEN], model_path_len
    
    ; Signal command
    mov rcx, hCmdEvent
    call SetEvent
    
    ; Wait for response
    mov rcx, hRespEvent
    mov edx, 30000
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne timeout
    
    ; Check response
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_STATUS]
    cmp eax, RESP_OK
    jne load_error
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString
    
    ; Wait for model to be READY
    lea rcx, msg_wait_ready
    call PrintString
    
wait_ready_loop:
    mov rbx, pShMem
    mov eax, [rbx + OFF_MODEL_STATE]
    cmp eax, MODEL_STATE_READY
    je model_ready
    mov ecx, 100
    call Sleep
    jmp wait_ready_loop

model_ready:
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; ================================================================
    ; STEP 2: Inference
    ; ================================================================
    lea rcx, msg_infer
    call PrintString
    
    mov rbx, pShMem
    mov rax, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], rax
    mov dword ptr [rbx + OFF_CMD_TYPE], CMD_INFER
    mov dword ptr [rbx + OFF_STATE], BEACON_READY
    
    ; Copy prompt to payload
    lea rsi, prompt
    lea rdi, [rbx + OFF_CMD_PAYLOAD]
    mov rcx, prompt_len
    rep movsb
    mov dword ptr [rbx + OFF_PAYLOAD_LEN], prompt_len
    
    ; Signal command
    mov rcx, hCmdEvent
    call SetEvent
    
    ; Wait for response (longer for inference)
    mov rcx, hRespEvent
    mov edx, 60000
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne timeout
    
    ; Check response
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_STATUS]
    cmp eax, RESP_OK
    jne infer_error
    
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString
    
    ; Print response
    lea rcx, msg_response
    call PrintString
    lea rcx, [rbx + OFF_RESP_PAYLOAD]
    call PrintString
    lea rcx, newline
    call PrintString
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

load_error:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_load
    call PrintString
    jmp cleanup

infer_error:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_infer
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

    banner      DB "Complete End-to-End Test", 13, 10
                DB "========================", 13, 10, 0
    newline     DB 13, 10, 0
    
    msg_open        DB "Opening shared memory... ", 0
    msg_map         DB "Mapping view... ", 0
    msg_events      DB "Opening events... ", 0
    msg_load        DB "Loading model... ", 0
    msg_wait_ready  DB "Waiting for model READY... ", 0
    msg_infer       DB "Running inference... ", 0
    msg_response    DB "Response: ", 0
    
    msg_ok          DB "OK", 0
    msg_fail        DB "FAILED", 0
    
    msg_err_open    DB "Cannot open shared memory", 13, 10, 0
    msg_err_map     DB "Cannot map view", 13, 10, 0
    msg_err_event   DB "Cannot open events", 13, 10, 0
    msg_err_timeout DB "Timeout", 13, 10, 0
    msg_err_load    DB "Model load failed", 13, 10, 0
    msg_err_infer   DB "Inference failed", 13, 10, 0
    
    shmem_name      DB "SOVEREIGN_BEACON_V1", 0
    cmd_event_name  DB "SOVEREIGN_CMD_EVENT", 0
    resp_event_name DB "SOVEREIGN_RESP_EVENT", 0
    
    model_path      DB "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf", 0
    model_path_len  EQU $ - model_path - 1
    
    prompt          DB '{"action":"generate","prompt":"Hello","max_tokens":20}', 0
    prompt_len      EQU $ - prompt - 1
    
    hShMem          DQ 0
    pShMem          DQ 0
    hCmdEvent       DQ 0
    hRespEvent      DQ 0
    written         DD 0

END
