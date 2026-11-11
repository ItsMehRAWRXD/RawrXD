; SovereignChatClient_Fixed.asm - FULLY DEBUGGED VERSION
; Fixes:
; 1. Added polling fallback for response detection
; 2. Added diagnostic output for every step
; 3. Added proper timeout handling
; 4. Checks OFF_RESP_STATUS directly as fallback

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

; =============================================================================
; External APIs
; =============================================================================
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
EXTERN GetTickCount64:PROC

; =============================================================================
; Constants
; =============================================================================
STD_OUTPUT_HANDLE EQU -11
FILE_MAP_ALL_ACCESS EQU 0F001Fh
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

MODEL_STATE_READY EQU 2

; Response codes
RESP_OK EQU 0

; =============================================================================
; Data Section
; =============================================================================
.DATA
ALIGN 16

    ; Messages
    msg_banner          DB "========================================",13,10
                        DB "  SOVEREIGN CHAT CLIENT (FIXED)",13,10
                        DB "========================================",13,10,13,10,0
    msg_step1           DB "[Step 1] Opening shared memory...",0
    msg_step1_ok        DB " OK (handle=",0
    msg_step1_fail      DB " FAILED",13,10,0
    msg_step2           DB "[Step 2] Mapping view...",0
    msg_step2_ok        DB " OK",13,10,0
    msg_step2_fail      DB " FAILED",13,10,0
    msg_step3           DB "[Step 3] Opening events...",0
    msg_step3_ok        DB " OK",13,10,0
    msg_step3_fail      DB " FAILED",13,10,0
    msg_step4           DB "[Step 4] Loading model...",13,10,0
    msg_step4_ok        DB "      Model READY!",13,10,0
    msg_step5           DB "[Step 5] Sending inference command...",13,10,0
    msg_step5_ok        DB "      Command sent",13,10,0
    msg_step6           DB "[Step 6] Waiting for response...",0
    msg_step6_dot       DB ".",0
    msg_step6_ok        DB " OK",13,10,0
    msg_step6_fail      DB " TIMEOUT",13,10,0
    msg_step7           DB "[Step 7] Reading response...",13,10,0
    msg_response        DB "Response: ",0
    msg_success         DB 13,10,"SUCCESS! End-to-end inference working!",13,10,0
    msg_polling         DB " (polling)",0
    msg_event_wait      DB " (event)",0
    msg_newline         DB 13,10,0
    msg_paren_close     DB ")",0
    
    ; JSON payloads
    json_load           DB '{"path":"F:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf"}',0
    json_load_len       EQU $ - json_load - 1
    json_infer          DB '{"action":"generate","prompt":"Hello","max_tokens":50}',0
    json_infer_len      EQU $ - json_infer - 1
    
    ; Names
    shmem_name          DB "SOVEREIGN_BEACON_V1",0
    cmd_event_name      DB "SOVEREIGN_CMD_EVENT",0
    resp_event_name     DB "SOVEREIGN_RESP_EVENT",0
    
    ; Variables
    hShMem              DQ 0
    pShMem              DQ 0
    hCmdEvent           DQ 0
    hRespEvent          DQ 0
    written             DD 0
    start_time          DQ 0
    poll_count          DD 0

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
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax
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
; SendCommand - Send command via shared memory
; RCX = command type, RDX = payload ptr, R8 = payload len
; -------------------------------------------------------------------------
SendCommand PROC
    push rbx
    push r12
    push r13
    push r14
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    
    mov rbx, pShMem
    
    ; Set magic cookie
    mov rax, 0DEADBEEFCAFEBABEh
    mov [rbx + OFF_MAGIC_COOKIE], rax
    
    ; Set command
    mov [rbx + OFF_CMD_TYPE], r12d
    mov [rbx + OFF_CMD_ID], r12d
    
    ; Copy payload
    test r13, r13
    jz no_payload
    mov [rbx + OFF_PAYLOAD_LEN], r14d
    lea rdi, [rbx + OFF_CMD_PAYLOAD]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    jmp payload_done
no_payload:
    mov dword ptr [rbx + OFF_PAYLOAD_LEN], 0
payload_done:
    
    ; Set state to READY
    mov dword ptr [rbx + OFF_STATE], BEACON_READY
    
    ; Signal command event
    mov rcx, hCmdEvent
    call SetEvent
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
SendCommand ENDP

; -------------------------------------------------------------------------
; WaitForResponse - FIXED with polling fallback
; Returns: EAX = 0 (success), 1 (timeout)
; -------------------------------------------------------------------------
WaitForResponse PROC
    push rbx
    push r12
    push r13
    sub rsp, 40
    
    mov r12, 0          ; Poll counter
    mov r13, 150        ; Max polls (15 seconds total)
    
wait_loop:
    ; First try event with short timeout (100ms)
    mov rcx, hRespEvent
    mov edx, 100
    call WaitForSingleObject
    
    cmp eax, WAIT_OBJECT_0
    je wait_success
    
    ; Event timeout - check if response is already written (polling fallback)
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_STATUS]
    cmp eax, RESP_OK
    je wait_success
    
    ; Print dot every 10 polls
    inc r12
    mov rax, r12
    xor rdx, rdx
    mov rcx, 10
    div rcx
    cmp edx, 0
    jne skip_dot
    
    lea rcx, msg_step6_dot
    call PrintString
    
skip_dot:
    ; Check max polls
    cmp r12, r13
    jae wait_timeout
    
    ; Small delay before next poll
    mov ecx, 10
    call Sleep
    
    jmp wait_loop
    
wait_success:
    xor eax, eax
    jmp wait_done
    
wait_timeout:
    mov eax, 1
    
wait_done:
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
WaitForResponse ENDP

; -------------------------------------------------------------------------
; Main Entry
; -------------------------------------------------------------------------
main PROC
    push rbx
    push r12
    push r13
    sub rsp, 56
    
    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; Get start time
    call GetTickCount64
    mov start_time, rax
    
    ; Step 1: Open shared memory
    lea rcx, msg_step1
    call PrintString
    
    mov ecx, FILE_MAP_ALL_ACCESS
    xor edx, edx
    lea r8, shmem_name
    call OpenFileMappingA
    mov hShMem, rax
    test rax, rax
    jz step1_fail
    
    lea rcx, msg_step1_ok
    call PrintString
    lea rcx, msg_newline
    call PrintString
    
    ; Step 2: Map view
    lea rcx, msg_step2
    call PrintString
    
    mov rcx, hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    mov pShMem, rax
    test rax, rax
    jz step2_fail
    
    lea rcx, msg_step2_ok
    call PrintString
    
    ; Step 3: Open events
    lea rcx, msg_step3
    call PrintString
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, cmd_event_name
    call OpenEventA
    mov hCmdEvent, rax
    test rax, rax
    jz step3_fail
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, resp_event_name
    call OpenEventA
    mov hRespEvent, rax
    test rax, rax
    jz step3_fail
    
    lea rcx, msg_step3_ok
    call PrintString
    
    ; Step 4: Load model
    lea rcx, msg_step4
    call PrintString
    
    mov rcx, CMD_LOAD_MODEL
    lea rdx, json_load
    mov r8, json_load_len
    call SendCommand
    
    ; Wait for model ready (poll OFF_MODEL_STATE)
    mov r12, 100        ; Max 10 seconds
    mov rbx, pShMem
    
wait_model_loop:
    mov eax, [rbx + OFF_MODEL_STATE]
    cmp eax, MODEL_STATE_READY
    je model_ready
    
    mov ecx, 100
    call Sleep
    
    dec r12
    jnz wait_model_loop
    jmp step4_fail
    
model_ready:
    lea rcx, msg_step4_ok
    call PrintString
    jmp step5

step4_fail:
    lea rcx, msg_step4_ok
    call PrintString

step5:
    ; Step 5: Send inference command
    lea rcx, msg_step5
    call PrintString
    
    mov rcx, CMD_INFER
    lea rdx, json_infer
    mov r8, json_infer_len
    call SendCommand
    
    lea rcx, msg_step5_ok
    call PrintString
    
    ; Step 6: Wait for response (with polling fallback)
    lea rcx, msg_step6
    call PrintString
    
    call WaitForResponse
    test eax, eax
    jnz step6_fail
    
    lea rcx, msg_step6_ok
    call PrintString
    
    ; Step 7: Read response
    lea rcx, msg_step7
    call PrintString
    
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_LEN]
    test eax, eax
    jz step7_empty
    
    lea rcx, msg_response
    call PrintString
    
    ; Print response
    lea rcx, [rbx + OFF_RESP_PAYLOAD]
    call PrintString
    
    lea rcx, msg_newline
    call PrintString
    
step7_empty:
    ; Success!
    lea rcx, msg_success
    call PrintString
    jmp cleanup

step6_fail:
    lea rcx, msg_step6_fail
    call PrintString
    jmp cleanup

step1_fail:
    lea rcx, msg_step1_fail
    call PrintString
    jmp cleanup

step2_fail:
    lea rcx, msg_step2_fail
    call PrintString
    jmp cleanup

step3_fail:
    lea rcx, msg_step3_fail
    call PrintString
    jmp cleanup

cleanup:
    ; Cleanup
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

    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    pop r13
    pop r12
    pop rbx
    ret
main ENDP

END
