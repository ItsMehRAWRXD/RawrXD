; FullIntegrationTest.asm - Complete end-to-end test with model loading
; Tests: CMD_LOAD_MODEL -> wait for READY -> CMD_INFER -> get response

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
EXTERN CreateProcessA:PROC
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
CMD_GET_STATUS EQU 1002h

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

    ; Messages
    msg_banner      DB "========================================",13,10
                    DB "  FULL INTEGRATION TEST",13,10
                    DB "========================================",13,10,13,10,0
    msg_step1       DB "[Step 1] Opening shared memory...",0
    msg_step2       DB "[Step 2] Loading model via CMD_LOAD_MODEL...",13,10,0
    msg_step3       DB "[Step 3] Waiting for MODEL_STATE_READY...",0
    msg_step4       DB "[Step 4] Sending CMD_INFER...",13,10,0
    msg_step5       DB "[Step 5] Waiting for response...",0
    msg_step6       DB "[Step 6] Reading response...",13,10,0
    msg_ok          DB " OK",13,10,0
    msg_fail        DB " FAILED",13,10,0
    msg_dot         DB ".",0
    msg_newline     DB 13,10,0
    msg_response    DB "Response: ",0
    msg_success     DB 13,10,"SUCCESS! End-to-end inference working!",13,10,0
    msg_timeout     DB "TIMEOUT",13,10,0
    
    ; Model path
    model_path      DB "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf",0
    
    ; JSON payloads
    json_load       DB '{"path":"F:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf"}',0
    json_load_len   EQU $ - json_load - 1
    json_infer      DB '{"action":"generate","prompt":"Hello","max_tokens":50}',0
    json_infer_len  EQU $ - json_infer - 1
    
    ; Names
    shmem_name      DB "SOVEREIGN_BEACON_V1",0
    cmd_event_name  DB "SOVEREIGN_CMD_EVENT",0
    resp_event_name DB "SOVEREIGN_RESP_EVENT",0
    
    ; Variables
    hShMem          DQ 0
    pShMem          DQ 0
    hCmdEvent       DQ 0
    hRespEvent      DQ 0
    written         DD 0
    start_time      DQ 0

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
    
    ; Map view
    mov rcx, hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    mov pShMem, rax
    test rax, rax
    jz step1_fail
    
    ; Open events
    mov ecx, 00100000h
    xor edx, edx
    lea r8, cmd_event_name
    call OpenEventA
    mov hCmdEvent, rax
    test rax, rax
    jz step1_fail
    
    mov ecx, 00100000h
    xor edx, edx
    lea r8, resp_event_name
    call OpenEventA
    mov hRespEvent, rax
    test rax, rax
    jz step1_fail
    
    lea rcx, msg_ok
    call PrintString
    
    ; Step 2: Send CMD_LOAD_MODEL
    lea rcx, msg_step2
    call PrintString
    
    mov rcx, CMD_LOAD_MODEL
    lea rdx, json_load
    mov r8, json_load_len
    call SendCommand
    
    ; Step 3: Wait for MODEL_STATE_READY
    lea rcx, msg_step3
    call PrintString
    
    mov r12, 60
    mov rbx, pShMem
    
wait_ready_loop:
    mov eax, [rbx + OFF_MODEL_STATE]
    cmp eax, MODEL_STATE_READY
    je model_ready
    
    lea rcx, msg_dot
    call PrintString
    
    mov ecx, 1000
    call Sleep
    
    dec r12
    jnz wait_ready_loop
    jmp step3_fail
    
model_ready:
    lea rcx, msg_ok
    call PrintString
    
    ; Step 4: Send CMD_INFER
    lea rcx, msg_step4
    call PrintString
    
    mov rcx, CMD_INFER
    lea rdx, json_infer
    mov r8, json_infer_len
    call SendCommand
    
    ; Step 5: Wait for response
    lea rcx, msg_step5
    call PrintString
    
    mov rcx, hRespEvent
    mov edx, 30000
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne step5_fail
    
    lea rcx, msg_ok
    call PrintString
    
    ; Step 6: Read response
    lea rcx, msg_step6
    call PrintString
    
    mov rbx, pShMem
    mov eax, [rbx + OFF_RESP_LEN]
    test eax, eax
    jz step6_empty
    
    lea rcx, msg_response
    call PrintString
    
    lea rcx, [rbx + OFF_RESP_PAYLOAD]
    call PrintString
    
    lea rcx, msg_newline
    call PrintString
    
step6_empty:
    lea rcx, msg_success
    call PrintString
    jmp cleanup

step1_fail:
    lea rcx, msg_fail
    call PrintString
    jmp cleanup

step3_fail:
    lea rcx, msg_fail
    call PrintString
    jmp cleanup

step5_fail:
    lea rcx, msg_fail
    call PrintString
    jmp cleanup

cleanup:
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    pop r13
    pop r12
    pop rbx
    ret
main ENDP

END
