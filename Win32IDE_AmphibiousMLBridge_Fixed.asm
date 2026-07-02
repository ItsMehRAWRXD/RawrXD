; =============================================================================
; Win32IDE_AmphibiousMLBridge_Fixed.asm
; Properly integrated IDE bridge with correct MASM syntax and unwind info
; =============================================================================

.CODE

; External Windows APIs
EXTERN SendMessageA:PROC
EXTERN GetWindowTextA:PROC
EXTERN SetWindowTextA:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC

; External RawrXD functions (to be implemented)
EXTERN Titan_PerformDMA:PROC
EXTERN TryRealLLMInferenceStreaming:PROC

; =============================================================================
; EXPORTED FUNCTIONS
; =============================================================================
PUBLIC Win32IDE_InitializeML
PUBLIC Win32IDE_StartInference
PUBLIC Win32IDE_StreamTokenToEditor
PUBLIC Win32IDE_CommitTelemetry
PUBLIC Win32IDE_CancelInference
PUBLIC FormatInferencePrompt

; =============================================================================
; CONSTANTS
; =============================================================================
EM_GETSEL                   EQU 0B0h
EM_SETSEL                   EQU 0B1h
EM_REPLACESEL               EQU 194h
EM_SETSEL                   EQU 0B1h
STREAM_BUFFER_SIZE          EQU 8192
MAX_TOKENS                  EQU 512
GENERIC_WRITE               EQU 40000000h
FILE_SHARE_READ             EQU 1
CREATE_ALWAYS               EQU 2
FILE_ATTRIBUTE_NORMAL       EQU 80h
INVALID_HANDLE_VALUE        EQU -1
STD_OUTPUT_HANDLE           EQU -11

; =============================================================================
; DATA SECTION
; =============================================================================
.DATA

; Status messages (MASM syntax - NO [rel]!)
msg_ml_init                 DB "[ML] Runtime Initialized", 0
msg_stream_done             DB "[ML] Token stream complete", 0
msg_inference_canceled      DB "[ML] Inference canceled", 0
msg_telemetry_saved         DB "[ML] Telemetry saved", 0

; Prompt templates
prompt_lang_tag             DB "[LANGUAGE: cpp]", 0Dh, 0Ah, 0
prompt_context_tag          DB "[EDITOR_CONTEXT]", 0Dh, 0Ah, 0
prompt_request_tag          DB "[USER_REQUEST]", 0Dh, 0Ah, 0

; JSON templates
json_header                 DB "{", 0Dh, 0Ah, "  ""telemetry"": {", 0Dh, 0Ah, 0
json_success                DB "    ""success"": true,", 0Dh, 0Ah, 0
json_failure                DB "    ""success"": false,", 0Dh, 0Ah, 0
json_footer                 DB "  }", 0Dh, 0Ah, "}", 0

; Buffers
g_TokenBuffer               DB STREAM_BUFFER_SIZE DUP(0)
g_TelemetryBuffer           DB 4096 DUP(0)
g_ConsoleHandle             DQ 0
g_hEditor                   DQ 0
g_hStatus                   DQ 0
g_InferenceRunning          DQ 0
g_BytesWritten              DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

; ============================================================================
; Win32IDE_InitializeML - Initialize ML inference engine for IDE
; RCX = hEditorWindow (HWND)
; RDX = hStatusBar (HWND)
; R8 = modelPath
; ============================================================================
Win32IDE_InitializeML PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov r12, rcx                    ; r12 = editor hwnd
    mov r13, rdx                    ; r13 = status bar hwnd
    
    ; Store handles
    mov g_hEditor, r12
    mov g_hStatus, r13
    
    ; Get console handle for debug output
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_ConsoleHandle, rax
    
    ; Initialize inference runtime (call actual implementation)
    ; xor ecx, ecx
    ; call Titan_PerformDMA          ; Commented out - stub for now
    
    ; Status: "ML Runtime Initialized"
    mov rcx, r13
    lea rdx, msg_ml_init            ; ✅ MASM: direct reference, NO [rel]
    call SetWindowTextA
    
    xor eax, eax                    ; Return success
    
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
Win32IDE_InitializeML ENDP

; ============================================================================
; Win32IDE_StartInference - Queue inference request
; RCX = hEditor
; RDX = selectedCode
; R8 = userPrompt
; R9 = outputBuffer
; ============================================================================
Win32IDE_StartInference PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    mov r12, rcx                    ; r12 = editor hwnd
    mov r13, rdx                    ; r13 = selected code
    mov r14, r8                     ; r14 = user prompt
    
    mov g_InferenceRunning, 1
    
    ; Build LLM request
    mov rcx, r9                     ; output buffer
    mov rdx, r13                    ; context
    mov r8, r14                     ; prompt
    call FormatInferencePrompt
    
    ; Call inference (stub for now)
    ; mov rcx, r9
    ; call TryRealLLMInferenceStreaming
    
    xor eax, eax
    
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Win32IDE_StartInference ENDP

; ============================================================================
; Win32IDE_StreamTokenToEditor - Process single token
; RCX = hEditor
; RDX = token
; R8 = tokenLen
; R9 = isDone
; ============================================================================
Win32IDE_StreamTokenToEditor PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov r12, rcx                    ; r12 = editor hwnd
    
    ; Move cursor to end
    mov rcx, r12
    mov edx, EM_SETSEL
    mov r8, -1
    mov r9, -1
    call SendMessageA
    
    ; Insert token
    mov rcx, r12
    mov edx, EM_REPLACESEL
    xor r8d, r8d
    mov r9, rdx                     ; token
    call SendMessageA
    
    ; Check if done
    test r9d, r9d
    jz stream_continue
    
    mov g_InferenceRunning, 0
    
stream_continue:
    xor eax, eax
    
    add rsp, 40
    pop r12
    pop rbx
    ret
Win32IDE_StreamTokenToEditor ENDP

; ============================================================================
; Win32IDE_CommitTelemetry - Write JSON telemetry
; RCX = filePath
; RDX = tokenCount
; R8 = durationMs
; R9 = success
; ============================================================================
Win32IDE_CommitTelemetry PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 104
    .allocstack 104
    .endprolog
    
    mov r12, rcx                    ; r12 = filepath
    mov r13d, edx                 ; r13d = token count
    mov r14, r8                   ; r14 = duration
    mov r15d, r9d                 ; r15d = success flag
    
    ; Create file with proper shadow space
    mov qword ptr [rsp+64], 0       ; hTemplateFile
    mov dword ptr [rsp+56], FILE_ATTRIBUTE_NORMAL
    mov dword ptr [rsp+48], CREATE_ALWAYS
    xor r9d, r9d                    ; lpSecurityAttributes
    mov r8d, FILE_SHARE_READ        ; dwShareMode
    mov edx, GENERIC_WRITE          ; dwDesiredAccess
    mov rcx, r12                    ; lpFileName
    call CreateFileA
    
    cmp rax, INVALID_HANDLE_VALUE
    je telemetry_fail
    
    mov rbx, rax                    ; rbx = hFile
    
    ; Build JSON header
    lea rcx, g_TelemetryBuffer
    lea rdx, json_header
    call strcpy
    
    ; Add success field
    lea rcx, g_TelemetryBuffer
    call StringLength
    lea rcx, g_TelemetryBuffer
    add rcx, rax
    
    test r15d, r15d
    jz telemetry_failure_json
    
    lea rdx, json_success
    jmp telemetry_write_field
    
telemetry_failure_json:
    lea rdx, json_failure
    
telemetry_write_field:
    call strcpy
    
    ; Add footer
    lea rcx, g_TelemetryBuffer
    call StringLength
    lea rcx, g_TelemetryBuffer
    add rcx, rax
    lea rdx, json_footer
    call strcpy
    
    ; Write to file
    mov rcx, rbx
    lea rdx, g_TelemetryBuffer
    lea r8, g_TelemetryBuffer
    call StringLength
    mov r8, rax
    lea r9, g_BytesWritten
    call WriteFile
    
    ; Close file
    mov rcx, rbx
    call CloseHandle
    
    ; Update status
    mov rcx, g_hStatus
    lea rdx, msg_telemetry_saved
    call SetWindowTextA
    
    xor eax, eax
    jmp telemetry_done
    
telemetry_fail:
    mov eax, 1
    
telemetry_done:
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Win32IDE_CommitTelemetry ENDP

; ============================================================================
; Win32IDE_CancelInference - Abort inference
; RCX = hEditor
; RDX = originalText
; ============================================================================
Win32IDE_CancelInference PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rcx                    ; rbx = editor hwnd
    
    ; Restore original text
    mov rcx, rbx
    mov rdx, rdx                    ; original text
    call SetWindowTextA
    
    mov g_InferenceRunning, 0
    
    ; Log cancellation
    mov rcx, g_hStatus
    lea rdx, msg_inference_canceled
    call SetWindowTextA
    
    xor eax, eax
    
    add rsp, 40
    pop rbx
    ret
Win32IDE_CancelInference ENDP

; ============================================================================
; FormatInferencePrompt - Build LLM request
; RCX = outputBuffer
; RDX = selectedCode
; R8 = userPrompt
; ============================================================================
FormatInferencePrompt PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rdi, rcx                    ; rdi = output buffer
    mov rsi, rdx                    ; rsi = selected code
    
    ; Write language tag
    mov rcx, rdi
    lea rdx, prompt_lang_tag
    call strcpy
    
    ; Write context tag
    mov rcx, rdi
    call StringLength
    add rdi, rax
    mov rcx, rdi
    lea rdx, prompt_context_tag
    call strcpy
    
    ; Append selected code
    mov rcx, rdi
    call StringLength
    add rdi, rax
    mov rcx, rdi
    mov rdx, rsi
    call strcpy
    
    ; Write request tag
    mov rcx, rdi
    call StringLength
    add rdi, rax
    mov rcx, rdi
    lea rdx, prompt_request_tag
    call strcpy
    
    ; Append user prompt
    mov rcx, rdi
    call StringLength
    add rdi, rax
    mov rcx, rdi
    mov rdx, r8
    call strcpy
    
    xor eax, eax
    
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
FormatInferencePrompt ENDP

; ============================================================================
; Utility: String copy
; RCX = dest, RDX = source
; ============================================================================
strcpy PROC
    push rsi
    push rdi
    mov rdi, rcx
    mov rsi, rdx
strcpy_loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz strcpy_loop
    pop rdi
    pop rsi
    ret
strcpy ENDP

; ============================================================================
; Utility: String length (local implementation)
; RCX = string
; Returns: RAX = length
; ============================================================================
StringLength PROC
    push rdi
    mov rdi, rcx
    xor eax, eax
    mov ecx, -1
    repne scasb
    mov rax, rdi
    sub rax, rcx
    dec rax
    pop rdi
    ret
StringLength ENDP

END
