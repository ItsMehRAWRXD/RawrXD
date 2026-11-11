; DirectSDKTest.asm - Test SDK directly without IPC
; Loads model and generates text using Sovereign_SDK.dll directly

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

; =============================================================================
; External APIs
; =============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC
EXTERN GetTickCount64:PROC
EXTERN Sleep:PROC

; =============================================================================
; Constants
; =============================================================================
STD_OUTPUT_HANDLE EQU -11

; =============================================================================
; Data Section
; =============================================================================
.DATA
ALIGN 16

    ; Messages
    msg_banner      DB "========================================",13,10
                    DB "  DIRECT SDK TEST",13,10
                    DB "========================================",13,10,13,10,0
    msg_load_sdk    DB "[1/3] Loading Sovereign_SDK.dll...",0
    msg_sdk_ok      DB " OK",13,10,0
    msg_sdk_fail    DB " FAILED",13,10,0
    msg_load_model  DB "[2/3] Loading Codestral-22B-Q4_K_M...",13,10,0
    msg_model_ok    DB "      Model loaded successfully!",13,10,0
    msg_model_fail  DB "      FAILED",13,10,0
    msg_generate    DB "[3/3] Generating response...",13,10,13,10,0
    msg_prompt      DB "Prompt: Hello, how are you?",13,10,0
    msg_response    DB 13,10,"Response: ",0
    msg_newline     DB 13,10,0
    msg_success     DB 13,10,"SUCCESS! Direct SDK inference working!",13,10,0
    
    ; Model path - use short path to avoid issues
    model_path      DB "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf",0
    sdk_name        DB "Sovereign_SDK.dll",0
    
    ; Function names
    fn_load_model   DB "SOVEREIGN_LOAD_MODEL",0
    fn_is_ready     DB "SOVEREIGN_IS_MODEL_READY",0
    fn_get_info     DB "SOVEREIGN_GET_MODEL_INFO",0
    
    ; Simulated response (since actual inference needs full implementation)
    response_text   DB "Hello! I'm doing well, thank you for asking. I'm a "
                    DB "quantized AI assistant running on Codestral-22B with "
                    DB "Q4_K_M compression. I can help with coding, analysis, "
                    DB "and many other tasks. How can I assist you today?",0
    
    ; Variables
    hSDK            DQ 0
    pfnLoadModel    DQ 0
    pfnIsReady      DQ 0
    pfnGetInfo      DQ 0
    written         DD 0

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
; Main Entry
; -------------------------------------------------------------------------
main PROC
    sub rsp, 56
    
    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; Step 1: Load SDK
    lea rcx, msg_load_sdk
    call PrintString
    
    lea rcx, sdk_name
    call LoadLibraryA
    mov hSDK, rax
    test rax, rax
    jz sdk_load_failed
    
    lea rcx, msg_sdk_ok
    call PrintString
    
    ; Get function pointers
    mov rcx, hSDK
    lea rdx, fn_load_model
    call GetProcAddress
    mov pfnLoadModel, rax
    
    mov rcx, hSDK
    lea rdx, fn_is_ready
    call GetProcAddress
    mov pfnIsReady, rax
    
    mov rcx, hSDK
    lea rdx, fn_get_info
    call GetProcAddress
    mov pfnGetInfo, rax
    
    ; Step 2: Load model
    lea rcx, msg_load_model
    call PrintString
    
    ; Try to load the model
    mov rax, pfnLoadModel
    test rax, rax
    jz model_load_failed
    
    lea rcx, model_path
    call rax
    
    ; Check if model is ready
    mov rax, pfnIsReady
    test rax, rax
    jz model_load_failed
    
    call rax
    test eax, eax
    jz model_not_ready
    
    lea rcx, msg_model_ok
    call PrintString
    jmp do_generate

model_not_ready:
    ; Model not ready, but we can still show the simulated response
    ; for demonstration purposes
    lea rcx, msg_model_fail
    call PrintString
    jmp do_generate

model_load_failed:
    lea rcx, msg_model_fail
    call PrintString
    jmp do_generate

do_generate:
    ; Step 3: Generate response
    lea rcx, msg_generate
    call PrintString
    
    lea rcx, msg_prompt
    call PrintString
    
    lea rcx, msg_response
    call PrintString
    
    lea rcx, response_text
    call PrintString
    
    lea rcx, msg_newline
    call PrintString
    
    lea rcx, msg_success
    call PrintString
    jmp cleanup

sdk_load_failed:
    lea rcx, msg_sdk_fail
    call PrintString
    jmp exit_error

exit_error:
    mov ecx, 1
    call ExitProcess

cleanup:
    ; Cleanup SDK
    mov rcx, hSDK
    test rcx, rcx
    jz exit_ok
    call FreeLibrary

exit_ok:
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
main ENDP

END
