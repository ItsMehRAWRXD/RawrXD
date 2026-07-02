; DirectInference.asm - Direct SDK inference without orchestrator IPC
; Loads model and generates text directly

OPTION CASEMAP:NONE

STD_OUTPUT_HANDLE EQU -11

.CODE

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC

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

    ; Load SDK
    lea rcx, msg_load_sdk
    call PrintString
    lea rcx, sdk_name
    call LoadLibraryA
    mov hSDK, rax
    test rax, rax
    jz load_sdk_fail
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
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

    ; Load model
    lea rcx, msg_load_model
    call PrintString
    mov rax, pfnLoadModel
    test rax, rax
    jz no_load_fn
    lea rcx, model_path
    call rax
    test eax, eax
    jz load_model_fail
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Check if ready
    lea rcx, msg_check_ready
    call PrintString
    mov rax, pfnIsReady
    test rax, rax
    jz no_ready_fn
    call rax
    test eax, eax
    jz not_ready
    lea rcx, msg_ok
    call PrintString
    lea rcx, newline
    call PrintString

    ; Generate text
    lea rcx, msg_generate
    call PrintString
    lea rcx, msg_not_impl
    call PrintString
    lea rcx, newline
    call PrintString
    jmp cleanup

load_sdk_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_sdk
    call PrintString
    jmp exit_error

no_load_fn:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_no_load
    call PrintString
    jmp cleanup

load_model_fail:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_model
    call PrintString
    jmp cleanup

no_ready_fn:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_no_ready
    call PrintString
    jmp cleanup

not_ready:
    lea rcx, msg_fail
    call PrintString
    lea rcx, msg_err_not_ready
    call PrintString
    jmp cleanup

cleanup:
    mov rcx, hSDK
    test rcx, rcx
    jz exit_now
    call FreeLibrary

exit_error:
    mov ecx, 1
    call ExitProcess

exit_now:
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

    banner          DB "Direct SDK Inference Test", 13, 10
                    DB "=========================", 13, 10, 0
    newline         DB 13, 10, 0
    
    msg_load_sdk    DB "Loading SDK... ", 0
    msg_load_model  DB "Loading model... ", 0
    msg_check_ready DB "Checking model ready... ", 0
    msg_generate    DB "Generating text... ", 0
    
    msg_ok          DB "OK", 0
    msg_fail        DB "FAILED", 0
    
    msg_err_sdk     DB "Cannot load SDK", 13, 10, 0
    msg_err_no_load DB "Load function not found", 13, 10, 0
    msg_err_model   DB "Model load failed", 13, 10, 0
    msg_err_no_ready DB "IsReady function not found", 13, 10, 0
    msg_err_not_ready DB "Model not ready", 13, 10, 0
    msg_not_impl    DB "(Inference not yet implemented in SDK)", 0
    
    sdk_name        DB "Sovereign_SDK.dll", 0
    fn_load_model   DB "SOVEREIGN_LOAD_MODEL", 0
    fn_is_ready     DB "SOVEREIGN_IS_MODEL_READY", 0
    
    model_path      DB "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf", 0
    
    hSDK            DQ 0
    pfnLoadModel    DQ 0
    pfnIsReady      DQ 0
    written         DD 0

END
