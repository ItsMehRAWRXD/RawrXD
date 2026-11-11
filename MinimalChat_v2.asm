; MinimalChat.asm - Ultra simple chat test
; Just loads SDK and checks model status

OPTION CASEMAP:NONE

; ----------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------
STD_OUTPUT_HANDLE EQU -11

; ----------------------------------------------------------------
; CODE
; ----------------------------------------------------------------
.CODE

; External Windows APIs
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

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
    sub rsp, 64
    .allocstack 64
    .endprolog

    ; Print loading message
    lea rcx, msg1
    call PrintString

    ; Load SDK
    lea rcx, sdkname
    call LoadLibraryA
    mov hSDK, rax
    test rax, rax
    jz load_fail

    ; Print success
    lea rcx, msg2
    call PrintString

    ; Get function pointer
    mov rcx, hSDK
    lea rdx, readyname
    call GetProcAddress
    mov pfnReady, rax

    ; Print checking message
    lea rcx, msg4
    call PrintString

    ; Check if function exists
    mov rax, pfnReady
    test rax, rax
    jz not_ready

    ; Call IsReady
    call rax
    test eax, eax
    jnz model_ready
    
    ; Try to load model
    lea rcx, msg_load_attempt
    call PrintString
    
    mov rcx, hSDK
    lea rdx, loadname
    call GetProcAddress
    test rax, rax
    jz no_load_func
    
    lea rcx, modelpath
    call rax
    test eax, eax
    jz load_failed
    
    ; Check again if ready
    mov rax, pfnReady
    call rax
    test eax, eax
    jnz model_ready
    jmp not_ready
    
no_load_func:
    lea rcx, msg_no_load
    call PrintString
    jmp not_ready
    
load_failed:
    lea rcx, msg_load_fail
    call PrintString
    jmp not_ready

model_ready:
    lea rcx, msg5
    call PrintString
    jmp done

not_ready:
    lea rcx, msg6
    call PrintString
    jmp done

load_fail:
    lea rcx, msg3
    call PrintString

done:
    ; Cleanup
    mov rcx, hSDK
    test rcx, rcx
    jz exit_now
    call FreeLibrary

exit_now:
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

    ; Messages
    msg1        DB "Loading SDK...", 13, 10, 0
    msg2        DB "SDK loaded OK", 13, 10, 0
    msg3        DB "SDK load failed", 13, 10, 0
    msg4        DB "Checking model...", 13, 10, 0
    msg5        DB "Model READY!", 13, 10, 0
    msg6        DB "Model NOT ready", 13, 10, 0
    msg_load_attempt DB "Attempting to load model...", 13, 10, 0
    msg_no_load DB "Load function not found", 13, 10, 0
    msg_load_fail DB "Model load failed", 13, 10, 0

    ; Strings for API calls
    sdkname     DB "Sovereign_SDK.dll", 0
    readyname   DB "SOVEREIGN_IS_MODEL_READY", 0
    loadname    DB "SOVEREIGN_LOAD_MODEL", 0
    
    ; Model path
    modelpath   DB "current_model.gguf", 0

    ; Variables
    hSDK        DQ 0
    pfnReady    DQ 0
    written     DD 0

END
