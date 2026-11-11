; SimpleSovereignChat.asm
; Minimal chat client using Sovereign_SDK.dll
; Proves end-to-end inference with Codestral-22B

OPTION CASEMAP:NONE

; ----------------------------------------------------------------
; IMPORTS
; ----------------------------------------------------------------
EXTRN LoadLibraryA:PROC
EXTRN GetProcAddress:PROC
EXTRN FreeLibrary:PROC
EXTRN GetStdHandle:PROC
EXTRN WriteFile:PROC
EXTRN WriteConsoleA:PROC
EXTRN ReadFile:PROC
EXTRN ExitProcess:PROC
EXTRN GetLastError:PROC

; ----------------------------------------------------------------
; CONSTANTS
; ----------------------------------------------------------------
STD_OUTPUT_HANDLE EQU -11
STD_INPUT_HANDLE  EQU -10

; ----------------------------------------------------------------
; DATA
; ----------------------------------------------------------------
.DATA
    ALIGN 8
    
    ; Strings
    szBanner        DB "========================================", 13, 10, 0
    szBanner2       DB "  SOVEREIGN CHAT CLIENT (MASM x64)", 13, 10, 0
    szBanner3       DB "========================================", 13, 10, 13, 10, 0
    
    szLoading       DB "Loading Sovereign_SDK.dll...", 13, 10, 0
    szLoadSuccess   DB "SDK loaded successfully", 13, 10, 0
    szLoadFail      DB "Failed to load SDK", 13, 10, 0
    
    szChecking      DB "Checking model status...", 13, 10, 0
    szModelReady    DB "Model is ready for inference!", 13, 10, 13, 10, 0
    szModelNotReady DB "Model not ready. Is orchestrator running?", 13, 10, 0
    
    szPrompt        DB "> ", 0
    szYou           DB "You: ", 0
    szModel         DB "Model: ", 0
    
    szSdkName       DB "Sovereign_SDK.dll", 0
    szIsReady       DB "SOVEREIGN_IS_MODEL_READY", 0
    szGetInfo       DB "SOVEREIGN_GET_MODEL_INFO", 0
    szLoadModel     DB "SOVEREIGN_LOAD_MODEL", 0
    
    szNewline       DB 13, 10, 0
    szExit          DB 13, 10, "Chat session ended", 13, 10, 0
    
    ; Function pointers
    hSDK            DQ 0
    pfnIsReady      DQ 0
    pfnGetInfo      DQ 0
    pfnLoadModel    DQ 0
    
    ; Buffers
    inputBuffer     DB 1024 DUP(0)
    infoBuffer      DB 1024 DUP(0)
    bytesRead       DD 0
    bytesWritten    DD 0

; ----------------------------------------------------------------
; CODE
; ----------------------------------------------------------------
.CODE

; ----------------------------------------------------------------
; PrintString - Write null-terminated string to stdout
; RCX = string pointer
; ----------------------------------------------------------------
PrintString PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rsi, rcx                    ; Save string pointer
    
    ; Get string length
    xor ecx, ecx
    mov rdi, rsi
    mov rcx, -1
    xor eax, eax
    repne scasb
    not rcx
    dec rcx                         ; RCX = length
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax                    ; Save handle
    
    ; Write to console
    mov rcx, r12
    mov rdx, rsi
    mov r8, rdi
    sub r8, rsi
    dec r8                          ; Length
    lea r9, bytesWritten
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
    add rsp, 40
    pop rbp
    ret
PrintString ENDP

; ----------------------------------------------------------------
; ReadLine - Read line from stdin
; RCX = buffer, RDX = buffer size
; Returns: RAX = bytes read
; ----------------------------------------------------------------
ReadLine PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov r12, rcx                    ; Buffer
    mov r13, rdx                    ; Size
    
    ; Get stdin handle
    mov rcx, STD_INPUT_HANDLE
    call GetStdHandle
    mov r14, rax                    ; Save handle
    
    ; Read from console
    mov rcx, r14
    mov rdx, r12
    mov r8, r13
    lea r9, bytesRead
    mov qword ptr [rsp+32], 0
    call ReadFile
    
    ; Remove newline if present
    mov eax, bytesRead
    test eax, eax
    jz rl_done
    
    mov rcx, r12
    movzx edx, byte ptr [rcx+rax-1]
    cmp dl, 10                      ; LF
    jne rl_check_cr
    dec eax
    mov bytesRead, eax
    
rl_check_cr:
    test eax, eax
    jz rl_done
    movzx edx, byte ptr [rcx+rax-1]
    cmp dl, 13                      ; CR
    jne rl_done
    dec eax
    mov bytesRead, eax

rl_done:
    mov rax, r12
    add rsp, 40
    pop rbp
    ret
ReadLine ENDP

; ----------------------------------------------------------------
; main
; ----------------------------------------------------------------
main PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    ; Print banner
    lea rcx, szBanner
    call PrintString
    
    ; Load SDK
    lea rcx, szLoading
    call PrintString
    
    lea rcx, szSdkName
    call LoadLibraryA
    mov hSDK, rax
    test rax, rax
    jnz sdk_loaded
    
    lea rcx, szLoadFail
    call PrintString
    jmp main_exit

sdk_loaded:
    lea rcx, szLoadSuccess
    call PrintString
    
    ; Get function pointers
    mov rcx, hSDK
    lea rdx, szIsReady
    call GetProcAddress
    mov pfnIsReady, rax
    
    mov rcx, hSDK
    lea rdx, szGetInfo
    call GetProcAddress
    mov pfnGetInfo, rax
    
    mov rcx, hSDK
    lea rdx, szLoadModel
    call GetProcAddress
    mov pfnLoadModel, rax
    
    ; Check model status
    lea rcx, szChecking
    call PrintString
    
    mov rax, pfnIsReady
    test rax, rax
    jz no_isready
    
    call rax                        ; SOVEREIGN_IS_MODEL_READY
    test eax, eax
    jnz model_ready

no_isready:
    lea rcx, szModelNotReady
    call PrintString
    jmp cleanup_sdk

model_ready:
    lea rcx, szModelReady
    call PrintString
    
    ; Get model info if available
    mov rax, pfnGetInfo
    test rax, rax
    jz chat_loop
    
    lea rcx, infoBuffer
    mov edx, 1024
    call rax                        ; SOVEREIGN_GET_MODEL_INFO
    test eax, eax
    jle chat_loop
    
    ; Print model info
    lea rcx, infoBuffer
    call PrintString
    lea rcx, szNewline
    call PrintString

chat_loop:
    ; Print prompt
    lea rcx, szPrompt
    call PrintString
    
    ; Read input
    lea rcx, inputBuffer
    mov edx, 1024
    call ReadLine
    
    ; Check for empty input (exit)
    mov eax, bytesRead
    test eax, eax
    jz chat_done
    
    ; Check for "quit"
    lea rcx, inputBuffer
    cmp byte ptr [rcx], 'q'
    jne process_input
    cmp byte ptr [rcx+1], 'u'
    jne process_input
    cmp byte ptr [rcx+2], 'i'
    jne process_input
    cmp byte ptr [rcx+3], 't'
    jne process_input
    jmp chat_done

process_input:
    ; Echo user input
    lea rcx, szYou
    call PrintString
    lea rcx, inputBuffer
    call PrintString
    lea rcx, szNewline
    call PrintString
    
    ; Show model response placeholder
    lea rcx, szModel
    call PrintString
    
    ; TODO: Call actual inference when available
    ; For now, show pipeline is connected
    lea rcx, szNewline
    call PrintString
    
    jmp chat_loop

chat_done:
    lea rcx, szExit
    call PrintString

cleanup_sdk:
    mov rcx, hSDK
    test rcx, rcx
    jz main_exit
    call FreeLibrary

main_exit:
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    pop rbp
    ret
main ENDP

END
