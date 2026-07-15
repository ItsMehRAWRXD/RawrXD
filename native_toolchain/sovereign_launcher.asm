;=============================================================================
; sovereign_launcher.asm - Runtime-First Launcher
; Pure x64 MASM - launches Sovereign_Engine.exe with model file
; Assemble: ml64 /c /W3 /nologo /Fo sovereign_launcher.obj sovereign_launcher.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:Start /OUT:sovereign_launcher.exe sovereign_launcher.obj kernel32.lib
;=============================================================================

OPTION CASEMAP:NONE

;=============================================================================
; External Windows API imports
;=============================================================================

EXTERN CreateProcessA:PROC
EXTERN WaitForSingleObject:PROC
EXTERN GetExitCodeProcess:PROC
EXTERN CloseHandle:PROC
EXTERN ExitProcess:PROC

;=============================================================================
; Data section
;=============================================================================

.DATA

; Process names
szSovereign     DB 'Sovereign_Engine.exe', 0
szModel         DB 'model.gguf', 0
szCmdLine       DB 'Sovereign_Engine.exe model.gguf', 0

; STARTUPINFOA structure (104 bytes)
align 8
startup_info    DB 104 DUP(0)

; PROCESS_INFORMATION structure (24 bytes)
align 8
proc_info       DB 24 DUP(0)

; Error messages
err_create      DB 'Failed to create Sovereign process', 13, 10, 0
err_wait        DB 'Wait failed', 13, 10, 0
msg_success     DB 'Sovereign completed successfully', 13, 10, 0

;=============================================================================
; Code section
;=============================================================================

.CODE

;=============================================================================
; Entry point
;=============================================================================

Start PROC
    push rbp
    mov rbp, rsp
    sub rsp, 88                     ; 32 shadow + 40 params + 8 local + alignment

    ; Debug: test PrintString
    lea rcx, err_create
    call PrintString

    ; Initialize STARTUPINFOA
    ; Set cb = sizeof(STARTUPINFOA) = 104
    mov DWORD PTR [startup_info], 104
    
    ; Create process
    ; CreateProcessA(
    ;   lpApplicationName = "Sovereign_Engine.exe",
    ;   lpCommandLine = "Sovereign_Engine.exe model.gguf",
    ;   lpProcessAttributes = NULL,
    ;   lpThreadAttributes = NULL,
    ;   bInheritHandles = FALSE,
    ;   dwCreationFlags = 0,
    ;   lpEnvironment = NULL,
    ;   lpCurrentDirectory = NULL,
    ;   lpStartupInfo = &startup_info,
    ;   lpProcessInformation = &proc_info
    ; )
    
    ; Set up stack parameters (right to left, at [rsp+32] after shadow)
    mov QWORD PTR [rsp+80], 0       ; alignment
    lea rax, proc_info
    mov QWORD PTR [rsp+72], rax     ; lpProcessInformation
    lea rax, startup_info
    mov QWORD PTR [rsp+64], rax     ; lpStartupInfo
    mov QWORD PTR [rsp+56], 0       ; lpCurrentDirectory
    mov QWORD PTR [rsp+48], 0       ; lpEnvironment
    
    ; Set up registers
    xor r8, r8                      ; lpProcessAttributes = NULL
    xor r9, r9                      ; lpThreadAttributes = NULL
    lea rcx, szSovereign            ; lpApplicationName
    lea rdx, szCmdLine              ; lpCommandLine
    
    ; 5th and 6th parameters go in stack (bInheritHandles, dwCreationFlags)
    mov QWORD PTR [rsp+40], 0       ; bInheritHandles = FALSE
    mov QWORD PTR [rsp+32], 0       ; dwCreationFlags = 0
    
    call CreateProcessA
    
    ; Debug: print RAX value
    push rax
    lea rcx, err_create
    call PrintString
    pop rax
    
    test rax, rax
    jz create_failed
    
    ; Wait for process to complete
    ; WaitForSingleObject(hProcess, INFINITE)
    mov rcx, QWORD PTR [proc_info]  ; hProcess
    mov rdx, 0FFFFFFFFh             ; INFINITE = -1
    call WaitForSingleObject
    
    cmp rax, 0                      ; WAIT_OBJECT_0 = 0
    jne wait_failed
    
    ; Get exit code
    ; GetExitCodeProcess(hProcess, &exitCode)
    mov rcx, QWORD PTR [proc_info]  ; hProcess
    lea rdx, [rsp+24]               ; &exitCode (local var)
    call GetExitCodeProcess
    
    ; Close handles
    mov rcx, QWORD PTR [proc_info]  ; hProcess
    call CloseHandle
    mov rcx, QWORD PTR [proc_info+8]; hThread
    call CloseHandle
    
    ; Print success message
    lea rcx, msg_success
    call PrintString
    
    ; Exit with child's exit code
    mov rcx, QWORD PTR [rsp+24]
    call ExitProcess

create_failed:
    lea rcx, err_create
    call PrintString
    mov rcx, 1
    call ExitProcess
    
wait_failed:
    lea rcx, err_wait
    call PrintString
    mov rcx, 1
    call ExitProcess

Start ENDP

;=============================================================================
; Print null-terminated string to stdout
; Uses WriteFile via stdout handle
;=============================================================================

PrintString PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    
    mov rsi, rcx                    ; string pointer
    
    ; Calculate string length
    mov rdi, rsi
    xor rcx, rcx
    dec rcx
    xor al, al
    repne scasb
    not rcx
    dec rcx                         ; RCX = length
    mov rbx, rcx                    ; Save length in RBX
    
    ; Get stdout handle (-11 = STD_OUTPUT_HANDLE)
    mov rcx, 0FFFFFFF5h
    call GetStdHandle
    
    ; WriteFile(stdout, buffer, length, &written, NULL)
    mov r8, rbx                     ; length (from RBX)
    mov rcx, rax                    ; handle
    mov rdx, rsi                    ; buffer
    lea r9, [rsp+32]                ; &written
    mov QWORD PTR [rsp+32], 0       ; overlapped = NULL
    sub rsp, 32
    call WriteFile
    add rsp, 32
    
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
PrintString ENDP

;=============================================================================
; GetStdHandle and WriteFile are imported from kernel32.dll
;=============================================================================

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

;=============================================================================
; End
;=============================================================================

END
