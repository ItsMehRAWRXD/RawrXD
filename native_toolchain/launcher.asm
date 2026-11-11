;=============================================================================
; launcher.asm - Runtime-First Launcher
; Pure x64 MASM - launches Sovereign_Engine.exe as child process
; Assemble: ml64 /c /W3 /nologo /Fo launcher.obj launcher.asm
; Link: rawrxd_native_linker.exe launcher.obj /out:launcher.exe
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
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

;=============================================================================
; Data section
;=============================================================================

.DATA
szSovereign     DB 'Sovereign_Engine.exe', 0
szModel         DB 'model.gguf', 0
szCmdLine       DB 'Sovereign_Engine.exe model.gguf', 0

; STARTUPINFOA structure (104 bytes)
startup_info    DB 104 DUP(0)
si_size         EQU $ - startup_info

; PROCESS_INFORMATION structure (24 bytes)
proc_info       DB 24 DUP(0)
pi_size         EQU $ - proc_info

; Error messages
err_create      DB 'Failed to create process', 13, 10, 0
err_wait        DB 'Wait failed', 13, 10, 0

;=============================================================================
; Code section
;=============================================================================

.CODE

;=============================================================================
; Entry point
;=============================================================================

Start PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64

    ; Initialize STARTUPINFO
    lea     rdi, startup_info
    xor     eax, eax
    mov     ecx, si_size
    rep     stosb

    ; Set STARTUPINFO.cb = sizeof(STARTUPINFOA)
    mov     DWORD PTR [startup_info], si_size

    ; Create process: Sovereign_Engine.exe model.gguf
    lea     rcx, szSovereign           ; lpApplicationName
    lea     rdx, szCmdLine              ; lpCommandLine
    xor     r8, r8                      ; lpProcessAttributes = NULL
    xor     r9, r9                      ; lpThreadAttributes = NULL
    push    0                           ; bInheritHandles = FALSE
    push    0                           ; dwCreationFlags = 0
    push    0                           ; lpEnvironment = NULL
    push    0                           ; lpCurrentDirectory = NULL
    lea     rax, startup_info
    push    rax                         ; lpStartupInfo
    lea     rax, proc_info
    push    rax                         ; lpProcessInformation
    sub     rsp, 32                     ; shadow space
    call    CreateProcessA
    add     rsp, 32 + 48                ; clean up shadow + 6 pushes
    test    rax, rax
    jz      create_failed

    ; Wait for process to finish
    mov     rcx, QWORD PTR [proc_info]         ; hProcess
    mov     rdx, -1                     ; INFINITE
    call    WaitForSingleObject
    cmp     rax, 0                      ; WAIT_OBJECT_0 = 0
    jne     wait_failed

    ; Get exit code
    mov     rcx, QWORD PTR [proc_info]         ; hProcess
    lea     rdx, [rsp + 32]             ; lpExitCode
    call    GetExitCodeProcess

    ; Close handles
    mov     rcx, QWORD PTR [proc_info]         ; hProcess
    call    CloseHandle
    mov     rcx, QWORD PTR [proc_info + 8]     ; hThread
    call    CloseHandle

    ; Exit with child's exit code
    mov     rcx, QWORD PTR [rsp + 32]
    call    ExitProcess

create_failed:
    lea     rcx, err_create
    call    PrintError
    mov     rcx, 1
    call    ExitProcess

wait_failed:
    lea     rcx, err_wait
    call    PrintError
    mov     rcx, 1
    call    ExitProcess

Start ENDP

;=============================================================================
; Print error string (uses WriteFile via import)
;=============================================================================

PrintError PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48

    ; Save string pointer
    mov     [rsp + 32], rcx

    ; Get stdout handle
    mov     rcx, -11                    ; STD_OUTPUT_HANDLE
    call    GetStdHandle
    test    rax, rax
    jz      print_done

    ; Calculate string length
    mov     rdi, [rsp + 32]             ; string
    xor     rcx, rcx
    dec     rcx
    xor     al, al
    repne   scasb
    not     rcx
    dec     rcx                         ; length in RCX

    ; Write string
    mov     r8, rcx                     ; length
    mov     rdx, [rsp + 32]             ; string
    lea     r9, [rsp + 40]              ; bytes written
    mov     QWORD PTR [rsp + 48], 0     ; overlapped
    call    WriteFile

print_done:
    mov     rsp, rbp
    pop     rbp
    ret
PrintError ENDP

;=============================================================================
; End
;=============================================================================

END Start
 
