;==============================================================================
; process_manager.asm - Pure MASM64 Process Management & Terminal Redirection
; ==========================================================================
; Handles execution of external tools (Git, Ollama, Shell) with pipe redirection.
; Zero C++ runtime dependencies.
;==============================================================================

.686p
.xmm
.model flat, c
option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==============================================================================
; STRUCTURES
;==============================================================================
PROCESS_INFO_EX STRUCT
    hProcess            QWORD ?
    hThread             QWORD ?
    hStdInWrite         QWORD ?
    hStdOutRead         QWORD ?
    hStdErrRead         QWORD ?
    dwProcessId         DWORD ?
    dwThreadId          DWORD ?
PROCESS_INFO_EX ENDS

;==============================================================================
; DATA SEGMENT
;==============================================================================
.data
    szCmdExe            BYTE "cmd.exe",0
    szGitExe            BYTE "git.exe",0
    szOllamaExe         BYTE "ollama.exe",0
    
    pipe_sa             SECURITY_ATTRIBUTES <sizeof SECURITY_ATTRIBUTES, 0, TRUE>

.code

;==============================================================================
; CreateRedirectedProcess - Starts a process with redirected I/O pipes
;==============================================================================
CreateRedirectedProcess PROC uses rbx rsi rdi lpCommandLine:QWORD, pInfo:PTR PROCESS_INFO_EX
    LOCAL si:STARTUPINFO
    LOCAL pi:PROCESS_INFORMATION
    LOCAL hStdInRead:QWORD
    LOCAL hStdOutWrite:QWORD
    LOCAL hStdErrWrite:QWORD
    
    ; 1. Create Pipes for StdOut
    invoke CreatePipe, addr [pInfo].hStdOutRead, addr hStdOutWrite, addr pipe_sa, 0
    .if rax == 0
        ret
    .endif
    invoke SetHandleInformation, [pInfo].hStdOutRead, HANDLE_FLAG_INHERIT, 0
    
    ; 2. Create Pipes for StdIn
    invoke CreatePipe, addr hStdInRead, addr [pInfo].hStdInWrite, addr pipe_sa, 0
    .if rax == 0
        invoke CloseHandle, [pInfo].hStdOutRead
        invoke CloseHandle, hStdOutWrite
        ret
    .endif
    invoke SetHandleInformation, [pInfo].hStdInWrite, HANDLE_FLAG_INHERIT, 0
    
    ; 3. Duplicate StdOut for StdErr (or create separate)
    invoke DuplicateHandle, GetCurrentProcess(), hStdOutWrite, GetCurrentProcess(), addr hStdErrWrite, 0, TRUE, DUPLICATE_SAME_ACCESS
    
    ; 4. Initialize StartupInfo
    invoke RtlZeroMemory, addr si, sizeof STARTUPINFO
    mov si.cb, sizeof STARTUPINFO
    mov si.dwFlags, STARTF_USESTDHANDLES OR STARTF_USESHOWWINDOW
    mov si.wShowWindow, SW_HIDE
    
    mov rax, hStdInRead
    mov si.hStdInput, rax
    mov rax, hStdOutWrite
    mov si.hStdOutput, rax
    mov rax, hStdErrWrite
    mov si.hStdError, rax
    
    ; 5. Create the Process
    invoke CreateProcessA, NULL, lpCommandLine, NULL, NULL, TRUE, \
           CREATE_NEW_CONSOLE, NULL, NULL, addr si, addr pi
           
    .if rax != 0
        ; Success - Store info
        mov rax, pi.hProcess
        mov [pInfo].hProcess, rax
        mov rax, pi.hThread
        mov [pInfo].hThread, rax
        mov eax, pi.dwProcessId
        mov [pInfo].dwProcessId, eax
        mov eax, pi.dwThreadId
        mov [pInfo].dwThreadId, eax
        
        ; Close handles we don't need (child has them now)
        invoke CloseHandle, hStdInRead
        invoke CloseHandle, hStdOutWrite
        invoke CloseHandle, hStdErrWrite
        
        mov rax, TRUE
    .else
        ; Failure - Cleanup
        invoke CloseHandle, [pInfo].hStdOutRead
        invoke CloseHandle, hStdOutWrite
        invoke CloseHandle, hStdInRead
        invoke CloseHandle, [pInfo].hStdInWrite
        invoke CloseHandle, hStdErrWrite
        xor rax, rax
    .endif
    
    ret
CreateRedirectedProcess ENDP

;==============================================================================
; ReadProcessOutput - Reads from the process's stdout pipe
;==============================================================================
ReadProcessOutput PROC uses rbx rsi rdi hPipe:QWORD, pBuffer:QWORD, dwBufferSize:DWORD
    LOCAL dwRead:DWORD
    
    invoke ReadFile, hPipe, pBuffer, dwBufferSize, addr dwRead, NULL
    .if rax != 0
        mov eax, dwRead
    .else
        mov eax, -1 ; Error or pipe closed
    .endif
    
    ret
ReadProcessOutput ENDP

;==============================================================================
; WriteProcessInput - Writes to the process's stdin pipe
;==============================================================================
WriteProcessInput PROC uses rbx rsi rdi hPipe:QWORD, pBuffer:QWORD, dwLength:DWORD
    LOCAL dwWritten:DWORD
    
    invoke WriteFile, hPipe, pBuffer, dwLength, addr dwWritten, NULL
    .if rax != 0
        mov eax, dwWritten
    .else
        mov eax, -1
    .endif
    
    ret
WriteProcessInput ENDP

END
