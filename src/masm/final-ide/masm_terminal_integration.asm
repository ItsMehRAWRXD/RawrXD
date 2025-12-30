; ============================================================================
; FILE: masm_terminal_integration.asm
; TITLE: MASM Terminal Integration System
; PURPOSE: Full command-line support with shell integration
; LINES: 600+ (Complete terminal system)
; ============================================================================

option casemap:none

include windows.inc

includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib
includelib shell32.lib

; ============================================================================
; EXTERNAL DECLARATIONS - Windows API
; ============================================================================
extern CreatePipe:proc
extern SetHandleInformation:proc
extern GetCurrentDirectoryA:proc
extern InvalidateRect:proc
extern Sleep:proc
extern PeekNamedPipe:proc

; ============================================================================
; CONSTANTS AND STRUCTURES
; ============================================================================

; Terminal buffer size
TERMINAL_BUFFER_SIZE = 4096
TERMINAL_MAX_LINES = 1000

; Terminal colors
TERMINAL_COLOR_BLACK = 0
TERMINAL_COLOR_WHITE = 00FFFFFFh
TERMINAL_COLOR_GREEN = 00008000h
TERMINAL_COLOR_RED = 000000FFh
TERMINAL_COLOR_BLUE = 00FF0000h
TERMINAL_COLOR_YELLOW = 0000FFFFh

; Terminal state structure
TERMINAL_STATE STRUCT
    hTerminal QWORD ?           ; Terminal window handle
    hProcess QWORD ?            ; Child process handle
    hStdInWrite QWORD ?         ; STDIN write handle
    hStdOutRead QWORD ?         ; STDOUT read handle
    hStdErrRead QWORD ?         ; STDERR read handle
    
    buffer BYTE TERMINAL_BUFFER_SIZE DUP(?)
    bufferPos DWORD ?
    
    lines QWORD TERMINAL_MAX_LINES DUP(?) ; Array of line pointers
    lineCount DWORD ?
    
    currentDir BYTE 260 DUP(?)
    prompt BYTE 100 DUP(?)
    
    isRunning BYTE ?
TERMINAL_STATE ENDS

; ============================================================================
; GLOBAL VARIABLES
; ============================================================================

.data

; Global terminal state
globalTerminal TERMINAL_STATE {}

; Shell commands
szCmdExe db "cmd.exe",0
szPowershell db "powershell.exe",0
szBash db "bash.exe",0

; Prompt strings
szPrompt db "> ",0
szPwshPrompt db "PS> ",0
szBashPrompt db "$ ",0

; ============================================================================
; PUBLIC API FUNCTIONS
; ============================================================================

.code

; terminal_init(hTerminalWindow: rcx) -> bool (rax)
; Initialize terminal system
PUBLIC terminal_init
terminal_init PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 64
    
    mov [globalTerminal.hTerminal], rcx
    
    ; Get current directory
    lea rcx, [globalTerminal.currentDir]
    mov rdx, 260
    call GetCurrentDirectoryA
    
    ; Setup default prompt
    lea rcx, [globalTerminal.prompt]
    lea rdx, szPrompt
    call strcpy
    
    ; Initialize buffer
    mov [globalTerminal.bufferPos], 0
    mov [globalTerminal.lineCount], 0
    mov [globalTerminal.isRunning], 0
    
    mov eax, 1
    leave
    ret
terminal_init ENDP

; terminal_start_shell(shellType: rcx) -> bool (rax)
; Start shell process
PUBLIC terminal_start_shell
terminal_start_shell PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 128
    
    ; Check if already running
    cmp [globalTerminal.isRunning], 0
    jne already_running
    
    ; Create pipes for STDIN, STDOUT, STDERR
    LOCAL hStdInRead:QWORD, hStdInWrite:QWORD
    LOCAL hStdOutRead:QWORD, hStdOutWrite:QWORD
    LOCAL hStdErrRead:QWORD, hStdErrWrite:QWORD
    LOCAL sa:SECURITY_ATTRIBUTES
    
    mov sa.nLength, sizeof SECURITY_ATTRIBUTES
    mov sa.lpSecurityDescriptor, 0
    mov sa.bInheritHandle, TRUE
    
    ; Create STDIN pipe
    lea rcx, hStdInRead
    lea rdx, hStdInWrite
    lea r8, sa
    mov r9, 0
    call CreatePipe
    test rax, rax
    jz pipe_failed
    
    ; Ensure the write handle to the pipe for STDIN is not inherited
    mov rcx, hStdInWrite
    mov rdx, HANDLE_FLAG_INHERIT
    mov r8, 0
    call SetHandleInformation
    
    ; Create STDOUT pipe
    lea rcx, hStdOutRead
    lea rdx, hStdOutWrite
    lea r8, sa
    mov r9, 0
    call CreatePipe
    test rax, rax
    jz pipe_failed
    
    ; Ensure the read handle to the pipe for STDOUT is not inherited
    mov rcx, hStdOutRead
    mov rdx, HANDLE_FLAG_INHERIT
    mov r8, 0
    call SetHandleInformation
    
    ; Create STDERR pipe
    lea rcx, hStdErrRead
    lea rdx, hStdErrWrite
    lea r8, sa
    mov r9, 0
    call CreatePipe
    test rax, rax
    jz pipe_failed
    
    ; Setup process startup info
    LOCAL si:STARTUPINFOA
    LOCAL pi:PROCESS_INFORMATION
    
    lea rdi, si
    mov rcx, sizeof STARTUPINFOA
    xor rax, rax
    rep stosb
    
    mov si.cb, sizeof STARTUPINFOA
    mov si.dwFlags, STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
    mov wptr [si.wShowWindow], SW_HIDE
    mov rax, hStdInRead
    mov si.hStdInput, rax
    mov rax, hStdOutWrite
    mov si.hStdOutput, rax
    mov rax, hStdErrWrite
    mov si.hStdError, rax
    
    ; Determine shell executable
    mov rdx, offset szCmdExe
    cmp ecx, 1
    je start_powershell
    cmp ecx, 2
    je start_bash
    jmp create_process
    
start_powershell:
    mov rdx, offset szPowershell
    jmp create_process
    
start_bash:
    mov rdx, offset szBash
    
create_process:
    ; Create process
    mov rcx, 0          ; lpApplicationName
    ; rdx already has lpCommandLine
    xor r8, r8          ; lpProcessAttributes
    xor r9, r9          ; lpThreadAttributes
    push 0              ; lpProcessInformation (pi)
    lea rax, pi
    mov [rsp], rax
    push 0              ; lpStartupInfo (si)
    lea rax, si
    mov [rsp], rax
    push 0              ; lpCurrentDirectory
    push 0              ; lpEnvironment
    push CREATE_NO_WINDOW ; dwCreationFlags
    push TRUE           ; bInheritHandles
    sub rsp, 32         ; shadow space
    call CreateProcessA
    add rsp, 32 + 48
    
    test rax, rax
    jz process_failed
    
    ; Store handles
    mov rax, pi.hProcess
    mov [globalTerminal.hProcess], rax
    mov rax, hStdInWrite
    mov [globalTerminal.hStdInWrite], rax
    mov rax, hStdOutRead
    mov [globalTerminal.hStdOutRead], rax
    mov rax, hStdErrRead
    mov [globalTerminal.hStdErrRead], rax
    
    mov [globalTerminal.isRunning], 1
    
    ; Close unused handles
    mov rcx, hStdInRead
    call CloseHandle
    mov rcx, hStdOutWrite
    call CloseHandle
    mov rcx, hStdErrWrite
    call CloseHandle
    mov rcx, pi.hThread
    call CloseHandle
    
    ; Start background reader thread
    xor rcx, rcx
    xor rdx, rdx
    lea r8, terminal_reader_thread
    xor r9, r9
    push 0

    push 0
    sub rsp, 32
    call CreateThread
    add rsp, 32 + 16
    
    mov eax, 1
    jmp done
    
pipe_failed:
process_failed:
    ; Cleanup on failure
    mov rcx, hStdInRead
    call CloseHandle
    mov rcx, hStdInWrite
    call CloseHandle
    mov rcx, hStdOutRead
    call CloseHandle
    mov rcx, hStdOutWrite
    call CloseHandle
    mov rcx, hStdErrRead
    call CloseHandle
    mov rcx, hStdErrWrite
    call CloseHandle
    
    xor eax, eax
    jmp done
    
already_running:
    mov eax, 1
    
done:
    leave
    ret
terminal_start_shell ENDP

; terminal_reader_thread(param: rcx)
; Background thread to read from terminal pipe
terminal_reader_thread PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 1024 + 64
    
@read_loop:
    cmp [globalTerminal.isRunning], 0
    je @thread_exit
    
    lea rcx, [rbp - 1024] ; buffer
    mov rdx, 1024
    call terminal_read_output
    
    test rax, rax
    jz @sleep_and_retry
    
    ; Add to buffer and update display
    mov rcx, rax
    lea rdx, [rbp - 1024]
    call terminal_add_to_buffer
    
    ; Trigger redraw
    mov rcx, [globalTerminal.hTerminal]
    call InvalidateRect
    
    jmp @read_loop
    
@sleep_and_retry:
    mov rcx, 50
    call Sleep
    jmp @read_loop
    
@thread_exit:
    xor eax, eax
    leave
    ret
terminal_reader_thread ENDP

; terminal_execute_command(command: rcx) -> bool (rax)
; Execute command in terminal
PUBLIC terminal_execute_command
terminal_execute_command PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 64
    
    ; Check if terminal is running
    cmp [globalTerminal.isRunning], 0
    je not_running
    
    ; Write command to STDIN
    mov rdx, rcx
    call strlen
    mov r8, rax        ; Command length
    
    LOCAL bytesWritten:DWORD
    lea r9, bytesWritten
    
    mov rcx, [globalTerminal.hStdInWrite]
    call WriteFile
    
    ; Add newline
    mov rcx, [globalTerminal.hStdInWrite]
    mov rdx, offset newline
    mov r8, 2
    lea r9, bytesWritten
    call WriteFile
    
    mov eax, 1
    jmp done
    
not_running:
    xor eax, eax
    
done:
    leave
    ret
terminal_execute_command ENDP

; terminal_read_output(buffer: rcx, maxLen: rdx) -> bytesRead (rax)
; Read output from terminal (non-blocking)
PUBLIC terminal_read_output
terminal_read_output PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 64
    push rbx

    push rsi
    push mov rbx, rcx        ; Buffer
    mov rsi, rdx        ; Max length

    ; Ensure shell is running
    cmp [globalTerminal.isRunning], 0
    je no_output

    ; Peek available bytes
    LOCAL bytesAvailable:DWORD
    mov rcx, [globalTerminal.hStdOutRead]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    lea r10, bytesAvailable
    xor r11, r11
    push r11

    push r10
    push call PeekNamedPipe
    add rsp, 16

    test rax, rax
    jz no_output

    cmp bytesAvailable, 0
    je no_output

    ; Read available data
    mov rcx, [globalTerminal.hStdOutRead]
    mov rdx, rbx
    mov r8, rsi
    cmp r8d, bytesAvailable
    jbe do_read
    mov r8d, bytesAvailable

do_read:
    LOCAL bytesRead:DWORD
    lea r9, bytesRead
    push 0
    push call
    push ReadFile
    push add rsp, 8

    test rax, rax
    jz no_output

    mov eax, bytesRead
    jmp done

no_output:
    xor eax, eax

done:

    pop rsi leave
    ret
    pop rbx
terminal_read_output ENDP

; terminal_update_display() -> bool (rax)
; Update terminal display with new output
PUBLIC terminal_update_display
terminal_update_display PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 64

    ; Read available output
    lea rcx, outputBuffer
    mov rdx, 1024
    call terminal_read_output

    test rax, rax
    jz no_update

    ; Append new data and refresh UI
    mov rcx, rax
    lea rdx, outputBuffer
    call terminal_add_to_buffer

    mov rcx, [globalTerminal.hTerminal]
    call InvalidateRect
    call terminal_redraw

    mov eax, 1
    jmp done

no_update:
    xor eax, eax

done:
    leave
    ret
terminal_update_display ENDP

; terminal_add_to_buffer(length: rcx, data: rdx)
; Add buffered output and update line cache
PUBLIC terminal_add_to_buffer
terminal_add_to_buffer PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 32

    mov r8, rcx
    mov r9, rdx
    mov r10, [globalTerminal.bufferPos]

    lea rdi, [globalTerminal.buffer]
    add rdi, r10

    mov rax, r10
    add rax, r8
    cmp rax, TERMINAL_BUFFER_SIZE
    jl append_ok

    xor r10, r10
    lea rdi, [globalTerminal.buffer]

append_ok:
    mov rsi, r9
    mov rcx, r8
    rep movsb

    mov rax, r10
    add rax, r8
    mov [globalTerminal.bufferPos], rax

    call terminal_process_lines

    mov eax, 1
    leave
    ret
terminal_add_to_buffer ENDP

; terminal_process_lines()
; Build index of newline-terminated strings
terminal_process_lines PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 64
    push rbx

    push rsi
    push rdi

    mov [globalTerminal.lineCount], 0
    xor rbx, rbx
    mov rsi, [globalTerminal.bufferPos]

line_loop:
    cmp rbx, rsi
    jae lines_done

    mov eax, [globalTerminal.lineCount]
    cmp eax, TERMINAL_MAX_LINES
    jae lines_done

    lea r11, [globalTerminal.buffer]
    add r11, rbx
    
    mov r10d, [globalTerminal.lineCount]
    lea r9, [globalTerminal.lines]
    mov [r9 + r10 * 8], r11
    inc [globalTerminal.lineCount]

find_newline:
    cmp rbx, [globalTerminal.bufferPos]
    jae lines_done

    mov dl, [globalTerminal.buffer + rbx]
    inc rbx
    cmp dl, 0Ah
    jne find_newline
    jmp line_loop

lines_done:

    pop rsi pop rdi


    pop leave rbx
    ret
terminal_process_lines ENDP
    
; terminal_redraw(hTerminal: rcx)
; Redraw terminal display using GDI
PUBLIC terminal_redraw
terminal_redraw PROC
    push rbp
    push mov rbp, rsp
    sub rsp, 128
    push rbx

    push rsi
    push rdi

    mov rbx, rcx        ; hWnd
    
    LOCAL ps:PAINTSTRUCT
    lea rdx, ps
    call BeginPaint
    mov rsi, rax        ; hdc
    
    ; Set colors
    mov rcx, rsi
    mov rdx, 00FFFFFFh  ; White text
    call SetTextColor
    
    mov rcx, rsi
    mov rdx, 00000000h  ; Black background
    call SetBkColor
    
    ; Draw lines
    xor rdi, rdi        ; line index
draw_loop:
    mov eax, [globalTerminal.lineCount]
    cmp edi, eax
    jae draw_done
    
    lea r9, [globalTerminal.lines]
    mov r9, [r9 + rdi * 8]
    xor r10, r10
@find_len:
    mov al, [r9 + r10]
    test al, al
    jz @len_found
    cmp al, 0Ah
    je @len_found
    inc r10
    jmp @find_len
@len_found:
    
    mov rcx, rsi
    mov rdx, 10
    mov rax, rdi
    imul rax, 16
    add rax, 10
    mov r8, rax
    ; r9 is already lpString
    mov [rsp + 32], r10 ; cbString
    call TextOutA
    
    inc edi
    jmp draw_loop

draw_done:
    lea rdx, ps
    mov rcx, rbx
    call EndPaint

    pop rsi pop rdi


    pop leave rbx
    ret
terminal_redraw ENDP

; ============================================================================
; UTILITY FUNCTIONS
; ============================================================================

; strlen(string: rcx) -> length (rax)
strlen PROC
    push rbp
    push mov rbp, rsp
    
    mov rax, rcx
    xor rcx, rcx
    
strlen_loop:
    cmp byte ptr [rax], 0
    je strlen_done
    inc rax
    inc rcx
    jmp strlen_loop
    
strlen_done:
    mov rax, rcx
    
    leave
    ret
strlen ENDP

; strcpy(dest: rcx, src: rdx)
strcpy PROC
    push rbp
    push mov rbp, rsp
    
    mov rdi, rcx
    mov rsi, rdx
    
strcpy_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz strcpy_done
    inc rsi
    inc rdi
    jmp strcpy_loop
    
strcpy_done:
    leave
    ret
strcpy ENDP

.data
newline db 0Dh, 0Ah, 0
outputBuffer BYTE 1024 DUP(?)

end




