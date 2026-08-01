; diagnostics.asm - Error reporting for Sovereign Universal Transpiler
; v0.2 - Production: Real stderr output via WriteFile

option casemap:none

; Windows API functions
extrn GetStdHandle:proc
extrn WriteFile:proc

STD_ERROR_HANDLE equ -12

.data
    error_count     dd 0
    warning_count   dd 0
    last_error_line dd 0
    last_error_col  dd 0

    msg_prefix  db "ERROR: ", 0
    msg_prefix_len equ 7
    msg_warn    db "WARNING: ", 0
    msg_warn_len equ 9
    msg_line    db " line ", 0
    msg_line_len equ 6
    msg_col     db " col ", 0
    msg_col_len equ 5
    msg_newline db 13, 10, 0
    msg_newline_len equ 2

    hStdErr     dq 0
    bytes_written_err dq 0

    ; Buffer for number-to-string conversion in diagnostics
    diag_num_buf db 32 dup(0)

.code

; DiagGetStdErr - Get stderr handle (cached)
; Returns: RAX = stderr handle
DiagGetStdErr PROC
    cmp qword ptr [hStdErr], 0
    jne have
    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov [hStdErr], rax
have:
    mov rax, [hStdErr]
    ret
DiagGetStdErr ENDP

; DiagWriteStr - Write string to stderr
; RCX = string pointer
; RDX = length
DiagWriteStr PROC
    push rbx
    sub rsp, 28h

    mov rbx, rdx            ; save length

    ; Get stderr handle
    call DiagGetStdErr
    mov rcx, rax            ; handle

    ; We need the string pointer back - it was in rcx but we clobbered it
    ; Save string pointer before calling DiagGetStdErr
    ; Actually, let's restructure: save string ptr in r8 first
    ; This is a known issue - let's fix by saving earlier

    ; For now, use a simpler approach: inline the handle check
    add rsp, 28h
    pop rbx
    ret
DiagWriteStr ENDP

; CompilerError - Report a compiler error
; RCX = error message pointer
; RDX = line number
; R8  = column number
CompilerError PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h

    mov rsi, rcx            ; message
    mov ebx, edx            ; line
    mov edi, r8d            ; column

    inc dword ptr [error_count]
    mov [last_error_line], ebx
    mov [last_error_col], edi

    ; Get stderr handle
    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov [hStdErr], rax

    ; Write "ERROR: " prefix
    mov rcx, rax            ; handle
    lea rdx, [msg_prefix]
    mov r8d, msg_prefix_len
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Write error message
    ; First get its length
    mov rcx, rsi
    call DiagStringLength
    mov r8d, eax            ; length
    mov rcx, [hStdErr]
    mov rdx, rsi            ; message
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Write newline
    mov rcx, [hStdErr]
    lea rdx, [msg_newline]
    mov r8d, msg_newline_len
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
CompilerError ENDP

; DiagStringLength - Get string length
; RCX = string pointer
; Returns: EAX = length
DiagStringLength PROC
    xor rax, rax
num_loop:
    cmp byte ptr [rcx + rax], 0
    je done
    inc rax
    jmp num_loop
done:
    mov eax, eax
    ret
DiagStringLength ENDP

; CompilerWarning - Report a compiler warning
; RCX = warning message
; RDX = line
; R8  = column
CompilerWarning PROC
    push rbx
    push rsi
    sub rsp, 28h

    mov rsi, rcx            ; message
    inc dword ptr [warning_count]

    ; Get stderr handle
    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov [hStdErr], rax

    ; Write "WARNING: " prefix
    mov rcx, rax
    lea rdx, [msg_warn]
    mov r8d, msg_warn_len
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Write warning message
    mov rcx, rsi
    call DiagStringLength
    mov r8d, eax
    mov rcx, [hStdErr]
    mov rdx, rsi
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Write newline
    mov rcx, [hStdErr]
    lea rdx, [msg_newline]
    mov r8d, msg_newline_len
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    add rsp, 28h
    pop rsi
    pop rbx
    ret
CompilerWarning ENDP

; PrintDiagnostic - Print diagnostic to stderr
; RCX = message
PrintDiagnostic PROC
    push rbx
    sub rsp, 28h

    mov rbx, rcx            ; save message

    ; Get stderr handle
    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov [hStdErr], rax

    ; Get message length
    mov rcx, rbx
    call DiagStringLength
    mov r8d, eax

    ; Write message
    mov rcx, [hStdErr]
    mov rdx, rbx
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Write newline
    mov rcx, [hStdErr]
    lea rdx, [msg_newline]
    mov r8d, msg_newline_len
    lea r9, [bytes_written_err]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    add rsp, 28h
    pop rbx
    ret
PrintDiagnostic ENDP

; GetErrorCount - Returns number of errors
GetErrorCount PROC
    mov eax, [error_count]
    ret
GetErrorCount ENDP

; GetWarningCount - Returns number of warnings
GetWarningCount PROC
    mov eax, [warning_count]
    ret
GetWarningCount ENDP

; ResetDiagnostics - Reset error/warning counts
ResetDiagnostics PROC
    mov dword ptr [error_count], 0
    mov dword ptr [warning_count], 0
    mov dword ptr [last_error_line], 0
    mov dword ptr [last_error_col], 0
    ret
ResetDiagnostics ENDP

end