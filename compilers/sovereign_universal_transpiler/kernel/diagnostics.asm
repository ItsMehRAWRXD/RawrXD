; diagnostics.asm - Error reporting for Sovereign Universal Transpiler

.data
    error_count     dd 0
    warning_count   dd 0
    last_error_line dd 0
    last_error_col  dd 0
    
    msg_prefix  db "ERROR: ", 0
    msg_warn    db "WARNING: ", 0
    msg_line    db " line ", 0
    msg_col     db " col ", 0
    msg_newline db 13, 10, 0

.code

; CompilerError - Report a compiler error
; RCX = error message pointer
; RDX = line number
; R8  = column number
CompilerError PROC
    inc dword ptr [error_count]
    mov [last_error_line], edx
    mov [last_error_col], r8d
    ; In production: write to stderr with line/col info
    ret
CompilerError ENDP

; CompilerWarning - Report a compiler warning
; RCX = warning message
; RDX = line
; R8  = column
CompilerWarning PROC
    inc dword ptr [warning_count]
    ret
CompilerWarning ENDP

; PrintDiagnostic - Print diagnostic to console
; RCX = message
PrintDiagnostic PROC
    ; In production: use WriteFile to stderr
    ret
PrintDiagnostic ENDP

; GetErrorCount - Returns number of errors
GetErrorCount PROC
    mov eax, [error_count]
    ret
GetErrorCount ENDP

end