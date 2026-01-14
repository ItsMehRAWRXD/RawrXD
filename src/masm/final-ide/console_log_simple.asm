; console_log_simple.asm - Simple console logging for MASM64
; Minimal implementation to support orchestration stubs

option casemap:none

.code

; External functions we need
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN lstrlenA:PROC

; Simple console output function
.data?
hStdOut QWORD ?
bytesWritten DWORD ?

.code

; console_log(msg: LPCSTR)
; Simple console logging function
PUBLIC console_log
console_log PROC
    push rbx
    sub rsp, 32
    
    mov rbx, rcx    ; Save message pointer
    
    ; Get stdout handle if not already cached
    cmp [hStdOut], 0
    jne write_message
    
    mov rcx, -11  ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOut], rax
    
write_message:
    ; Get message length
    mov rcx, rbx
    call lstrlenA
    mov r8, rax     ; length in r8
    
    ; Write message to console
    mov rcx, [hStdOut]      ; handle
    mov rdx, rbx            ; message pointer
    lea r9, [bytesWritten]  ; bytes written
    mov QWORD PTR [rsp + 32], 0  ; no overlap
    call WriteFile
    
    ; Add newline
    mov rcx, [hStdOut]
    lea rdx, newline
    mov r8, 2               ; length of newline (CRLF)
    lea r9, [bytesWritten]  ; bytes written
    mov QWORD PTR [rsp + 32], 0
    call WriteFile
    
    add rsp, 32
    pop rbx
    ret
console_log ENDP

.data
newline BYTE 13, 10

.code

END





