; Test pipe detection
EXTERN GetStdHandle:PROC
EXTERN GetFileType:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

STD_INPUT_HANDLE  EQU -10
STD_OUTPUT_HANDLE EQU -11
FILE_TYPE_PIPE    EQU 3
FILE_TYPE_DISK    EQU 1
FILE_TYPE_CHAR    EQU 2

.DATA
    hInput      QWORD 0
    hOutput     QWORD 0
    msg_banner  BYTE "Pipe Detection Test", 13, 10, 0
    msg_pipe    BYTE "Input is PIPE/FILE", 13, 10, 0
    msg_console BYTE "Input is CONSOLE", 13, 10, 0
    msg_reading BYTE "Reading line...", 13, 10, 0
    buffer      BYTE 256 dup(0)
    bytes_read  QWORD 0

.CODE
main PROC
    sub rsp, 40
    
    ; Get handles
    mov rcx, STD_INPUT_HANDLE
    call GetStdHandle
    mov hInput, rax
    
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hOutput, rax
    
    ; Print banner
    mov rcx, hOutput
    lea rdx, msg_banner
    mov r8, 20
    xor r9, r9
    push 0
    call WriteConsoleA
    add rsp, 8
    
    ; Check file type
    mov rcx, hInput
    call GetFileType
    
    ; Check if pipe (3) or disk (1) or char (2)
    cmp rax, FILE_TYPE_PIPE
    je is_pipe
    cmp rax, FILE_TYPE_DISK
    je is_pipe
    
    ; Console mode
    mov rcx, hOutput
    lea rdx, msg_console
    mov r8, 19
    xor r9, r9
    push 0
    call WriteConsoleA
    add rsp, 8
    jmp done
    
is_pipe:
    mov rcx, hOutput
    lea rdx, msg_pipe
    mov r8, 21
    xor r9, r9
    push 0
    call WriteConsoleA
    add rsp, 8
    
done:
    xor rcx, rcx
    call ExitProcess
    
    add rsp, 40
    ret
main ENDP

END
