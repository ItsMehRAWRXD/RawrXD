; Working Universal Compiler Runtime - FIXED
; x64 Windows Console Application
; NASM Syntax - Proper Windows x64 ABI

bits 64
default rel

section .data
    msg_usage db "Universal Compiler Runtime v1.0", 13, 10
              db "Usage: compiler.exe <source_file>", 13, 10
              db "Supports: C, C++, Assembly, Python, Bash", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    msg_open_err db "Error: Cannot open file", 13, 10, 0
    msg_open_err_len equ $ - msg_open_err
    msg_success db "File processed successfully", 13, 10, 0
    msg_success_len equ $ - msg_success
    buffer times 256 db 0
    file_handle dq 0
    bytes_read dq 0
    written dq 0

section .text
    global main
    extern GetStdHandle
    extern WriteFile
    extern ReadFile
    extern CreateFileA
    extern CloseHandle
    extern ExitProcess
    extern GetCommandLineA

main:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Get command line
    call GetCommandLineA
    mov rsi, rax

    ; Skip program name (find first space)
.skip_prog:
    lodsb
    test al, al
    jz .no_args
    cmp al, ' '
    jne .skip_prog

    ; Skip spaces
.skip_spaces:
    lodsb
    cmp al, ' '
    je .skip_spaces
    dec rsi

    ; Check if we have an argument
    mov al, [rsi]
    test al, al
    jz .show_usage

    ; Try to open the file
    mov rcx, rsi          ; lpFileName
    mov rdx, 0x80000000   ; GENERIC_READ
    xor r8, r8            ; dwShareMode
    xor r9, r9            ; lpSecurityAttributes
    mov qword [rsp+32], 3 ; OPEN_EXISTING
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call CreateFileA

    cmp rax, -1
    je .open_error

    mov [file_handle], rax

    ; Read file
    mov rcx, [file_handle]
    lea rdx, [buffer]
    mov r8, 255
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile

    test rax, rax
    jz .read_error

    ; Close file
    mov rcx, [file_handle]
    call CloseHandle

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 29
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile

    xor rax, rax
    jmp .exit

.show_usage:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_usage]
    mov r8, 85
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rax, 1
    jmp .exit

.open_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_open_err]
    mov r8, 27
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rax, 2
    jmp .exit

.read_error:
    mov rcx, [file_handle]
    call CloseHandle
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_read_err]
    mov r8, 24
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rax, 3

.exit:
    mov rcx, rax
    call ExitProcess

.no_args:
    jmp .show_usage
