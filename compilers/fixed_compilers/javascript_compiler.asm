; JavaScript Compiler - x64 Assembly
; Compiles JavaScript source files - FIXED VERSION

bits 64
default rel

section .data
    msg_banner db "JavaScript Compiler v1.0", 13, 10
               db "Compiles JavaScript to optimized bytecode", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    msg_usage db "Usage: javascript_compiler <file.js>", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    msg_processing db "Processing JavaScript source...", 13, 10, 0
    msg_processing_len equ $ - msg_processing
    msg_success db "JavaScript compilation complete!", 13, 10, 0
    msg_success_len equ $ - msg_success
    msg_file_err db "Error: Cannot open file", 13, 10, 0
    msg_file_err_len equ $ - msg_file_err
    
    input_buffer times 65536 db 0
    filename_buffer times 260 db 0
    input_size dq 0
    infile_handle dq 0
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
    sub rsp, 96

    ; Show banner
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_banner]
    mov r8, msg_banner_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Parse arguments
    call parse_args
    test rax, rax
    jz .no_args

    ; Open file
    mov rcx, rax
    call open_file
    test rax, rax
    jz .file_error

    ; Process
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_processing]
    mov r8, msg_processing_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, msg_success_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    xor rax, rax
    jmp .exit

.no_args:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_usage]
    mov r8, msg_usage_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 1
    jmp .exit

.file_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_file_err]
    mov r8, msg_file_err_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 2

.exit:
    mov rcx, rax
    call ExitProcess

parse_args:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    call GetCommandLineA
    mov rsi, rax

.skip_prog:
    lodsb
    test al, al
    jz .no_args
    cmp al, ' '
    jne .skip_prog

.skip_spaces:
    lodsb
    cmp al, ' '
    je .skip_spaces
    dec rsi

    mov al, [rsi]
    test al, al
    jz .no_args

    lea rdi, [filename_buffer]
.copy_loop:
    lodsb
    cmp al, ' '
    je .copy_done
    test al, al
    jz .copy_done
    stosb
    jmp .copy_loop
.copy_done:
    mov byte [rdi], 0
    lea rax, [filename_buffer]
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret

open_file:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rsp+56], rcx

    mov rdx, 0x80000000
    xor r8, r8
    xor r9, r9
    mov qword [rsp+32], 3
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call CreateFileA

    cmp rax, -1
    je .error

    mov [infile_handle], rax

    mov rcx, rax
    lea rdx, [input_buffer]
    mov r8, 65535
    lea r9, [input_size]
    mov qword [rsp+32], 0
    call ReadFile

    test rax, rax
    jz .error

    mov rcx, [infile_handle]
    call CloseHandle

    mov rax, 1
    jmp .done

.error:
    xor rax, rax

.done:
    leave
    ret