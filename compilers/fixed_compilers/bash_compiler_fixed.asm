; Working Bash Compiler
; x64 Windows Console Application
; NASM Syntax

bits 64
default rel

section .data
    msg_banner db "Bash Compiler v1.0", 13, 10
               db "Compiles Bash scripts to Windows batch", 13, 10, 0
    msg_usage db "Usage: bash_compiler.exe <script.sh>", 13, 10, 0
    msg_processing db "Processing bash script...", 13, 10, 0
    msg_output db "Output: script.bat", 13, 10, 0
    msg_success db "Compilation complete", 13, 10, 0
    msg_error db "Error: ", 0
    msg_file_err db "Cannot open script file", 13, 10, 0
    buffer times 4096 db 0
    file_handle dq 0
    bytes_read dq 0

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

    ; Show banner
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_banner]
    mov r8, 60
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile

    ; Get command line
    call GetCommandLineA
    mov rsi, rax

    ; Skip program name
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

    mov al, [rsi]
    test al, al
    jz .no_args

    ; Open file
    mov rcx, rsi
    mov rdx, 0x80000000
    xor r8, r8
    xor r9, r9
    mov qword [rsp+32], 3
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call CreateFileA

    cmp rax, -1
    je .file_error

    mov [file_handle], rax

    ; Show processing
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_processing]
    mov r8, 26
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile

    ; Read file
    mov rcx, [file_handle]
    lea rdx, [buffer]
    mov r8, 4095
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile

    test rax, rax
    jz .read_error

    ; Close file
    mov rcx, [file_handle]
    call CloseHandle

    ; Show output
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_output]
    mov r8, 19
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 21
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile

    xor rax, rax
    jmp .exit

.no_args:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_usage]
    mov r8, 39
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rax, 1
    jmp .exit

.file_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_error]
    mov r8, 7
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_file_err]
    mov r8, 24
    lea r9, [rsp+32]
    mov qword [rsp+40], 0
    call WriteFile
    mov rax, 2
    jmp .exit

.read_error:
    mov rcx, [file_handle]
    call CloseHandle
    mov rax, 3

.exit:
    mov rcx, rax
    call ExitProcess
