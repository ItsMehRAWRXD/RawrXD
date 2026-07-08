bits 64
default rel

section .data
    msg_banner db "RawrXD coffeescript Compiler v1.0", 13, 10
               db "Compiles coffeescript source", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    msg_usage db "Usage: coffeescript_compiler <file.coffee>", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    msg_open_err db "Error: Cannot open file", 13, 10, 0
    msg_open_err_len equ $ - msg_open_err
    msg_success db "coffeescript source processed successfully", 13, 10, 0
    msg_success_len equ $ - msg_success
    msg_parsing db "Parsing coffeescript source...", 13, 10, 0
    msg_parsing_len equ $ - msg_parsing
    
    filename_buffer times 260 db 0
    file_buffer times 65536 db 0
    token_buffer times 256 db 0
    
    file_handle dq 0
    bytes_read dq 0
    bytes_written dq 0
    token_count dq 0

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

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_banner]
    mov r8, msg_banner_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    call parse_arguments
    test rax, rax
    jz .no_args

    mov rcx, rax
    call open_file
    test rax, rax
    jz .open_error

    call parse_source

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, msg_success_len
    lea r9, [bytes_written]
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
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 1
    jmp .exit

.open_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_open_err]
    mov r8, msg_open_err_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 2

.exit:
    mov rcx, rax
    call ExitProcess

parse_source:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, msg_parsing_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    mov qword [token_count], 0
    lea rsi, [file_buffer]

.parse_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .parse_done

    cmp al, ' '
    je .skip_char
    cmp al, 9
    je .skip_char
    cmp al, 13
    je .skip_char
    cmp al, 10
    je .skip_char

    cmp al, '/'
    jne .not_comment
    movzx ebx, byte [rsi+1]
    cmp bl, '/'
    je .skip_line_comment

.not_comment:
    cmp al, 34
    je .parse_string
    cmp al, 39
    je .parse_string

    call is_alpha
    jc .parse_identifier
    call is_digit
    jc .parse_number

    inc qword [token_count]
    inc rsi
    jmp .parse_loop

.skip_char:
    inc rsi
    jmp .parse_loop

.skip_line_comment:
    add rsi, 2
.line_loop:
    movzx eax, byte [rsi]
    cmp al, 10
    je .parse_loop
    test al, al
    jz .parse_done
    inc rsi
    jmp .line_loop

.parse_string:
    inc qword [token_count]
    inc rsi
.str_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .parse_done
    cmp al, 34
    je .str_end
    cmp al, 39
    je .str_end
    cmp al, 92
    je .str_esc
    inc rsi
    jmp .str_loop
.str_esc:
    add rsi, 2
    jmp .str_loop
.str_end:
    inc rsi
    jmp .parse_loop

.parse_identifier:
    inc qword [token_count]
.ident_loop:
    inc rsi
    movzx eax, byte [rsi]
    call is_alpha
    jc .ident_loop
    call is_digit
    jc .ident_loop
    cmp al, '_'
    je .ident_loop
    jmp .parse_loop

.parse_number:
    inc qword [token_count]
    inc rsi
.num_loop:
    movzx eax, byte [rsi]
    call is_digit
    jc .num_loop
    jmp .parse_loop

.parse_done:
    leave
    ret

parse_arguments:
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

    mov [file_handle], rax

    mov rcx, rax
    lea rdx, [file_buffer]
    mov r8, 65535
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile

    test rax, rax
    jz .error

    mov rax, [bytes_read]
    lea rdi, [file_buffer]
    add rdi, rax
    mov byte [rdi], 0

    mov rcx, [file_handle]
    call CloseHandle

    mov rax, 1
    jmp .done

.error:
    xor rax, rax

.done:
    leave
    ret

is_alpha:
    cmp al, 'A'
    jb .not_alpha
    cmp al, 'Z'
    jbe .is_alpha
    cmp al, 'a'
    jb .not_alpha
    cmp al, 'z'
    jbe .is_alpha
.not_alpha:
    clc
    ret
.is_alpha:
    stc
    ret

is_digit:
    cmp al, '0'
    jb .not_digit
    cmp al, '9'
    ja .not_digit
    stc
    ret
.not_digit:
    clc
    ret
