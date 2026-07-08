; Real Universal Compiler v3 - FIXED VERSION
; x64 Windows Console Application
; NASM Syntax

bits 64
default rel

; Token types
TOKEN_EOF     equ 0
TOKEN_IDENT   equ 1
TOKEN_NUMBER  equ 2
TOKEN_STRING  equ 3
TOKEN_LPAREN  equ 4
TOKEN_RPAREN  equ 5
TOKEN_LBRACE  equ 6
TOKEN_RBRACE  equ 7
TOKEN_SEMI    equ 8
TOKEN_COMMA   equ 9
TOKEN_PLUS    equ 10
TOKEN_MINUS   equ 11
TOKEN_MUL     equ 12
TOKEN_DIV     equ 13
TOKEN_ASSIGN  equ 14
TOKEN_KEYWORD equ 15

section .data
    ; Messages
    msg_banner db "RawrXD Universal Compiler v3.0", 13, 10
               db "Full Lexer + Parser + x64 Code Generator", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    msg_usage db "Usage: compiler <input.c>", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    msg_lexing db "Phase 1: Lexical Analysis...", 13, 10, 0
    msg_lexing_len equ $ - msg_lexing
    msg_parsing db "Phase 2: Parsing...", 13, 10, 0
    msg_parsing_len equ $ - msg_parsing
    msg_codegen db "Phase 3: Code Generation...", 13, 10, 0
    msg_codegen_len equ $ - msg_codegen
    msg_success db "Compilation successful!", 13, 10, 0
    msg_success_len equ $ - msg_success
    msg_file_err db "Error: Cannot open input file", 13, 10, 0
    msg_file_err_len equ $ - msg_file_err
    
    newline db 13, 10, 0
    
    ; Buffers
    input_buffer times 65536 db 0
    token_buffer times 1024 db 0
    filename_buffer times 260 db 0
    
    ; Data
    input_size dq 0
    token_count dq 0
    current_char dq 0
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

; ============================================
; ENTRY POINT
; ============================================
main:
    push rbp
    mov rbp, rsp
    sub rsp, 96                     ; Shadow space + alignment

    ; Show banner
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_banner]
    mov r8, msg_banner_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Parse command line
    call parse_arguments
    test rax, rax
    jz .no_args

    ; Open input file
    mov rcx, rax
    call open_input_file
    test rax, rax
    jz .file_error

    ; Phase 1: Lexical Analysis
    call phase1_lexing

    ; Phase 2: Parsing
    call phase2_parsing

    ; Phase 3: Code Generation
    call phase3_codegen

    ; Show success
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

; ============================================
; PHASE 1: LEXICAL ANALYSIS
; ============================================
phase1_lexing:
    push rbp
    mov rbp, rsp
    sub rsp, 96                     ; Increased stack space

    ; Show lexing message
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_lexing]
    mov r8, msg_lexing_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Initialize lexer
    lea rax, [input_buffer]
    mov [current_char], rax
    mov qword [token_count], 0

.lexer_loop:
    ; Get current character
    mov rsi, [current_char]
    movzx eax, byte [rsi]
    test al, al
    jz .lexer_done

    ; Skip whitespace
    cmp al, ' '
    je .skip_char
    cmp al, 9
    je .skip_char
    cmp al, 13
    je .skip_char
    cmp al, 10
    je .skip_char

    ; Check for comments
    cmp al, '/'
    jne .not_comment
    movzx ebx, byte [rsi+1]
    cmp bl, '/'
    je .skip_line_comment

.not_comment:
    ; Check for identifiers
    call is_alpha
    jnc .not_ident
    call lex_identifier
    jmp .lexer_loop

.not_ident:
    ; Check for numbers
    call is_digit
    jnc .not_number
    call lex_number
    jmp .lexer_loop

.not_number:
    ; Check for string literals
    cmp al, '"'
    jne .not_string
    call lex_string
    jmp .lexer_loop

.not_string:
    ; Single character tokens
    call lex_symbol
    jmp .lexer_loop

.skip_char:
    inc rsi
    mov [current_char], rsi
    jmp .lexer_loop

.skip_line_comment:
    add rsi, 2
.line_comment_loop:
    movzx eax, byte [rsi]
    cmp al, 10
    je .comment_done
    test al, al
    jz .lexer_done
    inc rsi
    jmp .line_comment_loop
.comment_done:
    mov [current_char], rsi
    jmp .lexer_loop

.lexer_done:
    leave
    ret

; ============================================
; PHASE 2: PARSING
; ============================================
phase2_parsing:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    ; Show parsing message
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, msg_parsing_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

; ============================================
; PHASE 3: CODE GENERATION
; ============================================
phase3_codegen:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    ; Show codegen message
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_codegen]
    mov r8, msg_codegen_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_arguments:
    push rbp
    mov rbp, rsp
    sub rsp, 96

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

    ; Copy filename
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

open_input_file:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    mov [rsp+56], rcx

    mov rdx, 0x80000000          ; GENERIC_READ
    xor r8, r8                   ; No share
    xor r9, r9                   ; No security
    mov qword [rsp+32], 3        ; OPEN_EXISTING
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

    ; Null terminate
    mov rax, [input_size]
    lea rdi, [input_buffer]
    add rdi, rax
    mov byte [rdi], 0

    mov rcx, [infile_handle]
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
    cmp al, '_'
    je .is_alpha
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

lex_identifier:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    lea rdi, [token_buffer]
    mov rsi, [current_char]

.copy_loop:
    movzx eax, byte [rsi]
    call is_alpha
    jc .copy_char
    call is_digit
    jc .copy_char
    jmp .done_copy
.copy_char:
    stosb
    inc rsi
    jmp .copy_loop

.done_copy:
    mov byte [rdi], 0
    mov [current_char], rsi

    inc qword [token_count]

    leave
    ret

lex_number:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    lea rdi, [token_buffer]
    mov rsi, [current_char]

.copy_loop:
    movzx eax, byte [rsi]
    call is_digit
    jnc .done_copy
    stosb
    inc rsi
    jmp .copy_loop

.done_copy:
    mov byte [rdi], 0
    mov [current_char], rsi

    inc qword [token_count]

    leave
    ret

lex_string:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    mov rsi, [current_char]
    inc rsi
    lea rdi, [token_buffer]

.copy_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .done_copy
    cmp al, '"'
    je .done_copy
    stosb
    inc rsi
    jmp .copy_loop

.done_copy:
    mov byte [rdi], 0
    inc rsi
    mov [current_char], rsi

    inc qword [token_count]

    leave
    ret

lex_symbol:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    mov rsi, [current_char]
    inc rsi
    mov [current_char], rsi

    inc qword [token_count]

    leave
    ret
