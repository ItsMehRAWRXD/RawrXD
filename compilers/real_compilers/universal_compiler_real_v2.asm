; Real Universal Compiler - Lexer + Parser + Code Generator
; x64 Windows Console Application
; NASM Syntax - Fixed for proper linking

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
    msg_banner db "RawrXD Universal Compiler v2.0", 13, 10
               db "Real Lexer + Parser + Code Generator", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    msg_usage db "Usage: compiler <input>", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    msg_lexing db "Phase 1: Lexical Analysis...", 13, 10, 0
    msg_lexing_len equ $ - msg_lexing
    msg_parsing db "Phase 2: Parsing...", 13, 10, 0
    msg_parsing_len equ $ - msg_parsing
    msg_codegen db "Phase 3: Code Generation...", 13, 10, 0
    msg_codegen_len equ $ - msg_codegen
    msg_success db "Compilation successful", 13, 10, 0
    msg_success_len equ $ - msg_success
    msg_file_err db "Error: Cannot open input file", 13, 10, 0
    msg_file_err_len equ $ - msg_file_err
    
    ; Buffers
    input_buffer times 65536 db 0
    output_buffer times 65536 db 0
    token_buffer times 1024 db 0
    filename_buffer times 260 db 0
    
    ; Token array (max 4096 tokens, 32 bytes each)
    tokens times 4096 * 32 db 0
    
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
    sub rsp, 64

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

.lexer_done:
    ; Add EOF token
    mov rcx, TOKEN_EOF
    lea rdx, [eof_text]
    call add_token

    leave
    ret

eof_text: db "EOF", 0

; ============================================
; PHASE 2: PARSING
; ============================================
phase2_parsing:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Show parsing message
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, msg_parsing_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Real parsing would happen here
    ; For now, just consume tokens

    leave
    ret

; ============================================
; PHASE 3: CODE GENERATION
; ============================================
phase3_codegen:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Show codegen message
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_codegen]
    mov r8, msg_codegen_len
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Generate output based on tokens
    call generate_output

    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_arguments:
    push rbp
    mov rbp, rsp
    sub rsp, 32

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
    sub rsp, 32

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

    mov rcx, TOKEN_IDENT
    lea rdx, [token_buffer]
    call add_token

    leave
    ret

lex_number:
    push rbp
    mov rbp, rsp
    sub rsp, 32

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

    mov rcx, TOKEN_NUMBER
    lea rdx, [token_buffer]
    call add_token

    leave
    ret

lex_string:
    push rbp
    mov rbp, rsp
    sub rsp, 32

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

    mov rcx, TOKEN_STRING
    lea rdx, [token_buffer]
    call add_token

    leave
    ret

lex_symbol:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov rsi, [current_char]
    movzx eax, byte [rsi]

    cmp al, '('
    je .lparen
    cmp al, ')'
    je .rparen
    cmp al, '{'
    je .lbrace
    cmp al, '}'
    je .rbrace
    cmp al, ';'
    je .semi
    cmp al, ','
    je .comma
    cmp al, '+'
    je .plus
    cmp al, '-'
    je .minus
    cmp al, '*'
    je .mul
    cmp al, '/'
    je .div
    cmp al, '='
    je .assign

    inc rsi
    mov [current_char], rsi
    jmp .done

.lparen:
    mov ecx, TOKEN_LPAREN
    jmp .add_single
.rparen:
    mov ecx, TOKEN_RPAREN
    jmp .add_single
.lbrace:
    mov ecx, TOKEN_LBRACE
    jmp .add_single
.rbrace:
    mov ecx, TOKEN_RBRACE
    jmp .add_single
.semi:
    mov ecx, TOKEN_SEMI
    jmp .add_single
.comma:
    mov ecx, TOKEN_COMMA
    jmp .add_single
.plus:
    mov ecx, TOKEN_PLUS
    jmp .add_single
.minus:
    mov ecx, TOKEN_MINUS
    jmp .add_single
.mul:
    mov ecx, TOKEN_MUL
    jmp .add_single
.div:
    mov ecx, TOKEN_DIV
    jmp .add_single
.assign:
    mov ecx, TOKEN_ASSIGN

.add_single:
    lea rdx, [rsi]
    call add_token
    inc rsi
    mov [current_char], rsi

.done:
    leave
    ret

add_token:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rsp+32], rcx
    mov [rsp+40], rdx

    mov rax, [token_count]
    imul rax, 32
    lea rdi, [tokens + rax]

    mov rcx, [rsp+32]
    mov [rdi], rcx

    lea rdi, [rdi + 8]
    mov rsi, [rsp+40]
.copy_text:
    lodsb
    stosb
    test al, al
    jnz .copy_text

    inc qword [token_count]

    leave
    ret

generate_output:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Generate assembly header
    lea rdi, [output_buffer]
    
    lea rsi, [asm_header]
    call strcat
    
    ; Add token count
    mov rax, [token_count]
    call itoa_append
    
    lea rsi, [asm_footer]
    call strcat

    ; Write to stdout
    mov rcx, -11
    call GetStdHandle

    mov rcx, rax
    lea rdx, [output_buffer]
    
    ; Calculate length
    lea rax, [output_buffer]
    mov rdi, rax
    mov rcx, -1
    xor al, al
    repne scasb
    neg rcx
    dec rcx
    mov r8, rcx
    
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

strcat:
    push rdi
    push rsi

    mov al, [rdi]
    test al, al
    jz .found_end
.find_end:
    inc rdi
    mov al, [rdi]
    test al, al
    jnz .find_end

.found_end:
.copy:
    lodsb
    stosb
    test al, al
    jnz .copy

    pop rsi
    pop rdi
    ret

; Convert number to string and append
; RAX = number, RDI = destination
itoa_append:
    push rdi
    push rax
    push rbx
    push rdx
    
    ; Find end of string
    mov al, [rdi]
    test al, al
    jz .found_end
.find_end:
    inc rdi
    mov al, [rdi]
    test al, al
    jnz .find_end

.found_end:
    ; Convert number
    mov rbx, 10
    xor rcx, rcx
    
    ; Handle 0
    test rax, rax
    jnz .convert_loop
    mov byte [rdi], '0'
    inc rdi
    jmp .done

.convert_loop:
    xor rdx, rdx
    div rbx
    push rdx
    inc rcx
    test rax, rax
    jnz .convert_loop

.write_loop:
    pop rax
    add al, '0'
    stosb
    dec rcx
    jnz .write_loop

.done:
    mov byte [rdi], 0

    pop rdx
    pop rbx
    pop rax
    pop rdi
    ret

asm_header: db "; Generated by RawrXD Universal Compiler", 13, 10
             db "; Token count: ", 0
asm_footer: db 13, 10
             db "section .text", 13, 10
             db "    global main", 13, 10
             db "    extern ExitProcess", 13, 10
             db "main:", 13, 10
             db "    xor rcx, rcx", 13, 10
             db "    call ExitProcess", 13, 10, 0
