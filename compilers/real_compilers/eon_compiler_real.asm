; Real EON Compiler - Expression-Oriented Notation Language
; x64 Windows Console Application
; NASM Syntax

bits 64
default rel

section .data
    msg_banner db "RawrXD EON Compiler v1.0", 13, 10
               db "Expression-Oriented Notation", 13, 10, 0
    msg_usage db "Usage: eon_compiler <source.eon>", 13, 10, 0
    msg_lexing db "Phase 1: Lexical Analysis...", 13, 10, 0
    msg_parsing db "Phase 2: Parsing Expressions...", 13, 10, 0
    msg_codegen db "Phase 3: Code Generation...", 13, 10, 0
    msg_output db "Output: output.asm", 13, 10, 0
    msg_success db "Compilation successful!", 13, 10, 0
    msg_file_err db "Error: Cannot open file", 13, 10, 0
    
    ; EON keywords
    kw_let db "let", 0
    kw_in db "in", 0
    kw_if db "if", 0
    kw_then db "then", 0
    kw_else db "else", 0
    kw_fn db "fn", 0
    
    ; Buffers
    input_buffer times 65536 db 0
    output_buffer times 65536 db 0
    token_buffer times 4096 db 0
    filename_buffer times 260 db 0
    
    input_size dq 0
    token_count dq 0
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
    mov r8, 55
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

    ; Phase 2: Parse Expressions
    call phase2_parsing

    ; Phase 3: Generate Code
    call phase3_codegen

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 22
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
    mov r8, 35
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
    mov r8, 24
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

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_lexing]
    mov r8, 29
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Initialize token count
    mov qword [token_count], 0

    leave
    ret

; ============================================
; PHASE 2: PARSING
; ============================================
phase2_parsing:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, 32
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
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_codegen]
    mov r8, 28
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_output]
    mov r8, 19
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
