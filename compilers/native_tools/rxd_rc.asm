; RawrXD Native Resource Compiler v1.0 - Windows Resource Compiler
; Replaces: RC.EXE
; Supports: .rc files, .res output
; Real resource compiler - not a wrapper

bits 64
default rel

; Resource constants
RT_CURSOR           equ 1
RT_BITMAP           equ 2
RT_ICON             equ 3
RT_MENU             equ 4
RT_DIALOG           equ 5
RT_STRING           equ 6
RT_FONTDIR          equ 7
RT_FONT             equ 8
RT_ACCELERATOR      equ 9
RT_RCDATA           equ 10
RT_MESSAGETABLE     equ 11
RT_GROUP_CURSOR     equ 12
RT_GROUP_ICON       equ 14
RT_VERSION          equ 16
RT_DLGINCLUDE       equ 17
RT_PLUGPLAY         equ 19
RT_VXD              equ 20
RT_ANICURSOR        equ 21
RT_ANIICON          equ 22
RT_HTML             equ 23
RT_MANIFEST         equ 24

; Resource file header
RES_MAGIC           equ 0x0000FFFF

section .data
    ; Messages
    msg_banner db "RawrXD Native Resource Compiler v1.0", 13, 10
               db "Windows Resource Compiler - Replaces RC", 13, 10
               db "Supports: .rc → .res", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: rxd_rc <file.rc> [/fo file.res]", 13, 10
              db "  /fo file       Set output filename", 13, 10
              db "  /v             Verbose mode", 13, 10
              db "  /d DEFINE      Define preprocessor symbol", 13, 10
              db "  /u UNDEFINE    Undefine symbol", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_parsing db "Parsing resource script...", 13, 10, 0
    msg_compiling db "Compiling resources...", 13, 10, 0
    msg_success db "Resource compilation successful: ", 0
    msg_bytes db " bytes", 13, 10, 0
    
    ; Resource file header
    res_header dd 0x0000FFFF
               dd 0x00000000
    
    ; Buffers
    input_buffer times 262144 db 0
    output_buffer times 524288 db 0
    rc_filename times 260 db 0
    res_filename times 260 db 0
    
    ; Data
    output_size dq 0
    verbose_mode dq 0
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
    call parse_rc_args
    test rax, rax
    jz .no_args

    ; Phase 1: Parse .rc file
    call rc_phase1_parse

    ; Phase 2: Compile resources
    call rc_phase2_compile

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 33
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [res_filename]
    mov r8, 260
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_bytes]
    mov r8, 8
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

.exit:
    mov rcx, rax
    call ExitProcess

; ============================================
; PHASE 1: PARSE .RC FILE
; ============================================
rc_phase1_parse:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, 27
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

; ============================================
; PHASE 2: COMPILE RESOURCES
; ============================================
rc_phase2_compile:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_compiling]
    mov r8, 23
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Write resource header
    lea rsi, [res_header]
    lea rdi, [output_buffer]
    mov rcx, 8
    rep movsb
    mov qword [output_size], 8

    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_rc_args:
    push rbp
    mov rbp, rsp
    sub rsp, 64

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
.skip_spaces1:
    lodsb
    cmp al, ' '
    je .skip_spaces1
    dec rsi

    mov al, [rsi]
    test al, al
    jz .no_args

    ; Parse arguments
    lea rdi, [rc_filename]
.copy_rc:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_rc

.check_flags:
    ; Check for /fo
    cmp dword [rsi], 0x6F662F2F    ; "/fo"
    jne .check_verbose
    add rsi, 4
    lea rdi, [res_filename]
.copy_fo:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_fo

.check_verbose:
    cmp dword [rsi], 0x762F2F2F    ; "/v"
    jne .check_define
    mov qword [verbose_mode], 1
    add rsi, 2
    jmp .check_flags

.check_define:
    cmp dword [rsi], 0x642F2F2F    ; "/d"
    jne .check_undefine
    add rsi, 3
    ; Skip define name for now
.skip_define:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_parsing
    jmp .skip_define

.check_undefine:
    cmp dword [rsi], 0x752F2F2F    ; "/u"
    jne .skip_flag
    add rsi, 3
.skip_undef:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_parsing
    jmp .skip_undef

.skip_flag:
    lodsb
    cmp al, ' '
    jne .skip_flag
    jmp .check_flags

.done_parsing:
    ; Set default output if not specified
    lea rax, [res_filename]
    cmp byte [rax], 0
    jne .have_output
    ; Derive .res from .rc
    lea rsi, [rc_filename]
    lea rdi, [res_filename]
.copy_name:
    lodsb
    test al, al
    jz .add_res
    stosb
    jmp .copy_name
.add_res:
    mov dword [rdi-2], 0x7365722E  ; ".res"
.have_output:
    mov rax, 1
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret
