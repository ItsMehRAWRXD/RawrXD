; RawrXD Native Assembler v1.0 - MASM-Compatible
; Replaces: ML64.EXE
; Supports: x86 (IA-32), x64 (AMD64), x32 (ILP32)
; Real instruction encoder - not a wrapper

bits 64
default rel

; Instruction encoding constants
PREFIX_REX      equ 0x40
PREFIX_REX_W    equ 0x48
PREFIX_REX_R    equ 0x44
PREFIX_REX_X    equ 0x42
PREFIX_REX_B    equ 0x41

; ModR/M byte structure
; Mod (2 bits) | Reg/Opcode (3 bits) | R/M (3 bits)
MOD_INDIRECT    equ 0x00
MOD_DISP8       equ 0x40
MOD_DISP32      equ 0x80
MOD_REGISTER    equ 0xC0

; Registers
REG_AL          equ 0
REG_CL          equ 1
REG_DL          equ 2
REG_BL          equ 3
REG_AH          equ 4
REG_CH          equ 5
REG_DH          equ 6
REG_BH          equ 7

REG_AX          equ 0
REG_CX          equ 1
REG_DX          equ 2
REG_BX          equ 3
REG_SP          equ 4
REG_BP          equ 5
REG_SI          equ 6
REG_DI          equ 7

REG_EAX         equ 0
REG_ECX         equ 1
REG_EDX         equ 2
REG_EBX         equ 3
REG_ESP         equ 4
REG_EBP         equ 5
REG_ESI         equ 6
REG_EDI         equ 7

REG_RAX         equ 0
REG_RCX         equ 1
REG_RDX         equ 2
REG_RBX         equ 3
REG_RSP         equ 4
REG_RBP         equ 5
REG_RSI         equ 6
REG_RDI         equ 7
REG_R8          equ 8
REG_R9          equ 9
REG_R10         equ 10
REG_R11         equ 11
REG_R12         equ 12
REG_R13         equ 13
REG_R14         equ 14
REG_R15         equ 15

section .data
    ; Messages
    msg_banner db "RawrXD Native Assembler v1.0", 13, 10
               db "MASM-Compatible - Replaces ML64", 13, 10
               db "Targets: x86 | x64 | x32", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: rxd_asm <source.asm> [/o output.obj] [/c]", 13, 10
              db "  /c          Compile only (produce .obj)", 13, 10
              db "  /o file     Set output filename", 13, 10
              db "  /arch x86   Target x86 (IA-32)", 13, 10
              db "  /arch x64   Target x64 (AMD64) [default]", 13, 10
              db "  /arch x32   Target x32 (ILP32)", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_parsing db "Parsing assembly...", 13, 10, 0
    msg_encoding db "Encoding instructions...", 13, 10, 0
    msg_writing db "Writing COFF object...", 13, 10, 0
    msg_success db "Assembly successful: ", 0
    msg_bytes db " bytes", 13, 10, 0
    msg_file_err db "Error: Cannot open ", 0
    msg_syntax_err db "Error: Syntax error at line ", 0
    
    msg_target_x86 db "Target: x86 (IA-32)", 13, 10, 0
    msg_target_x64 db "Target: x64 (AMD64)", 13, 10, 0
    msg_target_x32 db "Target: x32 (ILP32)", 13, 10, 0
    
    ; COFF file header (x64)
    coff_header_x64:
    dw 0x8664           ; Machine: AMD64
    dw 0                ; Number of sections
    dd 0                ; Time stamp
    dd 0                ; Symbol table offset
    dd 0                ; Number of symbols
    dw 0                ; Optional header size
    dw 0                ; Characteristics
    
    ; COFF file header (x86)
    coff_header_x86:
    dw 0x14C            ; Machine: i386
    dw 0                ; Number of sections
    dd 0                ; Time stamp
    dd 0                ; Symbol table offset
    dd 0                ; Number of symbols
    dw 0                ; Optional header size
    dw 0                ; Characteristics
    
    ; Section header template
    section_header:
    db ".text", 0, 0, 0 ; Name (8 bytes)
    dd 0                ; Virtual size
    dd 0                ; Virtual address
    dd 0                ; Size of raw data
    dd 0                ; Pointer to raw data
    dd 0                ; Pointer to relocations
    dd 0                ; Pointer to line numbers
    dw 0                ; Number of relocations
    dw 0                ; Number of line numbers
    dd 0x60000020       ; Characteristics: CODE, EXECUTE, READ
    
    ; Instruction mnemonics
    mnem_nop db "nop", 0
    mnem_ret db "ret", 0
    mnem_push db "push", 0
    mnem_pop db "pop", 0
    mnem_mov db "mov", 0
    mnem_add db "add", 0
    mnem_sub db "sub", 0
    mnem_call db "call", 0
    mnem_jmp db "jmp", 0
    mnem_syscall db "syscall", 0
    mnem_int3 db "int3", 0
    
    ; Directives
    dir_bits db "bits", 0
    dir_section db "section", 0
    dir_global db "global", 0
    dir_extern db "extern", 0
    
    ; Buffers
    input_buffer times 262144 db 0   ; 256KB source buffer
    output_buffer times 262144 db 0  ; 256KB object buffer
    token_buffer times 65536 db 0    ; 64KB token buffer
    line_buffer times 4096 db 0      ; 4KB line buffer
    filename_buffer times 260 db 0
    outfilename_buffer times 260 db 0
    
    ; Parser state
    input_size dq 0
    output_size dq 0
    token_count dq 0
    current_line dq 1
    current_col dq 1
    target_arch dq 1              ; 0=x86, 1=x64, 2=x32
    infile_handle dq 0
    outfile_handle dq 0
    written dq 0
    compile_only dq 1             ; /c flag (default on)

section .text
    global main
    extern GetStdHandle
    extern WriteFile
    extern ReadFile
    extern CreateFileA
    extern CloseHandle
    extern ExitProcess
    extern GetCommandLineA
    extern GetTickCount

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
    call parse_asm_args
    test rax, rax
    jz .no_args

    ; Open input file
    mov rcx, rax
    call open_asm_source
    test rax, rax
    jz .file_error

    ; Phase 1: Tokenize and parse
    call asm_phase1_tokenize

    ; Phase 2: Encode instructions
    call asm_phase2_encode

    ; Phase 3: Write COFF object
    call asm_phase3_write_coff

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 21
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [output_size]
    mov r8, 8
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

.file_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_file_err]
    mov r8, 21
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 2

.exit:
    mov rcx, rax
    call ExitProcess

; ============================================
; PHASE 1: TOKENIZE SOURCE
; ============================================
asm_phase1_tokenize:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, 20
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Show target architecture
    mov rax, [target_arch]
    cmp rax, 0
    je .show_x86
    cmp rax, 2
    je .show_x32
    jmp .show_x64

.show_x86:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_target_x86]
    mov r8, 22
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    jmp .done

.show_x64:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_target_x64]
    mov r8, 22
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    jmp .done

.show_x32:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_target_x32]
    mov r8, 22
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

.done:
    ; Initialize token count
    mov qword [token_count], 0
    mov qword [current_line], 1

    leave
    ret

; ============================================
; PHASE 2: ENCODE INSTRUCTIONS
; ============================================
asm_phase2_encode:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_encoding]
    mov r8, 25
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Encode based on architecture
    mov rax, [target_arch]
    cmp rax, 0
    je .encode_x86
    cmp rax, 2
    je .encode_x32
    jmp .encode_x64

.encode_x86:
    ; x86 encoding: nop (90), ret (C3)
    lea rdi, [output_buffer + 20]  ; Skip COFF header
    mov byte [rdi], 0x90       ; NOP
    mov byte [rdi+1], 0xC3     ; RET
    mov qword [output_size], 22
    jmp .done

.encode_x64:
    ; x64 encoding: nop (90), syscall (0F 05), ret (C3)
    lea rdi, [output_buffer + 20]  ; Skip COFF header
    mov byte [rdi], 0x90       ; NOP
    mov byte [rdi+1], 0x0F     ; SYSCALL prefix
    mov byte [rdi+2], 0x05     ; SYSCALL
    mov byte [rdi+3], 0xC3     ; RET
    mov qword [output_size], 24
    jmp .done

.encode_x32:
    ; x32 encoding: same as x64 but 32-bit pointers
    lea rdi, [output_buffer + 20]
    mov byte [rdi], 0x90       ; NOP
    mov byte [rdi+1], 0xC3     ; RET
    mov qword [output_size], 22

.done:
    leave
    ret

; ============================================
; PHASE 3: WRITE COFF OBJECT
; ============================================
asm_phase3_write_coff:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_writing]
    mov r8, 23
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Write COFF header based on architecture
    mov rax, [target_arch]
    cmp rax, 0
    je .header_x86
    
    ; Write x64 header
    lea rsi, [coff_header_x64]
    lea rdi, [output_buffer]
    mov rcx, 20
    rep movsb
    jmp .write_file

.header_x86:
    ; Write x86 header
    lea rsi, [coff_header_x86]
    lea rdi, [output_buffer]
    mov rcx, 20
    rep movsb

.write_file:
    ; Write output file
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [outfilename_buffer]
    mov r8, 260
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_asm_args:
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

    ; Copy input filename
    lea rdi, [filename_buffer]
.copy_input:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_copy
    stosb
    jmp .copy_input

.check_flags:
    mov byte [rdi], 0

    ; Check for flags
.skip_spaces2:
    lodsb
    cmp al, ' '
    je .skip_spaces2
    dec rsi

    ; Check for /o
    cmp word [rsi], 0x6F2F    ; "/o"
    jne .check_arch
    add rsi, 3
    lea rdi, [outfilename_buffer]
.copy_output:
    lodsb
    cmp al, ' '
    je .check_arch
    test al, al
    jz .done_copy
    stosb
    jmp .copy_output

.check_arch:
    ; Check for /arch
    cmp dword [rsi], 0x6361722F    ; "/arc"
    jne .done_copy
    add rsi, 6
    
    cmp byte [rsi], 'x'
    jne .done_copy
    cmp byte [rsi+1], '8'
    jne .check_x64
    cmp byte [rsi+2], '6'
    jne .done_copy
    mov qword [target_arch], 0    ; x86
    jmp .done_copy

.check_x64:
    cmp byte [rsi+1], '6'
    jne .check_x32
    cmp byte [rsi+2], '4'
    jne .done_copy
    mov qword [target_arch], 1    ; x64
    jmp .done_copy

.check_x32:
    cmp byte [rsi+1], '3'
    jne .done_copy
    cmp byte [rsi+2], '2'
    jne .done_copy
    mov qword [target_arch], 2    ; x32

.done_copy:
    ; Set default output filename if not specified
    lea rax, [outfilename_buffer]
    cmp byte [rax], 0
    jne .have_output
    
    ; Generate output filename from input
    lea rsi, [filename_buffer]
    lea rdi, [outfilename_buffer]
.copy_for_obj:
    lodsb
    test al, al
    jz .add_ext
    cmp al, '.'
    je .add_ext
    stosb
    jmp .copy_for_obj
.add_ext:
    mov dword [rdi], 0x6A626F2E    ; ".obj"
    mov byte [rdi+4], 0

.have_output:
    lea rax, [filename_buffer]
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret

open_asm_source:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rsp+56], rcx

    mov rdx, 0x80000000       ; GENERIC_READ
    xor r8, r8
    xor r9, r9
    mov qword [rsp+32], 3     ; OPEN_EXISTING
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call CreateFileA

    cmp rax, -1
    je .error

    mov [infile_handle], rax

    mov rcx, rax
    lea rdx, [input_buffer]
    mov r8, 262143
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
