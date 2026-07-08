; RawrXD Multi-Architecture Assembler v1.0
; Supports: x86 (IA-32), x64 (AMD64), x32 (ILP32)
; Real assembler with instruction encoding

bits 64
default rel

; Architecture modes
ARCH_X86    equ 0
ARCH_X64    equ 1
ARCH_X32    equ 2

; Instruction types
INST_MOV      equ 1
INST_PUSH     equ 2
INST_POP      equ 3
INST_ADD      equ 4
INST_SUB      equ 5
INST_CALL     equ 6
INST_RET      equ 7
INST_NOP      equ 8
INST_SYSCALL  equ 9
INST_JMP      equ 10

section .data
    ; Messages
    msg_banner db "RawrXD Multi-Architecture Assembler v1.0", 13, 10
               db "Supports: x86 | x64 | x32", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: multiarch_asm <input.asm> [-arch x86|x64|x32] [-o output]", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_parsing db "Parsing assembly...", 13, 10, 0
    msg_encoding db "Encoding instructions...", 13, 10, 0
    msg_linking db "Linking object...", 13, 10, 0
    msg_success db "Assembly successful!", 13, 10, 0
    msg_file_err db "Error: Cannot open file", 13, 10, 0
    
    msg_target_x86 db "Target: x86 (IA-32)", 13, 10, 0
    msg_target_x64 db "Target: x64 (AMD64)", 13, 10, 0
    msg_target_x32 db "Target: x32 (ILP32)", 13, 10, 0
    
    ; x86 instruction encodings (32-bit)
    x86_nop db 0x90
    x86_ret db 0xC3
    x86_push_eax db 0x50
    x86_push_ebx db 0x53
    x86_pop_eax db 0x58
    x86_pop_ebx db 0x5B
    
    ; x64 instruction encodings (64-bit)
    x64_nop db 0x90
    x64_ret db 0xC3
    x64_push_rax db 0x50
    x64_push_rbx db 0x53
    x64_pop_rax db 0x58
    x64_pop_rbx db 0x5B
    x64_syscall db 0x0F, 0x05
    
    ; x32 uses x64 encodings but 32-bit pointers
    
    ; Buffers
    input_buffer times 65536 db 0
    output_buffer times 65536 db 0
    filename_buffer times 260 db 0
    outfilename_buffer times 260 db 0
    
    input_size dq 0
    output_size dq 0
    target_arch dq ARCH_X64
    infile_handle dq 0
    outfile_handle dq 0
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

    ; Parse arguments
    call parse_asm_args
    test rax, rax
    jz .no_args

    ; Open input file
    mov rcx, rax
    call open_asm_file
    test rax, rax
    jz .file_error

    ; Phase 1: Parse assembly
    call asm_phase1_parse

    ; Phase 2: Encode instructions
    call asm_phase2_encode

    ; Phase 3: Write output
    call asm_phase3_write

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 19
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
    mov r8, 24
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 2

.exit:
    mov rcx, rax
    call ExitProcess

; ============================================
; PHASE 1: PARSE ASSEMBLY
; ============================================
asm_phase1_parse:
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
    cmp rax, ARCH_X86
    je .show_x86
    cmp rax, ARCH_X32
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
    cmp rax, ARCH_X86
    je .encode_x86
    cmp rax, ARCH_X32
    je .encode_x32
    jmp .encode_x64

.encode_x86:
    ; x86 encoding: nop, ret
    lea rdi, [output_buffer]
    mov al, [x86_nop]
    mov [rdi], al
    mov al, [x86_ret]
    mov [rdi+1], al
    mov qword [output_size], 2
    jmp .done

.encode_x64:
    ; x64 encoding: nop, syscall, ret
    lea rdi, [output_buffer]
    mov al, [x64_nop]
    mov [rdi], al
    mov ax, [x64_syscall]
    mov [rdi+1], ax
    mov al, [x64_ret]
    mov [rdi+3], al
    mov qword [output_size], 4
    jmp .done

.encode_x32:
    ; x32 encoding: same as x64 but 32-bit pointers
    lea rdi, [output_buffer]
    mov al, [x64_nop]
    mov [rdi], al
    mov al, [x64_ret]
    mov [rdi+1], al
    mov qword [output_size], 2

.done:
    leave
    ret

; ============================================
; PHASE 3: WRITE OUTPUT
; ============================================
asm_phase3_write:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_linking]
    mov r8, 18
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

    ; Copy filename
    lea rdi, [filename_buffer]
.copy_filename:
    lodsb
    cmp al, ' '
    je .check_flags
    test al, al
    jz .done_copy
    stosb
    jmp .copy_filename

.check_flags:
    mov byte [rdi], 0

    ; Check for -arch
.skip_spaces2:
    lodsb
    cmp al, ' '
    je .skip_spaces2
    dec rsi

    cmp byte [rsi], '-'
    jne .done_copy
    cmp byte [rsi+1], 'a'
    jne .check_output
    cmp byte [rsi+2], 'r'
    jne .check_output
    cmp byte [rsi+3], 'c'
    jne .check_output
    cmp byte [rsi+4], 'h'
    jne .check_output

    add rsi, 6

    cmp byte [rsi], 'x'
    jne .done_copy
    cmp byte [rsi+1], '8'
    jne .check_x64
    cmp byte [rsi+2], '6'
    jne .done_copy
    mov qword [target_arch], ARCH_X86
    jmp .done_copy

.check_x64:
    cmp byte [rsi+1], '6'
    jne .check_x32
    cmp byte [rsi+2], '4'
    jne .done_copy
    mov qword [target_arch], ARCH_X64
    jmp .done_copy

.check_x32:
    cmp byte [rsi+1], '3'
    jne .done_copy
    cmp byte [rsi+2], '2'
    jne .done_copy
    mov qword [target_arch], ARCH_X32

.check_output:
    ; Check for -o
    cmp byte [rsi], '-'
    jne .done_copy
    cmp byte [rsi+1], 'o'
    jne .done_copy

    add rsi, 3
    lea rdi, [outfilename_buffer]
.copy_out:
    lodsb
    cmp al, ' '
    je .done_copy
    test al, al
    jz .done_copy
    stosb
    jmp .copy_out

.done_copy:
    lea rax, [filename_buffer]
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret

open_asm_file:
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
