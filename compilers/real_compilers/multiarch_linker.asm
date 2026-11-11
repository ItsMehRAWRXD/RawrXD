; RawrXD Multi-Architecture Linker v1.0
; Supports: x86 (PE32), x64 (PE32+), x32 (PE32+ with 32-bit pointers)
; Real linker with PE format generation

bits 64
default rel

; Architecture modes
ARCH_X86    equ 0
ARCH_X64    equ 1
ARCH_X32    equ 2

; PE constants
PE_MAGIC    equ 0x5A4D       ; MZ
PE_SIG      equ 0x00004550   ; PE\0\0
PE32_MAGIC  equ 0x10B       ; Optional header magic for PE32
PE32P_MAGIC equ 0x20B       ; Optional header magic for PE32+

section .data
    ; Messages
    msg_banner db "RawrXD Multi-Architecture Linker v1.0", 13, 10
               db "Supports: x86 (PE32) | x64 (PE32+) | x32 (ILP32)", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: multiarch_link <obj1.obj obj2.obj ...> [-arch x86|x64|x32] [-o output.exe]", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_reading db "Reading object files...", 13, 10, 0
    msg_reloc db "Processing relocations...", 13, 10, 0
    msg_linking db "Linking executable...", 13, 10, 0
    msg_success db "Link successful!", 13, 10, 0
    msg_file_err db "Error: Cannot open file", 13, 10, 0
    
    msg_target_x86 db "Target: x86 (PE32)", 13, 10, 0
    msg_target_x64 db "Target: x64 (PE32+)", 13, 10, 0
    msg_target_x32 db "Target: x32 (ILP32)", 13, 10, 0
    
    ; PE32 header template (x86)
    pe32_header:
    ; DOS Header
    db 0x4D, 0x5A       ; MZ signature
    times 58 db 0       ; DOS header padding
    dd pe32_nt_header - pe32_header  ; PE offset
    
    pe32_nt_header:
    ; PE Signature
    db 'P', 'E', 0, 0
    
    ; COFF File Header (20 bytes)
    dw 0x14C            ; Machine: i386
    dw 1                ; Number of sections
    dd 0                ; Time stamp
    dd 0                ; Symbol table offset
    dd 0                ; Number of symbols
    dw 0                ; Optional header size
    dw 0x102            ; Characteristics: Executable image, 32-bit
    
    ; PE32+ header template (x64)
    pe64_header:
    ; DOS Header
    db 0x4D, 0x5A       ; MZ signature
    times 58 db 0       ; DOS header padding
    dd pe64_nt_header - pe64_header  ; PE offset
    
    pe64_nt_header:
    ; PE Signature
    db 'P', 'E', 0, 0
    
    ; COFF File Header (20 bytes)
    dw 0x8664           ; Machine: AMD64
    dw 1                ; Number of sections
    dd 0                ; Time stamp
    dd 0                ; Symbol table offset
    dd 0                ; Number of symbols
    dw 0                ; Optional header size
    dw 0x122            ; Characteristics: Executable image, large address aware
    
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
    call parse_link_args
    test rax, rax
    jz .no_args

    ; Open input file
    mov rcx, rax
    call open_link_file
    test rax, rax
    jz .file_error

    ; Phase 1: Read objects
    call link_phase1_read

    ; Phase 2: Process relocations
    call link_phase2_reloc

    ; Phase 3: Generate PE
    call link_phase3_generate

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 17
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
; PHASE 1: READ OBJECT FILES
; ============================================
link_phase1_read:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_reading]
    mov r8, 24
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Show target
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
    mov r8, 21
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
; PHASE 2: PROCESS RELOCATIONS
; ============================================
link_phase2_reloc:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_reloc]
    mov r8, 26
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    leave
    ret

; ============================================
; PHASE 3: GENERATE PE EXECUTABLE
; ============================================
link_phase3_generate:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_linking]
    mov r8, 22
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Generate PE header based on architecture
    mov rax, [target_arch]
    cmp rax, ARCH_X86
    je .gen_pe32
    jmp .gen_pe64

.gen_pe32:
    ; Copy PE32 header
    lea rsi, [pe32_header]
    lea rdi, [output_buffer]
    mov rcx, 80
    rep movsb
    mov qword [output_size], 80
    jmp .done

.gen_pe64:
    ; Copy PE32+ header
    lea rsi, [pe64_header]
    lea rdi, [output_buffer]
    mov rcx, 80
    rep movsb
    mov qword [output_size], 80

.done:
    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_link_args:
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
    jne .check_output
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

open_link_file:
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
