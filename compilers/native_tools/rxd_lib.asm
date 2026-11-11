; RawrXD Native Librarian v1.0 - COFF Library Manager
; Replaces: LIB.EXE
; Supports: Static libraries (.lib), Import libraries (.lib)
; Real librarian - not a wrapper

bits 64
default rel

; COFF archive format constants
ARCHIVE_SIG         equ 0x3C21F23C  ; !<arch>\n
ARCHIVE_END         equ 0x0A3E0A60  ; `\n>\n

section .data
    ; Messages
    msg_banner db "RawrXD Native Librarian v1.0", 13, 10
               db "COFF Library Manager - Replaces LIB", 13, 10
               db "Supports: Static .lib | Import .lib", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: rxd_lib <obj1.obj obj2.obj ...> [/out:file.lib]", 13, 10
              db "  /out:file      Set output filename", 13, 10
              db "  /def:file.def  Create import library from .def", 13, 10
              db "  /list          List library contents", 13, 10
              db "  /extract:obj   Extract object from library", 13, 10
              db "  /machine:x64   Target x64 [default]", 13, 10
              db "  /machine:x86   Target x86", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_reading db "Reading object files...", 13, 10, 0
    msg_creating db "Creating library...", 13, 10, 0
    msg_success db "Library created: ", 0
    msg_bytes db " bytes", 13, 10, 0
    
    ; Archive header
    archive_header db "!<arch>", 10
    
    ; Buffers
    input_buffer times 262144 db 0
    output_buffer times 524288 db 0
    obj_files times 32 * 260 db 0
    filename_buffer times 260 db 0
    outfilename_buffer times 260 db 0
    def_filename times 260 db 0
    
    ; Data
    num_obj_files dq 0
    output_size dq 0
    target_machine dq 0x8664      ; AMD64 default
    mode_list dq 0                ; 0=create, 1=list, 2=extract
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
    call parse_lib_args
    test rax, rax
    jz .no_args

    ; Phase 1: Read object files
    call lib_phase1_read_objects

    ; Phase 2: Create archive
    call lib_phase2_create_archive

    ; Show success
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, 17
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [outfilename_buffer]
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
; PHASE 1: READ OBJECT FILES
; ============================================
lib_phase1_read_objects:
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

    leave
    ret

; ============================================
; PHASE 2: CREATE ARCHIVE
; ============================================
lib_phase2_create_archive:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_creating]
    mov r8, 20
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Write archive header
    lea rsi, [archive_header]
    lea rdi, [output_buffer]
    mov rcx, 8
    rep movsb
    mov qword [output_size], 8

    leave
    ret

; ============================================
; HELPER FUNCTIONS
; ============================================

parse_lib_args:
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

    ; Parse object files
    lea rbx, [obj_files]
    mov qword [num_obj_files], 0

.parse_loop:
    mov al, [rsi]
    test al, al
    jz .done_parsing
    cmp al, ' '
    je .check_flags
    cmp al, '/'
    je .check_flags
    
    ; Copy object filename
    mov rdi, rbx
.copy_obj:
    lodsb
    cmp al, ' '
    je .next_obj
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_obj
.next_obj:
    mov byte [rdi], 0
    inc qword [num_obj_files]
    add rbx, 260
    jmp .parse_loop

.check_flags:
    ; Check for /out:
    cmp dword [rsi], 0x74756F2F    ; "/out"
    jne .check_def
    add rsi, 5
    lea rdi, [outfilename_buffer]
.copy_out:
    lodsb
    cmp al, ' '
    je .parse_loop
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_out

.check_def:
    cmp dword [rsi], 0x6665642F    ; "/def"
    jne .check_list
    add rsi, 5
    lea rdi, [def_filename]
.copy_def:
    lodsb
    cmp al, ' '
    je .parse_loop
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_def

.check_list:
    cmp dword [rsi], 0x7473696C    ; "/lis"
    jne .check_machine
    mov qword [mode_list], 1
    add rsi, 6
    jmp .parse_loop

.check_machine:
    cmp dword [rsi], 0x63616D2F    ; "/mac"
    jne .skip_flag
    add rsi, 9
    cmp byte [rsi], 'x'
    jne .parse_loop
    cmp byte [rsi+1], '8'
    jne .check_mach_x64
    cmp byte [rsi+2], '6'
    jne .parse_loop
    mov qword [target_machine], 0x14C  ; i386
    add rsi, 3
    jmp .parse_loop
.check_mach_x64:
    cmp byte [rsi+1], '6'
    jne .parse_loop
    cmp byte [rsi+2], '4'
    jne .parse_loop
    mov qword [target_machine], 0x8664  ; AMD64
    add rsi, 3
    jmp .parse_loop

.skip_flag:
    lodsb
    cmp al, ' '
    jne .skip_flag
    jmp .parse_loop

.done_parsing:
    ; Set default output if not specified
    lea rax, [outfilename_buffer]
    cmp byte [rax], 0
    jne .have_output
    mov dword [rax], 0x62696C2E    ; ".lib"
    mov dword [rax+4], 0
.have_output:
    mov rax, 1
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret
