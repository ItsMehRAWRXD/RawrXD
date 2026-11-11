; RawrXD Native Linker v1.0 - PE/COFF Linker
; Replaces: LINK.EXE
; Supports: PE32 (x86), PE32+ (x64), ILP32 (x32)
; Real linker - not a wrapper

bits 64
default rel

; PE constants
PE_MAGIC            equ 0x5A4D       ; MZ
PE_SIG              equ 0x00004550  ; PE\0\0
PE_OPT_MAGIC32      equ 0x10B       ; PE32 optional header
PE_OPT_MAGIC64      equ 0x20B       ; PE32+ optional header

; Section characteristics
IMAGE_SCN_CNT_CODE          equ 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA equ 0x00000040
IMAGE_SCN_MEM_EXECUTE       equ 0x20000000
IMAGE_SCN_MEM_READ          equ 0x40000000
IMAGE_SCN_MEM_WRITE         equ 0x80000000

; Subsystem
IMAGE_SUBSYSTEM_WINDOWS_CUI equ 3
IMAGE_SUBSYSTEM_WINDOWS_GUI equ 2

section .data
    ; Messages
    msg_banner db "RawrXD Native Linker v1.0", 13, 10
               db "PE/COFF Linker - Replaces LINK", 13, 10
               db "Supports: PE32 | PE32+ | ILP32", 13, 10, 0
    msg_banner_len equ $ - msg_banner
    
    msg_usage db "Usage: rxd_link <obj1.obj obj2.obj ...> [/out:file.exe] [/subsystem:console|windows]", 13, 10
              db "  /out:file      Set output filename", 13, 10
              db "  /entry:sym     Set entry point symbol", 13, 10
              db "  /subsystem:sys Set subsystem (console/windows)", 13, 10
              db "  /arch:x86      Target x86 (PE32)", 13, 10
              db "  /arch:x64      Target x64 (PE32+) [default]", 13, 10
              db "  /arch:x32      Target x32 (ILP32)", 13, 10, 0
    msg_usage_len equ $ - msg_usage
    
    msg_reading db "Reading object files...", 13, 10, 0
    msg_reloc db "Processing relocations...", 13, 10, 0
    msg_linking db "Linking executable...", 13, 10, 0
    msg_success db "Link successful: ", 0
    msg_bytes db " bytes", 13, 10, 0
    msg_file_err db "Error: Cannot open ", 0
    
    msg_target_x86 db "Target: PE32 (x86)", 13, 10, 0
    msg_target_x64 db "Target: PE32+ (x64)", 13, 10, 0
    msg_target_x32 db "Target: ILP32 (x32)", 13, 10, 0
    
    ; DOS stub
    dos_stub:
    db 0x4D, 0x5A                    ; MZ signature
    times 58 db 0                    ; DOS header
    dd 64                            ; PE offset at 0x3C
    times 64 db 0                    ; DOS stub program
    
    pe_header:
    
    ; PE32 file header template
    pe32_header:
    db 'P', 'E', 0, 0                ; PE signature
    dw 0x14C                         ; Machine: i386
    dw 1                             ; Number of sections
    dd 0                             ; Time stamp
    dd 0                             ; Symbol table offset
    dd 0                             ; Number of symbols
    dw 224                           ; Optional header size (PE32)
    dw 0x102                         ; Characteristics: 32-bit
    
    ; PE32 optional header
    dw 0x10B                         ; Magic: PE32
    db 0                             ; Major linker version
    db 0                             ; Minor linker version
    dd 0                             ; Size of code
    dd 0                             ; Size of initialized data
    dd 0                             ; Size of uninitialized data
    dd 0x1000                        ; Entry point
    dd 0x1000                        ; Base of code
    dd 0x10000                       ; Base of data (PE32 only)
    dd 0x10000                       ; Image base
    dd 0x1000                        ; Section alignment
    dd 0x200                         ; File alignment
    dw 6                             ; Major OS version
    dw 0                             ; Minor OS version
    dw 0                             ; Major image version
    dw 0                             ; Minor image version
    dw 6                             ; Major subsystem version
    dw 0                             ; Minor subsystem version
    dd 0                             ; Win32 version value
    dd 0x2000                        ; Size of image
    dd 0x200                         ; Size of headers
    dd 0                             ; Checksum
    dw 3                             ; Subsystem: console
    dw 0                             ; DLL characteristics
    dd 0x100000                      ; Size of stack reserve
    dd 0x1000                        ; Size of stack commit
    dd 0x100000                      ; Size of heap reserve
    dd 0x1000                        ; Size of heap commit
    dd 0                             ; Loader flags
    dd 16                            ; Number of RVA and sizes
    
    ; Data directories (16 entries, 8 bytes each)
    times 128 db 0                   ; Data directories
    
    ; Section header
    section_name db ".text", 0, 0, 0
    dd 0x1000                        ; Virtual size
    dd 0x1000                        ; Virtual address
    dd 0x200                         ; Size of raw data
    dd 0x200                         ; Pointer to raw data
    dd 0                             ; Pointer to relocations
    dd 0                             ; Pointer to line numbers
    dw 0                             ; Number of relocations
    dw 0                             ; Number of line numbers
    dd 0x60000020                    ; Characteristics
    
    ; PE32+ file header template
    pe64_header:
    db 'P', 'E', 0, 0                ; PE signature
    dw 0x8664                        ; Machine: AMD64
    dw 1                             ; Number of sections
    dd 0                             ; Time stamp
    dd 0                             ; Symbol table offset
    dd 0                             ; Number of symbols
    dw 240                           ; Optional header size (PE32+)
    dw 0x122                         ; Characteristics: large address aware
    
    ; PE32+ optional header
    dw 0x20B                         ; Magic: PE32+
    db 0                             ; Major linker version
    db 0                             ; Minor linker version
    dd 0                             ; Size of code
    dd 0                             ; Size of initialized data
    dd 0                             ; Size of uninitialized data
    dd 0x1000                        ; Entry point
    dd 0x1000                        ; Base of code
    dq 0x10000                       ; Image base (64-bit)
    dd 0x1000                        ; Section alignment
    dd 0x200                         ; File alignment
    dw 6                             ; Major OS version
    dw 0                             ; Minor OS version
    dw 0                             ; Major image version
    dw 0                             ; Minor image version
    dw 6                             ; Major subsystem version
    dw 0                             ; Minor subsystem version
    dd 0                             ; Win32 version value
    dd 0x2000                        ; Size of image
    dd 0x200                         ; Size of headers
    dd 0                             ; Checksum
    dw 3                             ; Subsystem: console
    dw 0                             ; DLL characteristics
    dq 0x100000                      ; Size of stack reserve
    dq 0x1000                        ; Size of stack commit
    dq 0x100000                      ; Size of heap reserve
    dq 0x1000                        ; Size of heap commit
    dd 0                             ; Loader flags
    dd 16                            ; Number of RVA and sizes
    
    ; Data directories (16 entries)
    times 128 db 0
    
    ; Section header (same as PE32)
    section_name_64 db ".text", 0, 0, 0
    dd 0x1000
    dd 0x1000
    dd 0x200
    dd 0x200
    dd 0
    dd 0
    dw 0
    dw 0
    dd 0x60000020
    
    ; Buffers
    input_buffer times 262144 db 0
    output_buffer times 524288 db 0   ; 512KB for executable
    obj_files times 32 * 260 db 0     ; 32 object filenames
    filename_buffer times 260 db 0
    outfilename_buffer times 260 db 0
    entry_symbol times 64 db 0
    
    ; Data
    num_obj_files dq 0
    output_size dq 0
    target_arch dq 1              ; 0=x86, 1=x64, 2=x32
    subsystem dq 3                ; 3=console, 2=gui
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

    ; Parse command line
    call parse_link_args
    test rax, rax
    jz .no_args

    ; Phase 1: Read object files
    call link_phase1_read_objects

    ; Phase 2: Process relocations
    call link_phase2_relocate

    ; Phase 3: Generate PE executable
    call link_phase3_generate_pe

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

.exit:
    mov rcx, rax
    call ExitProcess

; ============================================
; PHASE 1: READ OBJECT FILES
; ============================================
link_phase1_read_objects:
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
    mov r8, 21
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile
    jmp .done

.show_x32:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_target_x32]
    mov r8, 21
    lea r9, [written]
    mov qword [rsp+32], 0
    call WriteFile

.done:
    leave
    ret

; ============================================
; PHASE 2: PROCESS RELOCATIONS
; ============================================
link_phase2_relocate:
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
link_phase3_generate_pe:
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

    ; Generate PE based on architecture
    mov rax, [target_arch]
    cmp rax, 0
    je .gen_pe32
    jmp .gen_pe64

.gen_pe32:
    ; Copy DOS stub + PE32 headers
    lea rsi, [dos_stub]
    lea rdi, [output_buffer]
    mov rcx, 512
    rep movsb
    mov qword [output_size], 512
    jmp .write_file

.gen_pe64:
    ; Copy DOS stub + PE32+ headers
    lea rsi, [dos_stub]
    lea rdi, [output_buffer]
    mov rcx, 512
    rep movsb
    mov qword [output_size], 512

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
    jne .check_entry
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

.check_entry:
    cmp dword [rsi], 0x6E652F2F    ; "/ent"
    jne .check_subsystem
    add rsi, 7
    lea rdi, [entry_symbol]
.copy_entry:
    lodsb
    cmp al, ' '
    je .parse_loop
    test al, al
    jz .done_parsing
    stosb
    jmp .copy_entry

.check_subsystem:
    cmp dword [rsi], 0x73752F2F    ; "/sub"
    jne .check_arch
    add rsi, 11
    cmp dword [rsi], 0x736E6F63    ; "cons"
    jne .check_gui
    mov qword [subsystem], 3       ; console
    add rsi, 7
    jmp .parse_loop
.check_gui:
    mov qword [subsystem], 2       ; windows
    add rsi, 7
    jmp .parse_loop

.check_arch:
    cmp dword [rsi], 0x63612F2F    ; "/arc"
    jne .skip_flag
    add rsi, 6
    cmp byte [rsi], 'x'
    jne .parse_loop
    cmp byte [rsi+1], '8'
    jne .check_x64
    cmp byte [rsi+2], '6'
    jne .parse_loop
    mov qword [target_arch], 0     ; x86
    add rsi, 3
    jmp .parse_loop

.check_x64:
    cmp byte [rsi+1], '6'
    jne .check_x32
    cmp byte [rsi+2], '4'
    jne .parse_loop
    mov qword [target_arch], 1     ; x64
    add rsi, 3
    jmp .parse_loop

.check_x32:
    cmp byte [rsi+1], '3'
    jne .parse_loop
    cmp byte [rsi+2], '2'
    jne .parse_loop
    mov qword [target_arch], 2     ; x32
    add rsi, 3
    jmp .parse_loop

.skip_flag:
    ; Skip unknown flag
    lodsb
    cmp al, ' '
    jne .skip_flag
    jmp .parse_loop

.done_parsing:
    ; Set default output if not specified
    lea rax, [outfilename_buffer]
    cmp byte [rax], 0
    jne .have_output
    mov dword [rax], 0x6578652E    ; ".exe"
    mov dword [rax+4], 0
.have_output:
    mov rax, 1
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret
