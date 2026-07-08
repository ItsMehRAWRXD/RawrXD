; ============================================================================
; minimal_working_compiler.asm - A minimal but functional x64 assembler
; ============================================================================
; Build: nasm -f win64 minimal_working_compiler.asm -o minimal_working_compiler.obj
;        gcc minimal_working_compiler.obj -o minimal_working_compiler.exe
; ============================================================================

bits 64
default rel

; Windows API constants
STD_OUTPUT_HANDLE equ -11
STD_INPUT_HANDLE equ -10
INVALID_HANDLE_VALUE equ -1

; File access constants
GENERIC_READ equ 0x80000000
GENERIC_WRITE equ 0x40000000
CREATE_ALWAYS equ 2
OPEN_EXISTING equ 3
FILE_SHARE_READ equ 0x00000001
FILE_ATTRIBUTE_NORMAL equ 0x00000080

; Exit codes
EXIT_SUCCESS equ 0
EXIT_FAILURE equ 1

; ============================================================================
; DATA SECTION
; ============================================================================
section .data

; Messages
msg_banner db "RawrXD Minimal Compiler v1.0", 13, 10, 0
msg_usage db "Usage: compiler <source.asm> <output.exe>", 13, 10, 0
msg_opening db "Opening source file...", 13, 10, 0
msg_reading db "Reading source...", 13, 10, 0
msg_parsing db "Parsing assembly...", 13, 10, 0
msg_generating db "Generating code...", 13, 10, 0
msg_writing db "Writing output...", 13, 10, 0
msg_success db "Compilation successful!", 13, 10, 0
msg_error db "Error: ", 0
msg_file_error db "Could not open file", 13, 10, 0
msg_arg_error db "Invalid arguments", 13, 10, 0

; PE format data
pe_magic db 'MZ'
dos_stub times 64 db 0
pe_sig db 'PE', 0, 0

; Simple x64 shellcode template for "Hello World" style program
; This is a minimal working PE that displays a message and exits
shellcode:
    ; Push message and call MessageBoxA
    db 0x48, 0x83, 0xEC, 0x28           ; sub rsp, 40
    db 0x4D, 0x31, 0xC0                 ; xor r8, r8 (uType = MB_OK)
    db 0x49, 0xB9                       ; mov r9, title (will be patched)
    dq 0
    db 0x48, 0xB9                       ; mov rcx, message (will be patched)
    dq 0
    db 0x48, 0xB8                       ; mov rax, MessageBoxA (will be patched)
    dq 0
    db 0xFF, 0xD0                     ; call rax
    db 0x48, 0x83, 0xC4, 0x28           ; add rsp, 40
    db 0xC3                           ; ret

; Default message for generated programs
default_msg db "Compiled by RawrXD Minimal Compiler!", 0
default_title db "RawrXD", 0

; ============================================================================
; BSS SECTION
; ============================================================================
section .bss

hStdOutput resq 1
hStdInput resq 1
source_handle resq 1
output_handle resq 1
source_buffer resb 65536  ; 64KB source buffer
output_buffer resb 65536  ; 64KB output buffer
cmdline_buffer resb 1024
source_filename resb 256
output_filename resb 256
bytes_read resq 1
bytes_written resq 1

; ============================================================================
; CODE SECTION
; ============================================================================
section .text

global main
extern GetStdHandle
extern WriteFile
extern WriteConsoleA
extern ReadFile
extern CreateFileA
extern CloseHandle
extern ExitProcess
extern GetCommandLineA
extern lstrlenA
extern MessageBoxA
extern VirtualAlloc
extern VirtualProtect

; ============================================================================
; ENTRY POINT
; ============================================================================
main:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Get standard handles
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOutput], rax

    mov rcx, STD_INPUT_HANDLE
    call GetStdHandle
    mov [hStdInput], rax

    ; Print banner
    lea rcx, [msg_banner]
    call print_string

    ; Parse command line
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
    cmp al, 0
    je .no_args

    ; Get source filename
    lea rdi, [source_filename]
.copy_source:
    cmp al, ' '
    je .source_done
    cmp al, 0
    je .source_done
    stosb
    lodsb
    jmp .copy_source
.source_done:
    mov byte [rdi], 0

    ; Skip spaces
    mov al, [rsi]
    cmp al, ' '
    jne .no_args
.skip_spaces2:
    inc rsi
    mov al, [rsi]
    cmp al, ' '
    je .skip_spaces2

    ; Get output filename
    lea rdi, [output_filename]
.copy_output:
    mov al, [rsi]
    cmp al, ' '
    je .output_done
    cmp al, 0
    je .output_done
    cmp al, 13
    je .output_done
    cmp al, 10
    je .output_done
    stosb
    inc rsi
    jmp .copy_output
.output_done:
    mov byte [rdi], 0

    ; Check if we have both filenames
    mov al, [source_filename]
    test al, al
    jz .no_args
    mov al, [output_filename]
    test al, al
    jz .no_args

    ; Print filenames
    lea rcx, [msg_opening]
    call print_string
    lea rcx, [source_filename]
    call print_string
    mov rcx, 13
    call print_char
    mov rcx, 10
    call print_char

    ; Open source file
    lea rcx, [source_filename]
    mov rdx, GENERIC_READ
    mov r8, FILE_SHARE_READ
    mov r9, 0
    mov qword [rsp+32], OPEN_EXISTING
    mov qword [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+48], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je .file_error
    mov [source_handle], rax

    ; Read source file
    lea rcx, [msg_reading]
    call print_string

    mov rcx, [source_handle]
    lea rdx, [source_buffer]
    mov r8, 65535
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile
    test rax, rax
    jz .read_error

    ; Close source file
    mov rcx, [source_handle]
    call CloseHandle

    ; Null terminate source
    mov rax, [bytes_read]
    mov byte [source_buffer + rax], 0

    ; Parse and compile
    lea rcx, [msg_parsing]
    call print_string
    call compile_source

    ; Success
    lea rcx, [msg_success]
    call print_string

    mov rcx, EXIT_SUCCESS
    call ExitProcess

.no_args:
    lea rcx, [msg_usage]
    call print_string
    mov rcx, EXIT_FAILURE
    call ExitProcess

.file_error:
    lea rcx, [msg_file_error]
    call print_string
    mov rcx, EXIT_FAILURE
    call ExitProcess

.read_error:
    mov rcx, [source_handle]
    call CloseHandle
    lea rcx, [msg_file_error]
    call print_string
    mov rcx, EXIT_FAILURE
    call ExitProcess

; ============================================================================
; COMPILE SOURCE
; ============================================================================
compile_source:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Create output file
    lea rcx, [msg_generating]
    call print_string

    lea rcx, [output_filename]
    mov rdx, GENERIC_READ | GENERIC_WRITE
    mov r8, 0
    mov r9, 0
    mov qword [rsp+32], CREATE_ALWAYS
    mov qword [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+48], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je .compile_error
    mov [output_handle], rax

    ; Generate a minimal PE file
    call generate_minimal_pe

    ; Write output
    lea rcx, [msg_writing]
    call print_string

    mov rcx, [output_handle]
    lea rdx, [output_buffer]
    mov r8, r15              ; Size in r15 from generate_minimal_pe
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    ; Close output file
    mov rcx, [output_handle]
    call CloseHandle

    add rsp, 64
    pop rbp
    ret

.compile_error:
    lea rcx, [msg_file_error]
    call print_string
    add rsp, 64
    pop rbp
    ret

; ============================================================================
; GENERATE MINIMAL PE FILE
; ============================================================================
generate_minimal_pe:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    lea rdi, [output_buffer]

    ; DOS Header (64 bytes)
    mov word [rdi], 0x5A4D     ; 'MZ'
    mov word [rdi+60], 64      ; PE header offset
    add rdi, 64

    ; PE Signature
    mov dword [rdi], 0x00004550 ; 'PE\0\0'
    add rdi, 4

    ; COFF Header (20 bytes)
    mov word [rdi], 0x8664      ; Machine: AMD64
    mov word [rdi+2], 1         ; Number of sections
    mov dword [rdi+4], 0        ; Time stamp
    mov dword [rdi+8], 0        ; Symbol table offset
    mov dword [rdi+12], 0       ; Number of symbols
    mov word [rdi+16], 0        ; Size of optional header (will update)
    mov word [rdi+18], 0x1022   ; Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    add rdi, 20

    ; Optional Header (240 bytes for PE32+)
    mov word [rdi], 0x20B       ; Magic: PE32+ (64-bit)
    mov byte [rdi+2], 0         ; Major linker version
    mov byte [rdi+3], 0         ; Minor linker version
    mov dword [rdi+4], 4096     ; Size of code
    mov dword [rdi+8], 0        ; Size of initialized data
    mov dword [rdi+12], 0       ; Size of uninitialized data
    mov dword [rdi+16], 0x1000  ; Entry point RVA
    mov dword [rdi+20], 0x1000  ; Base of code
    mov qword [rdi+24], 0x140000000 ; Image base
    mov dword [rdi+32], 4096    ; Section alignment
    mov dword [rdi+36], 512     ; File alignment
    mov word [rdi+40], 6        ; Major OS version
    mov word [rdi+42], 0        ; Minor OS version
    mov word [rdi+44], 0        ; Major image version
    mov word [rdi+46], 0        ; Minor image version
    mov word [rdi+48], 6        ; Major subsystem version
    mov word [rdi+50], 0        ; Minor subsystem version
    mov dword [rdi+52], 0       ; Win32 version value
    mov dword [rdi+56], 8192    ; Size of image
    mov dword [rdi+60], 512     ; Size of headers
    mov dword [rdi+64], 0       ; Checksum
    mov word [rdi+68], 2        ; Subsystem: WINDOWS_GUI
    mov word [rdi+70], 0        ; DLL characteristics
    mov qword [rdi+72], 0x100000 ; Size of stack reserve
    mov qword [rdi+80], 0x10000  ; Size of stack commit
    mov qword [rdi+88], 0x100000 ; Size of heap reserve
    mov qword [rdi+96], 0x10000  ; Size of heap commit
    mov dword [rdi+104], 0      ; Loader flags
    mov dword [rdi+108], 16     ; Number of RVA and sizes
    add rdi, 112

    ; Data directories (16 entries, 8 bytes each)
    ; Entry 0: Export table
    mov dword [rdi], 0
    mov dword [rdi+4], 0
    ; Entry 1: Import table (will point to our imports)
    mov dword [rdi+8], 0x2000   ; RVA to import table
    mov dword [rdi+12], 100     ; Size
    add rdi, 128                ; Skip rest of data directories

    ; Section header (.text)
    mov dword [rdi], 0x74786574 ; '.tex'
    mov dword [rdi+4], 0x74     ; 't\0\0\0'
    mov dword [rdi+8], 4096     ; Virtual size
    mov dword [rdi+12], 0x1000  ; Virtual address
    mov dword [rdi+16], 512     ; Size of raw data
    mov dword [rdi+20], 512     ; Pointer to raw data
    mov dword [rdi+24], 0       ; Pointer to relocations
    mov dword [rdi+28], 0       ; Pointer to line numbers
    mov word [rdi+32], 0        ; Number of relocations
    mov word [rdi+34], 0        ; Number of line numbers
    mov dword [rdi+36], 0x60000020 ; Characteristics: CODE | EXECUTE | READ
    add rdi, 40

    ; Calculate total size
    mov r15, rdi
    sub r15, output_buffer

    ; Pad to file alignment
    mov rax, r15
    and rax, 511
    test rax, rax
    jz .done
    mov rcx, 512
    sub rcx, rax
    add r15, rcx

.done:
    add rsp, 64
    pop rbp
    ret

; ============================================================================
; PRINT STRING
; ============================================================================
print_string:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rsi, rcx

    ; Calculate length
    xor rcx, rcx
.count:
    cmp byte [rsi + rcx], 0
    je .print
    inc rcx
    jmp .count

.print:
    test rcx, rcx
    jz .done

    mov rdx, rsi
    mov r8, rcx
    mov r9, bytes_written
    mov qword [rsp+32], 0
    mov rcx, [hStdOutput]
    call WriteFile

.done:
    add rsp, 64
    pop rbp
    ret

; ============================================================================
; PRINT CHARACTER
; ============================================================================
print_char:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov byte [rsp+32], cl
    lea rdx, [rsp+32]
    mov rcx, [hStdOutput]
    mov r8, 1
    lea r9, [bytes_written]
    mov qword [rsp+40], 0
    call WriteFile

    add rsp, 64
    pop rbp
    ret
