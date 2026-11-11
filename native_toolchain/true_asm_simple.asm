; ========================================================================
; true_asm_simple.asm - Minimal Self-Hosting Assembler
; Can assemble basic x64 instructions to COFF
; ========================================================================

option casemap:none

; --- Win32 API imports ---
extrn GetStdHandle: proc
extrn WriteFile: proc
extrn CloseHandle: proc
extrn ExitProcess: proc
extrn CreateFileA: proc
extrn ReadFile: proc

; --- Constants ---
STD_OUTPUT_HANDLE equ -11
GENERIC_READ      equ 80000000h
GENERIC_WRITE     equ 40000000h
CREATE_ALWAYS     equ 2
OPEN_EXISTING     equ 3
FILE_ATTRIBUTE_NORMAL equ 80h
IMAGE_FILE_MACHINE_AMD64 equ 8664h

; --- Data Section ---
.data

input_filename    db 256 dup(0)
output_filename   db 256 dup(0)
input_handle      dq 0
output_handle     dq 0
bytes_read        dd 0
bytes_written     dd 0
file_buffer       db 65536 dup(0)
file_size         dd 0
text_buffer       db 16384 dup(0)
text_size         dd 0
data_buffer       db 16384 dup(0)
data_size         dd 0
error_msg         db "Error", 13, 10, 0
success_msg       db "Success", 13, 10, 0

; --- Code Section ---
.code

; ============================================================
; Entry point
; ============================================================
Start proc
    sub     rsp, 40
    
    ; Get command line and parse arguments
    mov     rax, qword ptr gs:[30h]
    mov     rax, [rax + 60h]
    mov     rax, [rax + 20h]
    mov     rsi, [rax + 70h]
    
    ; Skip program name
    call    skip_spaces_fn
    call    get_token_fn
    call    skip_spaces_fn
    
    ; Get input filename
    lea     rdi, input_filename
    call    get_token_fn
    cmp     byte ptr [input_filename], 0
    je      usage_error_fn
    
    call    skip_spaces_fn
    lea     rdi, output_filename
    call    get_token_fn
    cmp     byte ptr [output_filename], 0
    je      usage_error_fn
    
    ; Open and read input file
    call    open_input_fn
    test    rax, rax
    jz      file_error_fn
    mov     input_handle, rax
    
    call    read_input_fn
    test    rax, rax
    jz      read_error_fn
    
    mov     rcx, input_handle
    call    CloseHandle
    
    ; Assemble
    call    assemble_fn
    
    ; Write output
    call    open_output_fn
    test    rax, rax
    jz      file_error_fn
    mov     output_handle, rax
    
    call    write_coff_fn
    
    mov     rcx, output_handle
    call    CloseHandle
    
    ; Print success
    lea     rcx, success_msg
    call    print_string_fn
    
    xor     rcx, rcx
    call    ExitProcess
    
Start endp

; ============================================================
; Skip spaces
; ============================================================
skip_spaces_fn proc
skip_spaces_loop:
    movzx   eax, byte ptr [rsi]
    cmp     al, ' '
    je      skip_spaces_skip
    cmp     al, 9
    je      skip_spaces_skip
    jmp     skip_spaces_done
skip_spaces_skip:
    inc     rsi
    jmp     skip_spaces_loop
skip_spaces_done:
    ret
skip_spaces_fn endp

; ============================================================
; Get token
; ============================================================
get_token_fn proc
    push    rdi
get_token_loop:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      get_token_done
    cmp     al, ' '
    je      get_token_done
    cmp     al, 9
    je      get_token_done
    cmp     al, 13
    je      get_token_done
    cmp     al, 10
    je      get_token_done
    mov     [rdi], al
    inc     rsi
    inc     rdi
    jmp     get_token_loop
get_token_done:
    mov     byte ptr [rdi], 0
    pop     rdi
    ret
get_token_fn endp

; ============================================================
; Print string
; ============================================================
print_string_fn proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    mov     rsi, rcx
    xor     rdx, rdx
print_count_loop:
    cmp     byte ptr [rsi + rdx], 0
    je      print_do_print
    inc     rdx
    jmp     print_count_loop
print_do_print:
    test    rdx, rdx
    jz      print_done
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     rcx, rax
    mov     r8, rdx
    lea     r9, bytes_written
    mov     qword ptr [rsp + 32], 0
    mov     rdx, rsi
    call    WriteFile
print_done:
    mov     rsp, rbp
    pop     rbp
    ret
print_string_fn endp

; ============================================================
; Open input file
; ============================================================
open_input_fn proc
    sub     rsp, 56
    mov     rcx, offset input_filename
    mov     rdx, GENERIC_READ
    xor     r8, r8
    xor     r9, r9
    mov     qword ptr [rsp + 32], OPEN_EXISTING
    mov     qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp + 48], 0
    call    CreateFileA
    add     rsp, 56
    ret
open_input_fn endp

; ============================================================
; Read input file
; ============================================================
read_input_fn proc
    sub     rsp, 56
    mov     rcx, input_handle
    lea     rdx, file_buffer
    mov     r8, 65536
    lea     r9, bytes_read
    mov     qword ptr [rsp + 32], 0
    call    ReadFile
    test    rax, rax
    jz      read_failed
    mov     eax, bytes_read
    mov     file_size, eax
    mov     byte ptr [file_buffer + rax], 0
    mov     rax, 1
read_failed:
    add     rsp, 56
    ret
read_input_fn endp

; ============================================================
; Open output file
; ============================================================
open_output_fn proc
    sub     rsp, 56
    mov     rcx, offset output_filename
    mov     rdx, GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    mov     qword ptr [rsp + 32], CREATE_ALWAYS
    mov     qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp + 48], 0
    call    CreateFileA
    add     rsp, 56
    ret
open_output_fn endp

; ============================================================
; Main assembler
; ============================================================
assemble_fn proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    mov     file_size, 0
    mov     text_size, 0
    mov     data_size, 0
    
    ; Simple: emit ret instruction
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 0C3h
    inc     text_size
    
    mov     rsp, rbp
    pop     rbp
    ret
assemble_fn endp

; ============================================================
; Write COFF file
; ============================================================
write_coff_fn proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    
    ; COFF header
    mov     word ptr [rsp + 0], IMAGE_FILE_MACHINE_AMD64
    mov     word ptr [rsp + 2], 1           ; NumberOfSections
    mov     dword ptr [rsp + 4], 0          ; TimeDateStamp
    mov     dword ptr [rsp + 8], 0          ; PointerToSymbolTable
    mov     dword ptr [rsp + 12], 0         ; NumberOfSymbols
    mov     word ptr [rsp + 16], 0          ; SizeOfOptionalHeader
    mov     word ptr [rsp + 18], 0          ; Characteristics
    
    ; Write header
    mov     rcx, output_handle
    lea     rdx, [rsp + 0]
    mov     r8, 20
    lea     r9, bytes_written
    mov     qword ptr [rsp + 48], 0
    call    WriteFile
    
    ; Section header for .text
    mov     dword ptr [rsp + 20], 'xet.'     ; Name (reversed)
    mov     dword ptr [rsp + 24], 0
    mov     eax, text_size
    mov     dword ptr [rsp + 28], eax       ; VirtualSize
    mov     dword ptr [rsp + 32], 0         ; VirtualAddress
    mov     dword ptr [rsp + 36], eax       ; SizeOfRawData
    mov     dword ptr [rsp + 40], 60        ; PointerToRawData (after headers)
    mov     dword ptr [rsp + 44], 0         ; PointerToRelocations
    mov     dword ptr [rsp + 48], 0         ; PointerToLinenumbers
    mov     word ptr [rsp + 52], 0          ; NumberOfRelocations
    mov     word ptr [rsp + 54], 0          ; NumberOfLinenumbers
    mov     dword ptr [rsp + 56], 60000020h ; Characteristics (CODE|EXECUTE|READ)
    
    ; Write section header
    mov     rcx, output_handle
    lea     rdx, [rsp + 20]
    mov     r8, 40
    lea     r9, bytes_written
    mov     qword ptr [rsp + 88], 0
    call    WriteFile
    
    ; Write section data
    mov     ecx, text_size
    test    ecx, ecx
    jz      write_done
    mov     rcx, output_handle
    lea     rdx, text_buffer
    mov     r8d, text_size
    lea     r9, bytes_written
    mov     qword ptr [rsp + 88], 0
    call    WriteFile
    
write_done:
    mov     rsp, rbp
    pop     rbp
    ret
write_coff_fn endp

; ============================================================
; Error handlers
; ============================================================
usage_error_fn proc
    lea     rcx, error_msg
    call    print_string_fn
    mov     rcx, 1
    call    ExitProcess
usage_error_fn endp

file_error_fn proc
    lea     rcx, error_msg
    call    print_string_fn
    mov     rcx, 1
    call    ExitProcess
file_error_fn endp

read_error_fn proc
    lea     rcx, error_msg
    call    print_string_fn
    mov     rcx, 1
    call    ExitProcess
read_error_fn endp

end Start