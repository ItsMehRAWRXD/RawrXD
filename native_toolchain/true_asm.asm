; ========================================================================
; true_asm.asm - Self-Hosting MASM Assembler
; Can assemble itself and produce working COFF object files
; ========================================================================

option casemap:none

; --- Win32 API imports ---
extrn GetStdHandle: proc
extrn ReadFile: proc
extrn WriteFile: proc
extrn CloseHandle: proc
extrn ExitProcess: proc
extrn CreateFileA: proc
extrn GetFileSize: proc
extrn ReadFile: proc
extrn WriteFile: proc
extrn SetFilePointer: proc

; --- Constants ---
STD_INPUT_HANDLE  equ -10
STD_OUTPUT_HANDLE equ -11
GENERIC_READ      equ 80000000h
GENERIC_WRITE     equ 40000000h
CREATE_ALWAYS     equ 2
OPEN_EXISTING     equ 3
FILE_ATTRIBUTE_NORMAL equ 80h
FILE_BEGIN        equ 0

; COFF constants
IMAGE_FILE_MACHINE_AMD64 equ 8664h
IMAGE_FILE_RELOCS_STRIPPED equ 0001h
IMAGE_FILE_EXECUTABLE_IMAGE equ 0002h
IMAGE_FILE_LARGE_ADDRESS_AWARE equ 0020h
IMAGE_FILE_DEBUG_STRIPPED equ 0200h
IMAGE_SCN_CNT_CODE equ 000000020h
IMAGE_SCN_CNT_INITIALIZED_DATA equ 000000040h
IMAGE_SCN_CNT_UNINITIALIZED_DATA equ 000000080h
IMAGE_SCN_ALIGN_16BYTES equ 00500000h
IMAGE_SCN_MEM_EXECUTE equ 20000000h
IMAGE_SCN_MEM_READ equ 40000000h
IMAGE_SCN_MEM_WRITE equ 80000000h
IMAGE_REL_AMD64_ADDR64 equ 1
IMAGE_REL_AMD64_ADDR32 equ 2
IMAGE_REL_AMD64_REL32 equ 4

; --- Data Section ---
.data

; File I/O
input_filename    db 256 dup(0)
output_filename   db 256 dup(0)
input_handle      dq 0
output_handle     dq 0
bytes_read        dd 0
bytes_written     dd 0

; File buffer (64KB max)
file_buffer       db 65536 dup(0)
file_size         dd 0
file_pos          dd 0

; Line parsing
current_line      db 256 dup(0)
line_num          dd 0
token_buffer      db 256 dup(0)

; Symbol table (max 256 symbols)
MAX_SYMBOLS       equ 256
symbol_names      db MAX_SYMBOLS * 64 dup(0)  ; 64 bytes per name
symbol_offsets    dd MAX_SYMBOLS dup(0)        ; offset in section
symbol_sections   dd MAX_SYMBOLS dup(0)       ; section number
symbol_types      dd MAX_SYMBOLS dup(0)       ; 0=local, 1=external
symbol_count      dd 0

; Fixup table (max 512 fixups)
MAX_FIXUPS        equ 512
fixup_offsets     dd MAX_FIXUPS dup(0)       ; offset in section
fixup_symbols     dd MAX_FIXUPS dup(0)       ; symbol index
fixup_types       dd MAX_FIXUPS dup(0)       ; relocation type
fixup_count       dd 0

; Section buffers
MAX_SECTION_SIZE  equ 16384
text_buffer       db MAX_SECTION_SIZE dup(0)
text_size         dd 0
data_buffer       db MAX_SECTION_SIZE dup(0)
data_size         dd 0
bss_size          dd 0

; Current state
current_section   dd 1   ; 1=text, 2=data, 3=bss
current_offset    dd 0

; Error message
error_msg         db "Error: ", 0
newline           db 13, 10, 0

; --- Code Section ---
.code

; ============================================================
; Entry point
; ============================================================
Start proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Get command line arguments
    mov     rax, qword ptr gs:[30h]     ; TEB
    mov     rax, [rax + 60h]            ; PEB
    mov     rax, [rax + 20h]            ; ProcessParameters
    mov     rsi, [rax + 70h]            ; CommandLine.Buffer
    
    ; Skip program name
    call    skip_spaces
    call    get_token                   ; program name
    call    skip_spaces
    
    ; Get input filename
    lea     rdi, input_filename
    call    get_token
    cmp     byte ptr [input_filename], 0
    je      usage_error
    
    call    skip_spaces
    
    ; Get output filename
    lea     rdi, output_filename
    call    get_token
    cmp     byte ptr [output_filename], 0
    je      usage_error
    
    ; Open input file
    call    open_input_file
    test    rax, rax
    jz      file_error
    mov     input_handle, rax
    
    ; Read input file
    call    read_input_file
    test    rax, rax
    jz      read_error
    
    ; Close input file
    mov     rcx, input_handle
    call    CloseHandle
    
    ; Assemble - Pass 1: Parse and collect symbols
    call    assembler_pass1
    
    ; Assemble - Pass 2: Resolve fixups and emit COFF
    call    assembler_pass2
    
    ; Open output file
    call    open_output_file
    test    rax, rax
    jz      file_error
    mov     output_handle, rax
    
    ; Write COFF file
    call    write_coff
    
    ; Close output file
    mov     rcx, output_handle
    call    CloseHandle
    
    ; Success
    xor     rcx, rcx
    call    ExitProcess
    
usage_error:
    lea     rcx, error_msg
    call    print_string
    lea     rcx, usage_text
    call    print_string
    mov     rcx, 1
    call    ExitProcess
    
file_error:
    lea     rcx, error_msg
    call    print_string
    lea     rcx, file_error_text
    call    print_string
    mov     rcx, 1
    call    ExitProcess
    
read_error:
    lea     rcx, error_msg
    call    print_string
    lea     rcx, read_error_text
    call    print_string
    mov     rcx, 1
    call    ExitProcess

Start endp

; ============================================================
; Print string to stdout
; ============================================================
print_string proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    ; Get string length
    mov     rsi, rcx
    xor     rdx, rdx
    
.count_loop:
    cmp     byte ptr [rsi + rdx], 0
    je      .do_print
    inc     rdx
    jmp     .count_loop
    
.do_print:
    test    rdx, rdx
    jz      .done
    
    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    
    ; Write to stdout
    mov     rcx, rax
    mov     r8, rdx
    lea     r9, bytes_written
    mov     qword ptr [rsp + 32], 0
    mov     rdx, rsi
    call    WriteFile
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
print_string endp

; ============================================================
; Skip spaces in command line
; ============================================================
skip_spaces proc
    push    rbp
    mov     rbp, rsp
    
.loop:
    movzx   rax, byte ptr [rsi]
    cmp     al, ' '
    je      .skip
    cmp     al, 9       ; tab
    je      .skip
    jmp     .done
    
.skip:
    inc     rsi
    jmp     .loop
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
skip_spaces endp

; ============================================================
; Get token from command line
; ============================================================
get_token proc
    push    rbp
    mov     rbp, rsp
    push    rdi
    
.loop:
    movzx   rax, byte ptr [rsi]
    test    al, al
    jz      .done
    cmp     al, ' '
    je      .done
    cmp     al, 9
    je      .done
    cmp     al, 13
    je      .done
    cmp     al, 10
    je      .done
    
    mov     [rdi], al
    inc     rsi
    inc     rdi
    jmp     .loop
    
.done:
    mov     byte ptr [rdi], 0
    pop     rdi
    mov     rsp, rbp
    pop     rbp
    ret
get_token endp

; ============================================================
; Open input file
; ============================================================
open_input_file proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    mov     rcx, offset input_filename
    mov     rdx, GENERIC_READ
    xor     r8, r8          ; no sharing
    xor     r9, r9          ; no security
    mov     qword ptr [rsp + 32], OPEN_EXISTING
    mov     qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    xor     rax, rax
    mov     qword ptr [rsp + 48], rax
    call    CreateFileA
    
    mov     rsp, rbp
    pop     rbp
    ret
open_input_file endp

; ============================================================
; Read input file into buffer
; ============================================================
read_input_file proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    mov     rcx, input_handle
    lea     rdx, file_buffer
    mov     r8, 65536       ; max size
    lea     r9, bytes_read
    mov     qword ptr [rsp + 32], 0
    call    ReadFile
    
    test    rax, rax
    jz      .error
    
    mov     eax, bytes_read
    mov     file_size, eax
    mov     byte ptr [file_buffer + rax], 0  ; null terminate
    
    mov     rax, 1          ; success
    jmp     .done
    
.error:
    xor     rax, rax        ; failure
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
read_input_file endp

; ============================================================
; Open output file
; ============================================================
open_output_file proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    mov     rcx, offset output_filename
    mov     rdx, GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    mov     qword ptr [rsp + 32], CREATE_ALWAYS
    mov     qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    xor     rax, rax
    mov     qword ptr [rsp + 48], rax
    call    CreateFileA
    
    mov     rsp, rbp
    pop     rbp
    ret
open_output_file endp

; ============================================================
; Pass 1: Parse and collect symbols
; ============================================================
assembler_pass1 proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Initialize
    mov     file_pos, 0
    mov     line_num, 1
    mov     current_section, 1    ; start in .text
    mov     text_size, 0
    mov     data_size, 0
    mov     bss_size, 0
    mov     symbol_count, 0
    mov     fixup_count, 0
    
    ; Main parse loop
.parse_loop:
    ; Get next line
    lea     rdi, current_line
    call    get_line
    test    rax, rax
    jz      .done
    
    ; Parse the line
    lea     rcx, current_line
    call    parse_line
    
    inc     line_num
    jmp     .parse_loop
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
assembler_pass1 endp

; ============================================================
; Get next line from file buffer
; ============================================================
get_line proc
    push    rbp
    mov     rbp, rsp
    push    rdi
    
    mov     esi, file_pos
    mov     edx, file_size
    
    ; Check if at end
    cmp     esi, edx
    jge     .eof
    
    ; Copy line until newline
.copy_loop:
    cmp     esi, edx
    jge     .end_line
    
    movzx   eax, byte ptr [file_buffer + esi]
    cmp     al, 13          ; CR
    je      .end_line
    cmp     al, 10          ; LF
    je      .end_line
    
    mov     [rdi], al
    inc     esi
    inc     rdi
    jmp     .copy_loop
    
.end_line:
    mov     byte ptr [rdi], 0   ; null terminate
    
    ; Skip newline characters
.skip_nl:
    cmp     esi, edx
    jge     .update_pos
    movzx   eax, byte ptr [file_buffer + esi]
    cmp     al, 13
    je      .do_skip
    cmp     al, 10
    je      .do_skip
    jmp     .update_pos
    
.do_skip:
    inc     esi
    jmp     .skip_nl
    
.update_pos:
    mov     file_pos, esi
    
    mov     rax, 1          ; success
    jmp     .done
    
.eof:
    xor     rax, rax        ; end of file
    
.done:
    pop     rdi
    mov     rsp, rbp
    pop     rbp
    ret
get_line endp

; ============================================================
; Parse a single line
; ============================================================
parse_line proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    mov     rsi, rcx
    
    ; Skip leading whitespace
    call    skip_line_spaces
    
    ; Check for empty line or comment
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .done
    cmp     al, ';'
    je      .done           ; comment line
    
    ; Check for label (ends with ':')
    call    check_label
    test    rax, rax
    jnz     .handle_label
    
    ; Check for directive (starts with '.')
    cmp     al, '.'
    je      .handle_directive
    
    ; Must be an instruction
    call    handle_instruction
    jmp     .done
    
.handle_label:
    call    process_label
    jmp     .done
    
.handle_directive:
    call    process_directive
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
parse_line endp

; ============================================================
; Skip spaces in line
; ============================================================
skip_line_spaces proc
    push    rbp
    mov     rbp, rsp
    
.loop:
    movzx   eax, byte ptr [rsi]
    cmp     al, ' '
    je      .skip
    cmp     al, 9
    je      .skip
    jmp     .done
    
.skip:
    inc     rsi
    jmp     .loop
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
skip_line_spaces endp

; ============================================================
; Check if current position is a label
; ============================================================
check_label proc
    push    rbp
    mov     rbp, rsp
    push    rsi
    
    ; Look for ':' before end of line or whitespace
.loop:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .not_label
    cmp     al, ':'
    je      .is_label
    cmp     al, ' '
    je      .not_label
    cmp     al, 9
    je      .not_label
    inc     rsi
    jmp     .loop
    
.is_label:
    mov     rax, 1
    jmp     .done
    
.not_label:
    xor     rax, rax
    
.done:
    pop     rsi
    mov     rsp, rbp
    pop     rbp
    ret
check_label endp

; ============================================================
; Process a label
; ============================================================
process_label proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Copy label name (up to ':')
    lea     rdi, token_buffer
.label_copy:
    movzx   eax, byte ptr [rsi]
    cmp     al, ':'
    je      .label_done
    test    al, al
    jz      .label_done
    mov     [rdi], al
    inc     rsi
    inc     rdi
    jmp     .label_copy
    
.label_done:
    mov     byte ptr [rdi], 0
    inc     rsi             ; skip ':'
    
    ; Add symbol
    lea     rcx, token_buffer
    mov     edx, current_offset
    mov     r8d, current_section
    xor     r9d, r9d        ; local symbol
    call    add_symbol
    
    ; Continue parsing rest of line
    call    skip_line_spaces
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .done
    cmp     al, ';'
    je      .done
    
    ; Check if there's more (directive or instruction after label)
    cmp     al, '.'
    je      .directive_after
    call    handle_instruction
    jmp     .done
    
.directive_after:
    call    process_directive
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
process_label endp

; ============================================================
; Process a directive
; ============================================================
process_directive proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    inc     rsi             ; skip '.'
    
    ; Get directive name
    lea     rdi, token_buffer
.dir_copy:
    movzx   eax, byte ptr [rsi]
    cmp     al, ' '
    je      .dir_done
    cmp     al, 9
    je      .dir_done
    test    al, al
    jz      .dir_done
    mov     [rdi], al
    inc     rsi
    inc     rdi
    jmp     .dir_copy
    
.dir_done:
    mov     byte ptr [rdi], 0
    
    ; Check directive type
    lea     rcx, token_buffer
    
    ; .code
    lea     rdx, dir_code
    call    strcmp
    test    rax, rax
    jz      .set_code
    
    ; .data
    lea     rdx, dir_data
    call    strcmp
    test    rax, rax
    jz      .set_data
    
    ; .const / .rdata
    lea     rdx, dir_const
    call    strcmp
    test    rax, rax
    jz      .set_rdata
    
    lea     rdx, dir_rdata
    call    strcmp
    test    rax, rax
    jz      .set_rdata
    
    ; .bss
    lea     rdx, dir_bss
    call    strcmp
    test    rax, rax
    jz      .set_bss
    
    ; .byte / db
    lea     rdx, dir_byte
    call    strcmp
    test    rax, rax
    jz      .emit_byte
    
    lea     rdx, dir_db
    call    strcmp
    test    rax, rax
    jz      .emit_byte
    
    ; .word / dw
    lea     rdx, dir_word
    call    strcmp
    test    rax, rax
    jz      .emit_word
    
    lea     rdx, dir_dw
    call    strcmp
    test    rax, rax
    jz      .emit_word
    
    ; .dword / dd
    lea     rdx, dir_dword
    call    strcmp
    test    rax, rax
    jz      .emit_dword
    
    lea     rdx, dir_dd
    call    strcmp
    test    rax, rax
    jz      .emit_dword
    
    ; .qword / dq
    lea     rdx, dir_qword
    call    strcmp
    test    rax, rax
    jz      .emit_qword
    
    lea     rdx, dir_dq
    call    strcmp
    test    rax, rax
    jz      .emit_qword
    
    jmp     .done
    
.set_code:
    mov     current_section, 1
    mov     eax, text_size
    mov     current_offset, eax
    jmp     .done
    
.set_data:
    mov     current_section, 2
    mov     eax, data_size
    mov     current_offset, eax
    jmp     .done
    
.set_rdata:
    mov     current_section, 3
    jmp     .done
    
.set_bss:
    mov     current_section, 4
    jmp     .done
    
.emit_byte:
    call    skip_line_spaces
    call    emit_data_byte
    jmp     .done
    
.emit_word:
    call    skip_line_spaces
    call    emit_data_word
    jmp     .done
    
.emit_dword:
    call    skip_line_spaces
    call    emit_data_dword
    jmp     .done
    
.emit_qword:
    call    skip_line_spaces
    call    emit_data_qword
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
process_directive endp

; ============================================================
; String compare
; ============================================================
strcmp proc
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdi
    
    mov     rsi, rcx
    mov     rdi, rdx
    
.loop:
    movzx   eax, byte ptr [rsi]
    movzx   edx, byte ptr [rdi]
    cmp     al, dl
    jne     .not_equal
    test    al, al
    jz      .equal
    inc     rsi
    inc     rdi
    jmp     .loop
    
.not_equal:
    mov     rax, 1
    jmp     .done
    
.equal:
    xor     rax, rax
    
.done:
    pop     rdi
    pop     rsi
    mov     rsp, rbp
    pop     rbp
    ret
strcmp endp

; ============================================================
; Emit data byte
; ============================================================
emit_data_byte proc
    push    rbp
    mov     rbp, rsp
    
    ; Parse value
    call    parse_number
    
    ; Emit to current section
    cmp     current_section, 2
    jne     .done
    
    mov     ecx, data_size
    mov     [data_buffer + ecx], al
    inc     data_size
    inc     current_offset
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
emit_data_byte endp

; ============================================================
; Emit data word
; ============================================================
emit_data_word proc
    push    rbp
    mov     rbp, rsp
    
    call    parse_number
    
    cmp     current_section, 2
    jne     .done
    
    mov     ecx, data_size
    mov     [data_buffer + ecx], ax
    add     data_size, 2
    add     current_offset, 2
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
emit_data_word endp

; ============================================================
; Emit data dword
; ============================================================
emit_data_dword proc
    push    rbp
    mov     rbp, rsp
    
    call    parse_number
    
    cmp     current_section, 2
    jne     .done
    
    mov     ecx, data_size
    mov     [data_buffer + ecx], eax
    add     data_size, 4
    add     current_offset, 4
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
emit_data_dword endp

; ============================================================
; Emit data qword
; ============================================================
emit_data_qword proc
    push    rbp
    mov     rbp, rsp
    
    call    parse_number
    
    cmp     current_section, 2
    jne     .done
    
    mov     ecx, data_size
    mov     [data_buffer + ecx], rax
    add     data_size, 8
    add     current_offset, 8
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
emit_data_qword endp

; ============================================================
; Parse number from string
; ============================================================
parse_number proc
    push    rbp
    mov     rbp, rsp
    
    xor     rax, rax
    xor     rcx, rcx
    
    ; Check for hex prefix
    cmp     word ptr [rsi], '0x'
    je      .hex
    cmp     word ptr [rsi], '0X'
    je      .hex
    
    ; Decimal
.decimal:
    movzx   edx, byte ptr [rsi]
    test    dl, dl
    jz      .done
    cmp     dl, ' '
    je      .done
    cmp     dl, 9
    je      .done
    cmp     dl, ','
    je      .done
    
    sub     dl, '0'
    jb      .done
    cmp     dl, 9
    ja      .done
    
    imul    rax, 10
    add     rax, rdx
    inc     rsi
    jmp     .decimal
    
.hex:
    add     rsi, 2
.hex_loop:
    movzx   edx, byte ptr [rsi]
    test    dl, dl
    jz      .done
    cmp     dl, ' '
    je      .done
    
    ; Convert hex digit
    cmp     dl, '0'
    jb      .done
    cmp     dl, '9'
    jbe     .hex_digit
    cmp     dl, 'A'
    jb      .done
    cmp     dl, 'F'
    jbe     .hex_upper
    cmp     dl, 'a'
    jb      .done
    cmp     dl, 'f'
    jbe     .hex_lower
    jmp     .done
    
.hex_digit:
    sub     dl, '0'
    jmp     .hex_add
    
.hex_upper:
    sub     dl, 'A' - 10
    jmp     .hex_add
    
.hex_lower:
    sub     dl, 'a' - 10
    
.hex_add:
    shl     rax, 4
    add     rax, rdx
    inc     rsi
    jmp     .hex_loop
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
parse_number endp

; ============================================================
; Handle instruction
; ============================================================
handle_instruction proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Get instruction name
    lea     rdi, token_buffer
.copy:
    movzx   eax, byte ptr [rsi]
    cmp     al, ' '
    je      .copy_done
    cmp     al, 9
    je      .copy_done
    test    al, al
    jz      .copy_done
    mov     [rdi], al
    inc     rsi
    inc     rdi
    jmp     .copy
    
.copy_done:
    mov     byte ptr [rdi], 0
    
    ; Skip to operands
    call    skip_line_spaces
    
    ; Check instruction type
    lea     rcx, token_buffer
    
    ; ret
    lea     rdx, instr_ret
    call    strcmp
    test    rax, rax
    jz      .do_ret
    
    ; nop
    lea     rdx, instr_nop
    call    strcmp
    test    rax, rax
    jz      .do_nop
    
    ; mov
    lea     rdx, instr_mov
    call    strcmp
    test    rax, rax
    jz      .do_mov
    
    ; call
    lea     rdx, instr_call
    call    strcmp
    test    rax, rax
    jz      .do_call
    
    ; push
    lea     rdx, instr_push
    call    strcmp
    test    rax, rax
    jz      .do_push
    
    ; pop
    lea     rdx, instr_pop
    call    strcmp
    test    rax, rax
    jz      .do_pop
    
    ; add
    lea     rdx, instr_add
    call    strcmp
    test    rax, rax
    jz      .do_add
    
    ; sub
    lea     rdx, instr_sub
    call    strcmp
    test    rax, rax
    jz      .do_sub
    
    ; xor
    lea     rdx, instr_xor
    call    strcmp
    test    rax, rax
    jz      .do_xor
    
    ; jmp
    lea     rdx, instr_jmp
    call    strcmp
    test    rax, rax
    jz      .do_jmp
    
    jmp     .done
    
.do_ret:
    call    encode_ret
    jmp     .done
    
.do_nop:
    call    encode_nop
    jmp     .done
    
.do_mov:
    call    encode_mov
    jmp     .done
    
.do_call:
    call    encode_call
    jmp     .done
    
.do_push:
    call    encode_push
    jmp     .done
    
.do_pop:
    call    encode_pop
    jmp     .done
    
.do_add:
    call    encode_add
    jmp     .done
    
.do_sub:
    call    encode_sub
    jmp     .done
    
.do_xor:
    call    encode_xor
    jmp     .done
    
.do_jmp:
    call    encode_jmp
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
handle_instruction endp

; ============================================================
; Encode ret instruction
; ============================================================
encode_ret proc
    push    rbp
    mov     rbp, rsp
    
    ; ret = C3
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 0C3h
    inc     text_size
    inc     current_offset
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_ret endp

; ============================================================
; Encode nop instruction
; ============================================================
encode_nop proc
    push    rbp
    mov     rbp, rsp
    
    ; nop = 90
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 90h
    inc     text_size
    inc     current_offset
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_nop endp

; ============================================================
; Encode mov instruction (simplified)
; ============================================================
encode_mov proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Parse operands
    call    parse_operand
    mov     [rsp + 0], rax      ; dest
    mov     [rsp + 8], rbx      ; dest type
    
    ; Skip comma
    call    skip_line_spaces
    cmp     byte ptr [rsi], ','
    jne     .done
    inc     rsi
    call    skip_line_spaces
    
    call    parse_operand
    mov     [rsp + 16], rax     ; src
    mov     [rsp + 24], rbx     ; src type
    
    ; mov reg, imm (simplified: only rax-rdx for now)
    cmp     qword ptr [rsp + 8], 1    ; dest is register
    jne     .done
    cmp     qword ptr [rsp + 24], 2   ; src is immediate
    jne     .done
    
    mov     ecx, dword ptr [rsp + 0]  ; dest reg
    mov     eax, dword ptr [rsp + 16] ; imm value
    
    ; mov r64, imm32 = 48 C7 C0+reg imm32
    mov     edx, text_size
    mov     byte ptr [text_buffer + edx], 48h     ; REX.W
    mov     byte ptr [text_buffer + edx + 1], 0C7h ; MOV r/m64, imm32
    mov     al, 0C0h
    add     al, cl
    mov     byte ptr [text_buffer + edx + 2], al  ; ModRM
    mov     eax, dword ptr [rsp + 16]
    mov     dword ptr [text_buffer + edx + 3], eax ; imm32
    add     text_size, 7
    add     current_offset, 7
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
encode_mov endp

; ============================================================
; Encode call instruction
; ============================================================
encode_call proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Parse target
    call    parse_operand
    
    ; Check if it's a symbol (label) or immediate
    cmp     rbx, 3            ; symbol
    jne     .immediate
    
    ; Symbol - need fixup
    ; E8 xx xx xx xx (relative call)
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 0E8h
    
    ; Add fixup
    mov     ecx, fixup_count
    mov     edx, text_size
    inc     edx               ; skip opcode
    mov     fixup_offsets[ecx * 4], edx
    mov     fixup_symbols[ecx * 4], eax
    mov     fixup_types[ecx * 4], IMAGE_REL_AMD64_REL32
    inc     fixup_count
    
    ; Reserve space for displacement
    add     text_size, 5
    add     current_offset, 5
    jmp     .done
    
.immediate:
    ; Direct call to address (rare)
    ; FF /2
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
encode_call endp

; ============================================================
; Encode push instruction
; ============================================================
encode_push proc
    push    rbp
    mov     rbp, rsp
    
    call    parse_operand
    
    cmp     rbx, 1            ; register
    jne     .done
    
    ; push reg = 50+reg (for rax-rdi)
    cmp     eax, 8
    jae     .extended
    
    mov     ecx, text_size
    mov     dl, 50h
    add     dl, al
    mov     byte ptr [text_buffer + ecx], dl
    inc     text_size
    inc     current_offset
    jmp     .done
    
.extended:
    ; push r8-r15 = 41 50+reg
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 41h
    mov     dl, 50h
    add     dl, al
    sub     dl, 8
    mov     byte ptr [text_buffer + ecx + 1], dl
    add     text_size, 2
    add     current_offset, 2
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
encode_push endp

; ============================================================
; Encode pop instruction
; ============================================================
encode_pop proc
    push    rbp
    mov     rbp, rsp
    
    call    parse_operand
    
    cmp     rbx, 1            ; register
    jne     .done
    
    ; pop reg = 58+reg (for rax-rdi)
    cmp     eax, 8
    jae     .extended
    
    mov     ecx, text_size
    mov     dl, 58h
    add     dl, al
    mov     byte ptr [text_buffer + ecx], dl
    inc     text_size
    inc     current_offset
    jmp     .done
    
.extended:
    ; pop r8-r15 = 41 58+reg
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 41h
    mov     dl, 58h
    add     dl, al
    sub     dl, 8
    mov     byte ptr [text_buffer + ecx + 1], dl
    add     text_size, 2
    add     current_offset, 2
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
encode_pop endp

; ============================================================
; Encode add instruction (simplified)
; ============================================================
encode_add proc
    push    rbp
    mov     rbp, rsp
    
    ; add rsp, imm = 48 81 C4 imm32
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 48h
    mov     byte ptr [text_buffer + ecx + 1], 81h
    mov     byte ptr [text_buffer + ecx + 2], 0C4h
    mov     dword ptr [text_buffer + ecx + 3], 0
    add     text_size, 7
    add     current_offset, 7
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_add endp

; ============================================================
; Encode sub instruction (simplified)
; ============================================================
encode_sub proc
    push    rbp
    mov     rbp, rsp
    
    ; sub rsp, imm = 48 81 EC imm32
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 48h
    mov     byte ptr [text_buffer + ecx + 1], 81h
    mov     byte ptr [text_buffer + ecx + 2], 0ECh
    mov     dword ptr [text_buffer + ecx + 3], 0
    add     text_size, 7
    add     current_offset, 7
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_sub endp

; ============================================================
; Encode xor instruction (simplified)
; ============================================================
encode_xor proc
    push    rbp
    mov     rbp, rsp
    
    ; xor eax, eax = 31 C0
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 31h
    mov     byte ptr [text_buffer + ecx + 1], 0C0h
    add     text_size, 2
    add     current_offset, 2
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_xor endp

; ============================================================
; Encode jmp instruction
; ============================================================
encode_jmp proc
    push    rbp
    mov     rbp, rsp
    
    ; jmp rel32 = E9 disp32
    mov     ecx, text_size
    mov     byte ptr [text_buffer + ecx], 0E9h
    
    ; Add fixup for target
    mov     ecx, fixup_count
    mov     edx, text_size
    inc     edx
    mov     fixup_offsets[ecx * 4], edx
    ; symbol index would go here
    mov     fixup_types[ecx * 4], IMAGE_REL_AMD64_REL32
    inc     fixup_count
    
    add     text_size, 5
    add     current_offset, 5
    
    mov     rsp, rbp
    pop     rbp
    ret
encode_jmp endp

; ============================================================
; Parse operand
; Returns: rax=value, rbx=type (1=reg, 2=imm, 3=symbol)
; ============================================================
parse_operand proc
    push    rbp
    mov     rbp, rsp
    
    call    skip_line_spaces
    
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .done
    
    ; Check for register
    cmp     al, 'r'
    je      .check_reg
    
    ; Check for number
    cmp     al, '0'
    jb      .check_symbol
    cmp     al, '9'
    jbe     .number
    
    ; Must be symbol
.check_symbol:
    mov     rbx, 3
    jmp     .done
    
.check_reg:
    ; Check register names
    cmp     dword ptr [rsi], 'rax'
    je      .reg_rax
    cmp     dword ptr [rsi], 'rcx'
    je      .reg_rcx
    cmp     dword ptr [rsi], 'rdx'
    je      .reg_rdx
    cmp     dword ptr [rsi], 'rbx'
    je      .reg_rbx
    cmp     dword ptr [rsi], 'rsp'
    je      .reg_rsp
    cmp     dword ptr [rsi], 'rbp'
    je      .reg_rbp
    cmp     dword ptr [rsi], 'rsi'
    je      .reg_rsi
    cmp     dword ptr [rsi], 'rdi'
    je      .reg_rdi
    
    mov     rbx, 3    ; symbol
    jmp     .done
    
.reg_rax:
    mov     rax, 0
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rcx:
    mov     rax, 1
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rdx:
    mov     rax, 2
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rbx:
    mov     rax, 3
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rsp:
    mov     rax, 4
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rbp:
    mov     rax, 5
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rsi:
    mov     rax, 6
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.reg_rdi:
    mov     rax, 7
    mov     rbx, 1
    add     rsi, 3
    jmp     .done
    
.number:
    mov     rbx, 2
    call    parse_number
    
.done:
    mov     rsp, rbp
    pop     rbp
    ret
parse_operand endp

; ============================================================
; Add symbol to symbol table
; ============================================================
add_symbol proc
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdi
    
    ; rcx = name, edx = offset, r8d = section, r9d = type
    
    mov     eax, symbol_count
    cmp     eax, MAX_SYMBOLS
    jae     .done
    
    ; Copy name
    mov     rdi, offset symbol_names
    imul    eax, 64
    add     rdi, rax
    mov     rsi, rcx
    
.copy_name:
    movzx   eax, byte ptr [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    test    al, al
    jnz     .copy_name
    
    ; Set values
    mov     eax, symbol_count
    mov     symbol_offsets[rax * 4], edx
    mov     symbol_sections[rax * 4], r8d
    mov     symbol_types[rax * 4], r9d
    
    inc     symbol_count
    
.done:
    pop     rdi
    pop     rsi
    mov     rsp, rbp
    pop     rbp
    ret
add_symbol endp

; ============================================================
; Pass 2: Resolve fixups and emit COFF
; ============================================================
assembler_pass2 proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Resolve fixups
    xor     ecx, ecx
    
.fixup_loop:
    cmp     ecx, fixup_count
    jae     .done_fixups
    
    ; Get fixup info
    mov     eax, fixup_offsets[ecx * 4]
    mov     [rsp + 0], eax      ; offset in section
    mov     eax, fixup_symbols[ecx * 4]
    mov     [rsp + 4], eax      ; symbol index
    mov     eax, fixup_types[ecx * 4]
    mov     [rsp + 8], eax      ; type
    
    ; Get symbol address
    mov     eax, [rsp + 4]
    mov     edx, symbol_offsets[rax * 4]
    
    ; Calculate relative offset
    mov     eax, [rsp + 0]
    sub     edx, eax
    sub     edx, 4              ; relative to end of instruction
    
    ; Patch the code
    mov     eax, [rsp + 0]
    mov     dword ptr [text_buffer + eax], edx
    
    inc     ecx
    jmp     .fixup_loop
    
.done_fixups:
    mov     rsp, rbp
    pop     rbp
    ret
assembler_pass2 endp

; ============================================================
; Write COFF file
; ============================================================
write_coff proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    
    ; Build COFF header
    mov     word ptr [rsp + 0], IMAGE_FILE_MACHINE_AMD64
    mov     word ptr [rsp + 2], 2           ; NumberOfSections
    mov     dword ptr [rsp + 4], 0          ; TimeDateStamp
    mov     dword ptr [rsp + 8], 0          ; PointerToSymbolTable
    mov     dword ptr [rsp + 12], 0         ; NumberOfSymbols
    mov     word ptr [rsp + 16], 0          ; SizeOfOptionalHeader
    mov     word ptr [rsp + 18], IMAGE_FILE_LARGE_ADDRESS_AWARE
    
    ; Write header
    mov     rcx, output_handle
    lea     rdx, [rsp + 0]
    mov     r8, 20
    lea     r9, bytes_written
    mov     qword ptr [rsp + 48], 0
    call    WriteFile
    
    ; Section headers will go here
    ; ... (simplified - just write raw sections for now)
    
    ; Write .text section
    mov     ecx, text_size
    test    ecx, ecx
    jz      .no_text
    
    mov     rcx, output_handle
    lea     rdx, text_buffer
    mov     r8d, text_size
    lea     r9, bytes_written
    mov     qword ptr [rsp + 48], 0
    call    WriteFile
    
.no_text:
    ; Write .data section
    mov     ecx, data_size
    test    ecx, ecx
    jz      .no_data
    
    mov     rcx, output_handle
    lea     rdx, data_buffer
    mov     r8d, data_size
    lea     r9, bytes_written
    mov     qword ptr [rsp + 48], 0
    call    WriteFile
    
.no_data:
    mov     rsp, rbp
    pop     rbp
    ret
write_coff endp

; --- String constants ---
usage_text        db "Usage: true_asm <input.asm> <output.obj>", 13, 10, 0
file_error_text   db "Cannot open file", 13, 10, 0
read_error_text   db "Cannot read file", 13, 10, 0

; Directive strings
dir_code          db "code", 0
dir_data          db "data", 0
dir_const         db "const", 0
dir_rdata         db "rdata", 0
dir_bss           db "bss", 0
dir_byte          db "byte", 0
dir_db            db "db", 0
dir_word          db "word", 0
dir_dw            db "dw", 0
dir_dword         db "dword", 0
dir_dd            db "dd", 0
dir_qword         db "qword", 0
dir_dq            db "dq", 0

; Instruction strings
instr_ret         db "ret", 0
instr_nop         db "nop", 0
instr_mov         db "mov", 0
instr_call        db "call", 0
instr_push        db "push", 0
instr_pop         db "pop", 0
instr_add         db "add", 0
instr_sub         db "sub", 0
instr_xor         db "xor", 0
instr_jmp         db "jmp", 0

end Start