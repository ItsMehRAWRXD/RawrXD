; True Self-Hosting Assembler - Pure x64 MASM
; Can assemble a subset of x64 instructions and produce COFF objects
; Assemble: ml64 /c /Fo true_self_hosting_assembler_ml64.obj true_self_hosting_assembler.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:Start true_self_hosting_assembler_ml64.obj kernel32.lib

; External imports
EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetCommandLineA:PROC
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

; Constants
STD_OUTPUT_HANDLE equ -11
GENERIC_READ equ 80000000h
GENERIC_WRITE equ 40000000h
CREATE_ALWAYS equ 2
OPEN_EXISTING equ 3
FILE_ATTRIBUTE_NORMAL equ 80h
FILE_SHARE_READ equ 1
FILE_SHARE_WRITE equ 2
INVALID_HANDLE_VALUE equ -1
HEAP_ZERO_MEMORY equ 00000008h

; COFF constants
IMAGE_FILE_MACHINE_AMD64 equ 8664h
IMAGE_REL_AMD64_REL32 equ 4
IMAGE_SYM_CLASS_EXTERNAL equ 2
IMAGE_SYM_CLASS_STATIC equ 3
IMAGE_SYM_CLASS_SECTION equ 104

; Section characteristics
IMAGE_SCN_CNT_CODE equ 00000020h
IMAGE_SCN_CNT_INITIALIZED_DATA equ 00000040h
IMAGE_SCN_MEM_EXECUTE equ 20000000h
IMAGE_SCN_MEM_READ equ 40000000h
IMAGE_SCN_MEM_WRITE equ 80000000h

; Buffer sizes
MAX_LINE_LEN equ 512
MAX_CODE_SIZE equ 8192
MAX_DATA_SIZE equ 4096
MAX_SYMBOLS equ 128
MAX_RELOCATIONS equ 64
MAX_SECTIONS equ 2

; Parse states
STATE_NONE equ 0
STATE_TEXT equ 1
STATE_DATA equ 2

; Data section
.DATA

; Output messages
msg_banner      DB 'True Self-Hosting Assembler v2.0', 13, 10, 0
msg_usage       DB 'Usage: assembler.exe <input.asm> <output.obj>', 13, 10, 0
msg_open_fail   DB 'Error: Cannot open input file', 13, 10, 0
msg_create_fail DB 'Error: Cannot create output file', 13, 10, 0
msg_assembling  DB '[ASSEMBLY] Processing input...', 13, 10, 0
msg_parsed      DB '[PARSE] Instructions parsed successfully', 13, 10, 0
msg_coff_write  DB '[COFF] Writing object file...', 13, 10, 0
msg_success     DB '[SUCCESS] Object file created', 13, 10, 0
msg_fail        DB '[FAIL] Assembly failed', 13, 10, 0
msg_line        DB '[LINE] Processing: ', 0
msg_newline     DB 13, 10, 0
msg_space       DB ' ', 0
msg_dot         DB '.', 0
msg_colon       DB ': ', 0
msg_bytes       DB ' bytes generated', 13, 10, 0

; Instruction mnemonics (must match instruction_table order)
mnem_nop        DB 'nop', 0
mnem_ret        DB 'ret', 0
mnem_call       DB 'call', 0
mnem_jmp        DB 'jmp', 0
mnem_je         DB 'je', 0
mnem_jne        DB 'jne', 0
mnem_jz         DB 'jz', 0
mnem_jnz        DB 'jnz', 0
mnem_push       DB 'push', 0
mnem_pop        DB 'pop', 0
mnem_mov        DB 'mov', 0
mnem_lea        DB 'lea', 0
mnem_add        DB 'add', 0
mnem_sub        DB 'sub', 0
mnem_inc        DB 'inc', 0
mnem_dec        DB 'dec', 0
mnem_xor        DB 'xor', 0
mnem_and        DB 'and', 0
mnem_or         DB 'or', 0
mnem_cmp        DB 'cmp', 0
mnem_test       DB 'test', 0
mnem_db         DB 'db', 0
mnem_align      DB 'align', 0

; Register names
reg_rax         DB 'rax', 0
reg_rcx         DB 'rcx', 0
reg_rdx         DB 'rdx', 0
reg_rbx         DB 'rbx', 0
reg_rsp         DB 'rsp', 0
reg_rbp         DB 'rbp', 0
reg_rsi         DB 'rsi', 0
reg_rdi         DB 'rdi', 0
reg_r8          DB 'r8', 0
reg_r9          DB 'r9', 0
reg_r10         DB 'r10', 0
reg_r11         DB 'r11', 0
reg_r12         DB 'r12', 0
reg_r13         DB 'r13', 0
reg_r14         DB 'r14', 0
reg_r15         DB 'r15', 0
reg_eax         DB 'eax', 0
reg_ecx         DB 'ecx', 0
reg_edx         DB 'edx', 0
reg_ebx         DB 'ebx', 0
reg_esp         DB 'esp', 0
reg_ebp         DB 'ebp', 0

; Section directives
sect_text       DB '.text', 0
sect_data       DB '.data', 0
sect_code       DB '.code', 0

; Directive strings
dir_extern     DB 'EXTERN', 0
dir_proc       DB 'PROC', 0
dir_endp       DB 'ENDP', 0
dir_end        DB 'END', 0

; Buffers
line_buffer     DB MAX_LINE_LEN DUP(0)
token_buffer    DB 64 DUP(0)
operand1        DB 64 DUP(0)
operand2        DB 64 DUP(0)
label_name      DB 64 DUP(0)

; Output buffers
output_buffer   DB MAX_CODE_SIZE DUP(0)
data_buffer     DB MAX_DATA_SIZE DUP(0)

; COFF header (20 bytes)
coff_header     DB 20 DUP(0)

; Section headers (80 bytes each)
section_headers DB MAX_SECTIONS * 80 DUP(0)

; Symbol table (18 bytes per symbol)
symbol_table    DB MAX_SYMBOLS * 18 DUP(0)

; Relocation table (10 bytes per relocation)
relocation_table DB MAX_RELOCATIONS * 10 DUP(0)

; String table
string_table    DB 4096 DUP(0)
string_table_size DD 4

; Variables
code_size       DD 0
data_size       DD 0
num_symbols     DD 0
num_relocs      DD 0
num_sections    DD 0
current_section DD 0
parse_state     DD 0
line_number     DD 0
input_handle    DQ 0
output_handle   DQ 0
heap_handle     DQ 0
bytes_read      DD 0
bytes_written   DD 0
input_filename  DQ 0
output_filename DQ 0

; Instruction encoding table
; Format: opcode, has_modrm, reg_field, operand_count, operand_types
instruction_table:
; nop - 0x90, no modrm, 0 operands
                DB 090h, 0, 0, 0, 0, 0, 0, 0
; ret - 0xC3, no modrm, 0 operands  
                DB 0C3h, 0, 0, 0, 0, 0, 0, 0
; call rel32 - 0xE8, no modrm, 1 operand (rel32)
                DB 0E8h, 0, 0, 1, 1, 0, 0, 0
; jmp rel32 - 0xE9, no modrm, 1 operand (rel32)
                DB 0E9h, 0, 0, 1, 1, 0, 0, 0
; je rel8 - 0x74, no modrm, 1 operand (rel8)
                DB 074h, 0, 0, 1, 2, 0, 0, 0
; jne rel8 - 0x75, no modrm, 1 operand (rel8)
                DB 075h, 0, 0, 1, 2, 0, 0, 0
; jz rel8 - 0x74 (same as je), no modrm, 1 operand
                DB 074h, 0, 0, 1, 2, 0, 0, 0
; jnz rel8 - 0x75 (same as jne), no modrm, 1 operand
                DB 075h, 0, 0, 1, 2, 0, 0, 0
; push r64 - 0x50+reg, no modrm, 1 operand (reg)
                DB 050h, 0, 0, 1, 3, 0, 0, 0
; pop r64 - 0x58+reg, no modrm, 1 operand (reg)
                DB 058h, 0, 0, 1, 3, 0, 0, 0
; mov r64, r/m64 - 0x8B, has modrm, 2 operands
                DB 08Bh, 1, 0, 2, 3, 4, 0, 0
; mov r/m64, r64 - 0x89, has modrm, 2 operands
                DB 089h, 1, 0, 2, 4, 3, 0, 0
; mov r64, imm32 - 0xC7 /0, has modrm, 2 operands
                DB 0C7h, 1, 0, 2, 3, 5, 0, 0
; lea r64, m - 0x8D, has modrm, 2 operands
                DB 08Dh, 1, 0, 2, 3, 6, 0, 0
; add r64, r/m64 - 0x03, has modrm, 2 operands
                DB 003h, 1, 0, 2, 3, 4, 0, 0
; sub r64, r/m64 - 0x2B, has modrm, 2 operands
                DB 02Bh, 1, 0, 2, 3, 4, 0, 0
; inc r64 - 0xFF /0, has modrm, 1 operand
                DB 0FFh, 1, 0, 1, 4, 0, 0, 0
; dec r64 - 0xFF /1, has modrm, 1 operand
                DB 0FFh, 1, 1, 1, 4, 0, 0, 0
; xor r64, r/m64 - 0x33, has modrm, 2 operands
                DB 033h, 1, 0, 2, 3, 4, 0, 0
; and r64, r/m64 - 0x23, has modrm, 2 operands
                DB 023h, 1, 0, 2, 3, 4, 0, 0
; or r64, r/m64 - 0x0B, has modrm, 2 operands
                DB 00Bh, 1, 0, 2, 3, 4, 0, 0
; cmp r64, r/m64 - 0x3B, has modrm, 2 operands
                DB 03Bh, 1, 0, 2, 3, 4, 0, 0
; test r64, r64 - 0x85, has modrm, 2 operands
                DB 085h, 1, 0, 2, 3, 4, 0, 0
; db - pseudo-op, special handling
                DB 0, 0, 0, 1, 7, 0, 0, 0
; align - pseudo-op, special handling
                DB 0, 0, 0, 1, 5, 0, 0, 0
NUM_INSTRUCTIONS equ ($ - instruction_table) / 8

; Code section
.CODE

;==============================================================================
; Entry point
;==============================================================================
Start PROC
    push rbp
    mov rbp, rsp
    sub rsp, 128
    
    ; Get heap handle
    call GetProcessHeap
    mov heap_handle, rax
    
    ; Get command line
    call GetCommandLineA
    mov rcx, rax
    lea rdx, [rbp-8]        ; argc
    lea r8, [rbp-16]        ; argv
    call ParseCommandLine
    
    ; Check argument count
    mov rax, [rbp-8]
    cmp rax, 3
    jne show_usage
    
    ; Get filenames from argv
    mov rax, [rbp-16]       ; argv
    mov rbx, [rax+8]        ; argv[1] = input
    mov input_filename, rbx
    mov rbx, [rax+16]       ; argv[2] = output
    mov output_filename, rbx
    
    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; Open input file
    mov rcx, input_filename
    call OpenInputFile
    test rax, rax
    jz open_failed
    mov input_handle, rax
    
    ; Create output file
    mov rcx, output_filename
    call CreateOutputFile
    test rax, rax
    jz create_failed
    mov output_handle, rax
    
    ; Initialize COFF header
    call InitCOFFHeader
    
    ; Initialize section headers
    call InitSectionHeaders
    
    ; Parse and assemble input
    call AssembleFile
    
    ; Write COFF file
    call WriteCOFFFile
    
    ; Close files
    mov rcx, input_handle
    call CloseHandle
    mov rcx, output_handle
    call CloseHandle
    
    ; Print success
    lea rcx, msg_success
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
    
show_usage:
    lea rcx, msg_usage
    call PrintString
    mov rcx, 1
    call ExitProcess
    
open_failed:
    lea rcx, msg_open_fail
    call PrintString
    mov rcx, 1
    call ExitProcess
    
create_failed:
    mov rcx, input_handle
    call CloseHandle
    lea rcx, msg_create_fail
    call PrintString
    mov rcx, 1
    call ExitProcess
Start ENDP

;==============================================================================
; Parse command line into argc/argv
; RCX = command line string
; RDX = pointer to argc
; R8 = pointer to argv array
;==============================================================================
ParseCommandLine PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    mov rsi, rcx            ; RSI = command line
    mov rdi, r8             ; RDI = argv array
    xor ebx, ebx            ; EBX = argc
    
parse_loop:
    ; Skip leading whitespace
    mov al, [rsi]
    test al, al
    jz parse_done
    cmp al, ' '
    jbe skip_whitespace
    
    ; Found start of argument
    mov [rdi], rsi          ; Store argv[argc]
    add rdi, 8
    inc ebx
    
    ; Find end of argument
arg_loop:
    mov al, [rsi]
    test al, al
    jz parse_done
    cmp al, ' '
    jbe arg_end
    inc rsi
    jmp arg_loop
    
arg_end:
    mov byte ptr [rsi], 0   ; Null terminate
    inc rsi
    jmp parse_loop
    
skip_whitespace:
    inc rsi
    jmp parse_loop
    
parse_done:
    mov [rdx], ebx          ; Store argc
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
ParseCommandLine ENDP

;==============================================================================
; Open input file for reading
; RCX = filename
; Returns: handle in RAX (0 on failure)
;==============================================================================
OpenInputFile PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
    mov rdx, GENERIC_READ
    mov r8, FILE_SHARE_READ
    xor r9, r9
    mov QWORD PTR [rsp+32], OPEN_EXISTING
    mov QWORD PTR [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+48], 0
    call CreateFileA
    
    cmp rax, INVALID_HANDLE_VALUE
    jne open_ok
    xor rax, rax
    
open_ok:
    add rsp, 32
    pop rbp
    ret
OpenInputFile ENDP

;==============================================================================
; Create output file for writing
; RCX = filename
; Returns: handle in RAX (0 on failure)
;==============================================================================
CreateOutputFile PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    mov rdx, GENERIC_WRITE
    xor r8, r8
    xor r9, r9
    mov QWORD PTR [rsp+32], CREATE_ALWAYS
    mov QWORD PTR [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+48], 0
    call CreateFileA
    
    cmp rax, INVALID_HANDLE_VALUE
    jne create_ok
    xor rax, rax
    
create_ok:
    add rsp, 32
    pop rbp
    ret
CreateOutputFile ENDP

;==============================================================================
; Initialize COFF header
;==============================================================================
InitCOFFHeader PROC
    push rdi
    
    lea rdi, coff_header
    
    ; Machine type (AMD64)
    mov WORD PTR [rdi], IMAGE_FILE_MACHINE_AMD64
    add rdi, 2
    
    ; Number of sections
    mov WORD PTR [rdi], 2       ; .text and .data
    add rdi, 2
    
    ; Time stamp
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to symbol table (will be calculated)
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Number of symbols
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Size of optional header
    mov WORD PTR [rdi], 0
    add rdi, 2
    
    ; Characteristics
    mov WORD PTR [rdi], 0
    
    mov num_sections, 2
    
    pop rdi
    ret
InitCOFFHeader ENDP

;==============================================================================
; Initialize section headers
;==============================================================================
InitSectionHeaders PROC
    push rdi
    push rbx
    
    ; Section 0: .text
    lea rdi, section_headers
    
    ; Name: .text
    mov DWORD PTR [rdi], 'xet.'
    mov DWORD PTR [rdi+4], 0
    add rdi, 8
    
    ; Virtual size
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Virtual address
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Size of raw data
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to raw data
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to relocations
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to line numbers
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Number of relocations
    mov WORD PTR [rdi], 0
    add rdi, 2
    
    ; Number of line numbers
    mov WORD PTR [rdi], 0
    add rdi, 2
    
    ; Characteristics
    mov ebx, IMAGE_SCN_CNT_CODE
    or ebx, IMAGE_SCN_MEM_EXECUTE
    or ebx, IMAGE_SCN_MEM_READ
    mov DWORD PTR [rdi], ebx
    add rdi, 4
    
    ; Section 1: .data
    ; Name: .data
    mov DWORD PTR [rdi], 'atad.'
    mov DWORD PTR [rdi+4], 0
    add rdi, 8
    
    ; Virtual size
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Virtual address
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Size of raw data
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to raw data
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to relocations
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Pointer to line numbers
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Number of relocations
    mov WORD PTR [rdi], 0
    add rdi, 2
    
    ; Number of line numbers
    mov WORD PTR [rdi], 0
    add rdi, 2
    
    ; Characteristics
    mov ebx, IMAGE_SCN_CNT_INITIALIZED_DATA
    or ebx, IMAGE_SCN_MEM_READ
    or ebx, IMAGE_SCN_MEM_WRITE
    mov DWORD PTR [rdi], ebx
    
    pop rbx
    pop rdi
    ret
InitSectionHeaders ENDP

;==============================================================================
; Main assembly loop - read and process input file
;==============================================================================
AssembleFile PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    mov current_section, STATE_TEXT
    mov parse_state, STATE_TEXT
    mov line_number, 0
    
assembly_loop:
    ; Read one line
    call ReadLine
    test rax, rax
    jz assembly_done
    
    inc line_number
    
    ; Skip empty lines and comments
    lea rcx, line_buffer
    call SkipWhitespace
    mov rsi, rax
    mov al, [rsi]
    test al, al
    jz assembly_loop        ; Empty line
    cmp al, ';'
    je assembly_loop        ; Comment line
    
    ; Parse the line
    lea rcx, line_buffer
    call ParseLine
    
    jmp assembly_loop
    
assembly_done:
    ; Update section headers with final sizes
    call UpdateSectionHeaders
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
AssembleFile ENDP

;==============================================================================
; Read one line from input file
; Returns: RAX = 1 if line read, 0 if EOF
;==============================================================================
ReadLine PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    lea rdi, line_buffer
    xor ebx, ebx            ; Character count
    
read_loop:
    cmp ebx, MAX_LINE_LEN - 1
    jae line_done
    
    ; Read one byte
    mov rcx, input_handle
    lea rdx, [rbp-1]        ; Buffer on stack
    mov r8, 1               ; Read 1 byte
    lea r9, bytes_read
    call ReadFile
    
    test rax, rax
    jz read_eof
    
    cmp bytes_read, 0
    je read_eof
    
    mov al, [rbp-1]
    cmp al, 10              ; LF
    je line_done
    cmp al, 13              ; CR
    je read_loop            ; Skip CR
    
    mov [rdi], al
    inc rdi
    inc ebx
    jmp read_loop
    
line_done:
    mov BYTE PTR [rdi], 0   ; Null terminate
    mov rax, 1
    jmp read_exit
    
read_eof:
    cmp ebx, 0
    je read_exit_zero
    mov BYTE PTR [rdi], 0
    mov rax, 1
    jmp read_exit
    
read_exit_zero:
    xor rax, rax
    
read_exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
ReadLine ENDP

;==============================================================================
; Skip whitespace at start of string
; RCX = string
; Returns: RAX = pointer to first non-whitespace
;==============================================================================
SkipWhitespace PROC
    mov rax, rcx
    
skip_loop:
    mov cl, [rax]
    test cl, cl
    jz skip_done
    cmp cl, ' '
    ja skip_done
    inc rax
    jmp skip_loop
    
skip_done:
    ret
SkipWhitespace ENDP

;==============================================================================
; Parse a single assembly line
; RCX = line buffer
;==============================================================================
ParseLine PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 32
    
    mov rsi, rcx            ; RSI = line pointer
    
    ; Check for section directive
    mov al, [rsi]
    cmp al, '.'
    jne check_label
    
    ; Check for .text, .data, .code
    lea rcx, sect_text
    lea rdx, [rsi+1]
    call StringCompare
    test rax, rax
    jnz is_text_section
    
    lea rcx, sect_data
    lea rdx, [rsi+1]
    call StringCompare
    test rax, rax
    jnz is_data_section
    
    lea rcx, sect_code
    lea rdx, [rsi+1]
    call StringCompare
    test rax, rax
    jnz is_text_section
    
    jmp check_instruction
    
is_text_section:
    mov current_section, STATE_TEXT
    jmp parse_done
    
is_data_section:
    mov current_section, STATE_DATA
    jmp parse_done
    
check_label:
    ; Check if line starts with a label (ends with :)
    mov rdi, rsi
    
find_colon:
    mov al, [rdi]
    test al, al
    jz check_instruction
    cmp al, ':'
    je found_label
    cmp al, ' '
    jbe check_instruction
    inc rdi
    jmp find_colon
    
found_label:
    ; Extract label name
    mov rcx, rsi
    mov rdx, rdi
    sub rdx, rsi            ; Length
    lea r8, label_name
    call CopyString
    
    ; Add label to symbol table
    lea rcx, label_name
    mov edx, current_section
    call AddLabel
    
    ; Move past label
    mov rsi, rdi
    inc rsi                 ; Skip ':'
    
    ; Skip whitespace
    mov rcx, rsi
    call SkipWhitespace
    mov rsi, rax
    
    ; Check if there's more on this line
    mov al, [rsi]
    test al, al
    jz parse_done
    
check_instruction:
    ; Get instruction mnemonic
    lea rdi, token_buffer
    
copy_mnem:
    mov al, [rsi]
    test al, al
    jz parse_done
    cmp al, ' '
    jbe mnem_done
    cmp al, 9               ; Tab
    je mnem_done
    mov [rdi], al
    inc rdi
    inc rsi
    jmp copy_mnem
    
mnem_done:
    mov BYTE PTR [rdi], 0   ; Null terminate
    
    ; Skip whitespace before operands
    mov rcx, rsi
    call SkipWhitespace
    mov rsi, rax
    
    ; Parse operands
    lea rdi, operand1
    lea r12, operand2
    call ParseOperands
    
    ; Assemble the instruction
    lea rcx, token_buffer
    lea rdx, operand1
    lea r8, operand2
    call AssembleInstruction
    
parse_done:
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
ParseLine ENDP

;==============================================================================
; Parse operands from line
; RSI = line pointer (after mnemonic)
; RDI = operand1 buffer
; R12 = operand2 buffer
;==============================================================================
ParseOperands PROC
    push rbx
    
    ; Clear operand buffers
    mov BYTE PTR [rdi], 0
    mov BYTE PTR [r12], 0
    
    ; Check for first operand
    mov al, [rsi]
    test al, al
    jz parse_ops_done
    
    ; Copy first operand
    mov rbx, rdi
    
operand1_loop:
    mov al, [rsi]
    test al, al
    jz parse_ops_done
    cmp al, ','
    je operand1_end
    cmp al, ';'             ; Comment
    je parse_ops_done
    mov [rbx], al
    inc rbx
    inc rsi
    jmp operand1_loop
    
operand1_end:
    mov BYTE PTR [rbx], 0
    inc rsi                 ; Skip ','
    
    ; Skip whitespace
    mov rcx, rsi
    call SkipWhitespace
    mov rsi, rax
    
    ; Copy second operand
    mov rbx, r12
    
operand2_loop:
    mov al, [rsi]
    test al, al
    jz parse_ops_done
    cmp al, ';'             ; Comment
    je parse_ops_done
    cmp al, ' '
    jbe trim_end            ; Trim trailing whitespace
    mov [rbx], al
    inc rbx
    inc rsi
    jmp operand2_loop
    
trim_end:
    mov BYTE PTR [rbx], 0
    
parse_ops_done:
    mov BYTE PTR [rdi], 0
    mov BYTE PTR [r12], 0
    
    pop rbx
    ret
ParseOperands ENDP

;==============================================================================
; Assemble a single instruction
; RCX = mnemonic
; RDX = operand1
; R8 = operand2
;==============================================================================
AssembleInstruction PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32
    
    mov r12, rcx            ; R12 = mnemonic
    mov r13, rdx            ; R13 = operand1
    
    ; Check for db directive
    lea rcx, mnem_db
    mov rdx, r12
    call StringCompare
    test rax, rax
    jnz handle_db
    
    ; Check for align directive
    lea rcx, mnem_align
    mov rdx, r12
    call StringCompare
    test rax, rax
    jnz handle_align
    
    ; Find instruction in table
    xor ebx, ebx            ; EBX = instruction index
    
find_instr_loop:
    cmp ebx, NUM_INSTRUCTIONS
    jae instr_not_found
    
    ; Get mnemonic for this instruction
    mov rax, rbx
    shl rax, 3              ; Multiply by 8 (entry size)
    lea rsi, instruction_table
    add rsi, rax
    
    ; Get opcode and check
    movzx eax, BYTE PTR [rsi]
    
    ; Compare mnemonic
    push rbx
    push rsi
    mov rcx, r12
    call GetMnemonicForIndex
    mov rdx, rax
    mov rcx, r12
    call StringCompare
    pop rsi
    pop rbx
    test rax, rax
    jnz found_instruction
    
    inc ebx
    jmp find_instr_loop
    
found_instruction:
    ; Get instruction details
    mov rax, rbx
    shl rax, 3
    lea rsi, instruction_table
    add rsi, rax
    
    movzx eax, BYTE PTR [rsi]       ; Opcode
    movzx ecx, BYTE PTR [rsi+1]     ; Has modrm
    movzx edx, BYTE PTR [rsi+2]     ; Reg field
    movzx r8d, BYTE PTR [rsi+3]     ; Operand count
    
    ; Assemble based on instruction type
    cmp ebx, 0                      ; nop
    je emit_simple
    cmp ebx, 1                      ; ret
    je emit_simple
    cmp ebx, 2                      ; call
    je emit_rel32
    cmp ebx, 3                      ; jmp
    je emit_rel32
    cmp ebx, 4                      ; je
    je emit_rel8
    cmp ebx, 5                      ; jne
    je emit_rel8
    cmp ebx, 8                      ; push
    je emit_push_pop
    cmp ebx, 9                      ; pop
    je emit_push_pop
    cmp ebx, 10                     ; mov r64, r/m64
    je emit_mov_reg_mem
    cmp ebx, 11                     ; mov r/m64, r64
    je emit_mov_mem_reg
    cmp ebx, 14                     ; lea
    je emit_lea
    cmp ebx, 15                     ; add
    je emit_alu
    cmp ebx, 16                     ; sub
    je emit_alu
    cmp ebx, 17                     ; inc
    je emit_inc_dec
    cmp ebx, 18                     ; dec
    je emit_inc_dec
    cmp ebx, 19                     ; xor
    je emit_alu
    cmp ebx, 20                     ; and
    je emit_alu
    cmp ebx, 21                     ; or
    je emit_alu
    cmp ebx, 22                     ; cmp
    je emit_alu
    cmp ebx, 23                     ; test
    je emit_alu
    
    jmp instr_done
    
emit_simple:
    ; Emit simple opcode
    movzx eax, BYTE PTR [rsi]
    call EmitByte
    jmp instr_done
    
emit_rel32:
    ; Emit call/jmp with rel32
    movzx eax, BYTE PTR [rsi]
    call EmitByte
    ; Emit 4 bytes of zeros (relocation will fix)
    xor eax, eax
    call EmitByte
    call EmitByte
    call EmitByte
    call EmitByte
    ; Add relocation
    mov rcx, r13
    call AddRelocation
    jmp instr_done
    
emit_rel8:
    ; Emit conditional jump with rel8
    movzx eax, BYTE PTR [rsi]
    call EmitByte
    xor eax, eax
    call EmitByte
    mov rcx, r13
    call AddRelocation
    jmp instr_done
    
emit_push_pop:
    ; Emit push/pop with register
    movzx eax, BYTE PTR [rsi]       ; Base opcode
    mov rcx, r13
    call ParseRegister
    add eax, ecx                    ; Add register number
    call EmitByte
    jmp instr_done
    
emit_mov_reg_mem:
    ; mov r64, r/m64 - 0x8B
    mov al, 08Bh
    call EmitByte
    ; Build ModR/M
    mov rcx, r13
    call ParseRegister              ; Destination
    mov ebx, ecx
    shl ebx, 3                    ; Reg field
    mov rcx, r8
    call ParseRegisterOrMemory      ; Source
    or ebx, ecx
    mov eax, ebx
    call EmitByte
    jmp instr_done
    
emit_mov_mem_reg:
    ; mov r/m64, r64 - 0x89
    mov al, 089h
    call EmitByte
    mov rcx, r13
    call ParseRegisterOrMemory
    mov ebx, ecx
    mov rcx, r8
    call ParseRegister
    shl ecx, 3
    or ebx, ecx
    mov eax, ebx
    call EmitByte
    jmp instr_done
    
emit_lea:
    ; lea r64, mem
    mov al, 08Dh
    call EmitByte
    mov rcx, r13
    call ParseRegister
    mov ebx, ecx
    shl ebx, 3
    mov rcx, r8
    call ParseMemoryOperand
    or ebx, ecx
    mov eax, ebx
    call EmitByte
    jmp instr_done
    
emit_alu:
    ; ALU operations
    movzx eax, BYTE PTR [rsi]
    call EmitByte
    mov rcx, r13
    call ParseRegister
    mov ebx, ecx
    shl ebx, 3
    mov rcx, r8
    call ParseRegisterOrMemory
    or ebx, ecx
    mov eax, ebx
    call EmitByte
    jmp instr_done
    
emit_inc_dec:
    ; inc/dec r64
    mov al, 0FFh
    call EmitByte
    movzx eax, BYTE PTR [rsi+2]     ; Reg field
    shl eax, 3
    mov rcx, r13
    call ParseRegisterOrMemory
    or eax, ecx
    call EmitByte
    jmp instr_done
    
handle_db:
    ; Handle db directive
    mov rcx, r13
    call ParseNumber
    call EmitByte
    jmp instr_done
    
handle_align:
    ; Handle align directive
    mov rcx, r13
    call ParseNumber
    mov ebx, eax
    mov eax, code_size
    and eax, ebx - 1
    jz instr_done
    sub ebx, eax
    mov ecx, ebx
align_loop:
    mov eax, 090h           ; nop
    call EmitByte
    loop align_loop
    jmp instr_done
    
instr_not_found:
    ; Unknown instruction - skip
    
instr_done:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
AssembleInstruction ENDP

;==============================================================================
; Emit a byte to output
; AL = byte to emit
;==============================================================================
EmitByte PROC
    push rbx
    
    mov ebx, code_size
    cmp current_section, STATE_TEXT
    jne emit_to_data
    
    ; Emit to code section
    lea rcx, output_buffer
    add rcx, rbx
    mov [rcx], al
    inc ebx
    mov code_size, ebx
    jmp emit_done
    
emit_to_data:
    ; Emit to data section
    lea rcx, data_buffer
    add rcx, rbx
    mov [rcx], al
    inc ebx
    mov data_size, ebx
    
emit_done:
    pop rbx
    ret
EmitByte ENDP

;==============================================================================
; Parse register name and return register number
; RCX = register name string
; Returns: ECX = register number (0-15)
;==============================================================================
ParseRegister PROC
    push rbx
    push rsi
    
    mov rsi, rcx
    
    ; Check for 64-bit registers
    lea rcx, reg_rax
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_0
    
    lea rcx, reg_rcx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_1
    
    lea rcx, reg_rdx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_2
    
    lea rcx, reg_rbx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_3
    
    lea rcx, reg_rsp
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_4
    
    lea rcx, reg_rbp
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_5
    
    lea rcx, reg_rsi
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_6
    
    lea rcx, reg_rdi
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_7
    
    ; Check for r8-r15
    cmp BYTE PTR [rsi], 'r'
    jne try_32bit
    cmp BYTE PTR [rsi+1], '8'
    jb try_32bit
    cmp BYTE PTR [rsi+1], '9'
    ja try_r10
    
    movzx ecx, BYTE PTR [rsi+1]
    sub ecx, '8'
    add ecx, 8
    jmp reg_done
    
try_r10:
    cmp BYTE PTR [rsi+1], '1'
    jne try_32bit
    movzx ecx, BYTE PTR [rsi+2]
    sub ecx, '0'
    add ecx, 10
    jmp reg_done
    
try_32bit:
    ; Check for 32-bit registers (map to same numbers)
    lea rcx, reg_eax
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_0
    
    lea rcx, reg_ecx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_1
    
    lea rcx, reg_edx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_2
    
    lea rcx, reg_ebx
    mov rdx, rsi
    call StringCompare
    test rax, rax
    jnz reg_is_3
    
    ; Default to 0
    xor ecx, ecx
    jmp reg_done
    
reg_is_0:
    xor ecx, ecx
    jmp reg_done
    
reg_is_1:
    mov ecx, 1
    jmp reg_done
    
reg_is_2:
    mov ecx, 2
    jmp reg_done
    
reg_is_3:
    mov ecx, 3
    jmp reg_done
    
reg_is_4:
    mov ecx, 4
    jmp reg_done
    
reg_is_5:
    mov ecx, 5
    jmp reg_done
    
reg_is_6:
    mov ecx, 6
    jmp reg_done
    
reg_is_7:
    mov ecx, 7
    
reg_done:
    pop rsi
    pop rbx
    ret
ParseRegister ENDP

;==============================================================================
; Parse register or memory operand
; RCX = operand string
; Returns: ECX = ModR/M byte value
;==============================================================================
ParseRegisterOrMemory PROC
    push rbx
    push rsi
    
    mov rsi, rcx
    mov al, [rsi]
    
    ; Check if it's a register
    cmp al, 'r'
    je try_register
    cmp al, 'e'
    je try_register
    
    ; Check for memory reference [reg]
    cmp al, '['
    jne is_immediate
    
    ; Parse memory operand
    inc rsi
    mov rcx, rsi
    call ParseRegister
    ; Mod = 00, R/M = reg
    and ecx, 7
    jmp mem_done
    
try_register:
    mov rcx, rsi
    call ParseRegister
    ; Mod = 11 (register), R/M = reg
    and ecx, 7
    or ecx, 0C0h
    jmp mem_done
    
is_immediate:
    ; Immediate value - use direct addressing
    xor ecx, ecx
    
mem_done:
    pop rsi
    pop rbx
    ret
ParseRegisterOrMemory ENDP

;==============================================================================
; Parse memory operand
; RCX = operand string (without brackets)
; Returns: ECX = R/M field value
;==============================================================================
ParseMemoryOperand PROC
    push rbx
    push rsi
    
    mov rsi, rcx
    mov rcx, rsi
    call ParseRegister
    and ecx, 7
    
    pop rsi
    pop rbx
    ret
ParseMemoryOperand ENDP

;==============================================================================
; Parse a number from string
; RCX = number string
; Returns: EAX = parsed number
;==============================================================================
ParseNumber PROC
    push rbx
    push rsi
    
    mov rsi, rcx
    xor ebx, ebx
    
    ; Check for hex prefix
    cmp WORD PTR [rsi], 'x0'
    je parse_hex
    cmp WORD PTR [rsi], 'X0'
    je parse_hex
    
    ; Check for 'h' suffix
    mov rcx, rsi
    call StringLength
    cmp BYTE PTR [rsi+rax-1], 'h'
    je parse_hex_suffix
    
    ; Parse decimal
    jmp parse_decimal
    
parse_hex:
    add rsi, 2
    
parse_hex_loop:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz parse_done
    
    shl ebx, 4
    
    cmp al, '0'
    jb check_hex_upper
    cmp al, '9'
    ja check_hex_upper
    sub al, '0'
    jmp add_digit
    
check_hex_upper:
    cmp al, 'A'
    jb check_hex_lower
    cmp al, 'F'
    ja check_hex_lower
    sub al, 'A' - 10
    jmp add_digit
    
check_hex_lower:
    cmp al, 'a'
    jb parse_done
    cmp al, 'f'
    ja parse_done
    sub al, 'a' - 10
    
add_digit:
    or bl, al
    inc rsi
    jmp parse_hex_loop
    
parse_hex_suffix:
    ; Remove 'h' and parse as hex
    mov BYTE PTR [rsi+rax-1], 0
    jmp parse_hex_loop
    
parse_decimal:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz parse_done
    cmp al, '0'
    jb parse_done
    cmp al, '9'
    ja parse_done
    
    sub al, '0'
    imul ebx, 10
    add ebx, eax
    inc rsi
    jmp parse_decimal
    
parse_done:
    mov eax, ebx
    
    pop rsi
    pop rbx
    ret
ParseNumber ENDP

;==============================================================================
; Add label to symbol table
; RCX = label name
; EDX = section number
;==============================================================================
AddLabel PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    
    ; Find symbol table entry
    mov ebx, num_symbols
    cmp ebx, MAX_SYMBOLS
    jae add_label_done
    
    ; Calculate symbol table offset
    mov rax, rbx
    imul rax, 18            ; 18 bytes per symbol
    lea rdi, symbol_table
    add rdi, rax
    
    ; Copy name (first 8 bytes)
    mov rcx, rsi
    mov rdx, rdi
    mov r8, 8
    call CopyStringMax
    
    ; Set value (offset in section)
    cmp current_section, STATE_TEXT
    jne label_in_data
    mov eax, code_size
    jmp set_value
    
label_in_data:
    mov eax, data_size
    
set_value:
    mov DWORD PTR [rdi+8], eax
    
    ; Section number
    mov WORD PTR [rdi+12], dx
    
    ; Type
    mov WORD PTR [rdi+14], 0
    
    ; Storage class
    mov BYTE PTR [rdi+16], IMAGE_SYM_CLASS_STATIC
    
    ; Aux symbols
    mov BYTE PTR [rdi+17], 0
    
    inc ebx
    mov num_symbols, ebx
    
add_label_done:
    pop rdi
    pop rsi
    pop rbx
    ret
AddLabel ENDP

;==============================================================================
; Add relocation entry
; RCX = symbol name
;==============================================================================
AddRelocation PROC
    push rbx
    push rsi
    
    mov rsi, rcx
    
    ; Find symbol
    call FindSymbol
    test rax, rax
    js add_reloc_done       ; Symbol not found
    
    ; Add relocation entry
    mov ebx, num_relocs
    cmp ebx, MAX_RELOCATIONS
    jae add_reloc_done
    
    ; Calculate relocation table offset
    mov rax, rbx
    imul rax, 10            ; 10 bytes per relocation
    lea rdx, relocation_table
    add rdx, rax
    
    ; Virtual address (current offset)
    mov eax, code_size
    sub eax, 4              ; Point to the operand
    mov DWORD PTR [rdx], eax
    
    ; Symbol table index
    mov DWORD PTR [rdx+4], 0    ; Will be fixed
    
    ; Type
    mov WORD PTR [rdx+8], IMAGE_REL_AMD64_REL32
    
    inc ebx
    mov num_relocs, ebx
    
add_reloc_done:
    pop rsi
    pop rbx
    ret
AddRelocation ENDP

;==============================================================================
; Find symbol in symbol table
; RCX = symbol name
; Returns: RAX = symbol index, or -1 if not found
;==============================================================================
FindSymbol PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    xor ebx, ebx
    
find_sym_loop:
    cmp ebx, num_symbols
    jae symbol_not_found
    
    mov rax, rbx
    imul rax, 18
    lea rdi, symbol_table
    add rdi, rax
    
    mov rcx, rsi
    mov rdx, rdi
    call StringCompareN
    test rax, rax
    jnz symbol_found
    
    inc ebx
    jmp find_sym_loop
    
symbol_found:
    mov rax, rbx
    jmp find_sym_done
    
symbol_not_found:
    mov rax, -1
    
find_sym_done:
    pop rdi
    pop rsi
    pop rbx
    ret
FindSymbol ENDP

;==============================================================================
; Update section headers with final sizes
;==============================================================================
UpdateSectionHeaders PROC
    push rdi
    
    ; Update .text section
    lea rdi, section_headers
    
    ; Size of raw data
    mov eax, code_size
    add eax, 15
    and eax, 0FFFFFFF0h     ; Align to 16 bytes
    mov DWORD PTR [rdi+16], eax
    
    ; Number of relocations
    mov ax, num_relocs
    mov WORD PTR [rdi+32], ax
    
    ; Update .data section
    add rdi, 40
    
    mov eax, data_size
    add eax, 15
    and eax, 0FFFFFFF0h
    mov DWORD PTR [rdi+16], eax
    
    pop rdi
    ret
UpdateSectionHeaders ENDP

;==============================================================================
; Write complete COFF file
;==============================================================================
WriteCOFFFile PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    ; Calculate file layout
    ; Header: 20 bytes
    ; Section headers: 2 * 40 = 80 bytes
    ; .text data: code_size (aligned)
    ; .data data: data_size (aligned)
    ; Relocations: num_relocs * 10
    ; Symbol table: num_symbols * 18
    ; String table: string_table_size
    
    ; Update COFF header
    lea rdi, coff_header
    
    ; Pointer to symbol table
    mov eax, 20             ; Header size
    add eax, 80             ; Section headers
    mov ebx, code_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    add eax, ebx            ; .text
    mov ebx, data_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    add eax, ebx            ; .data
    movzx ebx, num_relocs
    imul ebx, 10
    add eax, ebx            ; Relocations
    mov DWORD PTR [rdi+8], eax
    
    ; Number of symbols
    mov eax, num_symbols
    mov DWORD PTR [rdi+12], eax
    
    ; Write COFF header
    mov rcx, output_handle
    lea rdx, coff_header
    mov r8, 20
    lea r9, bytes_written
    call WriteFile
    
    ; Write section headers
    mov rcx, output_handle
    lea rdx, section_headers
    mov r8, 80
    lea r9, bytes_written
    call WriteFile
    
    ; Write .text section data
    mov ebx, code_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    test ebx, ebx
    jz skip_text
    mov rcx, output_handle
    lea rdx, output_buffer
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
skip_text:
    ; Write .data section data
    mov ebx, data_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    test ebx, ebx
    jz skip_data
    mov rcx, output_handle
    lea rdx, data_buffer
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
skip_data:
    ; Write relocation table
    movzx ebx, num_relocs
    test ebx, ebx
    jz skip_relocs
    imul ebx, 10
    mov rcx, output_handle
    lea rdx, relocation_table
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
skip_relocs:
    ; Write symbol table
    mov ebx, num_symbols
    test ebx, ebx
    jz skip_symbols
    imul ebx, 18
    mov rcx, output_handle
    lea rdx, symbol_table
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
skip_symbols:
    ; Write string table
    mov ecx, string_table_size
    mov rcx, output_handle
    lea rdx, string_table
    mov r8d, ecx
    lea r9, bytes_written
    call WriteFile
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
WriteCOFFFile ENDP

;==============================================================================
; Get mnemonic string for instruction index
; RCX = instruction index
; Returns: RAX = pointer to mnemonic string
;==============================================================================
GetMnemonicForIndex PROC
    cmp ecx, 0
    je mnem_0
    cmp ecx, 1
    je mnem_1
    cmp ecx, 2
    je mnem_2
    cmp ecx, 3
    je mnem_3
    cmp ecx, 4
    je mnem_4
    cmp ecx, 5
    je mnem_5
    cmp ecx, 6
    je mnem_6
    cmp ecx, 7
    je mnem_7
    cmp ecx, 8
    je mnem_8
    cmp ecx, 9
    je mnem_9
    cmp ecx, 10
    je mnem_10
    cmp ecx, 11
    je mnem_11
    cmp ecx, 12
    je mnem_12
    cmp ecx, 13
    je mnem_13
    cmp ecx, 14
    je mnem_14
    cmp ecx, 15
    je mnem_15
    cmp ecx, 16
    je mnem_16
    cmp ecx, 17
    je mnem_17
    cmp ecx, 18
    je mnem_18
    cmp ecx, 19
    je mnem_19
    cmp ecx, 20
    je mnem_20
    cmp ecx, 21
    je mnem_21
    cmp ecx, 22
    je mnem_22
    cmp ecx, 23
    je mnem_23
    cmp ecx, 24
    je mnem_24
    cmp ecx, 25
    je mnem_25
    
    lea rax, mnem_nop
    ret
    
mnem_0:
    lea rax, mnem_nop
    ret
mnem_1:
    lea rax, mnem_ret
    ret
mnem_2:
    lea rax, mnem_call
    ret
mnem_3:
    lea rax, mnem_jmp
    ret
mnem_4:
    lea rax, mnem_je
    ret
mnem_5:
    lea rax, mnem_jne
    ret
mnem_6:
    lea rax, mnem_jz
    ret
mnem_7:
    lea rax, mnem_jnz
    ret
mnem_8:
    lea rax, mnem_push
    ret
mnem_9:
    lea rax, mnem_pop
    ret
mnem_10:
    lea rax, mnem_mov
    ret
mnem_11:
    lea rax, mnem_mov
    ret
mnem_12:
    lea rax, mnem_mov
    ret
mnem_13:
    lea rax, mnem_mov
    ret
mnem_14:
    lea rax, mnem_lea
    ret
mnem_15:
    lea rax, mnem_add
    ret
mnem_16:
    lea rax, mnem_sub
    ret
mnem_17:
    lea rax, mnem_inc
    ret
mnem_18:
    lea rax, mnem_dec
    ret
mnem_19:
    lea rax, mnem_xor
    ret
mnem_20:
    lea rax, mnem_and
    ret
mnem_21:
    lea rax, mnem_or
    ret
mnem_22:
    lea rax, mnem_cmp
    ret
mnem_23:
    lea rax, mnem_test
    ret
mnem_24:
    lea rax, mnem_db
    ret
mnem_25:
    lea rax, mnem_align
    ret
GetMnemonicForIndex ENDP

;==============================================================================
; String comparison (case-sensitive)
; RCX = string 1
; RDX = string 2
; Returns: RAX = 1 if equal, 0 if not
;==============================================================================
StringCompare PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    
compare_loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne not_equal
    test al, al
    jz equal
    inc rsi
    inc rdi
    jmp compare_loop
    
not_equal:
    xor eax, eax
    jmp compare_done
    
equal:
    mov eax, 1
    
compare_done:
    pop rdi
    pop rsi
    pop rbx
    ret
StringCompare ENDP

;==============================================================================
; String comparison (max N bytes)
; RCX = string 1
; RDX = string 2
; R8 = max bytes
; Returns: RAX = 1 if equal, 0 if not
;==============================================================================
StringCompareN PROC
    push rbx
    push rsi
    push rdi
    push r8
    
    mov rsi, rcx
    mov rdi, rdx
    
compare_n_loop:
    test r8, r8
    jz equal_n
    
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne not_equal_n
    test al, al
    jz equal_n
    inc rsi
    inc rdi
    dec r8
    jmp compare_n_loop
    
not_equal_n:
    xor eax, eax
    jmp compare_n_done
    
equal_n:
    mov eax, 1
    
compare_n_done:
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
StringCompareN ENDP

;==============================================================================
; Copy string
; RCX = source
; RDX = destination
; R8 = max length
;==============================================================================
CopyStringMax PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    mov rbx, r8
    
copy_loop:
    test rbx, rbx
    jz copy_done
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz copy_done
    inc rsi
    inc rdi
    dec rbx
    jmp copy_loop
    
copy_done:
    pop rdi
    pop rsi
    pop rbx
    ret
CopyStringMax ENDP

;==============================================================================
; Copy string (null-terminated)
; RCX = source
; RDX = destination
; R8 = length
;==============================================================================
CopyString PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    mov rbx, r8
    
copy_str_loop:
    test rbx, rbx
    jz copy_str_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rbx
    jmp copy_str_loop
    
copy_str_done:
    mov BYTE PTR [rdi], 0
    pop rdi
    pop rsi
    pop rbx
    ret
CopyString ENDP

;==============================================================================
; Get string length
; RCX = string
; Returns: RAX = length
;==============================================================================
StringLength PROC
    push rsi
    
    mov rsi, rcx
    xor eax, eax
    
length_loop:
    mov dl, [rsi]
    test dl, dl
    jz length_done
    inc eax
    inc rsi
    jmp length_loop
    
length_done:
    pop rsi
    ret
StringLength ENDP

;==============================================================================
; Print null-terminated string to stdout
; RCX = string pointer
;==============================================================================
PrintString PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    
    mov rsi, rcx                    ; RSI = string pointer
    
    ; Calculate string length
    mov rdi, rsi
    xor rcx, rcx
    dec rcx
    xor al, al
    repne scasb
    not rcx
    dec rcx                         ; RCX = length
    mov rbx, rcx                    ; Save length in RBX
    
    ; Get stdout handle (-11 = STD_OUTPUT_HANDLE)
    mov rcx, 0FFFFFFF5h
    call GetStdHandle
    
    ; WriteFile(stdout, buffer, length, &written, NULL)
    mov r8, rbx                     ; Length
    mov rcx, rax                    ; Handle
    mov rdx, rsi                    ; Buffer
    lea r9, [rsp+32]                ; &written
    mov QWORD PTR [rsp+32], 0       ; Overlapped = NULL
    sub rsp, 32
    call WriteFile
    add rsp, 32
    
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
PrintString ENDP

END
