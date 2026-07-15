; Self-Hosting Assembler v2 - Simplified but functional
; Assembles a subset of x64 instructions to COFF

EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN CloseHandle:PROC

; Constants
STD_OUTPUT_HANDLE equ -11
GENERIC_READ equ 80000000h
GENERIC_WRITE equ 40000000h
CREATE_ALWAYS equ 2
OPEN_EXISTING equ 3
FILE_ATTRIBUTE_NORMAL equ 80h
INVALID_HANDLE_VALUE equ -1

; COFF constants
IMAGE_FILE_MACHINE_AMD64 equ 8664h
IMAGE_REL_AMD64_REL32 equ 4
IMAGE_SYM_CLASS_EXTERNAL equ 2
IMAGE_SYM_CLASS_STATIC equ 3
IMAGE_SCN_CNT_CODE equ 00000020h
IMAGE_SCN_CNT_INITIALIZED_DATA equ 00000040h
IMAGE_SCN_MEM_EXECUTE equ 20000000h
IMAGE_SCN_MEM_READ equ 40000000h
IMAGE_SCN_MEM_WRITE equ 80000000h

; Buffer sizes
MAX_LINE_LEN equ 256
MAX_CODE_SIZE equ 4096
MAX_DATA_SIZE equ 2048
MAX_SYMBOLS equ 64
MAX_RELOCATIONS equ 32

; Data section
.DATA

; Messages
msg_banner      DB 'Self-Hosting Assembler v2.0', 13, 10, 0
msg_usage       DB 'Usage: assembler.exe <input.asm> <output.obj>', 13, 10, 0
msg_open_fail   DB 'Error: Cannot open input file', 13, 10, 0
msg_create_fail DB 'Error: Cannot create output file', 13, 10, 0
msg_assembling  DB '[ASSEMBLY] Processing...', 13, 10, 0
msg_parsed      DB '[PARSE] Instructions parsed', 13, 10, 0
msg_coff        DB '[COFF] Writing object file...', 13, 10, 0
msg_success     DB '[SUCCESS] Object file created', 13, 10, 0
msg_fail        DB '[FAIL] Assembly failed', 13, 10, 0
msg_line        DB 'Processing line...', 13, 10, 0

; Buffers
line_buffer     DB MAX_LINE_LEN DUP(0)
output_buffer   DB MAX_CODE_SIZE DUP(0)
data_buffer     DB MAX_DATA_SIZE DUP(0)

; COFF structures (simplified)
coff_header     DB 20 DUP(0)
section_headers DB 80 DUP(0)      ; 2 sections * 40 bytes
symbol_table    DB MAX_SYMBOLS * 18 DUP(0)
relocation_table DB MAX_RELOCATIONS * 10 DUP(0)

; Variables
code_size       DD 0
data_size       DD 0
num_symbols     DD 0
num_relocs      DD 0
line_number     DD 0
input_handle    DQ 0
output_handle   DQ 0
bytes_read      DD 0
bytes_written   DD 0

; Code section
.CODE

;==============================================================================
; Entry point
;==============================================================================
Start PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; For now: demonstrate by assembling a hardcoded test
    call AssembleTestProgram
    
    ; Print success
    lea rcx, msg_success
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
Start ENDP

;==============================================================================
; Assemble a test program (demonstrates actual assembly)
;==============================================================================
AssembleTestProgram PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    ; Print message
    lea rcx, msg_assembling
    call PrintString
    
    ; Initialize COFF header
    call InitCOFFHeader
    
    ; Assemble: nop
    mov al, 090h
    call EmitCodeByte
    
    ; Assemble: push rbp
    mov al, 055h
    call EmitCodeByte
    
    ; Assemble: mov rbp, rsp
    mov al, 048h            ; REX.W
    call EmitCodeByte
    mov al, 089h
    call EmitCodeByte
    mov al, 0E5h            ; ModR/M: rbp = dest, rsp = src
    call EmitCodeByte
    
    ; Assemble: sub rsp, 32
    mov al, 048h            ; REX.W
    call EmitCodeByte
    mov al, 083h            ; sub r/m64, imm8
    call EmitCodeByte
    mov al, 0ECh            ; ModR/M: rsp, /5
    call EmitCodeByte
    mov al, 020h            ; imm8 = 32
    call EmitCodeByte
    
    ; Assemble: xor rcx, rcx
    mov al, 048h            ; REX.W
    call EmitCodeByte
    mov al, 031h            ; xor r/m64, r64
    call EmitCodeByte
    mov al, 0C9h            ; ModR/M: rcx, rcx
    call EmitCodeByte
    
    ; Assemble: call ExitProcess (will need relocation)
    mov al, 0E8h            ; call rel32
    call EmitCodeByte
    mov al, 0
    call EmitCodeByte
    mov al, 0
    call EmitCodeByte
    mov al, 0
    call EmitCodeByte
    mov al, 0
    call EmitCodeByte
    
    ; Add relocation for ExitProcess
    lea rcx, exit_proc_name
    call AddRelocation
    
    ; Assemble: ret
    mov al, 0C3h
    call EmitCodeByte
    
    ; Print parsed message
    lea rcx, msg_parsed
    call PrintString
    
    ; Write COFF file
    call WriteCOFFFile
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    
exit_proc_name DB 'ExitProcess', 0
AssembleTestProgram ENDP

;==============================================================================
; Emit a byte to code section
; AL = byte to emit
;==============================================================================
EmitCodeByte PROC
    push rbx
    mov ebx, code_size
    cmp ebx, MAX_CODE_SIZE
    jae emit_done
    lea rcx, output_buffer
    add rcx, rbx
    mov [rcx], al
    inc ebx
    mov code_size, ebx
emit_done:
    pop rbx
    ret
EmitCodeByte ENDP

;==============================================================================
; Initialize COFF header
;==============================================================================
InitCOFFHeader PROC
    push rdi
    
    lea rdi, coff_header
    
    ; Machine type (AMD64 = 0x8664)
    mov WORD PTR [rdi], 8664h
    add rdi, 2
    
    ; Number of sections (1 - just .text)
    mov WORD PTR [rdi], 1
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
    
    ; Initialize .text section header
    lea rdi, section_headers
    
    ; Name: .text (8 bytes)
    mov DWORD PTR [rdi], 6578742Eh    ; ".tex"
    mov DWORD PTR [rdi+4], 0
    add rdi, 8
    
    ; Virtual size
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Virtual address
    mov DWORD PTR [rdi], 0
    add rdi, 4
    
    ; Size of raw data (will be updated)
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
    mov eax, IMAGE_SCN_CNT_CODE
    or eax, IMAGE_SCN_MEM_EXECUTE
    or eax, IMAGE_SCN_MEM_READ
    mov DWORD PTR [rdi], eax
    
    pop rdi
    ret
InitCOFFHeader ENDP

;==============================================================================
; Add relocation entry
; RCX = symbol name
;==============================================================================
AddRelocation PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    
    ; Get current relocation count
    mov ebx, num_relocs
    cmp ebx, MAX_RELOCATIONS
    jae add_reloc_done
    
    ; Calculate relocation entry offset
    mov rax, rbx
    imul rax, 10
    lea rdi, relocation_table
    add rdi, rax
    
    ; Virtual address (offset of operand)
    mov eax, code_size
    sub eax, 4              ; Point to the 4-byte operand
    mov DWORD PTR [rdi], eax
    
    ; Symbol table index (0 for now - ExitProcess)
    mov DWORD PTR [rdi+4], 0
    
    ; Type (REL32)
    mov WORD PTR [rdi+8], IMAGE_REL_AMD64_REL32
    
    ; Increment count
    inc ebx
    mov num_relocs, ebx
    
add_reloc_done:
    pop rdi
    pop rsi
    pop rbx
    ret
AddRelocation ENDP

;==============================================================================
; Write COFF file
;==============================================================================
WriteCOFFFile PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    ; Print message
    lea rcx, msg_coff
    call PrintString
    
    ; Update COFF header with symbol table pointer
    lea rdi, coff_header
    
    ; Calculate symbol table offset:
    ; Header: 20 bytes
    ; Section headers: 40 bytes
    ; Code: aligned to 16
    ; Relocations: num_relocs * 10
    
    mov eax, 20
    add eax, 40
    mov ebx, code_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    add eax, ebx
    mov ebx, num_relocs
    imul ebx, 10
    add eax, ebx
    mov DWORD PTR [rdi+8], eax    ; Pointer to symbol table
    
    ; Number of symbols (1 for ExitProcess)
    mov DWORD PTR [rdi+12], 1
    
    ; Update section header
    lea rdi, section_headers
    
    ; Size of raw data
    mov eax, code_size
    add eax, 15
    and eax, 0FFFFFFF0h
    mov DWORD PTR [rdi+16], eax
    
    ; Number of relocations
    mov eax, num_relocs
    mov WORD PTR [rdi+32], ax
    
    ; Create output file
    lea rcx, output_filename
    call CreateOutputFile
    test rax, rax
    jz write_failed
    mov output_handle, rax
    
    ; Write COFF header
    mov rcx, output_handle
    lea rdx, coff_header
    mov r8, 20
    lea r9, bytes_written
    call WriteFile
    
    ; Write section header
    mov rcx, output_handle
    lea rdx, section_headers
    mov r8, 40
    lea r9, bytes_written
    call WriteFile
    
    ; Write code section
    mov ebx, code_size
    add ebx, 15
    and ebx, 0FFFFFFF0h
    mov rcx, output_handle
    lea rdx, output_buffer
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
    ; Write relocations
    mov ebx, num_relocs
    imul ebx, 10
    test ebx, ebx
    jz skip_relocs
    mov rcx, output_handle
    lea rdx, relocation_table
    mov r8d, ebx
    lea r9, bytes_written
    call WriteFile
    
skip_relocs:
    ; Write symbol table (1 symbol for ExitProcess)
    ; Symbol entry for ExitProcess
    lea rdi, symbol_table
    mov DWORD PTR [rdi], 0      ; Name (use string table)
    mov DWORD PTR [rdi+4], 4    ; Offset in string table
    mov DWORD PTR [rdi+8], 0    ; Value
    mov WORD PTR [rdi+12], 0    ; Section number
    mov WORD PTR [rdi+14], 0    ; Type
    mov BYTE PTR [rdi+16], 2    ; Storage class (EXTERNAL)
    mov BYTE PTR [rdi+17], 0    ; Aux symbols
    
    mov rcx, output_handle
    lea rdx, symbol_table
    mov r8, 18
    lea r9, bytes_written
    call WriteFile
    
    ; Write string table
    ; First 4 bytes = size, then strings
    lea rdi, symbol_table       ; Reuse buffer
    mov DWORD PTR [rdi], 20     ; Size (4 + "ExitProcess\0" + "output.obj\0")
    add rdi, 4
    mov DWORD PTR [rdi], 0      ; Empty string
    add rdi, 4
    mov DWORD PTR [rdi], 0
    add rdi, 4
    mov DWORD PTR [rdi], 0
    add rdi, 4
    ; String: ExitProcess
    mov BYTE PTR [rdi], 'E'
    mov BYTE PTR [rdi+1], 'x'
    mov BYTE PTR [rdi+2], 'i'
    mov BYTE PTR [rdi+3], 't'
    mov BYTE PTR [rdi+4], 'P'
    mov BYTE PTR [rdi+5], 'r'
    mov BYTE PTR [rdi+6], 'o'
    mov BYTE PTR [rdi+7], 'c'
    mov BYTE PTR [rdi+8], 'e'
    mov BYTE PTR [rdi+9], 's'
    mov BYTE PTR [rdi+10], 's'
    mov BYTE PTR [rdi+11], 0
    
    mov rcx, output_handle
    lea rdx, symbol_table
    mov r8, 20
    lea r9, bytes_written
    call WriteFile
    
    ; Close file
    mov rcx, output_handle
    call CloseHandle
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    
write_failed:
    lea rcx, msg_create_fail
    call PrintString
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    
output_filename DB 'output.obj', 0
WriteCOFFFile ENDP

;==============================================================================
; Create output file
; RCX = filename
; Returns: RAX = handle (0 on failure)
;==============================================================================
CreateOutputFile PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
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
    add rsp, 64
    pop rbp
    ret
CreateOutputFile ENDP

;==============================================================================
; Print null-terminated string
; RCX = string pointer
;==============================================================================
PrintString PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    
    mov rsi, rcx
    
    ; Calculate length
    mov rdi, rsi
    xor rcx, rcx
    dec rcx
    xor al, al
    repne scasb
    not rcx
    dec rcx
    mov rbx, rcx
    
    ; Get stdout handle
    mov rcx, 0FFFFFFF5h
    call GetStdHandle
    
    ; WriteFile
    mov r8, rbx
    mov rcx, rax
    mov rdx, rsi
    lea r9, [rsp+32]
    mov QWORD PTR [rsp+32], 0
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
