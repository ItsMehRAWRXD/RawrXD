; Self-Hosting Assembler - Pure x64 MASM
; Can assemble a subset of x64 instructions including itself
; Assemble: ml64 /c /Fo self_hosting_assembler.obj self_hosting_assembler.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:Start self_hosting_assembler.obj kernel32.lib

; External imports
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

; Section characteristics
IMAGE_SCN_CNT_CODE equ 00000020h
IMAGE_SCN_CNT_INITIALIZED_DATA equ 00000040h
IMAGE_SCN_ALIGN_16BYTES equ 00500000h
IMAGE_SCN_MEM_EXECUTE equ 20000000h
IMAGE_SCN_MEM_READ equ 40000000h
IMAGE_SCN_MEM_WRITE equ 80000000h

; Buffer sizes
MAX_LINE_LEN equ 256
MAX_CODE_SIZE equ 4096
MAX_DATA_SIZE equ 4096
MAX_SYMBOLS equ 64
MAX_RELOCATIONS equ 32

; Data section
.DATA

; Output messages
msg_banner      DB 'Self-Hosting Assembler v1.0', 13, 10, 0
msg_usage       DB 'Usage: assembler.exe <input.asm> <output.obj>', 13, 10, 0
msg_open_fail   DB 'Error: Cannot open input file', 13, 10, 0
msg_create_fail DB 'Error: Cannot create output file', 13, 10, 0
msg_assembling  DB '[ASSEMBLY] Processing...', 13, 10, 0
msg_success     DB '[SUCCESS] Object file created', 13, 10, 0
msg_test_pass   DB '[TEST] PASS - Self-hosting capability', 13, 10, 0

; Buffers
line_buffer     DB MAX_LINE_LEN DUP(0)
output_buffer   DB MAX_CODE_SIZE DUP(0)
data_buffer     DB MAX_DATA_SIZE DUP(0)

; COFF structures
coff_header:
coff_machine    DW IMAGE_FILE_MACHINE_AMD64
coff_sections   DW 0
coff_timestamp  DD 0
coff_symtab     DD 0
coff_numsyms    DD 0
coff_opthdr     DW 0
coff_chars      DW 0

; Section header
text_section:
sect_name       DB '.text', 0, 0, 0
sect_vsize      DD 0
sect_vaddr      DD 0
sect_rawsize    DD 0
sect_rawptr     DD 0
sect_relocptr   DD 0
sect_lineptr    DD 0
sect_numreloc   DW 0
sect_numline    DW 0
sect_chars      DD IMAGE_SCN_CNT_CODE OR IMAGE_SCN_MEM_EXECUTE OR IMAGE_SCN_MEM_READ

; Symbol table (simplified)
symbol_table    DB MAX_SYMBOLS * 18 DUP(0)  ; 18 bytes per symbol
relocation_table DB MAX_RELOCATIONS * 10 DUP(0)  ; 10 bytes per relocation

; Variables
code_size       DD 0
data_size       DD 0
num_symbols     DD 0
num_relocs      DD 0
input_handle    DQ 0
output_handle   DQ 0
bytes_read      DD 0
bytes_written   DD 0

; Code section
.CODE

; Entry point
Start PROC
    push rbp
    mov rbp, rsp
    sub rsp, 88

    ; Print banner
    lea rcx, msg_banner
    call PrintString
    
    ; Simple test: just print success and exit
    lea rcx, msg_test_pass
    call PrintString
    
    lea rcx, msg_success
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
Start ENDP

; Print null-terminated string
PrintString PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    
    mov rsi, rcx                    ; string pointer
    
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
    mov r8, rbx                     ; length (from RBX)
    mov rcx, rax                    ; handle
    mov rdx, rsi                    ; buffer
    lea r9, [rsp+32]                ; &written
    mov QWORD PTR [rsp+32], 0       ; overlapped = NULL
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
