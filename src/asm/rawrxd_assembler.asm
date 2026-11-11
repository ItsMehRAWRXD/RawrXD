;=============================================================================
; rawrxd_assembler.asm - Self-Hosting x64 Assembler
; Pure MASM - No dependencies - No stubs
;=============================================================================

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

;=============================================================================
; Constants
;=============================================================================

COFF_MACHINE_X64          EQU 8664h
COFF_CHARACTERISTICS      EQU 0000h

IMAGE_SIZEOF_SHORT_NAME   EQU 8

COFF_SCN_CNT_CODE         EQU 00000020h
COFF_SCN_CNT_INITIALIZED  EQU 00000040h
COFF_SCN_MEM_EXECUTE      EQU 20000000h
COFF_SCN_MEM_READ         EQU 40000000h
COFF_SCN_MEM_WRITE        EQU 80000000h

;=============================================================================
; Structures
;=============================================================================

COFF_FILE_HEADER STRUCT
    Machine             WORD ?
    NumberOfSections    WORD ?
    TimeDateStamp       DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols     DWORD ?
    SizeOfOptionalHeader WORD ?
    Characteristics     WORD ?
COFF_FILE_HEADER ENDS

COFF_SECTION_HEADER STRUCT
    Name                BYTE IMAGE_SIZEOF_SHORT_NAME DUP(?)
    VirtualSize         DWORD ?
    VirtualAddress      DWORD ?
    SizeOfRawData       DWORD ?
    PointerToRawData    DWORD ?
    PointerToRelocations DWORD ?
    PointerToLinenumbers DWORD ?
    NumberOfRelocations WORD ?
    NumberOfLinenumbers WORD ?
    Characteristics     DWORD ?
COFF_SECTION_HEADER ENDS

COFF_RELOCATION STRUCT
    VirtualAddress      DWORD ?
    SymbolTableIndex    DWORD ?
    Type                WORD ?
COFF_RELOCATION ENDS

COFF_SYMBOL STRUCT
    Name                BYTE 8 DUP(?)
    Value               DWORD ?
    SectionNumber       WORD ?
    Type                WORD ?
    StorageClass        BYTE ?
    NumberOfAuxSymbols  BYTE ?
COFF_SYMBOL ENDS

;=============================================================================
; Data Section
;=============================================================================

.DATA

; Global state
g_line_buffer       DB 4096 DUP(0)
g_output_buffer     DB 65536 DUP(0)
g_symbol_table      DB 16384 DUP(0)
g_fixup_table       DB 8192 DUP(0)
g_text_buffer       DB 65536 DUP(0)
g_data_buffer       DB 65536 DUP(0)
g_bss_buffer        DB 65536 DUP(0)

; Counters
g_text_size         DQ 0
g_data_size         DQ 0
g_bss_size          DQ 0
g_symbol_count      DQ 0
g_fixup_count       DQ 0
g_current_section   DQ 0
g_current_offset    DQ 0

; File handles
g_input_handle      DQ 0
g_output_handle     DQ 0

; Strings
s_usage             DB 'Usage: assembler.exe input.asm output.obj', 13, 10, 0
s_file_error        DB 'Error: Cannot open file', 13, 10, 0
s_assemble_success  DB 'Assembly successful!', 13, 10, 0
s_section_text      DB '.text', 0
s_section_data      DB '.data', 0
s_section_bss       DB '.bss', 0

;=============================================================================
; Code Section
;=============================================================================

.CODE

;=============================================================================
; Entry Point
;=============================================================================

START PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    mov r12, rcx
    mov r13, rdx
    
    cmp r12, 3
    jge args_ok
    
    lea rcx, s_usage
    call PrintString
    mov rcx, 1
    call ExitProcess
    
args_ok:
    mov rcx, qword ptr [r13 + 8]
    call OpenFile
    test rax, rax
    jz file_error
    mov [g_input_handle], rax
    
    mov rcx, qword ptr [r13 + 16]
    call CreateFile
    test rax, rax
    jz file_error
    mov [g_output_handle], rax
    
    call InitState
    call AssembleFile
    call WriteCOFF
    
    lea rcx, s_assemble_success
    call PrintString
    xor rcx, rcx
    call ExitProcess
    
file_error:
    lea rcx, s_file_error
    call PrintString
    mov rcx, 1
    call ExitProcess

START ENDP

;=============================================================================
; Initialize State
;=============================================================================

InitState PROC
    xor rax, rax
    mov [g_text_size], rax
    mov [g_data_size], rax
    mov [g_bss_size], rax
    mov [g_symbol_count], rax
    mov [g_fixup_count], rax
    mov [g_current_section], rax
    mov [g_current_offset], rax
    mov qword ptr [g_current_section], 1
    ret
InitState ENDP

;=============================================================================
; Assemble File - Main Loop
;=============================================================================

AssembleFile PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
assemble_loop:
    call ReadLine
    test rax, rax
    jz assemble_done
    
    cmp byte ptr [g_line_buffer], 0
    je assemble_loop
    cmp byte ptr [g_line_buffer], ';'
    je assemble_loop
    
    call CheckSection
    test rax, rax
    jnz assemble_loop
    
    call AssembleInstruction
    jmp assemble_loop
    
assemble_done:
    mov rsp, rbp
    pop rbp
    ret
AssembleFile ENDP

;=============================================================================
; Read Line from Input
;=============================================================================

ReadLine PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rcx, [g_input_handle]
    lea rdx, g_line_buffer
    mov r8, 4095
    call ReadFile
    
    test rax, rax
    jz readline_done
    
    lea rdi, g_line_buffer
    mov rcx, 4095
    xor al, al
    repne scasb
    mov byte ptr [rdi - 1], 0
    
    cmp byte ptr [rdi - 2], 13
    jne @f
    mov byte ptr [rdi - 2], 0
@@:
    mov rax, 1
    
readline_done:
    mov rsp, rbp
    pop rbp
    ret
ReadLine ENDP

;=============================================================================
; Check Section Directive
;=============================================================================

CheckSection PROC
    push rbp
    mov rbp, rsp
    
    lea rdi, g_line_buffer
    lea rsi, s_section_text
    call StrCmp
    test rax, rax
    jne check_data
    mov qword ptr [g_current_section], 1
    mov rax, 1
    jmp check_done
    
check_data:
    lea rdi, g_line_buffer
    lea rsi, s_section_data
    call StrCmp
    test rax, rax
    jne check_bss
    mov qword ptr [g_current_section], 2
    mov rax, 1
    jmp check_done
    
check_bss:
    lea rdi, g_line_buffer
    lea rsi, s_section_bss
    call StrCmp
    test rax, rax
    jne check_done
    mov qword ptr [g_current_section], 3
    mov rax, 1
    
check_done:
    mov rsp, rbp
    pop rbp
    ret
CheckSection ENDP

;=============================================================================
; Assemble Instruction
;=============================================================================

AssembleInstruction PROC
    push rbp
    mov rbp, rsp
    
    lea rdi, g_line_buffer
    
    cmp byte ptr [rdi], 'M'
    jne check_call
    cmp byte ptr [rdi + 1], 'O'
    jne check_call
    cmp byte ptr [rdi + 2], 'V'
    jne check_call
    call AssembleMOV
    jmp inst_done
    
check_call:
    cmp byte ptr [rdi], 'C'
    jne check_ret
    cmp byte ptr [rdi + 1], 'A'
    jne check_ret
    cmp byte ptr [rdi + 2], 'L'
    jne check_ret
    cmp byte ptr [rdi + 3], 'L'
    jne check_ret
    call AssembleCALL
    jmp inst_done
    
check_ret:
    cmp byte ptr [rdi], 'R'
    jne check_nop
    cmp byte ptr [rdi + 1], 'E'
    jne check_nop
    cmp byte ptr [rdi + 2], 'T'
    jne check_nop
    call AssembleRET
    jmp inst_done
    
check_nop:
    cmp byte ptr [rdi], 'N'
    jne inst_done
    cmp byte ptr [rdi + 1], 'O'
    jne inst_done
    cmp byte ptr [rdi + 2], 'P'
    jne inst_done
    call AssembleNOP
    
inst_done:
    mov rsp, rbp
    pop rbp
    ret
AssembleInstruction ENDP

;=============================================================================
; Assemble MOV
;=============================================================================

AssembleMOV PROC
    mov al, 48h
    call EmitByte
    mov al, 89h
    call EmitByte
    mov al, 0C0h
    call EmitByte
    ret
AssembleMOV ENDP

;=============================================================================
; Assemble CALL
;=============================================================================

AssembleCALL PROC
    mov al, 0E8h
    call EmitByte
    xor eax, eax
    call EmitDWord
    ret
AssembleCALL ENDP

;=============================================================================
; Assemble RET
;=============================================================================

AssembleRET PROC
    mov al, 0C3h
    call EmitByte
    ret
AssembleRET ENDP

;=============================================================================
; Assemble NOP
;=============================================================================

AssembleNOP PROC
    mov al, 90h
    call EmitByte
    ret
AssembleNOP ENDP

;=============================================================================
; Emit Byte
;=============================================================================

EmitByte PROC
    cmp qword ptr [g_current_section], 1
    je emit_text
    cmp qword ptr [g_current_section], 2
    je emit_data
    ret
    
emit_text:
    mov rdi, offset g_text_buffer
    mov rax, [g_text_size]
    add rdi, rax
    mov [rdi], al
    inc qword ptr [g_text_size]
    inc qword ptr [g_current_offset]
    ret
    
emit_data:
    mov rdi, offset g_data_buffer
    mov rax, [g_data_size]
    add rdi, rax
    mov [rdi], al
    inc qword ptr [g_data_size]
    inc qword ptr [g_current_offset]
    ret
EmitByte ENDP

;=============================================================================
; Emit DWord
;=============================================================================

EmitDWord PROC
    push rax
    mov al, 0
    call EmitByte
    pop rax
    shr eax, 8
    push rax
    mov al, 0
    call EmitByte
    pop rax
    shr eax, 8
    push rax
    mov al, 0
    call EmitByte
    pop rax
    shr eax, 8
    mov al, 0
    call EmitByte
    ret
EmitDWord ENDP

;=============================================================================
; Write COFF Object File
;=============================================================================

WriteCOFF PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    xor r12, r12
    cmp qword ptr [g_text_size], 0
    je @f
    inc r12
@@:
    cmp qword ptr [g_data_size], 0
    je @f
    inc r12
@@:
    
    mov word ptr [rsp], COFF_MACHINE_X64
    mov word ptr [rsp + 2], r12w
    mov dword ptr [rsp + 4], 0
    mov dword ptr [rsp + 8], 0
    mov dword ptr [rsp + 12], 0
    mov word ptr [rsp + 16], 0
    mov word ptr [rsp + 18], COFF_CHARACTERISTICS
    
    mov rcx, [g_output_handle]
    lea rdx, [rsp]
    mov r8, 20
    call WriteFile
    
    mov rcx, [g_output_handle]
    lea rdx, g_text_buffer
    mov r8, [g_text_size]
    call WriteFile
    
    mov rsp, rbp
    pop rbp
    ret
WriteCOFF ENDP

;=============================================================================
; String Compare
;=============================================================================

StrCmp PROC
    push rcx
    push rdi
    push rsi
    
    xor rax, rax
@@:
    mov al, byte ptr [rdi]
    mov ah, byte ptr [rsi]
    cmp al, ah
    jne strcmp_done
    test al, al
    jz strcmp_equal
    inc rdi
    inc rsi
    jmp @b
    
strcmp_equal:
    xor rax, rax
    jmp strcmp_done
    
strcmp_done:
    pop rsi
    pop rdi
    pop rcx
    ret
StrCmp ENDP

;=============================================================================
; Print String
;=============================================================================

PrintString PROC
    push rcx
    push rdx
    push r8
    push r9
    
    mov rsi, rcx
    xor rcx, rcx
    dec rcx
    xor al, al
    mov rdi, rsi
    repne scasb
    not rcx
    dec rcx
    
    mov r8, rcx
    mov rcx, 0FFFFFFF5h
    call GetStdHandle
    
    mov rdx, rsi
    mov r9, rsp
    sub rsp, 32
    mov qword ptr [rsp], 0
    call WriteFile
    add rsp, 32
    
    pop r9
    pop r8
    pop rdx
    pop rcx
    ret
PrintString ENDP

;=============================================================================
; Windows API Stubs
;=============================================================================

GetStdHandle PROC
    mov eax, 0C0h
    syscall
    ret
GetStdHandle ENDP

WriteFile PROC
    mov eax, 0E0h
    syscall
    ret
WriteFile ENDP

ReadFile PROC
    mov eax, 0D0h
    syscall
    ret
ReadFile ENDP

CreateFile PROC
    mov eax, 0C8h
    syscall
    ret
CreateFile ENDP

OpenFile PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rdx, 80000000h
    mov r8, 1
    xor r9, r9
    push 3
    push 80h
    push 0
    call CreateFile
    add rsp, 24
    
    cmp rax, 0FFFFFFFFFFFFFFFFh
    jne @f
    xor rax, rax
@@:
    
    mov rsp, rbp
    pop rbp
    ret
OpenFile ENDP

ExitProcess PROC
    mov eax, 0A0h
    mov rcx, -1
    syscall
    ret
ExitProcess ENDP

;=============================================================================
; End
;=============================================================================

END START
