; ============================================================================
; Sovereign Compiler Engine - Base Infrastructure
; Shared compiler kernel for 81+ language frontends
; Zero external dependencies, pure MASM64
; ============================================================================

option casemap:none
option win64:3
option frame:auto

; ============================================================================
; PE Format Constants
; ============================================================================
IMAGE_DOS_SIGNATURE           equ 5A4Dh
IMAGE_NT_SIGNATURE            equ 00004550h
IMAGE_FILE_MACHINE_AMD64      equ 8664h
IMAGE_SUBSYSTEM_WINDOWS_CUI   equ 3
IMAGE_SUBSYSTEM_WINDOWS_GUI   equ 2

SECTION_ALIGNMENT             equ 1000h
FILE_ALIGNMENT                equ 200h
IMAGE_BASE_DEFAULT            equ 140000000h

; ============================================================================
; Token Types (Shared across all frontends)
; ============================================================================
TOKEN_EOF                     equ 0
TOKEN_IDENTIFIER              equ 1
TOKEN_NUMBER                  equ 2
TOKEN_STRING                  equ 3
TOKEN_KEYWORD                 equ 4
TOKEN_OPERATOR                equ 5
TOKEN_SYMBOL                  equ 6
TOKEN_COMMENT                 equ 7
TOKEN_NEWLINE                 equ 8
TOKEN_WHITESPACE              equ 9

; ============================================================================
; IR Instruction Types (Intermediate Representation)
; ============================================================================
IR_NOP                        equ 0
IR_LOAD                       equ 1
IR_STORE                      equ 2
IR_ADD                        equ 3
IR_SUB                        equ 4
IR_MUL                        equ 5
IR_DIV                        equ 6
IR_MOD                        equ 7
IR_AND                        equ 8
IR_OR                         equ 9
IR_XOR                        equ 10
IR_SHL                        equ 11
IR_SHR                        equ 12
IR_CMP                        equ 13
IR_JMP                        equ 14
IR_JE                         equ 15
IR_JNE                        equ 16
IR_JL                         equ 17
IR_JG                         equ 18
IR_CALL                       equ 19
IR_RET                        equ 20
IR_PUSH                       equ 21
IR_POP                        equ 22
IR_MOV                        equ 23
IR_LEA                        equ 24
IR_SYSCALL                    equ 25

; ============================================================================
; Data Structures
; ============================================================================

; Token structure (32 bytes)
TOKEN STRUCT
    type_       DWORD ?         ; Token type
    length_     DWORD ?         ; Token length
    value       QWORD ?         ; Pointer to token value
    line        DWORD ?         ; Line number
    column      DWORD ?         ; Column number
    next        QWORD ?         ; Next token pointer
TOKEN ENDS

; IR Instruction structure (32 bytes)
IR_INSTRUCTION STRUCT
    opcode      DWORD ?         ; IR opcode
    dest        DWORD ?         ; Destination operand
    src1        DWORD ?         ; Source operand 1
    src2        DWORD ?         ; Source operand 2
    imm         QWORD ?         ; Immediate value
    next        QWORD ?         ; Next instruction
IR_INSTRUCTION ENDS

; Symbol table entry (48 bytes)
SYMBOL_ENTRY STRUCT
    name        QWORD ?         ; Pointer to name
    type_       DWORD ?         ; Symbol type
    size_       DWORD ?         ; Size in bytes
    offset_     DWORD ?         ; Stack/data offset
    scope       DWORD ?         ; Scope level
    next        QWORD ?         ; Next symbol
SYMBOL_ENTRY ENDS

; ============================================================================
; Global State
; ============================================================================
.data
    ; Compiler version
    sovereign_compiler_version db "Sovereign Compiler Engine v1.0", 0
    
    ; Token buffer (circular, 4096 tokens)
    token_buffer        TOKEN 4096 DUP(<>)
    token_count         DWORD 0
    token_head          QWORD 0
    token_tail          QWORD 0
    
    ; IR buffer (65536 instructions)
    ir_buffer           IR_INSTRUCTION 65536 DUP(<>)
    ir_count            DWORD 0
    ir_head             QWORD 0
    ir_tail             QWORD 0
    
    ; Symbol table (8192 entries)
    symbol_table        SYMBOL_ENTRY 8192 DUP(<>)
    symbol_count        DWORD 0
    current_scope       DWORD 0
    
    ; Source buffer
    source_buffer       QWORD ?
    source_length       DWORD ?
    source_position     DWORD ?
    current_line        DWORD 1
    current_column      DWORD 1
    
    ; Error handling
    error_count         DWORD 0
    warning_count       DWORD 0
    max_errors          DWORD 100

; ============================================================================
; Core Functions
; ============================================================================
.code

; ----------------------------------------------------------------------------
; Initialize Sovereign Compiler Engine
; ----------------------------------------------------------------------------
sovereign_compiler_init PROC
    push rbp
    mov rbp, rsp
    
    ; Initialize token system
    mov token_count, 0
    mov token_head, 0
    mov token_tail, 0
    
    ; Initialize IR system
    mov ir_count, 0
    mov ir_head, 0
    mov ir_tail, 0
    
    ; Initialize symbol table
    mov symbol_count, 0
    mov current_scope, 0
    
    ; Initialize source tracking
    mov source_position, 0
    mov current_line, 1
    mov current_column, 1
    mov error_count, 0
    mov warning_count, 0
    
    mov rax, 1                  ; Success
    leave
    ret
sovereign_compiler_init ENDP

; ----------------------------------------------------------------------------
; Token Management
; ----------------------------------------------------------------------------
token_create PROC
    ; rcx = type, rdx = value, r8 = length
    push rbp
    mov rbp, rsp
    
    ; Get next token slot
    mov eax, token_count
    cmp eax, 4096
    jae token_overflow
    
    ; Calculate token address
    mov rbx, SIZEOF TOKEN
    mul ebx
    lea rdi, token_buffer[rax]
    
    ; Fill token
    mov [rdi].TOKEN.type_, ecx
    mov [rdi].TOKEN.value, rdx
    mov [rdi].TOKEN.length_, r8d
    mov eax, current_line
    mov [rdi].TOKEN.line, eax
    mov eax, current_column
    mov [rdi].TOKEN.column, eax
    
    ; Increment count
    inc token_count
    
    mov rax, rdi              ; Return token pointer
    leave
    ret
    
token_overflow:
    xor rax, rax              ; Return NULL on overflow
    leave
    ret
token_create ENDP

; ----------------------------------------------------------------------------
; IR Generation
; ----------------------------------------------------------------------------
ir_emit PROC
    ; rcx = opcode, rdx = dest, r8 = src1, r9 = src2
    push rbp
    mov rbp, rsp
    
    ; Get next IR slot
    mov eax, ir_count
    cmp eax, 65536
    jae ir_overflow
    
    ; Calculate instruction address
    mov rbx, SIZEOF IR_INSTRUCTION
    mul ebx
    lea rdi, ir_buffer[rax]
    
    ; Fill instruction
    mov [rdi].IR_INSTRUCTION.opcode, ecx
    mov [rdi].IR_INSTRUCTION.dest, edx
    mov [rdi].IR_INSTRUCTION.src1, r8d
    mov [rdi].IR_INSTRUCTION.src2, r9d
    
    ; Increment count
    inc ir_count
    
    mov rax, rdi              ; Return instruction pointer
    leave
    ret
    
ir_overflow:
    xor rax, rax              ; Return NULL on overflow
    leave
    ret
ir_emit ENDP

; ----------------------------------------------------------------------------
; Symbol Table Management
; ----------------------------------------------------------------------------
symbol_lookup PROC
    ; rcx = name pointer
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    
    mov rsi, rcx              ; Name to find
    lea rdi, symbol_table
    mov ecx, symbol_count
    test ecx, ecx
    jz symbol_not_found
    
symbol_search_loop:
    push rcx
    push rdi
    
    ; Compare names
    mov rdx, [rdi].SYMBOL_ENTRY.name
    call strcmp
    test rax, rax
    jz symbol_found
    
    pop rdi
    pop rcx
    add rdi, SIZEOF SYMBOL_ENTRY
    loop symbol_search_loop
    
symbol_not_found:
    xor rax, rax              ; Return NULL
    jmp symbol_done
    
symbol_found:
    pop rax                   ; Return symbol entry
    pop rcx
    
symbol_done:
    pop rdi
    pop rsi
    leave
    ret
symbol_lookup ENDP

; ----------------------------------------------------------------------------
; String Utilities
; ----------------------------------------------------------------------------
strcmp PROC
    ; Compare strings at rsi and rdx
    push rbp
    mov rbp, rsp
    push rsi
    push rdx
    
strcmp_loop:
    mov al, [rsi]
    mov bl, [rdx]
    cmp al, bl
    jne strcmp_diff
    test al, al
    jz strcmp_equal
    inc rsi
    inc rdx
    jmp strcmp_loop
    
strcmp_diff:
    mov rax, 1                ; Not equal
    jmp strcmp_done
    
strcmp_equal:
    xor rax, rax              ; Equal
    
strcmp_done:
    pop rdx
    pop rsi
    leave
    ret
strcmp ENDP

; ----------------------------------------------------------------------------
; Error Reporting
; ----------------------------------------------------------------------------
report_error PROC
    ; rcx = message, rdx = line
    push rbp
    mov rbp, rsp
    
    inc error_count
    
    ; Check max errors
    mov eax, error_count
    cmp eax, max_errors
    jae too_many_errors
    
    ; Print error (simplified)
    ; In real implementation, would use WriteFile
    
    mov rax, 1
    leave
    ret
    
too_many_errors:
    xor rax, rax              ; Abort
    leave
    ret
report_error ENDP

END
