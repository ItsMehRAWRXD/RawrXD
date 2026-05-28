; =====================================================================================
; SOVEREIGN ENGINE - CONFIGURATION PARSER
; SUBSYSTEM: SEMANTIC BRIDGE & CANONICALIZATION CORE
; ARCHITECTURE: X86-64 (MASM64)
; CODENAME: CONFIG_PARSER v1.0.0
; =====================================================================================

; External dependencies from ConfigLexer and ConfigStore
EXTERN Sovereign_Lexer_Next_Token : PROC
EXTERN Sovereign_Config_Put : PROC
EXTERN Sovereign_Hash_Key : PROC

; Token Types (matching Lexer)
TOKEN_EOF       EQU 0
TOKEN_INT       EQU 1
TOKEN_BOOL      EQU 2
TOKEN_STRING    EQU 3
TOKEN_KEY       EQU 4
TOKEN_EQUALS    EQU 5
TOKEN_NEWLINE   EQU 6

; Config Types (matching Store)
CONFIG_TYPE_NONE    EQU 0
CONFIG_TYPE_INT     EQU 1
CONFIG_TYPE_BOOL    EQU 2
CONFIG_TYPE_STRING  EQU 3

; Structures (re-declared for local offset access, must match exactly)
SOVEREIGN_TOKEN STRUCT
    TokenType       QWORD ?
    ValueInt        QWORD ?
    ValueStrPtr     QWORD ?
    ValueStrLen     QWORD ?
    LineNumber      QWORD ?
SOVEREIGN_TOKEN ENDS

SOVEREIGN_CONFIG_ENTRY STRUCT
    Hash            QWORD ?
    KeyPtr          QWORD ?
    KeyLen          QWORD ?
    ValType         DWORD ?
    Flags           DWORD ?
    ValueInt        QWORD ?
    ValuePtr        QWORD ?
    ValueLen        QWORD ?
    Next            QWORD ?
SOVEREIGN_CONFIG_ENTRY ENDS

.CODE

; =====================================================================================
; API: Sovereign_Config_Parse_All
; INPUT:  RCX = Lexer pointer
;         RDX = Store pointer
; OUTPUT: RAX = 0 (success), -1 (syntax error)
; =====================================================================================
Sovereign_Config_Parse_All PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; Total stack space: Shadow(32) + Token(sizeof SOVEREIGN_TOKEN) + Entry(sizeof SOVEREIGN_CONFIG_ENTRY) + Alignment
    ; sizeof SOVEREIGN_TOKEN = 40
    ; sizeof SOVEREIGN_CONFIG_ENTRY = 72
    ; Total = 32 + 40 + 72 = 144
    sub rsp, 160

    mov rbx, rcx                    ; RBX = Lexer
    mov rsi, rdx                    ; RSI = Store
    lea r12, [rsp + 32]             ; R12 = local SOVEREIGN_TOKEN struct
    lea r15, [rsp + 80]             ; R15 = local SOVEREIGN_CONFIG_ENTRY template

parse_loop:
    ; 1. Expect KEY or EOF
    mov rcx, rbx
    mov rdx, r12
    call Sovereign_Lexer_Next_Token
    
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.TokenType]
    cmp rax, TOKEN_EOF
    je parse_success
    cmp rax, TOKEN_NEWLINE
    je parse_loop                   ; Skip empty lines
    cmp rax, TOKEN_KEY
    jne parse_error

    ; Save Key info for Put call
    mov r13, qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrPtr] ; R13 = Key Ptr
    mov r14, qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrLen] ; R14 = Key Len

    ; 2. Expect EQUALS
    mov rcx, rbx
    mov rdx, r12
    call Sovereign_Lexer_Next_Token
    cmp qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_EQUALS
    jne parse_error

    ; 3. Expect VALUE (INT, BOOL, or STRING)
    mov rcx, rbx
    mov rdx, r12
    call Sovereign_Lexer_Next_Token
    
    ; Zero template
    mov rdi, r15
    mov rcx, (SIZEOF SOVEREIGN_CONFIG_ENTRY) / 8
    xor rax, rax
    rep stosq
    mov rdi, r15                    ; RDI = template pointer

    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.TokenType]
    cmp rax, TOKEN_INT
    je handle_int
    cmp rax, TOKEN_BOOL
    je handle_bool
    cmp rax, TOKEN_STRING
    je handle_string
    
    ; Invalid value type
    jmp parse_error

handle_int:
    mov dword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValType], CONFIG_TYPE_INT
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.ValueInt]
    mov qword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValueInt], rax
    jmp dispatch

handle_bool:
    mov dword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValType], CONFIG_TYPE_BOOL
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.ValueInt]
    mov qword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValueInt], rax
    jmp dispatch

handle_string:
    mov dword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValType], CONFIG_TYPE_STRING
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrPtr]
    mov qword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValuePtr], rax
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrLen]
    mov qword ptr [rdi + SOVEREIGN_CONFIG_ENTRY.ValueLen], rax
    jmp dispatch

dispatch:
    mov rcx, rsi                    ; RCX = Store
    mov rdx, rdi                    ; RDX = Template (R15)
    mov r8, r13                     ; R8 = Key Ptr
    mov r9, r14                     ; R9 = Key Len
    call Sovereign_Config_Put
    
    ; 4. Expect NEWLINE or EOF
    mov rcx, rbx
    mov rdx, r12
    call Sovereign_Lexer_Next_Token
    mov rax, qword ptr [r12 + SOVEREIGN_TOKEN.TokenType]
    cmp rax, TOKEN_NEWLINE
    je parse_loop
    cmp rax, TOKEN_EOF
    je parse_success
    jmp parse_error

parse_success:
    xor rax, rax
    jmp parse_exit

parse_error:
    mov rax, -1

parse_exit:
    add rsp, 160
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Config_Parse_All ENDP

END
