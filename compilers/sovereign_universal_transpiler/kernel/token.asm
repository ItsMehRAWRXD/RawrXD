; ============================================================================
; token.asm - Token definitions for Sovereign Universal Transpiler
; ============================================================================

option casemap:none

; ----------------------------------------------------------------------------
; Token Types - Universal across all frontends
; ----------------------------------------------------------------------------
TOK_EOF         EQU 0
TOK_IDENTIFIER  EQU 1
TOK_STRING      EQU 2
TOK_NUMBER      EQU 3
TOK_KEYWORD     EQU 4
TOK_OPERATOR    EQU 5
TOK_SEMICOLON   EQU 6
TOK_LPAREN      EQU 7
TOK_RPAREN      EQU 8
TOK_LBRACE      EQU 9
TOK_RBRACE      EQU 10
TOK_COMMA       EQU 11
TOK_DOT         EQU 12
TOK_ASSIGN      EQU 13
TOK_PLUS        EQU 14
TOK_MINUS       EQU 15
TOK_STAR        EQU 16
TOK_SLASH       EQU 17
TOK_LT          EQU 18
TOK_GT          EQU 19
TOK_EQ          EQU 20
TOK_NE          EQU 21
TOK_LE          EQU 22
TOK_GE          EQU 23

; ----------------------------------------------------------------------------
; Token Structure (24 bytes - aligned)
; ----------------------------------------------------------------------------
TOKEN STRUCT
    tok_type    DWORD ?
    tok_flags   DWORD ?      ; Token flags (reserved for future use)
    tok_start   QWORD ?      ; Pointer to start in source
    tok_length  DWORD ?
    tok_line    DWORD ?
    tok_column  DWORD ?
    tok_value   QWORD ?      ; Parsed value (for numbers, etc.)
    tok_pad     DWORD ?      ; Padding to align
TOKEN ENDS

; ----------------------------------------------------------------------------
; Token Buffer (max 4096 tokens)
; ----------------------------------------------------------------------------
.data
ALIGN 16
token_buffer TOKEN 256 DUP(<>)
token_count DWORD 0

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; TokenInit - Initialize token buffer
; ============================================================================
TokenInit PROC
    push rbp
    mov rbp, rsp
    
    mov token_count, 0
    
    mov rax, 1
    leave
    ret
TokenInit ENDP

; ============================================================================
; TokenCreate - Create a new token
; RCX = type
; RDX = start pointer
; R8  = length
; R9  = line
; [RSP+28h] = column
; Returns: RAX = token index (or -1 if full)
; ============================================================================
TokenCreate PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    
    mov ebx, ecx        ; type
    
    ; Check capacity
    mov eax, token_count
    cmp eax, 4096
    jge full
    
    ; Calculate token address (TOKEN is now 24 bytes, but we use 32 for alignment)
    ; Actually, let's keep it simple: use SIZEOF TOKEN
    imul edi, eax, SIZEOF TOKEN
    lea rdi, [token_buffer + rdi]
    
    ; Fill token
    mov [rdi].TOKEN.tok_type, ebx
    mov dword ptr [rdi].TOKEN.tok_flags, 0     ; Initialize flags
    mov [rdi].TOKEN.tok_start, rdx
    mov [rdi].TOKEN.tok_length, r8d
    mov [rdi].TOKEN.tok_line, r9d
    mov eax, [rbp+28h]
    mov [rdi].TOKEN.tok_column, eax
    mov qword ptr [rdi].TOKEN.tok_value, 0     ; Initialize value
    mov dword ptr [rdi].TOKEN.tok_pad, 0       ; Initialize padding
    
    ; Return index and increment
    mov eax, token_count
    inc token_count
    
    jmp done
    
full:
    mov rax, -1
    
done:
    pop rdi
    pop rbx
    leave
    ret
TokenCreate ENDP

; ============================================================================
; TokenGet - Get token by index
; RCX = token index
; Returns: RAX = pointer to TOKEN (or NULL if invalid)
; ============================================================================
TokenGet PROC
    push rbp
    mov rbp, rsp
    
    cmp ecx, token_count
    jae invalid
    
    imul eax, ecx, SIZEOF TOKEN
    lea rax, [token_buffer + rax]
    jmp done
    
invalid:
    xor rax, rax
    
done:
    leave
    ret
TokenGet ENDP

; ============================================================================
; TokenGetCount - Get current token count
; Returns: RAX = token count
; ============================================================================
TokenGetCount PROC
    push rbp
    mov rbp, rsp
    
    mov eax, token_count
    
    leave
    ret
TokenGetCount ENDP

; ============================================================================
; TokenTypeToString - Get string representation of token type
; RCX = token type
; Returns: RAX = pointer to string
; ============================================================================
TokenTypeToString PROC
    push rbp
    mov rbp, rsp
    
    .data
    str_eof         db "EOF", 0
    str_identifier  db "IDENTIFIER", 0
    str_string      db "STRING", 0
    str_number      db "NUMBER", 0
    str_keyword     db "KEYWORD", 0
    str_operator    db "OPERATOR", 0
    str_semicolon   db "SEMICOLON", 0
    str_lparen      db "LPAREN", 0
    str_rparen      db "RPAREN", 0
    str_unknown     db "UNKNOWN", 0
    .code
    
    cmp ecx, TOK_EOF
    je eof
    cmp ecx, TOK_IDENTIFIER
    je identifier
    cmp ecx, TOK_STRING
    je string
    cmp ecx, TOK_NUMBER
    je number
    cmp ecx, TOK_KEYWORD
    je keyword
    cmp ecx, TOK_OPERATOR
    je operator
    cmp ecx, TOK_SEMICOLON
    je semicolon
    cmp ecx, TOK_LPAREN
    je lparen
    cmp ecx, TOK_RPAREN
    je rparen
    
    lea rax, str_unknown
    jmp done
    
eof:
    lea rax, str_eof
    jmp done
identifier:
    lea rax, str_identifier
    jmp done
string:
    lea rax, str_string
    jmp done
number:
    lea rax, str_number
    jmp done
keyword:
    lea rax, str_keyword
    jmp done
operator:
    lea rax, str_operator
    jmp done
semicolon:
    lea rax, str_semicolon
    jmp done
lparen:
    lea rax, str_lparen
    jmp done
rparen:
    lea rax, str_rparen
    
done:
    leave
    ret
TokenTypeToString ENDP

END
