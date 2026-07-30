; lexer.asm - Shared tokenizer for Sovereign Universal Transpiler
; Converts raw source into token stream
; Used by: PHP, C, Python frontends

include token.asm

.data
    ; Lexer state
    lexer_source    dq 0    ; pointer to source buffer
    lexer_pos       dq 0    ; current position
    lexer_end       dq 0    ; end of source
    lexer_line      dd 1    ; current line number
    lexer_col       dd 1    ; current column

.code

; LexerInit - Initialize lexer with source buffer
; RCX = source pointer
; RDX = source size
LexerInit PROC
    mov [lexer_source], rcx
    mov [lexer_pos], rcx
    mov rax, rcx
    add rax, rdx
    mov [lexer_end], rax
    mov dword ptr [lexer_line], 1
    mov dword ptr [lexer_col], 1
    ret
LexerInit ENDP

; LexerPeek - Get current char without advancing
; Returns: AL = current char, 0 if EOF
LexerPeek PROC
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jge peek_eof
    movzx eax, byte ptr [rax]
    ret
peek_eof:
    xor eax, eax
    ret
LexerPeek ENDP

; LexerAdvance - Move to next char
LexerAdvance PROC
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jge adv_done
    inc rax
    mov [lexer_pos], rax
    inc dword ptr [lexer_col]
    movzx eax, byte ptr [rax - 1]
    cmp eax, 10          ; newline
    jne adv_done
    inc dword ptr [lexer_line]
    mov dword ptr [lexer_col], 1
adv_done:
    ret
LexerAdvance ENDP

; LexerSkipWhitespace - Skip spaces, tabs, newlines
LexerSkipWhitespace PROC
skip_loop:
    call LexerPeek
    cmp al, ' '
    je skip_one
    cmp al, 9             ; tab
    je skip_one
    cmp al, 13            ; CR
    je skip_one
    cmp al, 10            ; LF
    je skip_one
    ret
skip_one:
    call LexerAdvance
    jmp skip_loop
LexerSkipWhitespace ENDP

; LexerNext - Get next token
; Returns: RAX = token type, token stored in current_token
.data
    current_token TOKEN <>
.code
LexerNext PROC
    call LexerSkipWhitespace
    
    ; Check EOF
    call LexerPeek
    test al, al
    jz lex_eof
    
    ; Check string literal (double quote)
    cmp al, '"'
    je lex_string
    
    ; Check string literal (single quote)
    cmp al, "'"
    je lex_string
    
    ; Check number
    cmp al, '0'
    jl lex_check_ident
    cmp al, '9'
    jle lex_number
    
lex_check_ident:
    ; Check identifier (letter or underscore)
    cmp al, '_'
    je lex_ident
    cmp al, 'A'
    jl lex_operator
    cmp al, 'Z'
    jle lex_ident
    cmp al, 'a'
    jl lex_operator
    cmp al, 'z'
    jle lex_ident
    jmp lex_operator
    
lex_eof:
    mov dword ptr [current_token.type], TOK_EOF
    mov rax, TOK_EOF
    ret
    
lex_string:
    mov dword ptr [current_token.type], TOK_STRING
    mov rax, [lexer_pos]
    mov [current_token.start], rax
    call LexerAdvance        ; skip opening quote
    mov rax, [lexer_pos]
    mov [current_token.start], rax  ; start after quote
str_loop:
    call LexerPeek
    test al, al
    jz str_end
    cmp al, '"'
    je str_end_dq
    cmp al, "'"
    je str_end_sq
    call LexerAdvance
    jmp str_loop
str_end_dq:
    mov rax, [lexer_pos]
    sub rax, [current_token.start]
    mov dword ptr [current_token.length], eax
    call LexerAdvance        ; skip closing quote
    mov rax, TOK_STRING
    ret
str_end_sq:
    mov rax, [lexer_pos]
    sub rax, [current_token.start]
    mov dword ptr [current_token.length], eax
    call LexerAdvance        ; skip closing quote
    mov rax, TOK_STRING
    ret
str_end:
    mov rax, [lexer_pos]
    sub rax, [current_token.start]
    mov dword ptr [current_token.length], eax
    mov rax, TOK_STRING
    ret
    
lex_number:
    mov dword ptr [current_token.type], TOK_NUMBER
    mov rax, [lexer_pos]
    mov [current_token.start], rax
num_loop:
    call LexerPeek
    cmp al, '0'
    jl num_end
    cmp al, '9'
    jg num_end
    call LexerAdvance
    jmp num_loop
num_end:
    mov rax, [lexer_pos]
    sub rax, [current_token.start]
    mov dword ptr [current_token.length], eax
    mov rax, TOK_NUMBER
    ret
    
lex_ident:
    mov dword ptr [current_token.type], TOK_IDENTIFIER
    mov rax, [lexer_pos]
    mov [current_token.start], rax
ident_loop:
    call LexerPeek
    cmp al, '_'
    je ident_adv
    cmp al, 'A'
    jl ident_end
    cmp al, 'Z'
    jle ident_adv
    cmp al, 'a'
    jl ident_end
    cmp al, 'z'
    jle ident_adv
    cmp al, '0'
    jl ident_end
    cmp al, '9'
    jle ident_adv
    jmp ident_end
ident_adv:
    call LexerAdvance
    jmp ident_loop
ident_end:
    mov rax, [lexer_pos]
    sub rax, [current_token.start]
    mov dword ptr [current_token.length], eax
    mov rax, TOK_IDENTIFIER
    ret
    
lex_operator:
    mov dword ptr [current_token.type], TOK_OPERATOR
    mov rax, [lexer_pos]
    mov [current_token.start], rax
    call LexerAdvance
    mov dword ptr [current_token.length], 1
    mov rax, TOK_OPERATOR
    ret
LexerNext ENDP

end