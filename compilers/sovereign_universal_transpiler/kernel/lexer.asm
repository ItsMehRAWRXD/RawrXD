; lexer.asm - Shared tokenizer for Sovereign Universal Transpiler
; v0.2 - Production: quote tracking, escapes, comments, multi-char ops, locations
; Used by: PHP, C, Python frontends

; External declarations from token.asm
extrn TokenInit:proc
extrn TokenCreate:proc
extrn TokenGet:proc
extrn TokenGetCount:proc
extrn TokenTypeToString:proc

; Token Types (from token.asm)
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

; TOKEN struct (from token.asm)
TOKEN STRUCT
    tok_type    DWORD ?
    tok_flags   DWORD ?
    tok_start   QWORD ?
    tok_length  DWORD ?
    tok_line    DWORD ?
    tok_column  DWORD ?
    tok_value   QWORD ?
    tok_pad     DWORD ?
TOKEN ENDS

.data
    ; Lexer state
    lexer_source    dq 0    ; pointer to source buffer
    lexer_pos       dq 0    ; current position
    lexer_end       dq 0    ; end of source
    lexer_line      dd 1    ; current line number
    lexer_col       dd 1    ; current column
    current_quote   db 0    ; opening quote for current string (' or ")
    current_token   TOKEN <>   ; Current token being built

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
    mov byte ptr [current_quote], 0
    ret
LexerInit ENDP

; LexerPeek - Get current char without advancing
; Returns: AL = current char, 0 if EOF
; NOTE: Uses position vs end comparison, NOT NUL check (NUL is valid in source)
LexerPeek PROC
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae peek_eof
    movzx eax, byte ptr [rax]
    ret
peek_eof:
    xor eax, eax
    ret
LexerPeek ENDP

; LexerAdvance - Move to next char
; Returns: AL = consumed char (for convenience)
LexerAdvance PROC
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae adv_done
    movzx eax, byte ptr [rax]       ; get current char
    inc rax
    mov [lexer_pos], rax
    inc dword ptr [lexer_col]
    cmp eax, 10                      ; newline
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

; LexerSkipComments - Skip comments (C-style and Python-style)
; Handles: // ... \n, /* ... */, # ... \n
LexerSkipComments PROC
comment_loop:
    call LexerPeek
    ; Check for // (C/PHP single-line)
    cmp al, '/'
    jne check_hash
    ; Peek next char
    mov rax, [lexer_pos]
    inc rax
    cmp rax, [lexer_end]
    jae no_comment
    mov cl, [rax]
    cmp cl, '/'
    je skip_line_comment
    cmp cl, '*'
    je skip_block_comment
    jmp no_comment

check_hash:
    cmp al, '#'
    je skip_line_comment
    jmp no_comment

skip_line_comment:
    call LexerAdvance       ; skip first char (/ or #)
    call LexerAdvance       ; skip second char (/ for //)
slc_loop:
    call LexerPeek
    test al, al
    jz slc_done
    cmp al, 10              ; newline ends comment
    je slc_done
    call LexerAdvance
    jmp slc_loop
slc_done:
    ; Skip the newline too, then continue checking for more comments
    call LexerAdvance
    jmp comment_loop

skip_block_comment:
    call LexerAdvance       ; skip /
    call LexerAdvance       ; skip *
bbc_loop:
    call LexerPeek
    test al, al
    jz bbc_done             ; EOF in comment
    cmp al, '*'
    jne bbc_adv
    ; Check for */
    mov rax, [lexer_pos]
    inc rax
    cmp rax, [lexer_end]
    jae bbc_done
    mov cl, [rax]
    cmp cl, '/'
    je bbc_end
bbc_adv:
    call LexerAdvance
    jmp bbc_loop
bbc_end:
    call LexerAdvance       ; skip *
    call LexerAdvance       ; skip /
    jmp comment_loop
bbc_done:
    jmp no_comment

no_comment:
    ret
LexerSkipComments ENDP

; LexerNext - Get next token
; Returns: RAX = token type, token stored in current_token
LexerNext PROC
    ; Skip whitespace and comments
lex_skip_all:
    call LexerSkipWhitespace
    call LexerSkipComments
    ; After skipping comments, might have whitespace again
    call LexerPeek
    cmp al, ' '
    je lex_skip_all
    cmp al, 9
    je lex_skip_all
    cmp al, 10
    je lex_skip_all
    cmp al, 13
    je lex_skip_all

    ; Record token start position (line/column)
    mov eax, [lexer_line]
    mov [current_token.tok_line], eax
    mov eax, [lexer_col]
    mov [current_token.tok_column], eax

    ; Check EOF (position-based, not NUL-based)
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae lex_eof

    ; Get current char
    call LexerPeek

    ; Check string literal (double or single quote)
    cmp al, '"'
    je lex_string
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
    mov dword ptr [current_token.tok_type], TOK_EOF
    mov rax, [lexer_pos]
    mov [current_token.tok_start], rax
    mov dword ptr [current_token.tok_length], 0
    mov rax, TOK_EOF
    ret

lex_string:
    ; Save the opening quote for proper delimiter matching
    mov [current_quote], al
    mov dword ptr [current_token.tok_type], TOK_STRING
    call LexerAdvance            ; skip opening quote
    mov rax, [lexer_pos]
    mov [current_token.tok_start], rax  ; start after quote
str_loop:
    call LexerPeek
    ; EOF check (position-based)
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae str_end
    call LexerPeek
    ; Check escape sequence
    cmp al, '\'
    jne check_quote
    ; Skip escape: advance over backslash and next char
    call LexerAdvance
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae str_end   ; Hit EOF after backslash
    call LexerAdvance
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae str_end   ; Hit EOF after escaped char
    jmp str_loop
check_quote:
    cmp al, [current_quote]      ; match opening quote only
    je str_end
    call LexerAdvance
    jmp str_loop
str_end:
    mov rax, [lexer_pos]
    sub rax, [current_token.tok_start]
    mov dword ptr [current_token.tok_length], eax
    ; Skip closing quote if not at EOF
    mov rax, [lexer_pos]
    cmp rax, [lexer_end]
    jae str_no_close
    call LexerAdvance
str_no_close:
    mov rax, TOK_STRING
    ret

lex_number:
    mov dword ptr [current_token.tok_type], TOK_NUMBER
    mov rax, [lexer_pos]
    mov [current_token.tok_start], rax
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
    sub rax, [current_token.tok_start]
    mov dword ptr [current_token.tok_length], eax
    mov rax, TOK_NUMBER
    ret

lex_ident:
    mov dword ptr [current_token.tok_type], TOK_IDENTIFIER
    mov rax, [lexer_pos]
    mov [current_token.tok_start], rax
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
    sub rax, [current_token.tok_start]
    mov dword ptr [current_token.tok_length], eax
    mov rax, TOK_IDENTIFIER
    ret

lex_operator:
    mov dword ptr [current_token.tok_type], TOK_OPERATOR
    mov rax, [lexer_pos]
    mov [current_token.tok_start], rax

    ; Try multi-character operators
    ; Peek first char
    call LexerPeek

    ; Check for two-character operators: == != <= >= += -= *= /= -> ++ --
    ; Save first char
    mov bl, al
    call LexerAdvance
    call LexerPeek
    mov bh, al

    ; Compare against known two-char operators
    ; == (3D 3D)
    cmp bl, '='
    jne not_eq
    cmp bh, '='
    je two_char
    ; = (single, assignment)
    mov dword ptr [current_token.tok_type], TOK_ASSIGN
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_ASSIGN
    ret
not_eq:
    ; != (21 3D)
    cmp bl, '!'
    jne not_ne
    cmp bh, '='
    je two_char
    ; ! (single)
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_OPERATOR
    ret
not_ne:
    ; <= (3C 3D)
    cmp bl, '<'
    jne not_le
    cmp bh, '='
    je two_char
    ; < (single)
    mov dword ptr [current_token.tok_type], TOK_LT
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_LT
    ret
not_le:
    ; >= (3E 3D)
    cmp bl, '>'
    jne not_ge
    cmp bh, '='
    je two_char
    ; > (single)
    mov dword ptr [current_token.tok_type], TOK_GT
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_GT
    ret
not_ge:
    ; + (2B) - check for ++ or +=
    cmp bl, '+'
    jne not_plus
    cmp bh, '+'
    je two_char
    cmp bh, '='
    je two_char
    mov dword ptr [current_token.tok_type], TOK_PLUS
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_PLUS
    ret
not_plus:
    ; - (2D) - check for -- or -= or ->
    cmp bl, '-'
    jne not_minus
    cmp bh, '-'
    je two_char
    cmp bh, '='
    je two_char
    cmp bh, '>'
    je two_char
    mov dword ptr [current_token.tok_type], TOK_MINUS
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_MINUS
    ret
not_minus:
    ; * (2A) - check for *=
    cmp bl, '*'
    jne not_star
    cmp bh, '='
    je two_char
    mov dword ptr [current_token.tok_type], TOK_STAR
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_STAR
    ret
not_star:
    ; / (2F) - check for /=
    cmp bl, '/'
    jne not_slash
    cmp bh, '='
    je two_char
    mov dword ptr [current_token.tok_type], TOK_SLASH
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_SLASH
    ret
not_slash:
    ; Single-char punctuation
    cmp bl, '('
    jne not_lparen
    mov dword ptr [current_token.tok_type], TOK_LPAREN
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_LPAREN
    ret
not_lparen:
    cmp bl, ')'
    jne not_rparen
    mov dword ptr [current_token.tok_type], TOK_RPAREN
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_RPAREN
    ret
not_rparen:
    cmp bl, '{'
    jne not_lbrace
    mov dword ptr [current_token.tok_type], TOK_LBRACE
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_LBRACE
    ret
not_lbrace:
    cmp bl, '}'
    jne not_rbrace
    mov dword ptr [current_token.tok_type], TOK_RBRACE
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_RBRACE
    ret
not_rbrace:
    cmp bl, ';'
    jne not_semi
    mov dword ptr [current_token.tok_type], TOK_SEMICOLON
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_SEMICOLON
    ret
not_semi:
    cmp bl, ','
    jne not_comma
    mov dword ptr [current_token.tok_type], TOK_COMMA
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_COMMA
    ret
not_comma:
    cmp bl, '.'
    jne not_dot
    mov dword ptr [current_token.tok_type], TOK_DOT
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_DOT
    ret
not_dot:
    ; Unknown single-char operator
    mov dword ptr [current_token.tok_length], 1
    mov rax, TOK_OPERATOR
    ret

two_char:
    ; Two-character operator matched
    call LexerAdvance            ; consume second char
    mov dword ptr [current_token.tok_length], 2
    mov rax, TOK_OPERATOR
    ret
LexerNext ENDP

end