; =====================================================================================
; SOVEREIGN ENGINE - CONFIGURATION LEXER
; SUBSYSTEM: ZERO-DEP SETTINGS PARSER (INT/BOOL/STRING)
; ARCHITECTURE: X86-64 (MASM64)
; CODENAME: CONFIG_FORGE v1.0.0
; =====================================================================================

.DATA
    ; Token Type Constants
    TOKEN_EOF       EQU 0
    TOKEN_INT       EQU 1
    TOKEN_BOOL      EQU 2
    TOKEN_STRING    EQU 3
    TOKEN_KEY       EQU 4
    TOKEN_EQUALS    EQU 5
    TOKEN_NEWLINE   EQU 6
    TOKEN_COMMENT   EQU 7

    ; Boolean keyword table (null-terminated, lowercase for compare)
    ALIGN 16
    KW_TRUE         DB "true", 0
    KW_FALSE        DB "false", 0
    KW_YES          DB "yes", 0
    KW_NO           DB "no", 0
    KW_ON           DB "on", 0
    KW_OFF          DB "off", 0

.CODE

; =====================================================================================
; STRUCTURE: LEXER STATE
; =====================================================================================
SOVEREIGN_LEXER STRUCT
    SourceBase      QWORD ?         ; Pointer to raw config buffer
    SourceLength    QWORD ?         ; Total bytes in buffer
    Cursor          QWORD ?         ; Current read position
    LineNumber      QWORD ?         ; 1-based line tracking
    LastTokenType   QWORD ?         ; Previous token for context
SOVEREIGN_LEXER ENDS

; =====================================================================================
; STRUCTURE: TOKEN OUTPUT
; =====================================================================================
SOVEREIGN_TOKEN STRUCT
    TokenType       QWORD ?         ; TOKEN_*
    ValueInt        QWORD ?         ; Parsed integer (for TOKEN_INT/TOKEN_BOOL)
    ValueStrPtr     QWORD ?         ; Pointer to string data in buffer
    ValueStrLen     QWORD ?         ; Length of string (for TOKEN_STRING/TOKEN_KEY)
    LineNumber      QWORD ?         ; Where this token was found
SOVEREIGN_TOKEN ENDS

; =====================================================================================
; API: Sovereign_Lexer_Init
; INPUT:  RCX = pointer to SOVEREIGN_LEXER
;         RDX = pointer to config buffer
;         R8  = buffer length
; OUTPUT: RAX = 0
; =====================================================================================
Sovereign_Lexer_Init PROC
    mov qword ptr [rcx + SOVEREIGN_LEXER.SourceBase], rdx
    mov qword ptr [rcx + SOVEREIGN_LEXER.SourceLength], r8
    mov qword ptr [rcx + SOVEREIGN_LEXER.Cursor], 0
    mov qword ptr [rcx + SOVEREIGN_LEXER.LineNumber], 1
    mov qword ptr [rcx + SOVEREIGN_LEXER.LastTokenType], TOKEN_EOF
    xor rax, rax
    ret
Sovereign_Lexer_Init ENDP

; =====================================================================================
; HELPER: Peek_Char
; INPUT:  RCX = lexer pointer
; OUTPUT: RAX = current char (zero-extended) or -1 if EOF
;         Does NOT advance cursor
; =====================================================================================
Peek_Char PROC
    mov rdx, qword ptr [rcx + SOVEREIGN_LEXER.Cursor]
    cmp rdx, qword ptr [rcx + SOVEREIGN_LEXER.SourceLength]
    jge pc_eof
    mov r8, qword ptr [rcx + SOVEREIGN_LEXER.SourceBase]
    xor rax, rax
    mov al, byte ptr [r8 + rdx]
    ret
pc_eof:
    mov rax, -1
    ret
Peek_Char ENDP

; =====================================================================================
; HELPER: Consume_Char
; INPUT:  RCX = lexer pointer
; OUTPUT: RAX = char consumed (same as Peek_Char)
; =====================================================================================
Consume_Char PROC
    call Peek_Char
    cmp rax, -1
    je cc_done
    inc qword ptr [rcx + SOVEREIGN_LEXER.Cursor]
    cmp al, 0Ah                     ; LF increments line counter
    jne cc_done
    inc qword ptr [rcx + SOVEREIGN_LEXER.LineNumber]
cc_done:
    ret
Consume_Char ENDP

; =====================================================================================
; HELPER: Skip_Whitespace
; Skips spaces, tabs, CR. Stops at LF (newline is significant).
; =====================================================================================
Skip_Whitespace PROC
    push rbx
    mov rbx, rcx                    ; RBX = lexer
sw_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je sw_done
    cmp al, 20h                     ; Space
    je sw_consume
    cmp al, 09h                     ; Tab
    je sw_consume
    cmp al, 0Dh                     ; CR
    je sw_consume
    jmp sw_done
sw_consume:
    mov rcx, rbx
    call Consume_Char
    jmp sw_loop
sw_done:
    pop rbx
    ret
Skip_Whitespace ENDP

; =====================================================================================
; HELPER: Skip_Comment
; If current char is # or ; or //, consume to end of line
; =====================================================================================
Skip_Comment PROC
    push rbx
    mov rbx, rcx
    call Peek_Char
    cmp rax, -1
    je sc_done
    cmp al, 23h                     ; '#'
    je sc_kill
    cmp al, 3Bh                     ; ';'
    je sc_kill
    cmp al, 2Fh                     ; '/'
    jne sc_done
    ; Check for second '/' (lookahead)
    mov rdx, qword ptr [rbx + SOVEREIGN_LEXER.Cursor]
    inc rdx
    cmp rdx, qword ptr [rbx + SOVEREIGN_LEXER.SourceLength]
    jge sc_done
    mov r8, qword ptr [rbx + SOVEREIGN_LEXER.SourceBase]
    cmp byte ptr [r8 + rdx], 2Fh
    jne sc_done
sc_kill:
    mov rcx, rbx
    call Consume_Char               ; Consume comment start
sc_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je sc_done
    cmp al, 0Ah                     ; LF ends comment
    je sc_done
    mov rcx, rbx
    call Consume_Char
    jmp sc_loop
sc_done:
    pop rbx
    ret
Skip_Comment ENDP

; =====================================================================================
; HELPER: To_Lowercase
; INPUT: AL = ASCII char
; OUTPUT: AL = lowercase if A-Z, unchanged otherwise
; =====================================================================================
To_Lowercase PROC
    cmp al, 41h                     ; 'A'
    jl tl_done
    cmp al, 5Ah                     ; 'Z'
    jg tl_done
    add al, 20h                     ; Convert to lowercase
tl_done:
    ret
To_Lowercase ENDP

; =====================================================================================
; HELPER: Parse_Integer
; Handles decimal and 0x/0X hex prefixes. Supports negative.
; INPUT:  RCX = lexer, RDX = token pointer
; OUTPUT: RAX = 0 (success), token filled
; =====================================================================================
Parse_Integer PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32

    mov rbx, rcx                    ; RBX = lexer
    mov r12, rdx                    ; R12 = token
    xor r13, r13                    ; R13 = accumulated value
    xor rsi, rsi                    ; RSI = sign flag (0=positive)

    call Peek_Char
    cmp rax, -1
    je pi_fail
    cmp al, 2Dh                     ; '-' negative?
    jne pi_check_hex
    mov rsi, 1
    mov rcx, rbx
    call Consume_Char

pi_check_hex:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je pi_fail
    cmp al, 30h                     ; '0'
    jne pi_decimal
    mov rcx, rbx
    call Consume_Char
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je pi_emit_zero
    cmp al, 78h                     ; 'x'
    je pi_hex_mode
    cmp al, 58h                     ; 'X'
    je pi_hex_mode
    ; It's just "0" or start of decimal like "05"
    jmp pi_decimal_loop

pi_hex_mode:
    mov rcx, rbx
    call Consume_Char               ; Consume 'x'
pi_hex_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je pi_emit
    call To_Lowercase
    cmp al, 30h
    jl pi_emit
    cmp al, 39h
    jle pi_hex_digit
    cmp al, 61h                     ; 'a'
    jl pi_emit
    cmp al, 66h                     ; 'f'
    jg pi_emit
    sub al, 57h                     ; 'a'-'f' -> 10-15
    jmp pi_hex_accum
pi_hex_digit:
    sub al, 30h                     ; '0'-'9'
pi_hex_accum:
    shl r13, 4
    or r13, rax
    mov rcx, rbx
    call Consume_Char
    jmp pi_hex_loop

pi_decimal:
    cmp al, 30h
    jl pi_fail
    cmp al, 39h
    jg pi_fail
pi_decimal_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je pi_emit
    cmp al, 30h
    jl pi_emit
    cmp al, 39h
    jg pi_emit
    sub al, 30h
    imul r13, r13, 10
    add r13, rax
    mov rcx, rbx
    call Consume_Char
    jmp pi_decimal_loop

pi_emit_zero:
    ; Value is already 0 in r13
pi_emit:
    test rsi, rsi
    jz pi_store
    neg r13
pi_store:
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_INT
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueInt], r13
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax
    jmp pi_exit

pi_fail:
    mov rax, -1

pi_exit:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Parse_Integer ENDP

; =====================================================================================
; HELPER: Parse_Boolean
; Case-insensitive match against true/false/yes/no/on/off
; INPUT:  RCX = lexer, RDX = token pointer
; OUTPUT: RAX = 0 (success, bool stored in ValueInt), -1 = not a bool
; =====================================================================================
Parse_Boolean PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32

    mov rbx, rcx                    ; RBX = lexer
    mov r12, rdx                    ; R12 = token

    ; Capture keyword into temporary stack buffer (max 8 chars)
    lea rdi, [rsp + 16]             ; RDI = temp buffer
    xor r13, r13                    ; R13 = length counter (max 8)

pb_capture:
    cmp r13, 8
    jge pb_check
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je pb_check
    cmp al, 30h                     ; '0'
    jl pb_check
    cmp al, 39h                     ; '9'
    jle pb_check                    ; Number = integer, not bool keyword
    cmp al, 41h                     ; Below 'A'
    jl pb_check
    cmp al, 5Ah                     ; 'A'-'Z'
    jle pb_store
    cmp al, 61h                     ; 'a'-'z'
    jl pb_check
    cmp al, 7Ah
    jg pb_check
pb_store:
    call To_Lowercase
    mov byte ptr [rdi + r13], al
    inc r13
    mov rcx, rbx
    call Consume_Char
    jmp pb_capture

pb_check:
    test r13, r13
    jz pb_not_bool
    mov byte ptr [rdi + r13], 0     ; Null terminate

    ; Compare against keyword table
    lea rsi, KW_TRUE
    call Str_Equal
    test rax, rax
    jnz pb_true
    lea rsi, KW_YES
    call Str_Equal
    test rax, rax
    jnz pb_true
    lea rsi, KW_ON
    call Str_Equal
    test rax, rax
    jnz pb_true

    lea rsi, KW_FALSE
    call Str_Equal
    test rax, rax
    jnz pb_false
    lea rsi, KW_NO
    call Str_Equal
    test rax, rax
    jnz pb_false
    lea rsi, KW_OFF
    call Str_Equal
    test rax, rax
    jnz pb_false

pb_not_bool:
    ; Backtrack cursor to before capture
    sub qword ptr [rbx + SOVEREIGN_LEXER.Cursor], r13
    mov rax, -1
    jmp pb_exit

pb_true:
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_BOOL
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueInt], 1
    jmp pb_emit

pb_false:
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_BOOL
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueInt], 0

pb_emit:
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax

pb_exit:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Parse_Boolean ENDP

; =====================================================================================
; HELPER: Str_Equal
; Case-sensitive compare of null-terminated strings at RSI and RDI
; OUTPUT: RAX = 1 if equal, 0 if not
; =====================================================================================
Str_Equal PROC
    push rbx
    push rsi
    push rdi
    xor rbx, rbx
se_loop:
    mov al, byte ptr [rsi + rbx]
    mov dl, byte ptr [rdi + rbx]
    cmp al, dl
    jne se_not_equal
    test al, al
    jz se_equal
    inc rbx
    jmp se_loop
se_not_equal:
    xor rax, rax
    jmp se_done
se_equal:
    mov rax, 1
se_done:
    pop rdi
    pop rsi
    pop rbx
    ret
Str_Equal ENDP

; =====================================================================================
; HELPER: Parse_String
; Handles "..." and '...' with escape sequences: \n \t \\ \" \' \r \0
; INPUT:  RCX = lexer, RDX = token pointer
; OUTPUT: RAX = 0 (success), -1 = error (unterminated)
; =====================================================================================
Parse_String PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 32

    mov rbx, rcx                    ; RBX = lexer
    mov r12, rdx                    ; R12 = token

    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je ps_fail
    mov r13, rax                    ; R13 = quote char (" or ')
    cmp al, 22h                     ; '"'
    je ps_open
    cmp al, 27h                     ; "'"
    jne ps_fail

ps_open:
    mov rcx, rbx
    call Consume_Char               ; Consume opening quote
    mov r14, qword ptr [rbx + SOVEREIGN_LEXER.Cursor]  ; R14 = string start offset

ps_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je ps_fail                      ; Unterminated string
    cmp al, r13b                    ; Closing quote?
    je ps_close
    cmp al, 5Ch                     ; '\' escape?
    je ps_escape
    mov rcx, rbx
    call Consume_Char
    jmp ps_loop

ps_escape:
    mov rcx, rbx
    call Consume_Char               ; Consume '\'
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je ps_fail
    cmp al, 6Eh                     ; 'n' -> LF
    je ps_esc_consume
    cmp al, 74h                     ; 't' -> TAB
    je ps_esc_consume
    cmp al, 72h                     ; 'r' -> CR
    je ps_esc_consume
    cmp al, 30h                     ; '0' -> NUL
    je ps_esc_consume
    cmp al, 5Ch                     ; '\' -> backslash
    je ps_esc_consume
    cmp al, 22h                     ; '"' -> quote
    je ps_esc_consume
    cmp al, 27h                     ; "'" -> quote
    je ps_esc_consume
    ; Unknown escape: keep literal char
ps_esc_consume:
    mov rcx, rbx
    call Consume_Char
    jmp ps_loop

ps_close:
    mov rcx, rbx
    call Consume_Char               ; Consume closing quote
    mov rsi, qword ptr [rbx + SOVEREIGN_LEXER.Cursor]
    dec rsi                           ; RSI = end position (exclusive of quote)
    sub rsi, r14                      ; RSI = string length

    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_STRING
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.SourceBase]
    add rax, r14
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrPtr], rax
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrLen], rsi
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax
    jmp ps_exit

ps_fail:
    mov rax, -1

ps_exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Parse_String ENDP

; =====================================================================================
; API: Sovereign_Lexer_Next_Token
; The main entry point. Fills the next token from the stream.
; INPUT:  RCX = lexer pointer
;         RDX = token pointer
; OUTPUT: RAX = 0 (success), -1 (error/EOF)
; =====================================================================================
Sovereign_Lexer_Next_Token PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32

    mov rbx, rcx                    ; RBX = lexer
    mov r12, rdx                    ; R12 = token

nt_skip_loop:
    mov rcx, rbx
    call Skip_Whitespace
    mov rcx, rbx
    call Skip_Comment
    mov rcx, rbx
    call Skip_Whitespace
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    jne nt_have_char
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_EOF
    xor rax, rax
    jmp nt_exit

nt_have_char:
    cmp al, 0Ah                     ; Newline
    je nt_newline
    cmp al, 3Dh                     ; '='
    je nt_equals
    cmp al, 22h                     ; '"'
    je nt_string
    cmp al, 27h                     ; "'"
    je nt_string
    cmp al, 30h                     ; '0'-'9' or '-'
    jl nt_check_alpha
    cmp al, 39h
    jle nt_number
    cmp al, 2Dh                     ; '-'
    je nt_number

nt_check_alpha:
    cmp al, 41h
    jl nt_key
    cmp al, 5Ah
    jle nt_bool
    cmp al, 61h
    jl nt_key
    cmp al, 7Ah
    jle nt_bool

nt_key:
    jmp nt_key_token                ; Unquoted key identifier

nt_newline:
    mov rcx, rbx
    call Consume_Char
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_NEWLINE
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    dec rax                           ; Line was incremented on consume
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax
    jmp nt_exit

nt_equals:
    mov rcx, rbx
    call Consume_Char
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_EQUALS
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax
    jmp nt_exit

nt_string:
    mov rcx, rbx
    mov rdx, r12
    call Parse_String
    jmp nt_exit

nt_number:
    ; Try boolean first (true/false/yes/no/on/off), fall back to integer
    mov rcx, rbx
    mov rdx, r12
    call Parse_Boolean
    test rax, rax
    jz nt_exit
    mov rcx, rbx
    mov rdx, r12
    call Parse_Integer
    jmp nt_exit

nt_bool:
    mov rcx, rbx
    mov rdx, r12
    call Parse_Boolean
    test rax, rax
    jz nt_exit
    ; Not a bool? Treat as unquoted key/identifier
    jmp nt_key_token

nt_key_token:
    ; Capture unquoted key: [A-Za-z0-9_.-]+
    mov r13, qword ptr [rbx + SOVEREIGN_LEXER.Cursor]  ; Start
nt_key_loop:
    mov rcx, rbx
    call Peek_Char
    cmp rax, -1
    je nt_key_emit
    cmp al, 30h
    jl nt_key_emit
    cmp al, 39h
    jle nt_key_advance
    cmp al, 41h
    jl nt_key_check_special
    cmp al, 5Ah
    jle nt_key_advance
    cmp al, 61h
    jl nt_key_check_special
    cmp al, 7Ah
    jle nt_key_advance
nt_key_check_special:
    cmp al, 2Eh                     ; '.'
    je nt_key_advance
    cmp al, 5Fh                     ; '_'
    je nt_key_advance
    cmp al, 2Dh                     ; '-'
    je nt_key_advance
    jmp nt_key_emit
nt_key_advance:
    mov rcx, rbx
    call Consume_Char
    jmp nt_key_loop
nt_key_emit:
    mov rsi, qword ptr [rbx + SOVEREIGN_LEXER.Cursor]
    sub rsi, r13
    mov qword ptr [r12 + SOVEREIGN_TOKEN.TokenType], TOKEN_KEY
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.SourceBase]
    add rax, r13
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrPtr], rax
    mov qword ptr [r12 + SOVEREIGN_TOKEN.ValueStrLen], rsi
    mov rax, qword ptr [rbx + SOVEREIGN_LEXER.LineNumber]
    mov qword ptr [r12 + SOVEREIGN_TOKEN.LineNumber], rax
    xor rax, rax

nt_exit:
    cmp rax, 0
    jne nt_skip_error
    mov rcx, qword ptr [r12 + SOVEREIGN_TOKEN.TokenType]
    mov qword ptr [rbx + SOVEREIGN_LEXER.LastTokenType], rcx
nt_skip_error:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Lexer_Next_Token ENDP

END
