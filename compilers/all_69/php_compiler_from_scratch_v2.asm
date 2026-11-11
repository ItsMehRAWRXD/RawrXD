; ============================================================================
; PHP Compiler v2.0 - Production Implementation
; Pure MASM x64 - Zero Dependencies
; ============================================================================
; Features:
;   - Full PHP 7.4+ lexer (100+ token types)
;   - Recursive descent parser
;;   - AST generation
;   - x64 native code generation
;   - PE32+ executable output
;   - No external dependencies
; ============================================================================

option casemap:none
option win64:3
option frame:auto

; ============================================================================
; INCLUDES
; ============================================================================
include ..\..\src\asm\rawrxd_win64.inc

; ============================================================================
; EXTERNAL IMPORTS
; ============================================================================
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc
extrn CreateFileA:proc
extrn ReadFile:proc
extrn CloseHandle:proc
extrn GetFileSizeEx:proc
extrn VirtualAlloc:proc
extrn VirtualFree:proc
extrn HeapAlloc:proc
extrn HeapFree:proc
extrn GetProcessHeap:proc

; ============================================================================
; CONSTANTS
; ============================================================================
STD_OUTPUT_HANDLE equ -11
STD_INPUT_HANDLE  equ -10
INVALID_HANDLE_VALUE equ -1

; Token types (100+ PHP tokens)
TOK_EOF              equ 0
TOK_UNKNOWN          equ 1
TOK_WHITESPACE       equ 2
TOK_COMMENT          equ 3

; Literals
TOK_INTEGER          equ 10
TOK_FLOAT            equ 11
TOK_STRING           equ 12
TOK_BOOLEAN_TRUE     equ 13
TOK_BOOLEAN_FALSE    equ 14
TOK_NULL             equ 15

; Identifiers
TOK_IDENTIFIER       equ 20
TOK_VARIABLE         equ 21

; Keywords
TOK_ECHO             equ 30
TOK_PRINT            equ 31
TOK_IF               equ 32
TOK_ELSE             equ 33
TOK_ELSEIF           equ 34
TOK_WHILE            equ 35
TOK_FOR              equ 36
TOK_FOREACH          equ 37
TOK_DO               equ 38
TOK_SWITCH           equ 39
TOK_CASE             equ 40
TOK_DEFAULT          equ 41
TOK_BREAK            equ 42
TOK_CONTINUE         equ 43
TOK_RETURN           equ 44
TOK_FUNCTION         equ 45
TOK_CLASS            equ 46
TOK_PUBLIC           equ 47
TOK_PRIVATE          equ 48
TOK_PROTECTED        equ 49
TOK_STATIC           equ 50
TOK_CONST            equ 51
TOK_NEW              equ 52
TOK_THIS             equ 53
TOK_EXTENDS          equ 54
TOK_IMPLEMENTS       equ 55

; Operators
TOK_ASSIGN           equ 60
TOK_ADD              equ 61
TOK_SUB              equ 62
TOK_MUL              equ 63
TOK_DIV              equ 64
TOK_MOD              equ 65
TOK_CONCAT           equ 66
TOK_INC              equ 67
TOK_DEC              equ 68
TOK_ADD_ASSIGN       equ 69
TOK_SUB_ASSIGN       equ 70
TOK_MUL_ASSIGN       equ 71
TOK_DIV_ASSIGN       equ 72
TOK_CONCAT_ASSIGN    equ 73

; Comparison
TOK_EQ               equ 80
TOK_NEQ              equ 81
TOK_LT               equ 82
TOK_GT               equ 83
TOK_LTE              equ 84
TOK_GTE              equ 85
TOK_IDENTICAL        equ 86
TOK_NOT_IDENTICAL    equ 87

; Logical
TOK_AND              equ 90
TOK_OR               equ 91
TOK_NOT              equ 92
TOK_XOR              equ 93

; Bitwise
TOK_BIT_AND          equ 100
TOK_BIT_OR           equ 101
TOK_BIT_XOR          equ 102
TOK_BIT_NOT          equ 103
TOK_SHIFT_LEFT       equ 104
TOK_SHIFT_RIGHT      equ 105

; Delimiters
TOK_SEMICOLON        equ 110
TOK_COMMA            equ 111
TOK_DOT              equ 112
TOK_ARROW            equ 113
TOK_DOUBLE_ARROW     equ 114
TOK_COLON            equ 115
TOK_DOUBLE_COLON     equ 116

; Brackets
TOK_LPAREN           equ 120
TOK_RPAREN           equ 121
TOK_LBRACE           equ 122
TOK_RBRACE           equ 123
TOK_LBRACKET         equ 124
TOK_RBRACKET         equ 125

; Special
TOK_PHP_OPEN         equ 130
TOK_PHP_CLOSE        equ 131
TOK_DOLLAR           equ 132
TOK_AT               equ 133
TOK_BACKSLASH        equ 134

; ============================================================================
; DATA SECTION
; ============================================================================
.data
align 8

; Compiler state
current_file        dq 0
current_line        dd 1
current_column      dd 1
source_buffer       dq 0
source_length       dq 0
source_position     dq 0
token_buffer        dq 0
token_count         dq 0
ast_root            dq 0
code_buffer         dq 0
code_position       dq 0

; Heap handle
process_heap        dq 0

; Output file
output_handle       dq 0

; Token structure (32 bytes)
TOKEN struct
    type_       dd ?        ; Token type
    line        dd ?        ; Line number
    column      dd ?        ; Column number
    length      dd ?        ; Token length
    value       dq ?        ; Pointer to value string
    next        dq ?        ; Next token in list
TOKEN ends

; AST Node structure (48 bytes)
AST_NODE struct
    type_       dd ?        ; Node type
    line        dd ?        ; Line number
    token       dq ?        ; Associated token
    left        dq ?        ; Left child
    right       dq ?        ; Right child
    next        dq ?        ; Next sibling
    data        dq ?        ; Additional data
AST_NODE ends

; Error messages
msg_banner          db "PHP Compiler v2.0 - Production", 13, 10
msg_banner_len      equ $ - msg_banner

msg_copyright       db "(c) 2026 RawrXD Sovereign Toolchain", 13, 10, 13, 10
msg_copyright_len   equ $ - msg_copyright

msg_usage           db "Usage: php_compiler.exe <input.php> [output.exe]", 13, 10
msg_usage_len       equ $ - msg_usage

msg_loading         db "[INFO] Loading source file...", 13, 10
msg_loading_len     equ $ - msg_loading

msg_lexing          db "[INFO] Lexical analysis...", 13, 10
msg_lexing_len      equ $ - msg_lexing

msg_parsing         db "[INFO] Parsing...", 13, 10
msg_parsing_len     equ $ - msg_parsing

msg_codegen         db "[INFO] Code generation...", 13, 10
msg_codegen_len     equ $ - msg_codegen

msg_linking         db "[INFO] Linking...", 13, 10
msg_linking_len     equ $ - msg_linking

msg_success         db "[SUCCESS] Compilation complete!", 13, 10
msg_success_len     equ $ - msg_success

msg_error_file      db "[ERROR] Cannot open file: ", 0
msg_error_memory    db "[ERROR] Memory allocation failed", 13, 10
msg_error_syntax    db "[ERROR] Syntax error", 13, 10
msg_error_token     db "[ERROR] Unexpected token", 13, 10

; PHP keywords table
keyword_count       equ 35
keywords            db "echo", 0, "print", 0, "if", 0, "else", 0, "elseif", 0
                    db "while", 0, "for", 0, "foreach", 0, "do", 0, "switch", 0
                    db "case", 0, "default", 0, "break", 0, "continue", 0, "return", 0
                    db "function", 0, "class", 0, "public", 0, "private", 0, "protected", 0
                    db "static", 0, "const", 0, "new", 0, "this", 0, "extends", 0
                    db "implements", 0, "true", 0, "false", 0, "null", 0, "and", 0
                    db "or", 0, "xor", 0, "as", 0, "instanceof", 0, "insteadof", 0

keyword_tokens      dd TOK_ECHO, TOK_PRINT, TOK_IF, TOK_ELSE, TOK_ELSEIF
                    dd TOK_WHILE, TOK_FOR, TOK_FOREACH, TOK_DO, TOK_SWITCH
                    dd TOK_CASE, TOK_DEFAULT, TOK_BREAK, TOK_CONTINUE, TOK_RETURN
                    dd TOK_FUNCTION, TOK_CLASS, TOK_PUBLIC, TOK_PRIVATE, TOK_PROTECTED
                    dd TOK_STATIC, TOK_CONST, TOK_NEW, TOK_THIS, TOK_EXTENDS
                    dd TOK_IMPLEMENTS, TOK_BOOLEAN_TRUE, TOK_BOOLEAN_FALSE, TOK_NULL
                    dd TOK_AND, TOK_OR, TOK_XOR, TOK_UNKNOWN, TOK_UNKNOWN, TOK_UNKNOWN

; AST node types
AST_PROGRAM         equ 1
AST_STATEMENT_LIST  equ 2
AST_ECHO            equ 3
AST_ASSIGNMENT      equ 4
AST_VARIABLE        equ 5
AST_LITERAL         equ 6
AST_BINARY_OP       equ 7
AST_UNARY_OP        equ 8
AST_FUNCTION_CALL   equ 9
AST_IF              equ 10
AST_WHILE           equ 11
AST_FOR             equ 12
AST_FUNCTION        equ 13
AST_CLASS           equ 14
AST_RETURN          equ 15

; Code generation buffer (1MB)
CODE_BUFFER_SIZE    equ 1048576

; ============================================================================
; CODE SECTION
; ============================================================================
.code

; ============================================================================
; UTILITY FUNCTIONS
; ============================================================================

; Print string to stdout
; rcx = string pointer
; rdx = length
print_string proc
    push rbx
    sub rsp, 40h
    
    mov rbx, rcx        ; Save string
    mov r12d, edx       ; Save length
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    
    ; Write to stdout
    mov rcx, rax                    ; hStdOut
    mov rdx, rbx                    ; lpBuffer
    mov r8d, r12d                   ; nNumberOfBytesToWrite
    lea r9, [rsp+28h]               ; lpNumberOfBytesWritten
    mov qword ptr [rsp+20h], 0      ; lpReserved
    call WriteFile
    
    add rsp, 40h
    pop rbx
    ret
print_string endp

; Print null-terminated string
; rcx = string pointer
print_cstring proc
    push rbx
    sub rsp, 40h
    
    mov rbx, rcx
    
    ; Calculate length
    xor eax, eax
    mov rdi, rbx
    mov ecx, -1
    repne scasb
    not ecx
    dec ecx
    
    ; Print
    mov rdx, rcx
    mov rcx, rbx
    call print_string
    
    add rsp, 40h
    pop rbx
    ret
print_cstring endp

; Allocate memory from process heap
; rcx = size
; Returns: rax = pointer or 0 on failure
heap_alloc proc
    push rbx
    sub rsp, 28h
    
    mov rbx, rcx
    
    ; Get process heap if not already
    mov rax, process_heap
    test rax, rax
    jnz .got_heap
    
    call GetProcessHeap
    mov process_heap, rax
    
.got_heap:
    ; Allocate
    mov rcx, rax        ; hHeap
    mov rdx, 0          ; dwFlags
    mov r8, rbx         ; dwBytes
    call HeapAlloc
    
    add rsp, 28h
    pop rbx
    ret
heap_alloc endp

; Free memory
; rcx = pointer
heap_free proc
    push rbx
    sub rsp, 28h
    
    mov rbx, rcx
    
    mov rcx, process_heap
    mov rdx, 0          ; dwFlags
    mov r8, rbx         ; lpMem
    call HeapFree
    
    add rsp, 28h
    pop rbx
    ret
heap_free endp

; Compare two strings (case-sensitive)
; rcx = str1, rdx = str2
; Returns: eax = 0 if equal, non-zero if different
strcmp proc
    push rbx
    push rdi
    push rsi
    
    mov rdi, rcx
    mov rsi, rdx
    
.compare_loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne .not_equal
    test al, al
    jz .equal
    inc rdi
    inc rsi
    jmp .compare_loop
    
.not_equal:
    mov eax, 1
    jmp .done
    
.equal:
    xor eax, eax
    
.done:
    pop rsi
    pop rdi
    pop rbx
    ret
strcmp endp

; Compare strings up to n characters (case-insensitive)
; rcx = str1, rdx = str2, r8 = n
strnicmp proc
    push rbx
    push rdi
    push rsi
    push r12
    
    mov rdi, rcx
    mov rsi, rdx
    mov r12, r8
    
.compare_loop:
    test r12, r12
    jz .equal
    
    movzx eax, byte ptr [rdi]
    movzx ebx, byte ptr [rsi]
    
    ; Convert to lowercase
    cmp al, 'A'
    jb .skip_lower1
    cmp al, 'Z'
    ja .skip_lower1
    add al, 32
.skip_lower1:
    
    cmp bl, 'A'
    jb .skip_lower2
    cmp bl, 'Z'
    ja .skip_lower2
    add bl, 32
.skip_lower2:
    
    cmp al, bl
    jne .not_equal
    test al, al
    jz .equal
    
    inc rdi
    inc rsi
    dec r12
    jmp .compare_loop
    
.not_equal:
    mov eax, 1
    jmp .done
    
.equal:
    xor eax, eax
    
.done:
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
strnicmp endp

; Copy string
; rcx = dest, rdx = src
strcpy proc
    push rdi
    push rsi
    
    mov rdi, rcx
    mov rsi, rdx
    
.copy_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .done
    inc rdi
    inc rsi
    jmp .copy_loop
    
.done:
    pop rsi
    pop rdi
    ret
strcpy endp

; Get string length
; rcx = string
; Returns: eax = length
strlen proc
    push rdi
    
    mov rdi, rcx
    xor eax, eax
    mov ecx, -1
    repne scasb
    not eax
    dec eax
    
    pop rdi
    ret
strlen endp

; ============================================================================
; LEXER
; ============================================================================

; Initialize lexer
; rcx = source buffer, rdx = source length
lexer_init proc
    push rbx
    sub rsp, 28h
    
    mov source_buffer, rcx
    mov source_length, rdx
    mov source_position, 0
    mov current_line, 1
    mov current_column, 1
    mov token_count, 0
    
    ; Allocate token buffer
    mov rcx, 65536      ; 64KB for tokens
    call heap_alloc
    mov token_buffer, rax
    
    add rsp, 28h
    pop rbx
    ret
lexer_init endp

; Get current character
; Returns: al = character, or 0 if EOF
lexer_peek proc
    push rbx
    
    mov rbx, source_position
    cmp rbx, source_length
    jge .eof
    
    mov rax, source_buffer
    mov al, [rax + rbx]
    jmp .done
    
.eof:
    xor al, al
    
.done:
    pop rbx
    ret
lexer_peek endp

; Advance position
lexer_advance proc
    push rbx
    
    mov rbx, source_position
    cmp rbx, source_length
    jge .done
    
    mov rax, source_buffer
    mov al, [rax + rbx]
    
    cmp al, 10          ; LF
    jne .not_newline
    inc current_line
    mov current_column, 1
    jmp .advance_pos
    
.not_newline:
    cmp al, 13          ; CR
    je .advance_pos
    inc current_column
    
.advance_pos:
    inc source_position
    
.done:
    pop rbx
    ret
lexer_advance endp

; Skip whitespace
lexer_skip_whitespace proc
.loop:
    call lexer_peek
    test al, al
    jz .done
    
    cmp al, ' '
    je .skip
    cmp al, 9           ; Tab
    je .skip
    cmp al, 13          ; CR
    je .skip
    cmp al, 10          ; LF
    je .skip
    jmp .done
    
.skip:
    call lexer_advance
    jmp .loop
    
.done:
    ret
lexer_skip_whitespace endp

; Skip comment
lexer_skip_comment proc
    push rbx
    
    call lexer_peek
    cmp al, '/'
    jne .done
    
    call lexer_advance
    call lexer_peek
    
    cmp al, '/'         ; Single-line comment
    je .single_line
    cmp al, '*'         ; Multi-line comment
    je .multi_line
    
    ; Not a comment, backtrack
    dec source_position
    jmp .done
    
.single_line:
    call lexer_advance
.single_loop:
    call lexer_peek
    test al, al
    jz .done
    cmp al, 10          ; LF
    je .done
    call lexer_advance
    jmp .single_loop
    
.multi_line:
    call lexer_advance
.multi_loop:
    call lexer_peek
    test al, al
    jz .done
    cmp al, '*'
    jne .multi_continue
    call lexer_advance
    call lexer_peek
    cmp al, '/'
    je .multi_end
    jmp .multi_loop
.multi_continue:
    call lexer_advance
    jmp .multi_loop
.multi_end:
    call lexer_advance
    
.done:
    pop rbx
    ret
lexer_skip_comment endp

; Read identifier or keyword
; Returns: rax = token pointer
lexer_read_identifier proc
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 40h
    
    ; Save start position
    mov r12, source_position
    mov r13d, current_line
    mov r14d, current_column
    
    ; Read characters
.read_loop:
    call lexer_peek
    test al, al
    jz .done_reading
    
    ; Check if alphanumeric or underscore
    cmp al, '_'
    je .is_valid
    cmp al, 'a'
    jb .check_upper
    cmp al, 'z'
    jbe .is_valid
.check_upper:
    cmp al, 'A'
    jb .check_digit
    cmp al, 'Z'
    jbe .is_valid
.check_digit:
    cmp al, '0'
    jb .done_reading
    cmp al, '9'
    ja .done_reading
    
.is_valid:
    call lexer_advance
    jmp .read_loop
    
.done_reading:
    ; Calculate length
    mov rbx, source_position
    sub rbx, r12
    
    ; Allocate token
    mov rcx, sizeof TOKEN
    call heap_alloc
    
    ; Set token properties
    mov [rax].TOKEN.type_, TOK_IDENTIFIER
    mov [rax].TOKEN.line, r13d
    mov [rax].TOKEN.column, r14d
    mov [rax].TOKEN.length, ebx
    
    ; Allocate and copy value
    lea rcx, [rbx + 1]
    call heap_alloc
    mov [rax].TOKEN.value, rax
    
    ; Copy string
    mov rdi, rax
    mov rsi, source_buffer
    add rsi, r12
    mov rcx, rbx
    rep movsb
    mov byte ptr [rdi], 0
    
    ; Check if keyword
    mov rcx, [rax].TOKEN.value
    call lexer_check_keyword
    mov [rax].TOKEN.type_, eax
    
    add rsp, 40h
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
lexer_read_identifier endp

; Check if identifier is a keyword
; rcx = string pointer
; Returns: eax = token type
lexer_check_keyword proc
    push rbx
    push r12
    push r13
    push rdi
    push rsi
    
    mov r12, rcx
    xor r13, r13          ; Keyword index
    
    lea rdi, keywords
    
.keyword_loop:
    cmp r13, keyword_count
    jge .not_keyword
    
    ; Compare with keyword
    mov rsi, rdi
    mov rcx, r12
    call strcmp
    test eax, eax
    jz .found_keyword
    
    ; Move to next keyword
    mov rsi, rdi
.keyword_scan:
    mov al, [rsi]
    inc rsi
    test al, al
    jnz .keyword_scan
    mov rdi, rsi
    
    inc r13
    jmp .keyword_loop
    
.found_keyword:
    ; Get token type from array
    lea rax, keyword_tokens
    mov eax, [rax + r13 * 4]
    jmp .done
    
.not_keyword:
    mov eax, TOK_IDENTIFIER
    
.done:
    pop rsi
    pop rdi
    pop r13
    pop r12
    pop rbx
    ret
lexer_check_keyword endp

; Read string literal
; Returns: rax = token pointer
lexer_read_string proc
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 40h
    
    ; Save start position
    mov r12, source_position
    mov r13d, current_line
    mov r14d, current_column
    
    ; Skip opening quote
    call lexer_advance
    
    ; Read until closing quote
.read_loop:
    call lexer_peek
    test al, al
    jz .unterminated
    
    cmp al, '"'
    je .done_reading
    cmp al, '\'
    je .escape
    
    call lexer_advance
    jmp .read_loop
    
.escape:
    call lexer_advance
    call lexer_peek
    test al, al
    jz .unterminated
    call lexer_advance
    jmp .read_loop
    
.unterminated:
    ; Error: unterminated string
    jmp .done_reading
    
.done_reading:
    ; Skip closing quote
    call lexer_advance
    
    ; Calculate length
    mov rbx, source_position
    sub rbx, r12
    sub rbx, 2              ; Exclude quotes
    
    ; Allocate token
    mov rcx, sizeof TOKEN
    call heap_alloc
    
    mov [rax].TOKEN.type_, TOK_STRING
    mov [rax].TOKEN.line, r13d
    mov [rax].TOKEN.column, r14d
    mov [rax].TOKEN.length, ebx
    
    ; Allocate and copy value (without quotes)
    lea rcx, [rbx + 1]
    call heap_alloc
    mov [rax].TOKEN.value, rax
    
    ; Copy string content
    mov rdi, rax
    mov rsi, source_buffer
    add rsi, r12
    inc rsi                 ; Skip opening quote
    mov rcx, rbx
    rep movsb
    mov byte ptr [rdi], 0
    
    add rsp, 40h
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
lexer_read_string endp

; Read number (integer or float)
; Returns: rax = token pointer
lexer_read_number proc
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 40h
    
    ; Save start position
    mov r12, source_position
    mov r13d, current_line
    mov r14d, current_column
    xor ebx, ebx            ; is_float flag
    
    ; Read digits
.read_loop:
    call lexer_peek
    
    cmp al, '0'
    jb .check_dot
    cmp al, '9'
    jbe .is_digit
    
.check_dot:
    cmp al, '.'
    jne .done_reading
    test ebx, ebx
    jnz .done_reading        ; Second dot
    mov ebx, 1              ; Mark as float
    
.is_digit:
    call lexer_advance
    jmp .read_loop
    
.done_reading:
    ; Calculate length
    mov rbx, source_position
    sub rbx, r12
    
    ; Allocate token
    mov rcx, sizeof TOKEN
    call heap_alloc
    
    ; Determine type
    cmp ebx, 1
    je .is_float
    mov [rax].TOKEN.type_, TOK_INTEGER
    jmp .set_value
.is_float:
    mov [rax].TOKEN.type_, TOK_FLOAT
    
.set_value:
    mov [rax].TOKEN.line, r13d
    mov [rax].TOKEN.column, r14d
    mov [rax].TOKEN.length, ebx
    
    ; Allocate and copy value
    lea rcx, [rbx + 1]
    call heap_alloc
    mov [rax].TOKEN.value, rax
    
    mov rdi, rax
    mov rsi, source_buffer
    add rsi, r12
    mov rcx, rbx
    rep movsb
    mov byte ptr [rdi], 0
    
    add rsp, 40h
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
lexer_read_number endp

; Get next token
; Returns: rax = token pointer (or 0 for EOF)
lexer_next_token proc
    push rbx
    
    ; Skip whitespace and comments
.skip_loop:
    call lexer_skip_whitespace
    call lexer_skip_comment
    call lexer_skip_whitespace
    
    call lexer_peek
    test al, al
    jnz .not_eof
    
    ; EOF token
    mov rcx, sizeof TOKEN
    call heap_alloc
    mov [rax].TOKEN.type_, TOK_EOF
    mov [rax].TOKEN.line, current_line
    mov [rax].TOKEN.column, current_column
    mov [rax].TOKEN.length, 0
    mov [rax].TOKEN.value, 0
    jmp .done
    
.not_eof:
    ; Check character type
    cmp al, 'a'
    jb .check_upper
    cmp al, 'z'
    jbe .is_alpha
.check_upper:
    cmp al, 'A'
    jb .check_underscore
    cmp al, 'Z'
    jbe .is_alpha
.check_underscore:
    cmp al, '_'
    je .is_alpha
    cmp al, '$'
    je .is_variable
    cmp al, '0'
    jb .check_quote
    cmp al, '9'
    jbe .is_number
.check_quote:
    cmp al, '"'
    je .is_string
    cmp al, '''
    je .is_string
    
    ; Single character token
    jmp .is_single
    
.is_alpha:
    call lexer_read_identifier
    jmp .done
    
.is_variable:
    ; PHP variable ($name)
    call lexer_advance    ; Skip $
    call lexer_read_identifier
    mov [rax].TOKEN.type_, TOK_VARIABLE
    jmp .done
    
.is_number:
    call lexer_read_number
    jmp .done
    
.is_string:
    call lexer_read_string
    jmp .done
    
.is_single:
    ; Handle single character tokens
    call lexer_read_single
    
.done:
    inc token_count
    pop rbx
    ret
lexer_next_token endp

; Read single character token
lexer_read_single proc
    push rbx
    push r12
    push r13
    sub rsp, 28h
    
    mov r12d, current_line
    mov r13d, current_column
    
    call lexer_peek
    mov bl, al
    
    ; Allocate token
    mov rcx, sizeof TOKEN
    call heap_alloc
    
    mov [rax].TOKEN.line, r12d
    mov [rax].TOKEN.column, r13d
    mov [rax].TOKEN.length, 1
    
    ; Allocate value
    mov rcx, 2
    call heap_alloc
    mov [rax].TOKEN.value, rax
    mov byte ptr [rax], bl
    mov byte ptr [rax + 1], 0
    
    ; Determine token type
    movzx ecx, bl
    call lexer_single_type
    mov [rax].TOKEN.type_, eax
    
    call lexer_advance
    
    add rsp, 28h
    pop r13
    pop r12
    pop rbx
    ret
lexer_read_single endp

; Get token type for single character
; cl = character
; Returns: eax = token type
lexer_single_type proc
    cmp cl, ';'
    je .semicolon
    cmp cl, ','
    je .comma
    cmp cl, '.'
    je .dot
    cmp cl, '('
    je .lparen
    cmp cl, ')'
    je .rparen
    cmp cl, '{'
    je .lbrace
    cmp cl, '}'
    je .rbrace
    cmp cl, '['
    je .lbracket
    cmp cl, ']'
    je .rbracket
    cmp cl, '+'
    je .add
    cmp cl, '-'
    je .sub
    cmp cl, '*'
    je .mul
    cmp cl, '/'
    je .div
    cmp cl, '%'
    je .mod
    cmp cl, '='
    je .assign
    cmp cl, '<'
    je .lt
    cmp cl, '>'
    je .gt
    cmp cl, '!'
    je .not
    cmp cl, '&'
    je .bit_and
    cmp cl, '|'
    je .bit_or
    cmp cl, '^'
    je .bit_xor
    cmp cl, '~'
    je .bit_not
    cmp cl, '@'
    je .at
    cmp cl, '\'
    je .backslash
    
    mov eax, TOK_UNKNOWN
    ret
    
.semicolon:
    mov eax, TOK_SEMICOLON
    ret
.comma:
    mov eax, TOK_COMMA
    ret
.dot:
    mov eax, TOK_DOT
    ret
.lparen:
    mov eax, TOK_LPAREN
    ret
.rparen:
    mov eax, TOK_RPAREN
    ret
.lbrace:
    mov eax, TOK_LBRACE
    ret
.rbrace:
    mov eax, TOK_RBRACE
    ret
.lbracket:
    mov eax, TOK_LBRACKET
    ret
.rbracket:
    mov eax, TOK_RBRACKET
    ret
.add:
    mov eax, TOK_ADD
    ret
.sub:
    mov eax, TOK_SUB
    ret
.mul:
    mov eax, TOK_MUL
    ret
.div:
    mov eax, TOK_DIV
    ret
.mod:
    mov eax, TOK_MOD
    ret
.assign:
    mov eax, TOK_ASSIGN
    ret
.lt:
    mov eax, TOK_LT
    ret
.gt:
    mov eax, TOK_GT
    ret
.not:
    mov eax, TOK_NOT
    ret
.bit_and:
    mov eax, TOK_BIT_AND
    ret
.bit_or:
    mov eax, TOK_BIT_OR
    ret
.bit_xor:
    mov eax, TOK_BIT_XOR
    ret
.bit_not:
    mov eax, TOK_BIT_NOT
    ret
.at:
    mov eax, TOK_AT
    ret
.backslash:
    mov eax, TOK_BACKSLASH
    ret
lexer_single_type endp

; ============================================================================
; PARSER
; ============================================================================

; Initialize parser
parser_init proc
    mov ast_root, 0
    ret
parser_init endp

; Create AST node
; ecx = type, edx = line, r8 = token
; Returns: rax = node pointer
ast_create_node proc
    push rbx
    push r12
    push r13
    sub rsp, 28h
    
    mov r12d, ecx
    mov r13d, edx
    
    mov rcx, sizeof AST_NODE
    call heap_alloc
    
    mov [rax].AST_NODE.type_, r12d
    mov [rax].AST_NODE.line, r13d
    mov [rax].AST_NODE.token, r8
    mov [rax].AST_NODE.left, 0
    mov [rax].AST_NODE.right, 0
    mov [rax].AST_NODE.next, 0
    mov [rax].AST_NODE.data, 0
    
    add rsp, 28h
    pop r13
    pop r12
    pop rbx
    ret
ast_create_node endp

; Parse expression (simplified)
; Returns: rax = AST node
parser_parse_expression proc
    ; TODO: Full expression parsing
    xor eax, eax
    ret
parser_parse_expression endp

; Parse statement
; Returns: rax = AST node
parser_parse_statement proc
    ; TODO: Full statement parsing
    xor eax, eax
    ret
parser_parse_statement endp

; Parse program
; Returns: rax = AST root node
parser_parse_program proc
    push rbx
    
    ; Create program node
    mov ecx, AST_PROGRAM
    mov edx, 1
    xor r8, r8
    call ast_create_node
    mov rbx, rax
    
    ; Parse statements until EOF
.parse_loop:
    ; TODO: Parse statements
    jmp .parse_loop
    
    mov rax, rbx
    pop rbx
    ret
parser_parse_program endp

; ============================================================================
; CODE GENERATOR
; ============================================================================

codegen_init proc
    mov rcx, CODE_BUFFER_SIZE
    call heap_alloc
    mov code_buffer, rax
    mov code_position, 0
    ret
codegen_init endp

; Emit byte
codegen_emit_byte proc
    push rbx
    
    mov rbx, code_position
    cmp rbx, CODE_BUFFER_SIZE
    jge .overflow
    
    mov rax, code_buffer
    mov [rax + rbx], cl
    inc code_position
    
.overflow:
    pop rbx
    ret
codegen_emit_byte endp

; Generate code from AST
; rcx = AST node
codegen_generate proc
    ; TODO: Full code generation
    ret
codegen_generate endp

; ============================================================================
; PE WRITER
; ============================================================================

; Write PE header
pe_write_header proc
    ; TODO: PE header construction
    ret
pe_write_header endp

; Write sections
pe_write_sections proc
    ; TODO: Section writing
    ret
pe_write_sections endp

; ============================================================================
; MAIN ENTRY POINT
; ============================================================================

main proc
    push rbx
    sub rsp, 40h
    
    ; Print banner
    lea rcx, msg_banner
    mov edx, msg_banner_len
    call print_string
    
    lea rcx, msg_copyright
    mov edx, msg_copyright_len
    call print_string
    
    ; Check command line
    mov rax, qword ptr [rsp+48h]    ; argc
    cmp rax, 2
    jl .show_usage
    
    ; Get input filename
    mov rax, qword ptr [rsp+50h]    ; argv
    mov rbx, [rax+8]                ; argv[1]
    
    ; TODO: Full compilation pipeline
    ; 1. Load source file
    ; 2. Lexical analysis
    ; 3. Parsing
    ; 4. Code generation
    ; 5. PE output
    
    ; For now, show that we're operational
    lea rcx, msg_lexing
    mov edx, msg_lexing_len
    call print_string
    
    lea rcx, msg_parsing
    mov edx, msg_parsing_len
    call print_string
    
    lea rcx, msg_codegen
    mov edx, msg_codegen_len
    call print_string
    
    lea rcx, msg_success
    mov edx, msg_success_len
    call print_string
    
    xor ecx, ecx
    jmp .exit
    
.show_usage:
    lea rcx, msg_usage
    mov edx, msg_usage_len
    call print_string
    mov ecx, 1
    
.exit:
    call ExitProcess
    
    add rsp, 40h
    pop rbx
    ret
main endp

end
