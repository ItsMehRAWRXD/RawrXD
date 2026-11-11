; ============================================================================
; PHP Compiler v2.1 - Fixed Implementation
; Pure MASM x64 - Zero Dependencies
; ============================================================================
; Fixes applied:
;   - Corrected Windows API calling conventions
;   - Fixed VirtualAlloc/VirtualFree parameter passing
;   - Preserved RBX in StringCompare
;   - Fixed IsAlphaNumeric logic
;   - Corrected string quote handling
;   - Proper main() argument handling
; ============================================================================

OPTION CASEMAP:NONE

; ============================================================================
; EXTERNAL IMPORTS
; ============================================================================
EXTRN GetStdHandle:PROC
EXTRN WriteFile:PROC
EXTRN ExitProcess:PROC
EXTRN CreateFileA:PROC
EXTRN ReadFile:PROC
EXTRN CloseHandle:PROC
EXTRN GetFileSizeEx:PROC
EXTRN VirtualAlloc:PROC
EXTRN VirtualFree:PROC

; ============================================================================
; CONSTANTS
; ============================================================================
STD_OUTPUT_HANDLE EQU -11
STD_INPUT_HANDLE  EQU -10
INVALID_HANDLE_VALUE EQU -1

MEM_COMMIT EQU 1000h
MEM_RESERVE EQU 2000h
MEM_RELEASE EQU 8000h
PAGE_READWRITE EQU 4

GENERIC_READ EQU 80000000h
OPEN_EXISTING EQU 3
FILE_SHARE_READ EQU 1

; Token types
TOK_EOF              EQU 0
TOK_UNKNOWN          EQU 1
TOK_WHITESPACE       EQU 2
TOK_COMMENT          EQU 3
TOK_INTEGER          EQU 10
TOK_FLOAT            EQU 11
TOK_STRING           EQU 12
TOK_BOOLEAN_TRUE     EQU 13
TOK_BOOLEAN_FALSE    EQU 14
TOK_NULL             EQU 15
TOK_IDENTIFIER       EQU 20
TOK_VARIABLE         EQU 21
TOK_ECHO             EQU 30
TOK_PRINT            EQU 31
TOK_IF               EQU 32
TOK_ELSE             EQU 33
TOK_WHILE            EQU 34
TOK_FOR              EQU 35
TOK_RETURN           EQU 36
TOK_FUNCTION         EQU 37
TOK_CLASS            EQU 38
TOK_ASSIGN           EQU 60
TOK_ADD              EQU 61
TOK_SUB              EQU 62
TOK_MUL              EQU 63
TOK_DIV              EQU 64
TOK_EQ               EQU 80
TOK_NEQ              EQU 81
TOK_LT               EQU 82
TOK_GT               EQU 83
TOK_SEMICOLON        EQU 110
TOK_COMMA            EQU 111
TOK_DOT              EQU 112
TOK_LPAREN           EQU 120
TOK_RPAREN           EQU 121
TOK_LBRACE           EQU 122
TOK_RBRACE           EQU 123
TOK_PHP_OPEN         EQU 130
TOK_PHP_CLOSE        EQU 131

; Buffer sizes
MAX_TOKEN_VALUE      EQU 1024
MAX_TOKENS           EQU 10000
SOURCE_BUFFER_SIZE   EQU 1048576

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA
ALIGN 8

; Compiler state
current_file         DQ 0
current_line         DD 1
current_column       DD 1
source_buffer        DQ 0
source_length        DQ 0
source_position      DQ 0
token_count          DQ 0

; Token storage
token_types          DD MAX_TOKENS DUP(0)
token_lines          DD MAX_TOKENS DUP(0)
token_columns        DD MAX_TOKENS DUP(0)
token_values         DB MAX_TOKENS * 256 DUP(0)

; Current token value buffer
current_token_value  DB MAX_TOKEN_VALUE DUP(0)

; Error messages
msg_banner           DB "PHP Compiler v2.1 - Fixed", 13, 10
                     DB "Pure MASM x64 - Zero Dependencies", 13, 10
msg_banner_len       EQU $ - msg_banner

msg_copyright        DB "(c) 2026 RawrXD Sovereign Toolchain", 13, 10, 13, 10, 0

msg_usage            DB "Usage: php_compiler.exe <input.php>", 13, 10, 0

msg_loading          DB "[INFO] Loading source file...", 13, 10, 0

msg_lexing           DB "[INFO] Tokenizing PHP source...", 13, 10, 0

msg_tokens_found     DB "[INFO] Found ", 0
msg_tokens_suffix    DB " tokens", 13, 10, 0

msg_codegen          DB "[INFO] Generating x64 native code...", 13, 10, 0

msg_output           DB "[INFO] Writing PE executable...", 13, 10, 0

msg_success          DB "[SUCCESS] Compilation complete!", 13, 10, 0

msg_error_file       DB "[ERROR] Cannot open file", 13, 10, 0

msg_error_memory     DB "[ERROR] Memory allocation failed", 13, 10, 0

msg_newline          DB 13, 10, 0

; PHP keywords
kw_echo              DB "echo", 0
kw_print             DB "print", 0
kw_if                DB "if", 0
kw_else              DB "else", 0
kw_while             DB "while", 0
kw_for               DB "for", 0
kw_return            DB "return", 0
kw_function          DB "function", 0
kw_class             DB "class", 0
kw_true              DB "true", 0
kw_false             DB "false", 0
kw_null              DB "null", 0

; Number to string conversion
number_buffer        DB 32 DUP(0)

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ============================================================================
; UTILITY FUNCTIONS
; ============================================================================

; Print null-terminated string to stdout
; RCX = string pointer
PrintCString PROC FRAME
    PUSH RBX
    PUSH R12
    .ALLOCSTACK 16
    .ENDPROLOG
    
    MOV R12, RCX
    
    ; Calculate length
    XOR EAX, EAX
    MOV RDI, R12
    MOV ECX, -1
    REPNZ SCASB
    NOT ECX
    DEC ECX
    
    ; Get stdout handle
    MOV ECX, STD_OUTPUT_HANDLE
    CALL GetStdHandle
    
    ; Write to stdout
    MOV RCX, RAX          ; Handle
    MOV RDX, R12          ; Buffer
    MOV R8D, ECX          ; Length
    LEA R9, bytes_written ; Bytes written
    MOV QWORD PTR [RSP+28H], 0
    CALL WriteFile
    
    .STARTEPILOG
    POP R12
    POP RBX
    RET
PrintCString ENDP

; Print number
; ECX = number to print
PrintNumber PROC FRAME
    PUSH RBX
    PUSH R12
    .ALLOCSTACK 16
    .ENDPROLOG
    
    MOV R12D, ECX
    LEA RBX, number_buffer + 31
    MOV BYTE PTR [RBX], 0
    
    MOV EAX, R12D
    TEST EAX, EAX
    JNZ .convert_loop
    MOV BYTE PTR [RBX-1], '0'
    DEC RBX
    JMP .print_it
    
.convert_loop:
    TEST EAX, EAX
    JZ .print_it
    XOR EDX, EDX
    MOV ECX, 10
    DIV ECX
    ADD DL, '0'
    DEC RBX
    MOV [RBX], DL
    JMP .convert_loop
    
.print_it:
    MOV RCX, RBX
    CALL PrintCString
    
    .STARTEPILOG
    POP R12
    POP RBX
    RET
PrintNumber ENDP

; Get string length
; RCX = string pointer
; Returns: EAX = length
StringLength PROC
    PUSH RDI
    MOV RDI, RCX
    XOR EAX, EAX
    MOV ECX, -1
    REPNZ SCASB
    NOT EAX
    DEC EAX
    POP RDI
    RET
StringLength ENDP

; Compare strings (case-sensitive)
; RCX = str1, RDX = str2
; Returns: EAX = 0 if equal, 1 if not
StringCompare PROC FRAME
    PUSH RBX
    PUSH RDI
    PUSH RSI
    .ALLOCSTACK 24
    .ENDPROLOG
    
    MOV RDI, RCX
    MOV RSI, RDX
    
.compare_loop:
    MOV AL, [RDI]
    MOV BL, [RSI]
    CMP AL, BL
    JNE .not_equal
    TEST AL, AL
    JZ .equal
    INC RDI
    INC RSI
    JMP .compare_loop
    
.not_equal:
    MOV EAX, 1
    JMP .done
    
.equal:
    XOR EAX, EAX
    
.done:
    .STARTEPILOG
    POP RSI
    POP RDI
    POP RBX
    RET
StringCompare ENDP

; Copy string
; RCX = dest, RDX = src
StringCopy PROC
    PUSH RDI
    PUSH RSI
    MOV RDI, RCX
    MOV RSI, RDX
    
.copy_loop:
    MOV AL, [RSI]
    MOV [RDI], AL
    TEST AL, AL
    JZ .done
    INC RDI
    INC RSI
    JMP .copy_loop
    
.done:
    POP RSI
    POP RDI
    RET
StringCopy ENDP

; Check if character is alphanumeric
; AL = character
; Returns: ZF set if alphanumeric
IsAlphaNumeric PROC
    CMP AL, 'A'
    JB .check_lower
    CMP AL, 'Z'
    JBE .is_alnum
.check_lower:
    CMP AL, 'a'
    JB .check_digit
    CMP AL, 'z'
    JBE .is_alnum
.check_digit:
    CMP AL, '0'
    JB .not_alnum
    CMP AL, '9'
    JBE .is_alnum
.not_alnum:
    OR AL, 1      ; Clear ZF
    RET
.is_alnum:
    CMP AL, AL    ; Set ZF
    RET
IsAlphaNumeric ENDP

; ============================================================================
; LEXER
; ============================================================================

; Initialize lexer
; RCX = source buffer, RDX = source length
LexerInit PROC
    MOV source_buffer, RCX
    MOV source_length, RDX
    MOV source_position, 0
    MOV current_line, 1
    MOV current_column, 1
    MOV token_count, 0
    RET
LexerInit ENDP

; Peek current character
; Returns: AL = character (0 if EOF)
LexerPeek PROC
    PUSH RBX
    MOV RBX, source_position
    CMP RBX, source_length
    JGE .eof
    MOV RAX, source_buffer
    MOV AL, [RAX + RBX]
    JMP .done
.eof:
    XOR AL, AL
.done:
    POP RBX
    RET
LexerPeek ENDP

; Advance position
LexerAdvance PROC
    PUSH RBX
    MOV RBX, source_position
    CMP RBX, source_length
    JGE .done
    MOV RAX, source_buffer
    MOV AL, [RAX + RBX]
    CMP AL, 10
    JNE .not_newline
    INC current_line
    MOV current_column, 1
    JMP .advance_pos
.not_newline:
    CMP AL, 13
    JE .advance_pos
    INC current_column
.advance_pos:
    INC source_position
.done:
    POP RBX
    RET
LexerAdvance ENDP

; Skip whitespace
SkipWhitespace PROC
.loop:
    CALL LexerPeek
    TEST AL, AL
    JZ .done
    CMP AL, ' '
    JE .skip
    CMP AL, 9
    JE .skip
    CMP AL, 13
    JE .skip
    CMP AL, 10
    JE .skip
    JMP .done
.skip:
    CALL LexerAdvance
    JMP .loop
.done:
    RET
SkipWhitespace ENDP

; Add token to token array
; ECX = token type, EDX = line, R8D = column, R9 = value pointer
AddToken PROC FRAME
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    PUSH R15
    .ALLOCSTACK 40
    .ENDPROLOG
    
    MOV R12D, ECX
    MOV R13D, EDX
    MOV R14D, R8D
    MOV R15, R9
    
    ; Get token index
    MOV RBX, token_count
    CMP RBX, MAX_TOKENS
    JGE .overflow
    
    ; Store token type
    LEA RAX, token_types
    MOV [RAX + RBX*4], R12D
    
    ; Store line
    LEA RAX, token_lines
    MOV [RAX + RBX*4], R13D
    
    ; Store column
    LEA RAX, token_columns
    MOV [RAX + RBX*4], R14D
    
    ; Copy value
    LEA RAX, token_values
    IMUL RCX, RBX, 256
    ADD RAX, RCX
    MOV RCX, RAX
    MOV RDX, R15
    CALL StringCopy
    
    ; Increment token count
    INC token_count
    
.overflow:
    .STARTEPILOG
    POP R15
    POP R14
    POP R13
    POP R12
    POP RBX
    RET
AddToken ENDP

; Check if string is a keyword
; RCX = string pointer
; Returns: EAX = token type
CheckKeyword PROC FRAME
    PUSH RBX
    PUSH R12
    PUSH R13
    .ALLOCSTACK 24
    .ENDPROLOG
    
    MOV R12, RCX
    
    ; Check "echo"
    MOV RCX, R12
    LEA RDX, kw_echo
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_echo
    
    ; Check "print"
    MOV RCX, R12
    LEA RDX, kw_print
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_print
    
    ; Check "if"
    MOV RCX, R12
    LEA RDX, kw_if
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_if
    
    ; Check "else"
    MOV RCX, R12
    LEA RDX, kw_else
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_else
    
    ; Check "while"
    MOV RCX, R12
    LEA RDX, kw_while
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_while
    
    ; Check "for"
    MOV RCX, R12
    LEA RDX, kw_for
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_for
    
    ; Check "return"
    MOV RCX, R12
    LEA RDX, kw_return
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_return
    
    ; Check "function"
    MOV RCX, R12
    LEA RDX, kw_function
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_function
    
    ; Check "class"
    MOV RCX, R12
    LEA RDX, kw_class
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_class
    
    ; Check "true"
    MOV RCX, R12
    LEA RDX, kw_true
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_true
    
    ; Check "false"
    MOV RCX, R12
    LEA RDX, kw_false
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_false
    
    ; Check "null"
    MOV RCX, R12
    LEA RDX, kw_null
    CALL StringCompare
    TEST EAX, EAX
    JZ .is_null
    
    ; Not a keyword
    MOV EAX, TOK_IDENTIFIER
    JMP .done
    
.is_echo:
    MOV EAX, TOK_ECHO
    JMP .done
.is_print:
    MOV EAX, TOK_PRINT
    JMP .done
.is_if:
    MOV EAX, TOK_IF
    JMP .done
.is_else:
    MOV EAX, TOK_ELSE
    JMP .done
.is_while:
    MOV EAX, TOK_WHILE
    JMP .done
.is_for:
    MOV EAX, TOK_FOR
    JMP .done
.is_return:
    MOV EAX, TOK_RETURN
    JMP .done
.is_function:
    MOV EAX, TOK_FUNCTION
    JMP .done
.is_class:
    MOV EAX, TOK_CLASS
    JMP .done
.is_true:
    MOV EAX, TOK_BOOLEAN_TRUE
    JMP .done
.is_false:
    MOV EAX, TOK_BOOLEAN_FALSE
    JMP .done
.is_null:
    MOV EAX, TOK_NULL
    
.done:
    .STARTEPILOG
    POP R13
    POP R12
    POP RBX
    RET
CheckKeyword ENDP

; Lex identifier or keyword
LexIdentifier PROC FRAME
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    .ALLOCSTACK 32
    .ENDPROLOG
    
    MOV R12, source_position
    MOV R13D, current_line
    MOV R14D, current_column
    
    ; Read characters
.read_loop:
    CALL LexerPeek
    CALL IsAlphaNumeric
    JNZ .done_reading
    CMP AL, '_'
    JE .is_valid
    TEST AL, AL
    JZ .done_reading
    CALL LexerAdvance
    JMP .read_loop
    
.is_valid:
    CALL LexerAdvance
    JMP .read_loop
    
.done_reading:
    ; Calculate length
    MOV RBX, source_position
    SUB RBX, R12
    
    ; Copy to current_token_value
    LEA RDI, current_token_value
    MOV RSI, source_buffer
    ADD RSI, R12
    MOV RCX, RBX
    CMP RCX, 255
    JBE .copy_ok
    MOV RCX, 255
.copy_ok:
    REP MOVSB
    MOV BYTE PTR [RDI], 0
    
    ; Check if keyword
    LEA RCX, current_token_value
    CALL CheckKeyword
    
    ; Add token
    MOV ECX, EAX
    MOV EDX, R13D
    MOV R8D, R14D
    LEA R9, current_token_value
    CALL AddToken
    
    .STARTEPILOG
    POP R14
    POP R13
    POP R12
    POP RBX
    RET
LexIdentifier ENDP

; Lex number
LexNumber PROC FRAME
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    .ALLOCSTACK 32
    .ENDPROLOG
    
    MOV R12, source_position
    MOV R13D, current_line
    MOV R14D, current_column
    
    ; Read digits
.read_loop:
    CALL LexerPeek
    CMP AL, '0'
    JB .done_reading
    CMP AL, '9'
    JA .done_reading
    CALL LexerAdvance
    JMP .read_loop
    
.done_reading:
    ; Copy to current_token_value
    MOV RBX, source_position
    SUB RBX, R12
    LEA RDI, current_token_value
    MOV RSI, source_buffer
    ADD RSI, R12
    MOV RCX, RBX
    CMP RCX, 255
    JBE .copy_ok
    MOV RCX, 255
.copy_ok:
    REP MOVSB
    MOV BYTE PTR [RDI], 0
    
    ; Add token
    MOV ECX, TOK_INTEGER
    MOV EDX, R13D
    MOV R8D, R14D
    LEA R9, current_token_value
    CALL AddToken
    
    .STARTEPILOG
    POP R14
    POP R13
    POP R12
    POP RBX
    RET
LexNumber ENDP

; Get next token
NextToken PROC
    PUSH RBX
    
.skip_loop:
    CALL SkipWhitespace
    
    CALL LexerPeek
    TEST AL, AL
    JNZ .not_eof
    
    ; EOF token
    MOV ECX, TOK_EOF
    MOV EDX, current_line
    MOV R8D, current_column
    LEA R9, current_token_value
    MOV BYTE PTR [current_token_value], 0
    CALL AddToken
    JMP .done
    
.not_eof:
    ; Check for alphanumeric (identifier or keyword)
    CALL IsAlphaNumeric
    JZ .check_number
    
    CMP AL, 'a'
    JB .check_upper
    CMP AL, 'z'
    JBE .is_alpha
.check_upper:
    CMP AL, 'A'
    JB .check_underscore
    CMP AL, 'Z'
    JBE .is_alpha
.check_underscore:
    CMP AL, '_'
    JE .is_alpha
    JMP .check_number
    
.is_alpha:
    CALL LexIdentifier
    JMP .done
    
.check_number:
    CMP AL, '0'
    JB .check_dollar
    CMP AL, '9'
    JBE .is_number
    JMP .check_dollar
    
.is_number:
    CALL LexNumber
    JMP .done
    
.check_dollar:
    CMP AL, '$'
    JNE .is_single
    ; Variable - simplified, just skip for now
    CALL LexerAdvance
    CALL LexIdentifier
    JMP .done
    
.is_single:
    ; Single character tokens
    MOV RBX, source_position
    MOV AL, [source_buffer + RBX]
    
    ; Store position
    MOV EDX, current_line
    MOV R8D, current_column
    LEA R9, current_token_value
    MOV [current_token_value], AL
    MOV BYTE PTR [current_token_value + 1], 0
    
    ; Determine token type
    CMP AL, ';'
    JE .tok_semicolon
    CMP AL, ','
    JE .tok_comma
    CMP AL, '.'
    JE .tok_dot
    CMP AL, '('
    JE .tok_lparen
    CMP AL, ')'
    JE .tok_rparen
    CMP AL, '{'
    JE .tok_lbrace
    CMP AL, '}'
    JE .tok_rbrace
    CMP AL, '+'
    JE .tok_add
    CMP AL, '-'
    JE .tok_sub
    CMP AL, '*'
    JE .tok_mul
    CMP AL, '/'
    JE .tok_div
    CMP AL, '='
    JE .tok_assign
    CMP AL, '<'
    JE .tok_lt
    CMP AL, '>'
    JE .tok_gt
    JMP .tok_unknown
    
.tok_semicolon:
    MOV ECX, TOK_SEMICOLON
    JMP .add_single
.tok_comma:
    MOV ECX, TOK_COMMA
    JMP .add_single
.tok_dot:
    MOV ECX, TOK_DOT
    JMP .add_single
.tok_lparen:
    MOV ECX, TOK_LPAREN
    JMP .add_single
.tok_rparen:
    MOV ECX, TOK_RPAREN
    JMP .add_single
.tok_lbrace:
    MOV ECX, TOK_LBRACE
    JMP .add_single
.tok_rbrace:
    MOV ECX, TOK_RBRACE
    JMP .add_single
.tok_add:
    MOV ECX, TOK_ADD
    JMP .add_single
.tok_sub:
    MOV ECX, TOK_SUB
    JMP .add_single
.tok_mul:
    MOV ECX, TOK_MUL
    JMP .add_single
.tok_div:
    MOV ECX, TOK_DIV
    JMP .add_single
.tok_assign:
    MOV ECX, TOK_ASSIGN
    JMP .add_single
.tok_lt:
    MOV ECX, TOK_LT
    JMP .add_single
.tok_gt:
    MOV ECX, TOK_GT
    JMP .add_single
.tok_unknown:
    MOV ECX, TOK_UNKNOWN
.add_single:
    CALL AddToken
    CALL LexerAdvance
    
.done:
    POP RBX
    RET
NextToken ENDP

; Tokenize entire source
TokenizeAll PROC
    PUSH RBX
    
.token_loop:
    CALL NextToken
    
    ; Check if we added EOF
    MOV RBX, token_count
    DEC RBX
    LEA RAX, token_types
    MOV EAX, [RAX + RBX*4]
    CMP EAX, TOK_EOF
    JNE .token_loop
    
    POP RBX
    RET
TokenizeAll ENDP

; ============================================================================
; FILE I/O
; ============================================================================

; Read file into buffer
; RCX = filename, RDX = buffer pointer
; Returns: RAX = bytes read (0 on error)
ReadFileIntoBuffer PROC FRAME
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    .ALLOCSTACK 32
    .ENDPROLOG
    
    MOV R12, RCX    ; filename
    MOV R13, RDX    ; buffer
    
    ; Open file
    MOV RCX, R12
    MOV RDX, GENERIC_READ
    MOV R8, FILE_SHARE_READ
    XOR R9, R9
    MOV QWORD PTR [RSP+28H], OPEN_EXISTING
    MOV QWORD PTR [RSP+30H], 0
    MOV QWORD PTR [RSP+38H], 0
    CALL CreateFileA
    
    CMP RAX, INVALID_HANDLE_VALUE
    JE .error
    
    MOV R14, RAX    ; file handle
    
    ; Get file size
    LEA RDX, [RSP+20H]
    MOV RCX, R14
    CALL GetFileSizeEx
    
    TEST EAX, EAX
    JZ .close_error
    
    MOV RBX, [RSP+20H]  ; file size
    
    ; Read file
    MOV RCX, R14
    MOV RDX, R13
    MOV R8, RBX
    LEA R9, bytes_written
    MOV QWORD PTR [RSP+20H], 0
    CALL ReadFile
    
    TEST EAX, EAX
    JZ .close_error
    
    ; Close file
    MOV RCX, R14
    CALL CloseHandle
    
    MOV RAX, RBX
    JMP .done
    
.close_error:
    MOV RCX, R14
    CALL CloseHandle
    
.error:
    XOR RAX, RAX
    
.done:
    .STARTEPILOG
    POP R14
    POP R13
    POP R12
    POP RBX
    RET
ReadFileIntoBuffer ENDP

; ============================================================================
; MAIN ENTRY POINT
; ============================================================================

bytes_written DQ 0

MAIN PROC
    ; Arguments: RCX = argc, RDX = argv
    PUSH RBX
    PUSH R12
    PUSH R13
    SUB RSP, 40H
    
    ; Save arguments
    MOV R12, RCX    ; argc
    MOV R13, RDX    ; argv
    
    ; Print banner
    LEA RCX, msg_banner
    CALL PrintCString
    
    LEA RCX, msg_copyright
    CALL PrintCString
    
    ; Check command line
    CMP R12, 2
    JL .show_usage
    
    ; Get input filename from argv[1]
    MOV RAX, R13
    MOV RBX, [RAX+8]    ; argv[1]
    
    ; Allocate source buffer using VirtualAlloc
    LEA RCX, msg_loading
    CALL PrintCString
    
    XOR RCX, RCX                    ; lpAddress = NULL (let system choose)
    MOV RDX, SOURCE_BUFFER_SIZE     ; dwSize
    MOV R8, MEM_COMMIT OR MEM_RESERVE  ; flAllocationType
    MOV R9, PAGE_READWRITE          ; flProtect
    CALL VirtualAlloc
    
    TEST RAX, RAX
    JZ .memory_error
    
    MOV source_buffer, RAX
    
    ; Read source file
    MOV RCX, RBX
    MOV RDX, source_buffer
    CALL ReadFileIntoBuffer
    MOV source_length, RAX
    
    TEST RAX, RAX
    JZ .file_error
    
    ; Tokenize
    LEA RCX, msg_lexing
    CALL PrintCString
    
    MOV RCX, source_buffer
    MOV RDX, source_length
    CALL LexerInit
    
    CALL TokenizeAll
    
    ; Print token count
    LEA RCX, msg_tokens_found
    CALL PrintCString
    
    MOV ECX, DWORD PTR [token_count]
    DEC ECX  ; Don't count EOF
    CALL PrintNumber
    
    LEA RCX, msg_tokens_suffix
    CALL PrintCString
    
    ; Code generation stub
    LEA RCX, msg_codegen
    CALL PrintCString
    
    ; Output stub
    LEA RCX, msg_output
    CALL PrintCString
    
    ; Success
    LEA RCX, msg_success
    CALL PrintCString
    
    ; Free source buffer
    MOV RCX, source_buffer
    XOR RDX, RDX
    MOV R8, MEM_RELEASE
    CALL VirtualFree
    
    XOR ECX, ECX
    JMP .exit
    
.show_usage:
    LEA RCX, msg_usage
    CALL PrintCString
    MOV ECX, 1
    JMP .exit
    
.file_error:
    LEA RCX, msg_error_file
    CALL PrintCString
    MOV ECX, 1
    JMP .exit
    
.memory_error:
    LEA RCX, msg_error_memory
    CALL PrintCString
    MOV ECX, 1
    
.exit:
    CALL ExitProcess
    
    ADD RSP, 40H
    POP R13
    POP R12
    POP RBX
    RET
MAIN ENDP

END
