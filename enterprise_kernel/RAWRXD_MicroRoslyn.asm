; ==============================================================================
; RAWRXD Enterprise Kernel - Micro-Roslyn C# Syntax Engine
; Pure x64 MASM - Zero Dependencies - In-Memory Blazing Fast
; Provides real-time syntax validation without external compiler invocation
; ==============================================================================

OPTION CASEMAP:NONE

; Public exports
PUBLIC MicroRoslyn_ValidateSyntax
PUBLIC MicroRoslyn_GetDiagnostic
PUBLIC MicroRoslyn_ClearDiagnostics

; ==============================================================================
; CONSTANTS
; ==============================================================================
MAX_MICRO_DIAGNOSTICS     EQU 64
MAX_NESTING_DEPTH         EQU 256

; Severity codes
SEVERITY_ERROR            EQU 1
SEVERITY_WARNING          EQU 2

; Error codes
ERR_UNMATCHED_CLOSE       EQU 1001
ERR_UNCLOSED_BLOCK        EQU 1002
ERR_UNMATCHED_PAREN       EQU 1003
ERR_UNCLOSED_PAREN        EQU 1004
ERR_MISSING_SEMICOLON     EQU 1005
ERR_INVALID_TOKEN         EQU 1006
ERR_UNCLOSED_STRING       EQU 1007
ERR_UNCLOSED_COMMENT      EQU 1008
ERR_UNMATCHED_ANGLE       EQU 1009
ERR_UNCLOSED_ANGLE        EQU 1010

; Token type flags
TOKEN_KEYWORD             EQU 1
TOKEN_IDENTIFIER            EQU 2
TOKEN_NUMBER              EQU 3
TOKEN_STRING              EQU 4
TOKEN_OPERATOR            EQU 5
TOKEN_BRACE_OPEN          EQU 6
TOKEN_BRACE_CLOSE         EQU 7
TOKEN_PAREN_OPEN          EQU 8
TOKEN_PAREN_CLOSE         EQU 9
TOKEN_SEMICOLON           EQU 10
TOKEN_COMMA               EQU 11
TOKEN_DOT                 EQU 12
TOKEN_ANGLE_OPEN          EQU 13
TOKEN_ANGLE_CLOSE         EQU 14
TOKEN_COMMENT             EQU 15
TOKEN_WHITESPACE          EQU 16
TOKEN_EOF                 EQU 17

; ==============================================================================
; DATA SECTION
; ==============================================================================
.data
align 8

; C# Keywords (simplified set)
KeywordTable LABEL BYTE
    db "abstract", 0, "as", 0, "base", 0, "bool", 0, "break", 0
    db "byte", 0, "case", 0, "catch", 0, "char", 0, "checked", 0
    db "class", 0, "const", 0, "continue", 0, "decimal", 0, "default", 0
    db "delegate", 0, "do", 0, "double", 0, "else", 0, "enum", 0
    db "event", 0, "explicit", 0, "extern", 0, "false", 0, "finally", 0
    db "fixed", 0, "float", 0, "for", 0, "foreach", 0, "goto", 0
    db "if", 0, "implicit", 0, "in", 0, "int", 0, "interface", 0
    db "internal", 0, "is", 0, "lock", 0, "long", 0, "namespace", 0
    db "new", 0, "null", 0, "object", 0, "operator", 0, "out", 0
    db "override", 0, "params", 0, "private", 0, "protected", 0
    db "public", 0, "readonly", 0, "ref", 0, "return", 0, "sbyte", 0
    db "sealed", 0, "short", 0, "sizeof", 0, "stackalloc", 0, "static", 0
    db "string", 0, "struct", 0, "switch", 0, "this", 0, "throw", 0
    db "true", 0, "try", 0, "typeof", 0, "uint", 0, "ulong", 0
    db "unchecked", 0, "unsafe", 0, "ushort", 0, "using", 0, "virtual", 0
    db "void", 0, "volatile", 0, "while", 0, 0  ; Double null = end

; Diagnostic structure
MICRO_DIAGNOSTIC STRUCT
    LineNumber      DWORD ?
    ColumnNumber    DWORD ?
    ErrorCode       DWORD ?
    Severity        DWORD ?
    Message         BYTE 128 DUP(?)
MICRO_DIAGNOSTIC ENDS

; State tracking
MicroDiagnostics        MICRO_DIAGNOSTIC MAX_MICRO_DIAGNOSTICS DUP(<0,0,0,0,0>)
MicroDiagCount          DWORD 0

; Nesting stacks
BraceStack              DWORD MAX_NESTING_DEPTH DUP(?)
ParenStack              DWORD MAX_NESTING_DEPTH DUP(?)
AngleStack              DWORD MAX_NESTING_DEPTH DUP(?)
BraceDepth              DWORD 0
ParenDepth              DWORD 0
AngleDepth              DWORD 0

; Parser state
CurrentLine             DWORD 1
CurrentColumn           DWORD 0
InString                BYTE 0
InChar                  BYTE 0
InLineComment           BYTE 0
InBlockComment          BYTE 0
InVerbatimString        BYTE 0
LastToken               DWORD 0
ExpectSemicolon         BYTE 0

; Error messages
szErrUnmatchedClose     BYTE "Unmatched closing brace", 0
szErrUnclosedBlock      BYTE "Unclosed code block", 0
szErrUnmatchedParen     BYTE "Unmatched closing parenthesis", 0
szErrUnclosedParen      BYTE "Unclosed parenthesis", 0
szErrMissingSemicolon   BYTE "Missing semicolon", 0
szErrInvalidToken       BYTE "Invalid token sequence", 0
szErrUnclosedString     BYTE "Unclosed string literal", 0
szErrUnclosedComment    BYTE "Unclosed block comment", 0
szErrUnmatchedAngle     BYTE "Unmatched closing angle bracket", 0
szErrUnclosedAngle      BYTE "Unclosed angle bracket", 0

; ==============================================================================
; CODE SECTION
; ==============================================================================
.code
align 8

; ==============================================================================
; Helper: Get error message pointer
; RCX = error code
; Returns RAX = pointer to message string
; ==============================================================================
GetErrorMessage PROC FRAME
    .ENDPROLOG
    cmp ecx, ERR_UNMATCHED_CLOSE
    je msg_unmatched_close
    cmp ecx, ERR_UNCLOSED_BLOCK
    je msg_unclosed_block
    cmp ecx, ERR_UNMATCHED_PAREN
    je msg_unmatched_paren
    cmp ecx, ERR_UNCLOSED_PAREN
    je msg_unclosed_paren
    cmp ecx, ERR_MISSING_SEMICOLON
    je msg_missing_semicolon
    cmp ecx, ERR_INVALID_TOKEN
    je msg_invalid_token
    cmp ecx, ERR_UNCLOSED_STRING
    je msg_unclosed_string
    cmp ecx, ERR_UNCLOSED_COMMENT
    je msg_unclosed_comment
    cmp ecx, ERR_UNMATCHED_ANGLE
    je msg_unmatched_angle
    cmp ecx, ERR_UNCLOSED_ANGLE
    je msg_unclosed_angle
    lea rax, szErrInvalidToken
    ret
msg_unmatched_close:
    lea rax, szErrUnmatchedClose
    ret
msg_unclosed_block:
    lea rax, szErrUnclosedBlock
    ret
msg_unmatched_paren:
    lea rax, szErrUnmatchedParen
    ret
msg_unclosed_paren:
    lea rax, szErrUnclosedParen
    ret
msg_missing_semicolon:
    lea rax, szErrMissingSemicolon
    ret
msg_invalid_token:
    lea rax, szErrInvalidToken
    ret
msg_unclosed_string:
    lea rax, szErrUnclosedString
    ret
msg_unclosed_comment:
    lea rax, szErrUnclosedComment
    ret
msg_unmatched_angle:
    lea rax, szErrUnmatchedAngle
    ret
msg_unclosed_angle:
    lea rax, szErrUnclosedAngle
    ret
GetErrorMessage ENDP

; ==============================================================================
; Helper: Add diagnostic
; RCX = line number
; RDX = column number
; R8D = error code
; R9D = severity
; ==============================================================================
AddDiagnostic PROC FRAME
    .ENDPROLOG
    push rbx
    push rsi
    push rdi
    
    mov eax, MicroDiagCount
    cmp eax, MAX_MICRO_DIAGNOSTICS
    jge AddDiagnostic_done
    
    imul rax, rax, SIZEOF MICRO_DIAGNOSTIC
    lea rdi, MicroDiagnostics
    add rdi, rax
    
    mov [rdi].MICRO_DIAGNOSTIC.LineNumber, ecx
    mov [rdi].MICRO_DIAGNOSTIC.ColumnNumber, edx
    mov [rdi].MICRO_DIAGNOSTIC.ErrorCode, r8d
    mov [rdi].MICRO_DIAGNOSTIC.Severity, r9d
    
    ; Copy error message
    mov rcx, r8d
    call GetErrorMessage
    mov rsi, rax
    lea rdi, [rdi].MICRO_DIAGNOSTIC.Message
    mov rcx, 127
    rep movsb
    
    inc MicroDiagCount
    
AddDiagnostic_done:
    pop rdi
    pop rsi
    pop rbx
    ret
AddDiagnostic ENDP

; ==============================================================================
; MicroRoslyn_ClearDiagnostics - Reset diagnostic state
; ==============================================================================
MicroRoslyn_ClearDiagnostics PROC FRAME
    .ENDPROLOG
    mov MicroDiagCount, 0
    mov BraceDepth, 0
    mov ParenDepth, 0
    mov AngleDepth, 0
    mov CurrentLine, 1
    mov CurrentColumn, 0
    mov InString, 0
    mov InChar, 0
    mov InLineComment, 0
    mov InBlockComment, 0
    mov InVerbatimString, 0
    mov LastToken, 0
    mov ExpectSemicolon, 0
    ret
MicroRoslyn_ClearDiagnostics ENDP

; ==============================================================================
; MicroRoslyn_ValidateSyntax - Fast C# syntax validation
; RCX = pointer to null-terminated C# source (ASCII/UTF-8)
; Returns: RAX = 1 (clean), 0 (errors found)
; ==============================================================================
MicroRoslyn_ValidateSyntax PROC FRAME
    .ENDPROLOG
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx            ; r12 = source cursor
    call MicroRoslyn_ClearDiagnostics
    
    xor r13, r13            ; r13 = current token type
    xor r14, r14            ; r14 = previous non-whitespace char
    
ScanLoop:
    movzx eax, byte ptr [r12]
    test al, al
    jz ScanEOF
    
    inc CurrentColumn
    
    ; Handle newlines
    cmp al, 10              ; '\n'
    jne CheckCarriageReturn
    inc CurrentLine
    mov CurrentColumn, 0
    mov InLineComment, 0
    jmp NextChar
    
CheckCarriageReturn:
    cmp al, 13              ; '\r'
    je NextChar
    
    ; Skip line comments
    cmp InLineComment, 0
    jne NextChar
    
    ; Handle block comments
    cmp InBlockComment, 0
    je CheckBlockCommentEnd
    cmp al, '*'
    jne NextChar
    movzx ebx, byte ptr [r12 + 1]
    cmp bl, '/'
    jne NextChar
    mov InBlockComment, 0
    inc r12
    inc CurrentColumn
    jmp NextChar
    
CheckBlockCommentEnd:
    ; Check for comment start
    cmp al, '/'
    jne CheckString
    movzx ebx, byte ptr [r12 + 1]
    cmp bl, '/'
    jne CheckBlockStart
    mov InLineComment, 1
    inc r12
    inc CurrentColumn
    jmp NextChar
    
CheckBlockStart:
    cmp bl, '*'
    jne CheckString
    mov InBlockComment, 1
    inc r12
    inc CurrentColumn
    jmp NextChar
    
CheckString:
    ; Handle strings
    cmp InString, 0
    je CheckCharLiteral
    cmp al, '"'
    jne CheckStringEscape
    mov InString, 0
    jmp NextChar
    
CheckStringEscape:
    cmp al, '\\'
    jne NextChar
    ; Skip escaped char
    inc r12
    inc CurrentColumn
    jmp NextChar
    
CheckCharLiteral:
    cmp InChar, 0
    je CheckVerbatim
    cmp al, ''''
    jne CheckCharEscape
    mov InChar, 0
    jmp NextChar
    
CheckCharEscape:
    cmp al, '\\'
    jne NextChar
    inc r12
    inc CurrentColumn
    jmp NextChar
    
CheckVerbatim:
    cmp InVerbatimString, 0
    je ProcessToken
    cmp al, '"'
    jne NextChar
    movzx ebx, byte ptr [r12 + 1]
    cmp bl, '"'
    jne EndVerbatim
    ; Escaped quote in verbatim
    inc r12
    inc CurrentColumn
    jmp NextChar
    
EndVerbatim:
    mov InVerbatimString, 0
    jmp NextChar
    
ProcessToken:
    ; Process actual tokens
    cmp al, '"'
    jne CheckVerbatimStart
    mov InString, 1
    mov r13, TOKEN_STRING
    jmp NextChar
    
CheckVerbatimStart:
    cmp al, '@'
    jne CheckCharStart
    movzx ebx, byte ptr [r12 + 1]
    cmp bl, '"'
    jne CheckCharStart
    mov InVerbatimString, 1
    inc r12
    inc CurrentColumn
    mov r13, TOKEN_STRING
    jmp NextChar
    
CheckCharStart:
    cmp al, ''''
    jne CheckBraceOpen
    mov InChar, 1
    mov r13, TOKEN_STRING
    jmp NextChar
    
CheckBraceOpen:
    cmp al, '{'
    jne CheckBraceClose
    mov eax, BraceDepth
    cmp eax, MAX_NESTING_DEPTH
    jge StackOverflow
    mov BraceStack[rax*4], ecx
    inc BraceDepth
    mov r13, TOKEN_BRACE_OPEN
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckBraceClose:
    cmp al, '}'
    jne CheckParenOpen
    cmp BraceDepth, 0
    jle UnmatchedBrace
    dec BraceDepth
    mov r13, TOKEN_BRACE_CLOSE
    mov ExpectSemicolon, 0
    jmp NextChar
    
UnmatchedBrace:
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNMATCHED_CLOSE
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    jmp NextChar
    
CheckParenOpen:
    cmp al, '('
    jne CheckParenClose
    mov eax, ParenDepth
    cmp eax, MAX_NESTING_DEPTH
    jge StackOverflow
    mov ParenStack[rax*4], ecx
    inc ParenDepth
    mov r13, TOKEN_PAREN_OPEN
    jmp NextChar
    
CheckParenClose:
    cmp al, ')'
    jne CheckAngleOpen
    cmp ParenDepth, 0
    jle UnmatchedParen
    dec ParenDepth
    mov r13, TOKEN_PAREN_CLOSE
    jmp NextChar
    
UnmatchedParen:
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNMATCHED_PAREN
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    jmp NextChar
    
CheckAngleOpen:
    cmp al, '<'
    jne CheckAngleClose
    mov eax, AngleDepth
    cmp eax, MAX_NESTING_DEPTH
    jge StackOverflow
    mov AngleStack[rax*4], ecx
    inc AngleDepth
    mov r13, TOKEN_ANGLE_OPEN
    jmp NextChar
    
CheckAngleClose:
    cmp al, '>'
    jne CheckSemicolon
    cmp AngleDepth, 0
    jle UnmatchedAngle
    dec AngleDepth
    mov r13, TOKEN_ANGLE_CLOSE
    jmp NextChar
    
UnmatchedAngle:
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNMATCHED_ANGLE
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    jmp NextChar
    
CheckSemicolon:
    cmp al, ';'
    jne CheckComma
    mov r13, TOKEN_SEMICOLON
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckComma:
    cmp al, ','
    jne CheckDot
    mov r13, TOKEN_COMMA
    jmp NextChar
    
CheckDot:
    cmp al, '.'
    jne CheckOperator
    mov r13, TOKEN_DOT
    jmp NextChar
    
CheckOperator:
    ; Simple operator detection
    cmp al, '+'
    je IsOperator
    cmp al, '-'
    je IsOperator
    cmp al, '*'
    je IsOperator
    cmp al, '/'
    je IsOperator
    cmp al, '='
    je IsOperator
    cmp al, '!'
    je IsOperator
    cmp al, '&'
    je IsOperator
    cmp al, '|'
    je IsOperator
    cmp al, '^'
    je IsOperator
    cmp al, '%'
    je IsOperator
    cmp al, '~'
    je IsOperator
    cmp al, '?'
    je IsOperator
    cmp al, ':'
    je IsOperator
    jmp CheckWhitespace
    
IsOperator:
    mov r13, TOKEN_OPERATOR
    jmp NextChar
    
CheckWhitespace:
    cmp al, ' '
    je IsWhitespace
    cmp al, 9               ; tab
    je IsWhitespace
    jmp CheckIdentifier
    
IsWhitespace:
    mov r13, TOKEN_WHITESPACE
    jmp NextChar
    
CheckIdentifier:
    ; Check if alphanumeric or underscore
    cmp al, '_'
    je IsIdentifier
    cmp al, 'a'
    jl CheckUpper
    cmp al, 'z'
    jle IsIdentifier
CheckUpper:
    cmp al, 'A'
    jl CheckDigit
    cmp al, 'Z'
    jle IsIdentifier
CheckDigit:
    cmp al, '0'
    jl CheckKeyword
    cmp al, '9'
    jle IsNumber
    jmp InvalidToken
    
IsIdentifier:
    mov r13, TOKEN_IDENTIFIER
    jmp NextChar
    
IsNumber:
    mov r13, TOKEN_NUMBER
    jmp NextChar
    
InvalidToken:
    mov r13, TOKEN_INVALID
    jmp NextChar
    
StackOverflow:
    ; Nesting too deep - add error
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_BLOCK
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    jmp NextChar
    
NextChar:
    mov r14b, al            ; Save as previous char
    mov LastToken, r13d
    inc r12
    jmp ScanLoop
    
ScanEOF:
    ; Final validation checks
    cmp InString, 0
    je CheckUnclosedChar
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_STRING
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
CheckUnclosedChar:
    cmp InChar, 0
    je CheckUnclosedBlock
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_STRING
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
CheckUnclosedBlock:
    cmp InBlockComment, 0
    je CheckUnclosedBrace
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_COMMENT
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
CheckUnclosedBrace:
    cmp BraceDepth, 0
    je CheckUnclosedParen
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_BLOCK
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
CheckUnclosedParen:
    cmp ParenDepth, 0
    je CheckUnclosedAngle
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_PAREN
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
CheckUnclosedAngle:
    cmp AngleDepth, 0
    je ValidationDone
    mov ecx, CurrentLine
    mov edx, CurrentColumn
    mov r8d, ERR_UNCLOSED_ANGLE
    mov r9d, SEVERITY_ERROR
    call AddDiagnostic
    
ValidationDone:
    ; Return result
    mov eax, MicroDiagCount
    test eax, eax
    jnz HasErrors
    mov rax, 1              ; Clean
    jmp ValidateExit
    
HasErrors:
    xor rax, rax            ; Has errors
    
ValidateExit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
MicroRoslyn_ValidateSyntax ENDP

; ==============================================================================
; MicroRoslyn_GetDiagnostic - Retrieve a specific diagnostic
; RCX = index (0-based)
; RDX = pointer to MICRO_DIAGNOSTIC structure to fill
; Returns: RAX = 1 (found), 0 (not found)
; ==============================================================================
MicroRoslyn_GetDiagnostic PROC FRAME
    .ENDPROLOG
    push rsi
    push rdi
    
    mov eax, MicroDiagCount
    cmp ecx, eax
    jge GetDiag_NotFound
    
    imul rcx, rcx, SIZEOF MICRO_DIAGNOSTIC
    lea rsi, MicroDiagnostics
    add rsi, rcx
    mov rdi, rdx
    
    mov rcx, SIZEOF MICRO_DIAGNOSTIC
    rep movsb
    
    mov rax, 1
    jmp GetDiag_Exit
    
GetDiag_NotFound:
    xor rax, rax
    
GetDiag_Exit:
    pop rdi
    pop rsi
    ret
MicroRoslyn_GetDiagnostic ENDP

END
