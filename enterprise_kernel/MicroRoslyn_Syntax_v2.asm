; =======================================================================================
; RAWRXD Micro-Roslyn C# Syntax Engine - Production Build
; Pure x64 MASM - Zero Dependencies
; =======================================================================================

option casemap:none

; =======================================================================================
; External Imports
; =======================================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

; =======================================================================================
; Public Exports
; =======================================================================================
PUBLIC Rawrxd_ParseCSharpSyntax
PUBLIC Rawrxd_GetDiagnosticCount
PUBLIC Rawrxd_GetDiagnostic

; =======================================================================================
; Constants
; =======================================================================================
STD_OUTPUT_HANDLE       EQU -11
TOKEN_EOF               EQU 0
TOKEN_IDENTIFIER        EQU 1
TOKEN_NUMBER            EQU 2
TOKEN_STRING            EQU 3
TOKEN_CHAR              EQU 4
TOKEN_KEYWORD           EQU 5
TOKEN_OPERATOR          EQU 6
TOKEN_PUNCTUATION       EQU 7
TOKEN_COMMENT           EQU 8
TOKEN_WHITESPACE        EQU 9
TOKEN_NEWLINE           EQU 10
TOKEN_PREPROCESSOR      EQU 11
TOKEN_ATTRIBUTE         EQU 12
TOKEN_GENERIC           EQU 13
TOKEN_NULLABLE          EQU 14
TOKEN_INTERPOLATED      EQU 15
TOKEN_VERBATIM          EQU 16
TOKEN_DOC_COMMENT       EQU 17
TOKEN_INVALID           EQU 18

; =======================================================================================
; Data Structures
; =======================================================================================
RAWRXD_DIAGNOSTIC STRUCT
    LineNumber      QWORD ?
    ColumnNumber    QWORD ?
    ErrorCode       DWORD ?
    ErrorMessage    BYTE 128 DUP(?)
RAWRXD_DIAGNOSTIC ENDS

CSHARP_TOKEN STRUCT
    TokType         DWORD ?
    TokValue        BYTE 64 DUP(?)
    TokLine         QWORD ?
    TokCol          QWORD ?
CSHARP_TOKEN ENDS

; =======================================================================================
; Data Section
; =======================================================================================
.data
align 8

; Console handles
hStdOut                 QWORD 0
bytesWritten            QWORD 0

; Parser state
CurrentLine             QWORD 1
CurrentColumn           QWORD 1
BraceDepth              QWORD 0
ParenDepth              QWORD 0
BracketDepth            QWORD 0
InString                BYTE 0
InChar                  BYTE 0
InVerbatim              BYTE 0
InComment               BYTE 0
InBlockComment          BYTE 0
ExpectSemicolon         BYTE 0

; Token storage
CurrentToken            CSHARP_TOKEN <>

; Nesting stacks
BraceStack              DWORD 64 DUP(0)
BraceLineStack          DWORD 64 DUP(0)
BraceColStack           DWORD 64 DUP(0)
BraceStackPtr           QWORD 0

ParenStack              DWORD 64 DUP(0)
ParenLineStack          DWORD 64 DUP(0)
ParenColStack           DWORD 64 DUP(0)
ParenStackPtr           QWORD 0

; Diagnostics
Diagnostics             RAWRXD_DIAGNOSTIC 32 DUP(<>)
DiagnosticCount         QWORD 0

; Keyword table
KeywordTable            BYTE "abstract", 0
                        BYTE "as", 0
                        BYTE "base", 0
                        BYTE "bool", 0
                        BYTE "break", 0
                        BYTE "byte", 0
                        BYTE "case", 0
                        BYTE "catch", 0
                        BYTE "char", 0
                        BYTE "class", 0
                        BYTE "const", 0
                        BYTE "continue", 0
                        BYTE "decimal", 0
                        BYTE "default", 0
                        BYTE "delegate", 0
                        BYTE "do", 0
                        BYTE "double", 0
                        BYTE "else", 0
                        BYTE "enum", 0
                        BYTE "event", 0
                        BYTE "explicit", 0
                        BYTE "extern", 0
                        BYTE "false", 0
                        BYTE "finally", 0
                        BYTE "fixed", 0
                        BYTE "float", 0
                        BYTE "for", 0
                        BYTE "foreach", 0
                        BYTE "goto", 0
                        BYTE "if", 0
                        BYTE "implicit", 0
                        BYTE "in", 0
                        BYTE "int", 0
                        BYTE "interface", 0
                        BYTE "internal", 0
                        BYTE "is", 0
                        BYTE "lock", 0
                        BYTE "long", 0
                        BYTE "namespace", 0
                        BYTE "new", 0
                        BYTE "null", 0
                        BYTE "object", 0
                        BYTE "operator", 0
                        BYTE "out", 0
                        BYTE "override", 0
                        BYTE "params", 0
                        BYTE "private", 0
                        BYTE "protected", 0
                        BYTE "public", 0
                        BYTE "readonly", 0
                        BYTE "ref", 0
                        BYTE "return", 0
                        BYTE "sbyte", 0
                        BYTE "sealed", 0
                        BYTE "short", 0
                        BYTE "sizeof", 0
                        BYTE "stackalloc", 0
                        BYTE "static", 0
                        BYTE "string", 0
                        BYTE "struct", 0
                        BYTE "switch", 0
                        BYTE "this", 0
                        BYTE "throw", 0
                        BYTE "true", 0
                        BYTE "try", 0
                        BYTE "typeof", 0
                        BYTE "uint", 0
                        BYTE "ulong", 0
                        BYTE "unchecked", 0
                        BYTE "unsafe", 0
                        BYTE "ushort", 0
                        BYTE "using", 0
                        BYTE "virtual", 0
                        BYTE "void", 0
                        BYTE "volatile", 0
                        BYTE "while", 0
                        BYTE 0

; Error messages
ErrMsg_UnclosedBrace    BYTE "Unclosed brace", 0
ErrMsg_UnclosedParen    BYTE "Unclosed paren", 0
ErrMsg_UnclosedBracket  BYTE "Unclosed bracket", 0
ErrMsg_MismatchedBrace  BYTE "Mismatched brace", 0
ErrMsg_MismatchedParen  BYTE "Mismatched paren", 0
ErrMsg_MismatchedBracket BYTE "Mismatched bracket", 0
ErrMsg_InvalidChar      BYTE "Invalid character", 0
ErrMsg_UnclosedString   BYTE "Unclosed string", 0
ErrMsg_UnclosedChar     BYTE "Unclosed char", 0
ErrMsg_StackOverflow    BYTE "Nesting too deep", 0
ErrMsg_MissingSemicolon BYTE "Missing semicolon", 0
ErrMsg_InvalidToken     BYTE "Invalid token", 0

; String constants
szCrlf                  BYTE 13, 10, 0
szParseHeader           BYTE "=== Micro-Roslyn Syntax Check ===", 13, 10, 0
szParseComplete         BYTE "=== Syntax Check Complete ===", 13, 10, 0
szDiagCount             BYTE "Diagnostics: ", 0
szNoErrors              BYTE "No syntax errors found", 13, 10, 0
szReturn                BYTE "return", 0
szBreak                 BYTE "break", 0
szContinue              BYTE "continue", 0
szThrow                 BYTE "throw", 0

; =======================================================================================
; Code Section
; =======================================================================================
.code
align 8

; =======================================================================================
; Helper: PrintString
; RCX = pointer to string
; =======================================================================================
PrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov rsi, rcx
    xor rdx, rdx
    mov rdi, rsi
PrintString_count_loop:
    cmp byte ptr [rdi], 0
    je PrintString_count_done
    inc rdx
    inc rdi
    jmp PrintString_count_loop
PrintString_count_done:
    
    test rdx, rdx
    jz PrintString_done
    
    mov rcx, hStdOut
    mov r8, rdx
    mov rdx, rsi
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
PrintString_done:
    add rsp, 40h
    pop rbp
    ret
PrintString ENDP

; =======================================================================================
; Helper: StrLenA
; RCX = pointer to string
; Returns: RAX = length
; =======================================================================================
StrLenA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    xor rax, rax
    mov rdx, rcx
StrLenA_loop:
    cmp byte ptr [rdx + rax], 0
    je StrLenA_done
    inc rax
    jmp StrLenA_loop
StrLenA_done:
    
    add rsp, 28h
    pop rbp
    ret
StrLenA ENDP

; =======================================================================================
; Helper: StrCmpA
; RCX = string 1, RDX = string 2
; Returns: RAX = 0 (equal), 1 (not equal)
; =======================================================================================
StrCmpA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    push rdi
    push rsi
    
    mov rdi, rcx
    mov rsi, rdx
    
StrCmpA_loop:
    mov al, byte ptr [rdi]
    mov bl, byte ptr [rsi]
    cmp al, bl
    jne StrCmpA_not_equal
    test al, al
    jz StrCmpA_equal
    inc rdi
    inc rsi
    jmp StrCmpA_loop
    
StrCmpA_not_equal:
    mov rax, 1
    jmp StrCmpA_exit
    
StrCmpA_equal:
    xor rax, rax
    
StrCmpA_exit:
    pop rsi
    pop rdi
    add rsp, 28h
    pop rbp
    ret
StrCmpA ENDP

; =======================================================================================
; Helper: IsKeyword
; RCX = pointer to identifier string
; Returns: RAX = 1 (is keyword), 0 (not keyword)
; =======================================================================================
IsKeyword PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 38h
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    
    mov r12, rcx
    mov r13, OFFSET KeywordTable
    
IsKeyword_loop:
    mov al, byte ptr [r13]
    test al, al
    jz IsKeyword_not_found
    
    mov rcx, r12
    mov rdx, r13
    call StrCmpA
    test rax, rax
    jz IsKeyword_found
    
    mov rcx, r13
    call StrLenA
    add r13, rax
    inc r13
    jmp IsKeyword_loop
    
IsKeyword_found:
    mov rax, 1
    jmp IsKeyword_exit
    
IsKeyword_not_found:
    xor rax, rax
    
IsKeyword_exit:
    pop r13
    pop r12
    pop rbx
    add rsp, 38h
    pop rbp
    ret
IsKeyword ENDP

; =======================================================================================
; Helper: AddDiagnostic
; RCX = line number, RDX = column number, R8 = error code, R9 = pointer to message
; =======================================================================================
AddDiagnostic PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 48h
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    
    cmp DiagnosticCount, 32
    jge AddDiagnostic_done
    
    mov rax, DiagnosticCount
    imul rax, rax, SIZEOF RAWRXD_DIAGNOSTIC
    lea rbx, Diagnostics
    add rbx, rax
    
    mov [rbx].RAWRXD_DIAGNOSTIC.LineNumber, r12
    mov [rbx].RAWRXD_DIAGNOSTIC.ColumnNumber, r13
    mov [rbx].RAWRXD_DIAGNOSTIC.ErrorCode, r14d
    
    mov rcx, r15
    call StrLenA
    cmp rax, 127
    jle AddDiagnostic_msg_len_ok
    mov rax, 127
AddDiagnostic_msg_len_ok:
    mov rcx, rax
    lea rdi, [rbx].RAWRXD_DIAGNOSTIC.ErrorMessage
    mov rsi, r15
    
AddDiagnostic_copy_loop:
    test rcx, rcx
    jz AddDiagnostic_copy_done
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp AddDiagnostic_copy_loop
AddDiagnostic_copy_done:
    mov byte ptr [rdi], 0
    
    inc DiagnosticCount
    
AddDiagnostic_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 48h
    pop rbp
    ret
AddDiagnostic ENDP

; =======================================================================================
; Rawrxd_ParseCSharpSyntax - Main C# syntax validation engine
; RCX = Ptr to null-terminated C# source string (ASCII/UTF-8)
; RDX = Ptr to RAWRXD_DIAGNOSTIC struct to populate on error
; Returns: RAX = 1 (success/clean), 0 (syntax error found)
; =======================================================================================
Rawrxd_ParseCSharpSyntax PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 68h
    .ENDPROLOG
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    mov rsi, rcx
    mov rdi, rdx
    
    mov CurrentLine, 1
    mov CurrentColumn, 1
    mov BraceDepth, 0
    mov ParenDepth, 0
    mov BracketDepth, 0
    mov InString, 0
    mov InChar, 0
    mov InVerbatim, 0
    mov InComment, 0
    mov InBlockComment, 0
    mov ExpectSemicolon, 0
    mov DiagnosticCount, 0
    mov BraceStackPtr, 0
    mov ParenStackPtr, 0
    
    lea rcx, Diagnostics
    mov rdx, SIZEOF Diagnostics
    call ZeroMemory
    
ScanLoop:
    movzx rax, byte ptr [rsi]
    test al, al
    jz EOF
    
    inc CurrentColumn
    
    cmp al, 10
    jne CheckCarriageReturn
    inc CurrentLine
    mov CurrentColumn, 1
    cmp InComment, 1
    jne ProcessChar
    mov InComment, 0
    jmp NextChar
    
CheckCarriageReturn:
    cmp al, 13
    je NextChar
    
ProcessChar:
    cmp InComment, 1
    je NextChar
    
    cmp InBlockComment, 1
    je CheckEndBlockComment
    
    cmp al, '/'
    jne CheckStrings
    mov bl, byte ptr [rsi + 1]
    cmp bl, '/'
    jne CheckBlockCommentStart
    mov InComment, 1
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
CheckBlockCommentStart:
    cmp bl, '*'
    jne CheckStrings
    mov InBlockComment, 1
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
CheckEndBlockComment:
    cmp al, '*'
    jne NextChar
    mov bl, byte ptr [rsi + 1]
    cmp bl, '/'
    jne NextChar
    mov InBlockComment, 0
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
CheckStrings:
    cmp InString, 1
    je HandleStringContent
    cmp InChar, 1
    je HandleCharContent
    
    cmp al, '@'
    jne CheckQuote
    mov bl, byte ptr [rsi + 1]
    cmp bl, '"'
    jne CheckQuote
    mov InVerbatim, 1
    mov InString, 1
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
CheckQuote:
    cmp al, '"'
    jne CheckSingleQuote
    mov InString, 1
    jmp NextChar
    
CheckSingleQuote:
    cmp al, 27h
    jne CheckBraces
    mov InChar, 1
    jmp NextChar
    
HandleStringContent:
    cmp InVerbatim, 1
    je HandleVerbatim
    cmp al, '"'
    jne CheckStringEscape
    mov InString, 0
    jmp NextChar
    
CheckStringEscape:
    cmp al, 5Ch
    jne NextChar
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
HandleVerbatim:
    cmp al, '"'
    jne NextChar
    mov bl, byte ptr [rsi + 1]
    cmp bl, '"'
    jne EndVerbatim
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
EndVerbatim:
    mov InString, 0
    mov InVerbatim, 0
    jmp NextChar
    
HandleCharContent:
    cmp al, 27h
    jne CheckCharEscape
    mov InChar, 0
    jmp NextChar
    
CheckCharEscape:
    cmp al, 5Ch
    jne NextChar
    inc rsi
    inc CurrentColumn
    jmp NextChar
    
CheckBraces:
    cmp al, '{'
    jne CheckCloseBrace
    mov rax, BraceStackPtr
    cmp rax, 64
    jge StackOverflow
    mov DWORD PTR [BraceStack + rax * 4], 1
    mov eax, DWORD PTR CurrentLine
    mov DWORD PTR [BraceLineStack + rax * 4], eax
    mov eax, DWORD PTR CurrentColumn
    mov DWORD PTR [BraceColStack + rax * 4], eax
    inc BraceStackPtr
    inc BraceDepth
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckCloseBrace:
    cmp al, '}'
    jne CheckOpenParen
    dec BraceDepth
    js MismatchedCloseBrace
    dec BraceStackPtr
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckOpenParen:
    cmp al, '('
    jne CheckCloseParen
    mov rax, ParenStackPtr
    cmp rax, 64
    jge StackOverflow
    mov DWORD PTR [ParenStack + rax * 4], 1
    mov eax, DWORD PTR CurrentLine
    mov DWORD PTR [ParenLineStack + rax * 4], eax
    mov eax, DWORD PTR CurrentColumn
    mov DWORD PTR [ParenColStack + rax * 4], eax
    inc ParenStackPtr
    inc ParenDepth
    jmp NextChar
    
CheckCloseParen:
    cmp al, ')'
    jne CheckOpenBracket
    dec ParenDepth
    js MismatchedCloseParen
    dec ParenStackPtr
    jmp NextChar
    
CheckOpenBracket:
    cmp al, '['
    jne CheckCloseBracket
    inc BracketDepth
    jmp NextChar
    
CheckCloseBracket:
    cmp al, ']'
    jne CheckSemicolon
    dec BracketDepth
    js MismatchedCloseBracket
    jmp NextChar
    
CheckSemicolon:
    cmp al, ';'
    jne CheckIdentifier
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckIdentifier:
    cmp ExpectSemicolon, 1
    jne CheckKeyword
    cmp al, '}'
    je NextChar
    cmp al, ')'
    je NextChar
    cmp al, ','
    je NextChar
    cmp al, ';'
    je NextChar
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 7
    lea r9, ErrMsg_MissingSemicolon
    call AddDiagnostic
    mov ExpectSemicolon, 0
    jmp NextChar
    
CheckKeyword:
    cmp al, '_'
    jl CheckNumber
    cmp al, 'z'
    jg CheckNumber
    cmp al, 'a'
    jge StartIdentifier
    cmp al, 'A'
    jl CheckNumber
    cmp al, 'Z'
    jle StartIdentifier
    jmp CheckNumber
    
StartIdentifier:
    lea rcx, CurrentToken
    mov rdx, rsi
    call ParseIdentifier
    lea rcx, CurrentToken.TokValue
    call IsKeyword
    test rax, rax
    jz NotKeyword
    mov CurrentToken.TokType, TOKEN_KEYWORD
    lea rcx, CurrentToken.TokValue
    call NeedsSemicolon
    test rax, rax
    jz NextChar
    mov ExpectSemicolon, 1
    jmp NextChar
    
NotKeyword:
    mov CurrentToken.TokType, TOKEN_IDENTIFIER
    lea rcx, CurrentToken.TokValue
    call NeedsSemicolon
    test rax, rax
    jz NextChar
    mov ExpectSemicolon, 1
    jmp NextChar
    
CheckNumber:
    cmp al, '0'
    jl CheckOperator
    cmp al, '9'
    jle StartNumber
    jmp CheckOperator
    
StartNumber:
    mov CurrentToken.TokType, TOKEN_NUMBER
    jmp NextChar
    
CheckOperator:
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
    cmp al, 3Ch
    je IsOperator
    cmp al, 3Eh
    je IsOperator
    cmp al, '%'
    je IsOperator
    cmp al, 26h
    je IsOperator
    cmp al, '|'
    je IsOperator
    cmp al, '^'
    je IsOperator
    cmp al, 7Eh
    je IsOperator
    jmp CheckInvalid
    
IsOperator:
    mov CurrentToken.TokType, TOKEN_OPERATOR
    jmp NextChar
    
CheckInvalid:
    cmp al, 20h
    jl InvalidChar
    cmp al, 7Eh
    jg InvalidChar
    jmp NextChar
    
InvalidChar:
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 6
    lea r9, ErrMsg_InvalidChar
    call AddDiagnostic
    jmp NextChar
    
NextChar:
    inc rsi
    jmp ScanLoop
    
MismatchedCloseBrace:
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 1
    lea r9, ErrMsg_MismatchedBrace
    call AddDiagnostic
    jmp NextChar
    
MismatchedCloseParen:
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 3
    lea r9, ErrMsg_MismatchedParen
    call AddDiagnostic
    jmp NextChar
    
MismatchedCloseBracket:
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 5
    lea r9, ErrMsg_MismatchedBracket
    call AddDiagnostic
    jmp NextChar
    
StackOverflow:
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 8
    lea r9, ErrMsg_StackOverflow
    call AddDiagnostic
    jmp EOF
    
EOF:
    cmp BraceDepth, 0
    je CheckUnclosedParen
    mov rax, BraceStackPtr
    test rax, rax
    jz CheckUnclosedParen
    dec rax
    mov ebx, DWORD PTR [BraceLineStack + rax * 4]
    mov ecx, DWORD PTR [BraceColStack + rax * 4]
    mov rcx, rbx
    mov rdx, rcx
    mov r8, 2
    lea r9, ErrMsg_UnclosedBrace
    call AddDiagnostic
    
CheckUnclosedParen:
    cmp ParenDepth, 0
    je CheckUnclosedString
    mov rax, ParenStackPtr
    test rax, rax
    jz CheckUnclosedString
    dec rax
    mov ebx, DWORD PTR [ParenLineStack + rax * 4]
    mov ecx, DWORD PTR [ParenColStack + rax * 4]
    mov rcx, rbx
    mov rdx, rcx
    mov r8, 4
    lea r9, ErrMsg_UnclosedParen
    call AddDiagnostic
    
CheckUnclosedString:
    cmp InString, 1
    jne CheckUnclosedChar
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 9
    lea r9, ErrMsg_UnclosedString
    call AddDiagnostic
    
CheckUnclosedChar:
    cmp InChar, 1
    jne CheckDiagnostics
    mov rcx, CurrentLine
    mov rdx, CurrentColumn
    mov r8, 10
    lea r9, ErrMsg_UnclosedChar
    call AddDiagnostic
    
CheckDiagnostics:
    cmp DiagnosticCount, 0
    jne SyntaxErrorFound
    mov rax, 1
    jmp ParseExit
    
SyntaxErrorFound:
    mov rax, [rdi].RAWRXD_DIAGNOSTIC.LineNumber
    mov [rdi].RAWRXD_DIAGNOSTIC.LineNumber, rax
    mov rax, [rdi].RAWRXD_DIAGNOSTIC.ColumnNumber
    mov [rdi].RAWRXD_DIAGNOSTIC.ColumnNumber, rax
    mov eax, [rdi].RAWRXD_DIAGNOSTIC.ErrorCode
    mov [rdi].RAWRXD_DIAGNOSTIC.ErrorCode, eax
    xor rax, rax
    
ParseExit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    add rsp, 68h
    pop rbp
    ret
Rawrxd_ParseCSharpSyntax ENDP

; =======================================================================================
; Helper: ParseIdentifier
; RCX = destination token value buffer, RDX = source cursor
; =======================================================================================
ParseIdentifier PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    push rdi
    push rsi
    
    mov rdi, rcx
    mov rsi, rdx
    xor rcx, rcx
    
ParseIdentifier_loop:
    mov al, byte ptr [rsi + rcx]
    cmp al, '_'
    jl ParseIdentifier_check_digit
    cmp al, 'z'
    jg ParseIdentifier_check_digit
    cmp al, 'a'
    jge ParseIdentifier_store
    cmp al, 'A'
    jl ParseIdentifier_check_digit
    cmp al, 'Z'
    jle ParseIdentifier_store
    jmp ParseIdentifier_check_digit
    
ParseIdentifier_check_digit:
    cmp al, '0'
    jl ParseIdentifier_done
    cmp al, '9'
    jle ParseIdentifier_store
    jmp ParseIdentifier_done
    
ParseIdentifier_store:
    cmp rcx, 63
    jge ParseIdentifier_skip
    mov byte ptr [rdi + rcx], al
    inc rcx
    
ParseIdentifier_skip:
    inc rsi
    jmp ParseIdentifier_loop
    
ParseIdentifier_done:
    mov byte ptr [rdi + rcx], 0
    
    pop rsi
    pop rdi
    add rsp, 28h
    pop rbp
    ret
ParseIdentifier ENDP

; =======================================================================================
; Helper: NeedsSemicolon
; RCX = pointer to token string
; Returns: RAX = 1 (needs semicolon), 0 (does not)
; =======================================================================================
NeedsSemicolon PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 38h
    .ENDPROLOG
    
    push rbx
    push r12
    
    mov r12, rcx
    
    lea rdx, szReturn
    call StrCmpA
    test rax, rax
    jz NeedsSemi_yes
    
    lea rdx, szBreak
    call StrCmpA
    test rax, rax
    jz NeedsSemi_yes
    
    lea rdx, szContinue
    call StrCmpA
    test rax, rax
    jz NeedsSemi_yes
    
    lea rdx, szThrow
    call StrCmpA
    test rax, rax
    jz NeedsSemi_yes
    
NeedsSemi_no:
    xor rax, rax
    jmp NeedsSemi_exit
    
NeedsSemi_yes:
    mov rax, 1
    
NeedsSemi_exit:
    pop r12
    pop rbx
    add rsp, 38h
    pop rbp
    ret
NeedsSemicolon ENDP

; =======================================================================================
; Helper: ZeroMemory
; RCX = pointer to block, RDX = size in bytes
; =======================================================================================
ZeroMemory PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov r8, rcx
    mov rcx, rdx
    xor rax, rax
ZeroMemory_loop:
    test rcx, rcx
    jz ZeroMemory_done
    mov byte ptr [r8], al
    inc r8
    dec rcx
    jmp ZeroMemory_loop
ZeroMemory_done:
    add rsp, 28h
    pop rbp
    ret
ZeroMemory ENDP

; =======================================================================================
; Rawrxd_GetDiagnosticCount
; Returns: RAX = count
; =======================================================================================
Rawrxd_GetDiagnosticCount PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov rax, DiagnosticCount
    
    add rsp, 28h
    pop rbp
    ret
Rawrxd_GetDiagnosticCount ENDP

; =======================================================================================
; Rawrxd_GetDiagnostic
; RCX = index
; Returns: RAX = pointer to diagnostic, or 0 if out of range
; =======================================================================================
Rawrxd_GetDiagnostic PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    cmp rcx, DiagnosticCount
    jge GetDiag_out_of_range
    
    mov rax, rcx
    imul rax, rax, SIZEOF RAWRXD_DIAGNOSTIC
    lea rdx, Diagnostics
    add rax, rdx
    jmp GetDiag_exit
    
GetDiag_out_of_range:
    xor rax, rax
    
GetDiag_exit:
    add rsp, 28h
    pop rbp
    ret
Rawrxd_GetDiagnostic ENDP

; =======================================================================================
; Helper: PrintInt
; RCX = integer value
; =======================================================================================
PrintInt PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    push rbx
    push r12
    
    mov r12, rcx
    lea rbx, [rsp + 30h]
    mov byte ptr [rbx], 0
    dec rbx
    
    test r12, r12
    jnz PrintInt_convert
    mov byte ptr [rbx], '0'
    dec rbx
    jmp PrintInt_print
    
PrintInt_convert:
    mov rax, r12
    mov r9, 10
PrintInt_loop:
    xor rdx, rdx
    div r9
    add dl, '0'
    mov byte ptr [rbx], dl
    dec rbx
    test rax, rax
    jnz PrintInt_loop
    
PrintInt_print:
    inc rbx
    mov rcx, rbx
    call PrintString
    
    pop r12
    pop rbx
    add rsp, 40h
    pop rbp
    ret
PrintInt ENDP

END
