; =============================================================================
; syntax_highlight.asm - Syntax Highlighter Implementation
; =============================================================================
; High-performance MASM syntax highlighter using table-driven DFA.
; Uses parallel token table (not in GapBuffer) for O(1) lookup during paint.
;
; Architecture:
;   - Token Table: Dense array of (StartOffset, Length, TokenType)
;   - Keyword Tables: Pre-computed hash tables for O(1) keyword lookup
;   - DFA Scanner: State machine for tokenization
;   - Line-based: Each line has its own token array
;
; Version: 1.0
; Date: 2026-06-18
; =============================================================================

option casemap:none

; Include interface definitions
include plugin_iface.inc

; =============================================================================
; Constants
; =============================================================================

; Maximum tokens per line
MAX_TOKENS_PER_LINE     EQU 256

; Maximum keyword length
MAX_KEYWORD_LEN         EQU 32

; Keyword hash table size (prime for better distribution)
KEYWORD_HASH_SIZE       EQU 257

; Initial line table capacity
INITIAL_LINE_CAPACITY   EQU 1024

; =============================================================================
; Data Structures
; =============================================================================

; Line token array (stores tokens for a single line)
LINE_TOKENS STRUCT
    pTokens         QWORD ?         ; Pointer to TOKEN_ENTRY array
    tokenCount     DWORD ?          ; Number of tokens
    capacity       DWORD ?          ; Capacity of token array
    _reserved      DWORD ?          ; Padding
LINE_TOKENS ENDS

; Keyword entry for hash table
KEYWORD_ENTRY STRUCT
    pKeyword        QWORD ?         ; Pointer to keyword string (WCHAR*)
    keywordLen      DWORD ?         ; Keyword length
    tokenType       BYTE ?          ; TOKEN_* type
    _reserved       BYTE 3 dup(?)
    pNext           QWORD ?         ; Next in hash chain (for collisions)
KEYWORD_ENTRY ENDS

; Syntax highlighter state
SYNTAX_STATE STRUCT
    ; Line table (array of LINE_TOKENS)
    pLineTable      QWORD ?         ; LINE_TOKENS* array
    lineCount       DWORD ?         ; Current line count
    lineCapacity    DWORD ?         ; Line table capacity
    
    ; Keyword hash tables
    pOpcodeTable    QWORD ?         ; Hash table for opcodes
    pRegisterTable  QWORD ?         ; Hash table for registers
    pDirectiveTable QWORD ?        ; Hash table for directives
    
    ; Statistics
    totalTokens     QWORD ?         ; Total tokens scanned
    linesScanned    QWORD ?         ; Lines processed
    
    ; Initialization flag
    initialized     DWORD ?         ; TRUE if initialized
    _reserved       DWORD ?
SYNTAX_STATE ENDS

; =============================================================================
; .data Section - Static Data
; =============================================================================

.data

; Global state
g_SyntaxState    SYNTAX_STATE <>
g_bInitialized   DWORD FALSE

; =============================================================================
; Keyword Strings (defined BEFORE label arrays that reference them)
; =============================================================================

; Opcode strings
sz_mov           BYTE "mov", 0
sz_add           BYTE "add", 0
sz_sub           BYTE "sub", 0
sz_mul           BYTE "mul", 0
sz_div           BYTE "div", 0
sz_xor           BYTE "xor", 0
sz_and           BYTE "and", 0
sz_or            BYTE "or", 0
sz_not           BYTE "not", 0
sz_neg           BYTE "neg", 0
sz_inc           BYTE "inc", 0
sz_dec           BYTE "dec", 0
sz_cmp           BYTE "cmp", 0
sz_test          BYTE "test", 0
sz_jmp           BYTE "jmp", 0
sz_je            BYTE "je", 0
sz_jne           BYTE "jne", 0
sz_jz            BYTE "jz", 0
sz_jnz           BYTE "jnz", 0
sz_jg            BYTE "jg", 0
sz_jl            BYTE "jl", 0
sz_jge           BYTE "jge", 0
sz_jle           BYTE "jle", 0
sz_ja            BYTE "ja", 0
sz_jb            BYTE "jb", 0
sz_jae           BYTE "jae", 0
sz_jbe           BYTE "jbe", 0
sz_call          BYTE "call", 0
sz_ret           BYTE "ret", 0
sz_push          BYTE "push", 0
sz_pop           BYTE "pop", 0
sz_lea           BYTE "lea", 0
sz_nop           BYTE "nop", 0
sz_int           BYTE "int", 0
sz_syscall       BYTE "syscall", 0
sz_cpuid         BYTE "cpuid", 0
sz_lfence        BYTE "lfence", 0
sz_mfence        BYTE "mfence", 0
sz_sfence        BYTE "sfence", 0
sz_pause         BYTE "pause", 0

; Register strings
sz_rax           BYTE "rax", 0
sz_rbx           BYTE "rbx", 0
sz_rcx           BYTE "rcx", 0
sz_rdx           BYTE "rdx", 0
sz_rsi           BYTE "rsi", 0
sz_rdi           BYTE "rdi", 0
sz_rsp           BYTE "rsp", 0
sz_rbp           BYTE "rbp", 0
sz_r8            BYTE "r8", 0
sz_r9            BYTE "r9", 0
sz_r10           BYTE "r10", 0
sz_r11           BYTE "r11", 0
sz_r12           BYTE "r12", 0
sz_r13           BYTE "r13", 0
sz_r14           BYTE "r14", 0
sz_r15           BYTE "r15", 0
sz_eax           BYTE "eax", 0
sz_ebx           BYTE "ebx", 0
sz_ecx           BYTE "ecx", 0
sz_edx           BYTE "edx", 0
sz_esi           BYTE "esi", 0
sz_edi           BYTE "edi", 0
sz_esp           BYTE "esp", 0
sz_ebp           BYTE "ebp", 0
sz_ax            BYTE "ax", 0
sz_bx            BYTE "bx", 0
sz_cx            BYTE "cx", 0
sz_dx            BYTE "dx", 0
sz_si            BYTE "si", 0
sz_di            BYTE "di", 0
sz_sp            BYTE "sp", 0
sz_bp            BYTE "bp", 0
sz_al            BYTE "al", 0
sz_bl            BYTE "bl", 0
sz_cl            BYTE "cl", 0
sz_dl            BYTE "dl", 0
sz_ah            BYTE "ah", 0
sz_bh            BYTE "bh", 0
sz_ch            BYTE "ch", 0
sz_dh            BYTE "dh", 0
sz_r8d           BYTE "r8d", 0
sz_r9d           BYTE "r9d", 0
sz_r10d          BYTE "r10d", 0
sz_r11d          BYTE "r11d", 0
sz_r12d          BYTE "r12d", 0
sz_r13d          BYTE "r13d", 0
sz_r14d          BYTE "r14d", 0
sz_r15d          BYTE "r15d", 0
sz_r8w           BYTE "r8w", 0
sz_r9w           BYTE "r9w", 0
sz_r10w          BYTE "r10w", 0
sz_r11w          BYTE "r11w", 0
sz_r12w          BYTE "r12w", 0
sz_r13w          BYTE "r13w", 0
sz_r14w          BYTE "r14w", 0
sz_r15w          BYTE "r15w", 0
sz_r8b           BYTE "r8b", 0
sz_r9b           BYTE "r9b", 0
sz_r10b          BYTE "r10b", 0
sz_r11b          BYTE "r11b", 0
sz_r12b          BYTE "r12b", 0
sz_r13b          BYTE "r13b", 0
sz_r14b          BYTE "r14b", 0
sz_r15b          BYTE "r15b", 0
sz_rip           BYTE "rip", 0
sz_rflags        BYTE "rflags", 0

; Directive strings
sz_code          BYTE ".code", 0
sz_data          BYTE ".data", 0
sz_stack         BYTE ".stack", 0
sz_const         BYTE ".const", 0
sz_model         BYTE ".model", 0
sz_486           BYTE ".486", 0
sz_586           BYTE ".586", 0
sz_686           BYTE ".686", 0
sz_mmx           BYTE ".mmx", 0
sz_xmm           BYTE ".xmm", 0
sz_ymm           BYTE ".ymm", 0
sz_zmm           BYTE ".zmm", 0
sz_if            BYTE ".if", 0
sz_else          BYTE ".else", 0
sz_endif         BYTE ".endif", 0
sz_while         BYTE ".while", 0
sz_endw          BYTE ".endw", 0
sz_repeat        BYTE ".repeat", 0
sz_endr          BYTE ".endr", 0
sz_for           BYTE ".for", 0
sz_endf          BYTE ".endf", 0
sz_macro         BYTE ".macro", 0
sz_endm          BYTE ".endm", 0
sz_proc          BYTE ".proc", 0
sz_endp          BYTE ".endp", 0
sz_struct        BYTE ".struct", 0
sz_ends          BYTE ".ends", 0
sz_extern        BYTE ".extern", 0
sz_public        BYTE ".public", 0
sz_option        BYTE ".option", 0
sz_textsegment   BYTE ".textsegment", 0
sz_cref          BYTE ".cref", 0
sz_nocref        BYTE ".nocref", 0
sz_list          BYTE ".list", 0
sz_nolist        BYTE ".nolist", 0
sz_title         BYTE ".title", 0
sz_subtitle      BYTE ".subtitle", 0
sz_page          BYTE ".page", 0

; =============================================================================
; Keyword Pointer Arrays (defined AFTER strings)
; =============================================================================

; Pre-defined MASM keywords (opcodes)
g_OpcodeKeywords LABEL QWORD
    DQ OFFSET sz_mov
    DQ OFFSET sz_add
    DQ OFFSET sz_sub
    DQ OFFSET sz_mul
    DQ OFFSET sz_div
    DQ OFFSET sz_xor
    DQ OFFSET sz_and
    DQ OFFSET sz_or
    DQ OFFSET sz_not
    DQ OFFSET sz_neg
    DQ OFFSET sz_inc
    DQ OFFSET sz_dec
    DQ OFFSET sz_cmp
    DQ OFFSET sz_test
    DQ OFFSET sz_jmp
    DQ OFFSET sz_je
    DQ OFFSET sz_jne
    DQ OFFSET sz_jz
    DQ OFFSET sz_jnz
    DQ OFFSET sz_jg
    DQ OFFSET sz_jl
    DQ OFFSET sz_jge
    DQ OFFSET sz_jle
    DQ OFFSET sz_ja
    DQ OFFSET sz_jb
    DQ OFFSET sz_jae
    DQ OFFSET sz_jbe
    DQ OFFSET sz_call
    DQ OFFSET sz_ret
    DQ OFFSET sz_push
    DQ OFFSET sz_pop
    DQ OFFSET sz_lea
    DQ OFFSET sz_nop
    DQ OFFSET sz_int
    DQ OFFSET sz_syscall
    DQ OFFSET sz_cpuid
    DQ OFFSET sz_lfence
    DQ OFFSET sz_mfence
    DQ OFFSET sz_sfence
    DQ OFFSET sz_pause
    DQ 0    ; Sentinel

; Pre-defined x64 registers
g_RegisterKeywords LABEL QWORD
    DQ OFFSET sz_rax
    DQ OFFSET sz_rbx
    DQ OFFSET sz_rcx
    DQ OFFSET sz_rdx
    DQ OFFSET sz_rsi
    DQ OFFSET sz_rdi
    DQ OFFSET sz_rsp
    DQ OFFSET sz_rbp
    DQ OFFSET sz_r8
    DQ OFFSET sz_r9
    DQ OFFSET sz_r10
    DQ OFFSET sz_r11
    DQ OFFSET sz_r12
    DQ OFFSET sz_r13
    DQ OFFSET sz_r14
    DQ OFFSET sz_r15
    DQ OFFSET sz_eax
    DQ OFFSET sz_ebx
    DQ OFFSET sz_ecx
    DQ OFFSET sz_edx
    DQ OFFSET sz_esi
    DQ OFFSET sz_edi
    DQ OFFSET sz_esp
    DQ OFFSET sz_ebp
    DQ OFFSET sz_ax
    DQ OFFSET sz_bx
    DQ OFFSET sz_cx
    DQ OFFSET sz_dx
    DQ OFFSET sz_si
    DQ OFFSET sz_di
    DQ OFFSET sz_sp
    DQ OFFSET sz_bp
    DQ OFFSET sz_al
    DQ OFFSET sz_bl
    DQ OFFSET sz_cl
    DQ OFFSET sz_dl
    DQ OFFSET sz_ah
    DQ OFFSET sz_bh
    DQ OFFSET sz_ch
    DQ OFFSET sz_dh
    DQ OFFSET sz_r8d
    DQ OFFSET sz_r9d
    DQ OFFSET sz_r10d
    DQ OFFSET sz_r11d
    DQ OFFSET sz_r12d
    DQ OFFSET sz_r13d
    DQ OFFSET sz_r14d
    DQ OFFSET sz_r15d
    DQ OFFSET sz_r8w
    DQ OFFSET sz_r9w
    DQ OFFSET sz_r10w
    DQ OFFSET sz_r11w
    DQ OFFSET sz_r12w
    DQ OFFSET sz_r13w
    DQ OFFSET sz_r14w
    DQ OFFSET sz_r15w
    DQ OFFSET sz_r8b
    DQ OFFSET sz_r9b
    DQ OFFSET sz_r10b
    DQ OFFSET sz_r11b
    DQ OFFSET sz_r12b
    DQ OFFSET sz_r13b
    DQ OFFSET sz_r14b
    DQ OFFSET sz_r15b
    DQ OFFSET sz_rip
    DQ OFFSET sz_rflags
    DQ 0    ; Sentinel

; Pre-defined MASM directives
g_DirectiveKeywords LABEL QWORD
    DQ OFFSET sz_code
    DQ OFFSET sz_data
    DQ OFFSET sz_stack
    DQ OFFSET sz_const
    DQ OFFSET sz_model
    DQ OFFSET sz_486
    DQ OFFSET sz_586
    DQ OFFSET sz_686
    DQ OFFSET sz_mmx
    DQ OFFSET sz_xmm
    DQ OFFSET sz_ymm
    DQ OFFSET sz_zmm
    DQ OFFSET sz_if
    DQ OFFSET sz_else
    DQ OFFSET sz_endif
    DQ OFFSET sz_while
    DQ OFFSET sz_endw
    DQ OFFSET sz_repeat
    DQ OFFSET sz_endr
    DQ OFFSET sz_for
    DQ OFFSET sz_endf
    DQ OFFSET sz_macro
    DQ OFFSET sz_endm
    DQ OFFSET sz_proc
    DQ OFFSET sz_endp
    DQ OFFSET sz_struct
    DQ OFFSET sz_ends
    DQ OFFSET sz_extern
    DQ OFFSET sz_public
    DQ OFFSET sz_option
    DQ OFFSET sz_textsegment
    DQ OFFSET sz_cref
    DQ OFFSET sz_nocref
    DQ OFFSET sz_list
    DQ OFFSET sz_nolist
    DQ OFFSET sz_title
    DQ OFFSET sz_subtitle
    DQ OFFSET sz_page
    DQ 0    ; Sentinel

; =============================================================================
; .code Section - Implementation
; =============================================================================

.code

; External functions
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

; -----------------------------------------------------------------------------
; Syntax_Init - Initialize the syntax highlighter
; -----------------------------------------------------------------------------
; Returns: RAX = TRUE on success, FALSE on failure
; -----------------------------------------------------------------------------
Syntax_Init PROC PUBLIC
    ; Check if already initialized
    mov eax, g_bInitialized
    test eax, eax
    jnz already_initialized
    
    ; Allocate line table
    sub rsp, 40         ; Shadow space for Win64 ABI
    call GetProcessHeap
    mov rcx, rax
    xor rdx, rdx
    mov r8, INITIAL_LINE_CAPACITY
    imul r8, SIZEOF LINE_TOKENS
    call HeapAlloc
    add rsp, 40
    test rax, rax
    jz init_failed
    
    ; Store line table pointer
    mov g_SyntaxState.pLineTable, rax
    mov g_SyntaxState.lineCapacity, INITIAL_LINE_CAPACITY
    mov g_SyntaxState.lineCount, 0
    mov g_SyntaxState.totalTokens, 0
    mov g_SyntaxState.linesScanned, 0
    
    ; Mark as initialized
    mov g_bInitialized, TRUE
    mov eax, TRUE
    ret
    
already_initialized:
    mov eax, TRUE
    ret
    
init_failed:
    xor eax, eax
    ret
Syntax_Init ENDP

; -----------------------------------------------------------------------------
; Syntax_Shutdown - Clean up syntax highlighter resources
; -----------------------------------------------------------------------------
Syntax_Shutdown PROC PUBLIC
    ; Check if initialized
    mov eax, g_bInitialized
    test eax, eax
    jz shutdown_done
    
    ; Free line table
    mov rcx, g_SyntaxState.pLineTable
    test rcx, rcx
    jz skip_line_table_free
    
    sub rsp, 40         ; Shadow space for Win64 ABI
    call GetProcessHeap
    mov rcx, rax
    xor rdx, rdx
    mov r8, g_SyntaxState.pLineTable
    call HeapFree
    add rsp, 40
    
skip_line_table_free:
    ; Reset state
    mov g_SyntaxState.pLineTable, 0
    mov g_SyntaxState.lineCount, 0
    mov g_SyntaxState.lineCapacity, 0
    mov g_SyntaxState.totalTokens, 0
    mov g_SyntaxState.linesScanned, 0
    mov g_bInitialized, FALSE
    
shutdown_done:
    ret
Syntax_Shutdown ENDP

; -----------------------------------------------------------------------------
; Syntax_ScanLine - Scan a single line and tokenize it
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = line number (DWORD)
;   RDX = pointer to line text (WCHAR*)
;   R8 = line length (DWORD)
; Returns: RAX = number of tokens found
; -----------------------------------------------------------------------------
Syntax_ScanLine PROC PUBLIC
    ; Save registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Parameters
    mov r12d, ecx        ; line number
    mov r13, rdx         ; text pointer
    mov r14d, r8d        ; text length
    
    ; Check initialization
    cmp g_bInitialized, TRUE
    jne scan_failed
    
    ; Check line bounds
    mov eax, g_SyntaxState.lineCount
    cmp r12d, eax
    jae scan_failed
    
    ; Get line token array
    mov rcx, g_SyntaxState.pLineTable
    mov eax, r12d
    imul eax, SIZEOF LINE_TOKENS
    add rcx, rax
    mov r15, rcx         ; r15 = LINE_TOKENS* for this line
    
    ; Reset token count for this line
    mov DWORD PTR [r15 + LINE_TOKENS.tokenCount], 0
    
    ; Initialize scanner state
    xor esi, esi         ; current position in text
    xor edi, edi         ; token start position
    
scan_loop:
    ; Check if we've reached end of line
    cmp esi, r14d
    jge scan_done
    
    ; Get current character
    movzx eax, WORD PTR [r13 + rsi*2]  ; WCHAR is 2 bytes
    
    ; Skip whitespace
    cmp al, ' '
    je skip_whitespace
    cmp al, 9    ; tab
    je skip_whitespace
    
    ; Check for comment (;)
    cmp al, ';'
    je scan_comment
    
    ; Check for string (")
    cmp al, '"'
    je scan_string
    
    ; Check for number
    cmp al, '0'
    jb check_identifier
    cmp al, '9'
    jbe scan_number
    
    ; Check for identifier (letter or underscore)
check_identifier:
    cmp al, 'A'
    jb check_operator
    cmp al, 'Z'
    jbe scan_identifier
    cmp al, 'a'
    jb check_operator
    cmp al, 'z'
    jbe scan_identifier
    cmp al, '_'
    je scan_identifier
    
    ; Check for operator
check_operator:
    cmp al, '+'
    je scan_operator
    cmp al, '-'
    je scan_operator
    cmp al, '*'
    je scan_operator
    cmp al, '/'
    je scan_operator
    cmp al, '['
    je scan_operator
    cmp al, ']'
    je scan_operator
    cmp al, '<'
    je scan_operator
    cmp al, '>'
    je scan_operator
    cmp al, '='
    je scan_operator
    cmp al, ','
    je scan_operator
    cmp al, ':'
    je scan_label
    
    ; Unknown token
    jmp scan_unknown
    
skip_whitespace:
    inc esi
    jmp scan_loop
    
scan_comment:
    ; Comment token: from ; to end of line
    mov edi, esi         ; token start
    mov eax, r14d        ; end of line
    sub eax, edi         ; token length
    
    ; Add token
    mov ecx, TOKEN_COMMENT
    call add_token
    jmp scan_done
    
scan_string:
    ; String token: from " to next "
    mov edi, esi         ; token start
    inc esi              ; skip opening quote
    
string_loop:
    cmp esi, r14d
    jge string_done
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, '"'
    je string_done
    inc esi
    jmp string_loop
    
string_done:
    inc esi              ; include closing quote
    mov ecx, TOKEN_STRING
    call add_token
    jmp scan_loop
    
scan_number:
    ; Number token: digits, 0x prefix, b suffix
    mov edi, esi         ; token start
    
    ; Check for hex prefix
    cmp esi, r14d
    jge number_done
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, '0'
    jne number_decimal
    inc esi
    cmp esi, r14d
    jge number_done
    movzx eax, WORD PTR [r13 + rsi*2]
    or al, 20h           ; lowercase
    cmp al, 'x'
    je number_hex
    
number_decimal:
    ; Decimal digits
    cmp esi, r14d
    jge number_done
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, '0'
    jb number_suffix
    cmp al, '9'
    ja number_suffix
    inc esi
    jmp number_decimal
    
number_hex:
    ; Hex digits
    inc esi
hex_loop:
    cmp esi, r14d
    jge number_done
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, '0'
    jb number_done
    cmp al, '9'
    jbe hex_continue
    or al, 20h
    cmp al, 'a'
    jb number_done
    cmp al, 'f'
    ja number_done
hex_continue:
    inc esi
    jmp hex_loop
    
number_suffix:
    ; Check for binary suffix
    movzx eax, WORD PTR [r13 + rsi*2]
    or al, 20h
    cmp al, 'b'
    jne number_done
    inc esi
    
number_done:
    mov ecx, TOKEN_NUMBER
    call add_token
    jmp scan_loop
    
scan_identifier:
    ; Identifier token: letters, digits, underscores
    mov edi, esi         ; token start
    
identifier_loop:
    cmp esi, r14d
    jge identifier_done
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, 'A'
    jb identifier_check_digit
    cmp al, 'Z'
    jbe identifier_continue
    cmp al, 'a'
    jb identifier_check_digit
    cmp al, 'z'
    jbe identifier_continue
    cmp al, '_'
    je identifier_continue
    
identifier_check_digit:
    cmp al, '0'
    jb identifier_done
    cmp al, '9'
    ja identifier_done
    
identifier_continue:
    inc esi
    jmp identifier_loop
    
identifier_done:
    ; Check if it's a keyword
    call classify_identifier
    call add_token
    jmp scan_loop
    
scan_operator:
    ; Operator token: single character
    mov edi, esi
    inc esi
    mov ecx, TOKEN_OPERATOR
    call add_token
    jmp scan_loop
    
scan_label:
    ; Check if next char is ':'
    mov edi, esi
    inc esi
    cmp esi, r14d
    jge scan_operator
    
    ; It's a label if followed by ':'
    movzx eax, WORD PTR [r13 + rsi*2]
    cmp al, ':'
    jne scan_operator
    
    inc esi
    mov ecx, TOKEN_LABEL
    call add_token
    jmp scan_loop
    
scan_unknown:
    ; Unknown token: single character
    mov edi, esi
    inc esi
    mov ecx, TOKEN_UNKNOWN
    call add_token
    jmp scan_loop
    
scan_done:
    ; Return token count
    mov eax, [r15 + LINE_TOKENS.tokenCount]
    jmp scan_exit
    
scan_failed:
    xor eax, eax
    
scan_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
; Helper: Add token to line token array
; Parameters:
;   EDI = start offset
;   ESI = end offset (current position)
;   ECX = token type
;   R15 = LINE_TOKENS* for this line
add_token:
    push rbx
    
    ; Calculate token length
    mov eax, esi
    sub eax, edi
    
    ; Get token array
    mov rbx, [r15 + LINE_TOKENS.pTokens]
    test rbx, rbx
    jz add_token_done
    
    ; Get current token count
    mov edx, [r15 + LINE_TOKENS.tokenCount]
    
    ; Check capacity
    cmp edx, [r15 + LINE_TOKENS.capacity]
    jae add_token_done
    
    ; Store token
    imul rdx, SIZEOF TOKEN_ENTRY
    mov [rbx + rdx + TOKEN_ENTRY.startOffset], edi
    mov [rbx + rdx + TOKEN_ENTRY.tokenLength], eax
    mov [rbx + rdx + TOKEN_ENTRY.tokenType], cl
    
    ; Increment token count
    inc edx
    mov [r15 + LINE_TOKENS.tokenCount], edx
    
    ; Update statistics
    inc g_SyntaxState.totalTokens
    
add_token_done:
    pop rbx
    ret
    
; Helper: Classify identifier as opcode, register, directive, or identifier
; Parameters:
;   R13 = text pointer
;   EDI = start offset
;   ESI = end offset
; Returns: ECX = token type
classify_identifier:
    ; TODO: Implement keyword hash table lookup
    ; For now, return TOKEN_IDENTIFIER
    mov ecx, TOKEN_IDENTIFIER
    ret
    
Syntax_ScanLine ENDP

; -----------------------------------------------------------------------------
; Syntax_ScanAll - Scan all lines in the buffer
; -----------------------------------------------------------------------------
Syntax_ScanAll PROC PUBLIC
    ; Check initialization
    cmp g_bInitialized, TRUE
    jne scanall_done
    
    ; TODO: Iterate through all lines and call Syntax_ScanLine
    
scanall_done:
    ret
Syntax_ScanAll ENDP

; -----------------------------------------------------------------------------
; Syntax_InvalidateLine - Mark a line as needing re-scan
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = line number (DWORD)
; -----------------------------------------------------------------------------
Syntax_InvalidateLine PROC PUBLIC
    ; Check initialization
    cmp g_bInitialized, TRUE
    jne invalidate_done
    
    ; Check line bounds
    mov eax, g_SyntaxState.lineCount
    cmp ecx, eax
    jae invalidate_done
    
    ; Get line token array
    mov rdx, g_SyntaxState.pLineTable
    mov eax, ecx
    imul eax, SIZEOF LINE_TOKENS
    add rdx, rax
    
    ; Reset token count (marks as invalid)
    mov DWORD PTR [rdx + LINE_TOKENS.tokenCount], 0
    
invalidate_done:
    ret
Syntax_InvalidateLine ENDP

; -----------------------------------------------------------------------------
; Syntax_GetTokenAt - Get token at specific position
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = line number (DWORD)
;   RDX = column (DWORD)
;   R8 = pointer to TOKEN_ENTRY to fill
; Returns: RAX = TRUE if found, FALSE if not
; -----------------------------------------------------------------------------
Syntax_GetTokenAt PROC PUBLIC
    ; Check initialization
    cmp g_bInitialized, TRUE
    jne gettoken_failed
    
    ; Check line bounds
    mov eax, g_SyntaxState.lineCount
    cmp ecx, eax
    jae gettoken_failed
    
    ; Get line token array
    mov rax, g_SyntaxState.pLineTable
    mov r9d, ecx
    imul r9d, SIZEOF LINE_TOKENS
    add rax, r9
    
    ; Iterate through tokens
    mov r9d, [rax + LINE_TOKENS.tokenCount]
    test r9d, r9d
    jz gettoken_failed
    
    xor r10d, r10d       ; token index
    
gettoken_loop:
    cmp r10d, r9d
    jge gettoken_failed
    
    ; Get token
    mov rcx, [rax + LINE_TOKENS.pTokens]
    mov r11d, r10d
    imul r11d, SIZEOF TOKEN_ENTRY
    add rcx, r11
    
    ; Check if column is within token range
    mov r11d, [rcx + TOKEN_ENTRY.startOffset]
    cmp edx, r11d
    jb gettoken_next
    
    mov r11d, [rcx + TOKEN_ENTRY.startOffset]
    add r11d, [rcx + TOKEN_ENTRY.tokenLength]
    cmp edx, r11d
    jae gettoken_next
    
    ; Found! Copy token to output
    mov eax, [rcx + TOKEN_ENTRY.startOffset]
    mov [r8 + TOKEN_ENTRY.startOffset], eax
    mov eax, [rcx + TOKEN_ENTRY.tokenLength]
    mov [r8 + TOKEN_ENTRY.tokenLength], eax
    mov al, [rcx + TOKEN_ENTRY.tokenType]
    mov [r8 + TOKEN_ENTRY.tokenType], al
    
    mov eax, TRUE
    ret
    
gettoken_next:
    inc r10d
    jmp gettoken_loop
    
gettoken_failed:
    xor eax, eax
    ret
Syntax_GetTokenAt ENDP

; -----------------------------------------------------------------------------
; Syntax_GetLineTokens - Get all tokens for a line
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = line number (DWORD)
;   RDX = pointer to TOKEN_ENTRY buffer
;   R8 = max count
; Returns: RAX = number of tokens copied
; -----------------------------------------------------------------------------
Syntax_GetLineTokens PROC PUBLIC
    ; Check initialization
    cmp g_bInitialized, TRUE
    jne getline_failed
    
    ; Check line bounds
    mov eax, g_SyntaxState.lineCount
    cmp ecx, eax
    jae getline_failed
    
    ; Get line token array
    mov rax, g_SyntaxState.pLineTable
    mov r9d, ecx
    imul r9d, SIZEOF LINE_TOKENS
    add rax, r9
    
    ; Get token count
    mov r9d, [rax + LINE_TOKENS.tokenCount]
    
    ; Limit to max count
    cmp r9d, r8d
    cmova r9d, r8d
    
    ; Copy tokens
    mov rcx, [rax + LINE_TOKENS.pTokens]
    test rcx, rcx
    jz getline_failed
    
    mov r8, rdx          ; destination
    mov rdx, rcx         ; source
    mov ecx, r9d         ; count
    imul ecx, SIZEOF TOKEN_ENTRY
    rep movsb
    
    ; Return count
    mov eax, r9d
    ret
    
getline_failed:
    xor eax, eax
    ret
Syntax_GetLineTokens ENDP

; -----------------------------------------------------------------------------
; Syntax_AddKeyword - Add a keyword to the hash table
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = keyword string (WCHAR*)
;   RDX = token type (BYTE)
; Returns: RAX = TRUE on success
; -----------------------------------------------------------------------------
Syntax_AddKeyword PROC PUBLIC
    ; TODO: Implement keyword hash table insertion
    mov eax, TRUE
    ret
Syntax_AddKeyword ENDP

; -----------------------------------------------------------------------------
; Syntax_LoadKeywords - Load keywords from config file
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = config file path (WCHAR*)
; Returns: RAX = TRUE on success
; -----------------------------------------------------------------------------
Syntax_LoadKeywords PROC PUBLIC
    ; TODO: Implement keyword file loading
    mov eax, TRUE
    ret
Syntax_LoadKeywords ENDP

; -----------------------------------------------------------------------------
; Syntax_GetStats - Get syntax highlighter statistics
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = pointer to totalTokens (QWORD*)
;   RDX = pointer to linesScanned (QWORD*)
; -----------------------------------------------------------------------------
Syntax_GetStats PROC PUBLIC
    ; Check pointers
    test rcx, rcx
    jz skip_total
    mov rax, g_SyntaxState.totalTokens
    mov [rcx], rax
    
skip_total:
    test rdx, rdx
    jz skip_lines
    mov rax, g_SyntaxState.linesScanned
    mov [rdx], rax
    
skip_lines:
    ret
Syntax_GetStats ENDP

; =============================================================================
; VTable Export
; =============================================================================

.data

; Static vtable initialized with function pointers
g_SyntaxVTable SYNTAX_HIGHLIGHTER_VTABLE \
    <Syntax_Init, \
     Syntax_Shutdown, \
     Syntax_ScanLine, \
     Syntax_ScanAll, \
     Syntax_InvalidateLine, \
     Syntax_GetTokenAt, \
     Syntax_GetLineTokens, \
     Syntax_AddKeyword, \
     Syntax_LoadKeywords, \
     Syntax_GetStats>

.code

; -----------------------------------------------------------------------------
; GetVTable - Returns pointer to the syntax highlighter vtable
; -----------------------------------------------------------------------------
; Returns: RAX = pointer to SYNTAX_HIGHLIGHTER_VTABLE
; -----------------------------------------------------------------------------
GetVTable PROC PUBLIC
    lea rax, g_SyntaxVTable
    ret
GetVTable ENDP

; -----------------------------------------------------------------------------
; DllMain - DLL entry point
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = hinstDLL (HMODULE)
;   RDX = fdwReason (DWORD)
;   R8 = lpvReserved (LPVOID)
; Returns: RAX = TRUE
; -----------------------------------------------------------------------------
DllMain PROC PUBLIC
    mov eax, 1
    ret
DllMain ENDP

END
