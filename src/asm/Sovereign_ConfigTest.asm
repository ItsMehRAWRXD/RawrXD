; =====================================================================================
; SOVEREIGN ENGINE - CONFIGURATION INTEGRATION TEST
; SUBSYSTEM: END-TO-END PIPELINE VALIDATION
; ARCHITECTURE: X86-64 (MASM64)
; =====================================================================================

; External API Imports
EXTERN Sovereign_Lexer_Init : PROC
EXTERN Sovereign_Config_Init : PROC
EXTERN Sovereign_Config_Parse_All : PROC
EXTERN Sovereign_Config_Get : PROC
EXTERN Sovereign_Hash_Key : PROC

; Structures (matching the pipeline contract)
SOVEREIGN_LEXER STRUCT
    SourceBase      QWORD ?
    SourceLength    QWORD ?
    Cursor          QWORD ?
    LineNumber      QWORD ?
    LastTokenType   QWORD ?
SOVEREIGN_LEXER ENDS

SOVEREIGN_CONFIG_STORE STRUCT
    BucketCount     QWORD ?
    BucketMask      QWORD ?
    Buckets         QWORD ?
    ArenaBase       QWORD ?
    ArenaOffset     QWORD ?
    ArenaSize       QWORD ?
SOVEREIGN_CONFIG_STORE ENDS

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

.DATA
    ; Test Configuration Data
    ALIGN 16
    TEST_CONFIG_DATA DB 'gpu_enabled = true', 0Ah
                    DB 'max_tokens = 8192', 0Ah
                    DB 'model_path = "D:\Models\codestral.gguf"', 0Ah
                    DB 'invalid_line $$$ @@@', 0Ah ; This should cause a parse error if not skipped
    TEST_CONFIG_LEN  EQU $ - TEST_CONFIG_DATA

    ; Keys for lookup validation
    KEY_GPU_ENABLED  DB "gpu_enabled", 0
    LEN_GPU_ENABLED  EQU $ - KEY_GPU_ENABLED - 1
    
    KEY_MAX_TOKENS   DB "max_tokens", 0
    LEN_MAX_TOKENS   EQU $ - KEY_MAX_TOKENS - 1
    
    KEY_MODEL_PATH   DB "model_path", 0
    LEN_MODEL_PATH   EQU $ - KEY_MODEL_PATH - 1

    ; Allocation areas
    ALIGN 16
    CONFIG_ARENA    DB 65536 DUP(0)  ; 64KB Arena
    
    ; Components
    STORE_STATE     SOVEREIGN_CONFIG_STORE <>
    LEXER_STATE     SOVEREIGN_LEXER <>

.CODE

; = :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; MAIN ENTRY POINT: CONFIG_STRESS_TEST
; RETURN: RAX = Bitmask of pass/fail (0 = success)
; :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
main PROC
    sub rsp, 40                     ; Shadow space + alignment

    ; 1. Initialize Configuration Store
    lea rcx, STORE_STATE
    lea rdx, CONFIG_ARENA
    mov r8, 65536                   ; Arena size
    mov r9, 256                     ; 256 Hash Buckets
    call Sovereign_Config_Init

    ; 2. Initialize Lexer with Test Data
    lea rcx, LEXER_STATE
    lea rdx, TEST_CONFIG_DATA
    mov r8, TEST_CONFIG_LEN
    call Sovereign_Lexer_Init

    ; 3. Run Parser (This calls Sovereign_Lexer_Next_Token internally)
    lea rcx, LEXER_STATE
    lea rdx, STORE_STATE
    call Sovereign_Config_Parse_All
    
    ; NOTE: We expect RAX = -1 here because of the 'invalid_line' intentionally planted.
    ; If it returned 0, the error checking is not strict enough.
    cmp rax, -1
    jne fail_parse_strictness

    ; 4. Validate Booleans (gpu_enabled = true)
    lea rcx, STORE_STATE
    lea rdx, KEY_GPU_ENABLED
    mov r8, LEN_GPU_ENABLED
    call Sovereign_Config_Get
    test rax, rax
    jz fail_bool_lookup
    cmp qword ptr [rax + SOVEREIGN_CONFIG_ENTRY.ValueInt], 1
    jne fail_bool_value

    ; 5. Validate Integers (max_tokens = 8192)
    lea rcx, STORE_STATE
    lea rdx, KEY_MAX_TOKENS
    mov r8, LEN_MAX_TOKENS
    call Sovereign_Config_Get
    test rax, rax
    jz fail_int_lookup
    cmp qword ptr [rax + SOVEREIGN_CONFIG_ENTRY.ValueInt], 8192
    jne fail_int_value

    ; 6. Validate Strings (model_path = "...")
    lea rcx, STORE_STATE
    lea rdx, KEY_MODEL_PATH
    mov r8, LEN_MODEL_PATH
    call Sovereign_Config_Get
    test rax, rax
    jz fail_string_lookup
    ; Check length of the string value (24 chars)
    cmp qword ptr [rax + SOVEREIGN_CONFIG_ENTRY.ValueLen], 24
    jne fail_string_len

    ; Success return
    xor rax, rax
    jmp exit_main

fail_parse_strictness:
    mov rax, 1
    jmp exit_main

fail_bool_lookup:
    mov rax, 2
    jmp exit_main

fail_bool_value:
    mov rax, 3
    jmp exit_main

fail_int_lookup:
    mov rax, 4
    jmp exit_main

fail_int_value:
    mov rax, 5
    jmp exit_main

fail_string_lookup:
    mov rax, 6
    jmp exit_main

fail_string_len:
    mov rax, 7
    jmp exit_main

exit_main:
    add rsp, 40
    ret
main ENDP

END
