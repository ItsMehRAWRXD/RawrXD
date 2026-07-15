; =============================================================================
; RawrXD_QueryEngine.asm - Streaming LLM Response Parser
; Based on Claude Code's QueryEngine (46K lines in leak)
; =============================================================================

OPTION CASEMAP:NONE

include masm64_compat.inc

; Parser states
PARSE_STATE_INIT            EQU 0
PARSE_STATE_READING         EQU 1
PARSE_STATE_TOOL_START      EQU 2
PARSE_STATE_CONTENT         EQU 4

; Buffer sizes
STREAM_BUFFER_SIZE          EQU 65536
MAX_TOOL_ARGS_SIZE          EQU 32768
MAX_CONTENT_SIZE            EQU 1048576

; Structures
QUERY_PARSER_CONTEXT STRUCT
    state               DWORD ?
    nestingDepth        DWORD ?
    braceCount          DWORD ?
    bracketCount        DWORD ?
    streamBuffer        QWORD ?
    bufferWritePos      DWORD ?
    bufferReadPos       DWORD ?
    bufferSize          DWORD ?
    currentToken        DWORD ?
    tokenBuffer         QWORD ?
    tokenLength         DWORD ?
    toolName            BYTE 128 DUP(?)
    toolArgsBuffer      QWORD ?
    toolArgsLength      DWORD ?
    toolArgsCapacity    DWORD ?
    contentBuffer       QWORD ?
    contentLength       DWORD ?
    contentCapacity     DWORD ?
    thinkingBuffer      QWORD ?
    thinkingLength      DWORD ?
    isThinking          BYTE ?
    onContent           QWORD ?
    onToolCall          QWORD ?
    onThinking          QWORD ?
    onError             QWORD ?
    onComplete          QWORD ?
    userData            QWORD ?
QUERY_PARSER_CONTEXT ENDS

RETRY_CONTEXT STRUCT
    attemptNumber       DWORD ?
    maxAttempts         DWORD ?
    baseDelayMs         DWORD ?
    currentDelayMs      DWORD ?
    lastError           DWORD ?
    exponentialBackoff  BYTE ?
    jitterEnabled       BYTE ?
RETRY_CONTEXT ENDS

QUERY_ENGINE_CONTEXT STRUCT
    hSession            QWORD ?
    hConnect            QWORD ?
    hRequest            QWORD ?
    parser              QUERY_PARSER_CONTEXT <>
    retry               RETRY_CONTEXT <>
    startTime           QWORD ?
    firstTokenTime      QWORD ?
    totalTokens         DWORD ?
    toolCalls           DWORD ?
    modelName           BYTE 64 DUP(?)
    apiKey              BYTE 128 DUP(?)
    endpoint            BYTE 256 DUP(?)
    timeoutMs           DWORD ?
    maxTokens           DWORD ?
    temperature         REAL4 ?
QUERY_ENGINE_CONTEXT ENDS

.CODE

; =============================================================================
; Struct offset constants (MASM64 doesn't support OFFSET on nested struct members)
; =============================================================================
; RETRY_CONTEXT offsets
RETRY_CONTEXT_attemptNumber      EQU 0
RETRY_CONTEXT_maxAttempts        EQU 4
RETRY_CONTEXT_baseDelayMs        EQU 8
RETRY_CONTEXT_currentDelayMs     EQU 12
RETRY_CONTEXT_lastError          EQU 16
RETRY_CONTEXT_exponentialBackoff EQU 20
RETRY_CONTEXT_jitterEnabled      EQU 21
RETRY_CONTEXT_SIZE               EQU 24

; QUERY_PARSER_CONTEXT offsets
QUERY_PARSER_CONTEXT_state               EQU 0
QUERY_PARSER_CONTEXT_nestingDepth        EQU 4
QUERY_PARSER_CONTEXT_braceCount          EQU 8
QUERY_PARSER_CONTEXT_bracketCount        EQU 12
QUERY_PARSER_CONTEXT_streamBuffer         EQU 16
QUERY_PARSER_CONTEXT_bufferWritePos       EQU 24
QUERY_PARSER_CONTEXT_bufferReadPos        EQU 28
QUERY_PARSER_CONTEXT_bufferSize           EQU 32
QUERY_PARSER_CONTEXT_currentToken         EQU 36
QUERY_PARSER_CONTEXT_tokenBuffer          EQU 40
QUERY_PARSER_CONTEXT_tokenLength          EQU 48
QUERY_PARSER_CONTEXT_toolName             EQU 52
QUERY_PARSER_CONTEXT_toolArgsBuffer       EQU 180
QUERY_PARSER_CONTEXT_toolArgsLength       EQU 188
QUERY_PARSER_CONTEXT_toolArgsCapacity     EQU 192
QUERY_PARSER_CONTEXT_contentBuffer        EQU 196
QUERY_PARSER_CONTEXT_contentLength        EQU 204
QUERY_PARSER_CONTEXT_contentCapacity      EQU 208
QUERY_PARSER_CONTEXT_thinkingBuffer       EQU 212
QUERY_PARSER_CONTEXT_thinkingLength       EQU 220
QUERY_PARSER_CONTEXT_isThinking           EQU 224
QUERY_PARSER_CONTEXT_onContent            EQU 232
QUERY_PARSER_CONTEXT_onToolCall           EQU 240
QUERY_PARSER_CONTEXT_onThinking          EQU 248
QUERY_PARSER_CONTEXT_onError              EQU 256
QUERY_PARSER_CONTEXT_onComplete           EQU 264
QUERY_PARSER_CONTEXT_userData             EQU 272
QUERY_PARSER_CONTEXT_SIZE                 EQU 280

; QUERY_ENGINE_CONTEXT offsets
QUERY_ENGINE_CONTEXT_hSession       EQU 0
QUERY_ENGINE_CONTEXT_hConnect       EQU 8
QUERY_ENGINE_CONTEXT_hRequest       EQU 16
QUERY_ENGINE_CONTEXT_parser         EQU 24
QUERY_ENGINE_CONTEXT_retry           EQU 304      ; 24 + QUERY_PARSER_CONTEXT_SIZE (280)
QUERY_ENGINE_CONTEXT_startTime      EQU 328      ; 304 + RETRY_CONTEXT_SIZE (24)
QUERY_ENGINE_CONTEXT_firstTokenTime EQU 336
QUERY_ENGINE_CONTEXT_totalTokens    EQU 344
QUERY_ENGINE_CONTEXT_toolCalls      EQU 348
QUERY_ENGINE_CONTEXT_modelName      EQU 352
QUERY_ENGINE_CONTEXT_apiKey         EQU 416
QUERY_ENGINE_CONTEXT_endpoint       EQU 544
QUERY_ENGINE_CONTEXT_timeoutMs      EQU 800
QUERY_ENGINE_CONTEXT_maxTokens      EQU 804
QUERY_ENGINE_CONTEXT_temperature    EQU 808
QUERY_ENGINE_CONTEXT_SIZE           EQU 816

; =============================================================================
; QueryEngine_Initialize - Initialize streaming query engine
; =============================================================================
; Input:  RCX = pointer to QUERY_ENGINE_CONTEXT
; Output: RAX = TRUE on success, FALSE on failure
; =============================================================================
QueryEngine_Initialize PROC FRAME
    ; Prologue - save non-volatile registers
    push rbx
    .pushframe
    push rdi
    .endprolog
    
    mov rbx, rcx                    ; Context pointer -> RBX
    
    ; Zero context structure
    mov rdi, rbx
    mov rcx, (QUERY_ENGINE_CONTEXT_SIZE / 8) + 1
    xor rax, rax
    rep stosq
    
    ; Initial retry config - use calculated offsets
    ; retry.maxAttempts is at QUERY_ENGINE_CONTEXT_retry + RETRY_CONTEXT_maxAttempts
    mov DWORD PTR [rbx + QUERY_ENGINE_CONTEXT_retry + RETRY_CONTEXT_maxAttempts], 5
    mov DWORD PTR [rbx + QUERY_ENGINE_CONTEXT_retry + RETRY_CONTEXT_baseDelayMs], 1000
    mov BYTE PTR [rbx + QUERY_ENGINE_CONTEXT_retry + RETRY_CONTEXT_exponentialBackoff], 1
    
    ; Setup default timeout
    mov DWORD PTR [rbx + QUERY_ENGINE_CONTEXT_timeoutMs], 30000
    
    mov rax, TRUE
    
    ; Epilogue
    pop rdi
    pop rbx
    ret
QueryEngine_Initialize ENDP

PUBLIC QueryEngine_Initialize

END


