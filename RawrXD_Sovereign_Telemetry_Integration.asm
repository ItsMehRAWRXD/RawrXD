; RawrXD_Sovereign_Telemetry_Integration.asm
; Integration layer: Sovereign Engine → Telemetry Buffer
; Purpose: Instrument the inference pipeline with zero-overhead metrics

; =============================================================================
; External Dependencies
; =============================================================================
EXTERNDEF Telemetry_Init:PROC
EXTERNDEF Telemetry_LogEvent:PROC
EXTERNDEF Telemetry_Flush:PROC
EXTERNDEF Telemetry_GetStats:PROC

; =============================================================================
; Metric Type Constants (match RawrXD_Telemetry.asm)
; =============================================================================
METRIC_NONE             EQU 0
METRIC_INFERENCE_START  EQU 1
METRIC_INFERENCE_END    EQU 2
METRIC_TOKEN_GENERATED  EQU 3
METRIC_CACHE_HIT        EQU 4
METRIC_CACHE_MISS       EQU 5
METRIC_PRECISION_SWITCH EQU 6
METRIC_SECURITY_EVENT   EQU 7

; =============================================================================
; Quantization Type Constants
; =============================================================================
QUANT_INT8  EQU 0
QUANT_BF16  EQU 1
QUANT_FP32  EQU 2

; =============================================================================
; Session State Structure
; =============================================================================
SESSION_STATE STRUCT
    session_id      DWORD ?     ; Unique session identifier
    start_time      QWORD ?     ; RDTSC at session start
    token_count     DWORD ?     ; Tokens generated this session
    quant_type      BYTE ?       ; Current quantization mode
    cache_hits      DWORD ?     ; Cache hits this session
    cache_misses    DWORD ?     ; Cache misses this session
    total_latency   QWORD ?     ; Cumulative latency (microseconds)
SESSION_STATE ENDS

; =============================================================================
; Global Session State
; =============================================================================
.DATA
    g_sessionState      SESSION_STATE <>
    g_nextSessionId     DWORD 1
    g_telemetryReady    BYTE 0       ; 1 = initialized
    
    ; Performance counters
    g_totalInferences   QWORD 0
    g_totalTokens       QWORD 0
    g_totalLatencyUs    QWORD 0

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; =============================================================================
; Sovereign_Telemetry_Init
; Initialize telemetry subsystem for Sovereign Engine
; =============================================================================
Sovereign_Telemetry_Init PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Check if already initialized
    cmp g_telemetryReady, 1
    je @init_done
    
    ; Initialize telemetry buffer
    call Telemetry_Init
    test rax, rax
    jz @init_failed
    
    ; Mark as ready
    mov g_telemetryReady, 1
    
    ; Log initialization event
    mov rcx, METRIC_SECURITY_EVENT
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call Telemetry_LogEvent
    
@init_done:
    mov rax, 1          ; Success
    jmp @init_exit
    
@init_failed:
    xor rax, rax        ; Failed
    
@init_exit:
    add rsp, 32
    pop rbp
    ret
Sovereign_Telemetry_Init ENDP

; =============================================================================
; Sovereign_Inference_Begin
; Called at the start of each inference request
; Parameters: rcx = prompt_length
; Returns: rax = session_id
; =============================================================================
Sovereign_Inference_Begin PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rcx        ; Save prompt_length
    
    ; Check telemetry ready
    cmp g_telemetryReady, 1
    jne @begin_skip_telemetry
    
    ; Generate new session ID
    mov eax, g_nextSessionId
    inc g_nextSessionId
    mov [g_sessionState.session_id], eax
    
    ; Record start time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [g_sessionState.start_time], rax
    
    ; Initialize session counters
    mov [g_sessionState.token_count], 0
    mov [g_sessionState.cache_hits], 0
    mov [g_sessionState.cache_misses], 0
    mov [g_sessionState.total_latency], 0
    
    ; Get current quantization type from engine
    call Sovereign_GetCurrentQuantization
    mov [g_sessionState.quant_type], al
    
    ; Log inference start
    mov rcx, METRIC_INFERENCE_START
    mov edx, [g_sessionState.session_id]
    mov r8d, ebx        ; prompt_length
    xor r9d, r9d        ; latency = 0 (start event)
    call Telemetry_LogEvent
    
@begin_skip_telemetry:
    ; Return session ID
    mov eax, [g_sessionState.session_id]
    
    add rsp, 40
    pop rdi
    pop rbx
    pop rbp
    ret
Sovereign_Inference_Begin ENDP

; =============================================================================
; Sovereign_Token_Generated
; Called after each token is generated
; Parameters: rcx = token_id, rdx = generation_latency_us
; =============================================================================
Sovereign_Token_Generated PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rdx        ; Save latency
    
    ; Check telemetry ready
    cmp g_telemetryReady, 1
    jne @token_skip
    
    ; Increment token count
    inc [g_sessionState.token_count]
    
    ; Accumulate latency
    mov rax, [g_sessionState.total_latency]
    add rax, rbx
    mov [g_sessionState.total_latency], rax
    
    ; Log token generation
    mov rcx, METRIC_TOKEN_GENERATED
    mov edx, [g_sessionState.session_id]
    mov r8d, [g_sessionState.token_count]
    mov r9d, ebx        ; latency_us
    call Telemetry_LogEvent
    
    ; Update global counters
    inc g_totalTokens
    
@token_skip:
    add rsp, 40
    pop rbx
    pop rbp
    ret
Sovereign_Token_Generated ENDP

; =============================================================================
; Sovereign_Cache_Access
; Called on KV cache access
; Parameters: rcx = cache_line_id, dl = 1 if hit, 0 if miss
; =============================================================================
Sovereign_Cache_Access PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Check telemetry ready
    cmp g_telemetryReady, 1
    jne @cache_skip
    
    ; Determine hit/miss
    test dl, dl
    jz @cache_miss
    
    ; Cache hit
    inc [g_sessionState.cache_hits]
    mov rcx, METRIC_CACHE_HIT
    jmp @cache_log
    
@cache_miss:
    ; Cache miss
    inc [g_sessionState.cache_misses]
    mov rcx, METRIC_CACHE_MISS
    
@cache_log:
    ; Log cache event
    mov edx, [g_sessionState.session_id]
    mov r8d, ecx        ; cache_line_id
    xor r9d, r9d
    call Telemetry_LogEvent
    
@cache_skip:
    add rsp, 32
    pop rbp
    ret
Sovereign_Cache_Access ENDP

; =============================================================================
; Sovereign_Precision_Switch
; Called when switching quantization precision
; Parameters: cl = new_quant_type (0=INT8, 1=BF16, 2=FP32)
; =============================================================================
Sovereign_Precision_Switch PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Check telemetry ready
    cmp g_telemetryReady, 1
    jne @precision_skip
    
    ; Update session state
    mov [g_sessionState.quant_type], cl
    
    ; Log precision switch
    movzx rcx, cl       ; quant_type
    add rcx, METRIC_PRECISION_SWITCH
    mov edx, [g_sessionState.session_id]
    xor r8d, r8d
    xor r9d, r9d
    call Telemetry_LogEvent
    
@precision_skip:
    add rsp, 32
    pop rbp
    ret
Sovereign_Precision_Switch ENDP

; =============================================================================
; Sovereign_Inference_End
; Called at the end of each inference request
; Returns: rax = total_tokens_generated
; =============================================================================
Sovereign_Inference_End PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Check telemetry ready
    cmp g_telemetryReady, 1
    jne @end_skip
    
    ; Calculate total latency
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [g_sessionState.start_time]
    
    ; Convert to microseconds (approximate)
    ; Assuming 3GHz: 1 tick = 0.333ns, so divide by 3 to get microseconds
    xor rdx, rdx
    mov rcx, 3
    div rcx
    
    ; Update session total latency
    mov [g_sessionState.total_latency], rax
    
    ; Log inference end
    mov rcx, METRIC_INFERENCE_END
    mov edx, [g_sessionState.session_id]
    mov r8d, [g_sessionState.token_count]
    mov r9d, eax        ; total_latency_us (lower 32 bits)
    call Telemetry_LogEvent
    
    ; Update global counters
    inc g_totalInferences
    mov rax, [g_sessionState.total_latency]
    add g_totalLatencyUs, rax
    
    ; Flush telemetry periodically (every 10 inferences)
    mov rax, g_totalInferences
    and rax, 0Fh        ; Check if multiple of 16
    jnz @end_skip
    call Telemetry_Flush
    
@end_skip:
    ; Return token count
    mov eax, [g_sessionState.token_count]
    
    add rsp, 32
    pop rbp
    ret
Sovereign_Inference_End ENDP

; =============================================================================
; Sovereign_GetCurrentQuantization
; Stub: Returns current quantization type
; Returns: al = quant_type (0=INT8, 1=BF16, 2=FP32)
; =============================================================================
Sovereign_GetCurrentQuantization PROC
    ; In real implementation, query the engine state
    ; For now, return INT8 as default
    mov al, QUANT_INT8
    ret
Sovereign_GetCurrentQuantization ENDP

; =============================================================================
; Sovereign_GetTelemetryStats
; Get aggregated telemetry statistics
; Parameters: rcx = pointer to TELEMETRY_STATS structure
; =============================================================================
Sovereign_GetTelemetryStats PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rdi, rcx        ; Save stats pointer
    
    ; Copy global counters
    mov rax, g_totalInferences
    mov [rdi], rax          ; total_inferences
    
    mov rax, g_totalTokens
    mov [rdi+8], rax        ; total_tokens
    
    mov rax, g_totalLatencyUs
    mov [rdi+16], rax       ; total_latency_us
    
    ; Calculate average latency
    mov rax, g_totalInferences
    test rax, rax
    jz @stats_no_avg
    
    mov rax, g_totalLatencyUs
    xor rdx, rdx
    div g_totalInferences
    mov [rdi+24], eax       ; avg_latency_us
    jmp @stats_done
    
@stats_no_avg:
    mov DWORD PTR [rdi+24], 0
    
@stats_done:
    ; Get current session stats
    mov eax, [g_sessionState.token_count]
    mov [rdi+28], eax       ; current_session_tokens
    
    mov eax, [g_sessionState.cache_hits]
    mov [rdi+32], eax       ; session_cache_hits
    
    mov eax, [g_sessionState.cache_misses]
    mov [rdi+36], eax       ; session_cache_misses
    
    mov al, [g_sessionState.quant_type]
    mov [rdi+40], al        ; current_quant_type
    
    add rsp, 40
    pop rdi
    pop rbp
    ret
Sovereign_GetTelemetryStats ENDP

; =============================================================================
; TELEMETRY_STATS Structure (for external consumption)
; =============================================================================
; typedef struct {
;     uint64_t total_inferences;
;     uint64_t total_tokens;
;     uint64_t total_latency_us;
;     uint32_t avg_latency_us;
;     uint32_t current_session_tokens;
;     uint32_t session_cache_hits;
;     uint32_t session_cache_misses;
;     uint8_t  current_quant_type;
; } TELEMETRY_STATS;

END
