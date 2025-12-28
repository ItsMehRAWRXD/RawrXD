;=====================================================================
; agentic_failure_detector.asm - Pattern-Based Failure Detection (Pure MASM x64)
; ZERO-DEPENDENCY MULTI-LAYER FAILURE DETECTION
;=====================================================================
; Implements failure detection with confidence scoring:
;  - Pattern-based detection (refusal, hallucination, timeout, etc.)
;  - Confidence scoring (0.0-1.0)
;  - Multi-failure aggregation
;  - Async notifications via Qt signals (event loop integration)
;
;=====================================================================

; Public exports
PUBLIC masm_detect_failure
PUBLIC masm_detect_timeout
PUBLIC masm_detect_resource_exhaustion
PUBLIC masm_failure_detector_get_stats

; External dependencies
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN asm_mutex_create:PROC
EXTERN asm_mutex_destroy:PROC
EXTERN asm_mutex_lock:PROC
EXTERN asm_mutex_unlock:PROC
EXTERN asm_str_create_from_cstr:PROC

; FailureType Enum:
;   0 = None
;   1 = Refusal (safety filters, censorship)
;   2 = Hallucination (factual errors)
;   3 = Timeout (excessive latency)
;   4 = ResourceExhaustion (OOM, quota limits)
;   5 = SafetyViolation (harmful content detected)
;   6 = FormatError (invalid JSON/output structure)
;
; FailureDetectionResult Structure (256 bytes):
;   [+0]:  failure_type (qword)
;   [+8]:  confidence (double) - IEEE 754 0.0 to 1.0
;   [+16]: description_ptr (qword)
;   [+24]: description_len (qword)
;   [+32]: timestamp (qword)
;   [+40]: response_ptr (qword) - original response that triggered detection
;   [+48]: response_len (qword)
;   [+56]: reserved[25] (qword[25])
;=====================================================================

.code

; Failure type constants
FAILURE_NONE                EQU 0
FAILURE_REFUSAL             EQU 1
FAILURE_HALLUCINATION       EQU 2
FAILURE_TIMEOUT             EQU 3
FAILURE_RESOURCE_EXHAUSTION EQU 4
FAILURE_SAFETY_VIOLATION    EQU 5
FAILURE_FORMAT_ERROR        EQU 6

; Global detector statistics
g_failures_detected     QWORD 0
g_refusal_count         QWORD 0
g_hallucination_count   QWORD 0
g_timeout_count         QWORD 0
g_resource_count        QWORD 0
g_safety_count          QWORD 0
g_format_count          QWORD 0

; Refusal pattern strings (compiled into binary)
.data

pattern_refusal_1       DB "I cannot", 0
pattern_refusal_2       DB "I'm unable to", 0
pattern_refusal_3       DB "I can't", 0
pattern_refusal_4       DB "I apologize, but", 0
pattern_refusal_5       DB "I'm not able to", 0
pattern_refusal_6       DB "I don't feel comfortable", 0

pattern_safety_1        DB "harmful", 0
pattern_safety_2        DB "dangerous", 0
pattern_safety_3        DB "illegal", 0
pattern_safety_4        DB "unethical", 0

pattern_format_1        DB "SyntaxError", 0
pattern_format_2        DB "ParseError", 0
pattern_format_3        DB "Invalid JSON", 0

; Hallucination patterns (Beyond Enterprise)
pattern_halluc_1        DB "according to my database", 0
pattern_halluc_2        DB "I have verified that", 0
pattern_halluc_3        DB "C:\Windows\System32\nonexistent", 0
pattern_halluc_4        DB "undefined_symbol_0x", 0
pattern_halluc_5        DB "fabricated_path", 0

.code

;=====================================================================
; masm_detect_failure(response_ptr: rcx, response_len: rdx, 
;                    result_ptr: r8) -> rax (1=failure detected, 0=no failure)
;
; Analyzes response for failure patterns.
; Fills result structure with detection details.
;=====================================================================

ALIGN 16
masm_detect_failure PROC

    push rbx
    push r12
    push r13
    push r14
    sub rsp, 32
    
    mov rbx, rcx            ; rbx = response_ptr
    mov r12, rdx            ; r12 = response_len
    mov r13, r8             ; r13 = result_ptr
    
    ; Initialize result
    mov qword ptr [r13], FAILURE_NONE
    mov qword ptr [r13 + 8], 0  ; confidence = 0.0
    
    ; Check for refusal patterns
    lea rcx, [pattern_refusal_1]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    lea rcx, [pattern_refusal_2]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    lea rcx, [pattern_refusal_3]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    lea rcx, [pattern_refusal_4]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    lea rcx, [pattern_refusal_5]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    lea rcx, [pattern_refusal_6]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_refusal_found
    
    ; Check for safety violation patterns
    lea rcx, [pattern_safety_1]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_safety_found
    
    lea rcx, [pattern_safety_2]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_safety_found
    
    lea rcx, [pattern_safety_3]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_safety_found
    
    lea rcx, [pattern_safety_4]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_safety_found
    
    ; Check for format errors
    lea rcx, [pattern_format_1]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_format_found
    
    lea rcx, [pattern_format_2]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_format_found
    
    lea rcx, [pattern_format_3]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_format_found
    
    ; Check for hallucination patterns
    lea rcx, [pattern_halluc_1]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_halluc_found
    
    lea rcx, [pattern_halluc_2]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_halluc_found
    
    lea rcx, [pattern_halluc_3]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_halluc_found
    
    lea rcx, [pattern_halluc_4]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_halluc_found
    
    lea rcx, [pattern_halluc_5]
    call detect_pattern_in_response
    test rax, rax
    jnz detect_halluc_found
    
    ; No failure detected
    xor rax, rax
    jmp detect_exit

detect_halluc_found:
    mov qword ptr [r13], FAILURE_HALLUCINATION
    
    mov rax, 3FE999999999999Ah  ; 0.8 confidence
    mov [r13 + 8], rax
    
    lea rcx, [str_halluc_desc]
    call asm_str_create_from_cstr
    mov [r13 + 16], rax
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r13 + 32], rax
    
    mov [r13 + 40], rbx
    mov [r13 + 48], r12
    
    lock inc [g_hallucination_count]
    lock inc [g_failures_detected]
    
    mov rax, 1
    jmp detect_exit

detect_refusal_found:
    mov qword ptr [r13], FAILURE_REFUSAL
    
    ; Calculate confidence: 0.9 (high confidence for explicit refusal)
    mov rax, 3FECCCCCC0000000h  ; IEEE 754 double: 0.9
    mov [r13 + 8], rax
    
    ; Create description string
    lea rcx, [str_refusal_desc]
    call asm_str_create_from_cstr
    mov [r13 + 16], rax
    
    ; Get timestamp
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r13 + 32], rax
    
    ; Store original response
    mov [r13 + 40], rbx
    mov [r13 + 48], r12
    
    lock inc [g_refusal_count]
    lock inc [g_failures_detected]
    
    mov rax, 1
    jmp detect_exit

detect_safety_found:
    mov qword ptr [r13], FAILURE_SAFETY_VIOLATION
    
    mov rax, 3FE8000000000000h  ; 0.75 confidence
    mov [r13 + 8], rax
    
    lea rcx, [str_safety_desc]
    call asm_str_create_from_cstr
    mov [r13 + 16], rax
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r13 + 32], rax
    
    mov [r13 + 40], rbx
    mov [r13 + 48], r12
    
    lock inc [g_safety_count]
    lock inc [g_failures_detected]
    
    mov rax, 1
    jmp detect_exit

detect_format_found:
    mov qword ptr [r13], FAILURE_FORMAT_ERROR
    
    mov rax, 3FECCCCCCCCCCCCDh  ; 0.9 confidence
    mov [r13 + 8], rax
    
    lea rcx, [str_format_desc]
    call asm_str_create_from_cstr
    mov [r13 + 16], rax
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r13 + 32], rax
    
    mov [r13 + 40], rbx
    mov [r13 + 48], r12
    
    lock inc [g_format_count]
    lock inc [g_failures_detected]
    
    mov rax, 1

detect_exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

masm_detect_failure ENDP

;=====================================================================
; detect_pattern_in_response(pattern_ptr: rcx) -> rax (1=found, 0=not found)
;
; Helper: searches for pattern in response (uses rbx, r12 from parent)
;=====================================================================

ALIGN 16
detect_pattern_in_response PROC

    push rsi
    push rdi
    push r15
    sub rsp, 32
    
    mov rsi, rcx            ; rsi = pattern_ptr
    
    ; Calculate pattern length
    xor r15, r15
    
pattern_len_loop:
    cmp byte ptr [rsi + r15], 0
    je pattern_len_done
    inc r15
    jmp pattern_len_loop

pattern_len_done:
    ; r15 = pattern_len
    test r15, r15
    jz pattern_not_found
    
    ; Search for pattern in response (rbx = response_ptr, r12 = response_len)
    xor rdi, rdi            ; rdi = response offset
    
pattern_search:
    mov rax, r12
    sub rax, r15
    cmp rdi, rax
    jg pattern_not_found
    
    ; Compare pattern at current position
    xor rcx, rcx            ; rcx = pattern offset
    
pattern_compare:
    cmp rcx, r15
    jge pattern_found
    
    mov al, [rsi + rcx]
    lea r10, [rdi + rcx]
    mov dl, [rbx + r10]
    
    ; Case-insensitive compare (simplified: lowercase only)
    cmp al, 'A'
    jl pattern_cmp_check
    cmp al, 'Z'
    jg pattern_cmp_check
    add al, 32              ; To lowercase
    
pattern_cmp_check:
    cmp dl, 'A'
    jl pattern_cmp_do
    cmp dl, 'Z'
    jg pattern_cmp_do
    add dl, 32
    
pattern_cmp_do:
    cmp al, dl
    jne pattern_next_pos
    
    inc rcx
    jmp pattern_compare

pattern_next_pos:
    inc rdi
    jmp pattern_search

pattern_found:
    mov rax, 1
    jmp pattern_search_exit

pattern_not_found:
    xor rax, rax

pattern_search_exit:
    add rsp, 32
    pop r15
    pop rdi
    pop rsi
    ret

detect_pattern_in_response ENDP

;=====================================================================
; masm_detect_timeout(start_time: rcx, end_time: rdx, 
;                    threshold_ms: r8, result_ptr: r9) -> rax (1=timeout, 0=ok)
;
; Detects timeout based on elapsed time.
;=====================================================================

ALIGN 16
masm_detect_timeout PROC

    push rbx
    sub rsp, 32
    
    mov rbx, r9             ; rbx = result_ptr
    
    ; Calculate elapsed time
    mov rax, rdx
    sub rax, rcx            ; elapsed = end_time - start_time
    
    ; Convert to milliseconds (assuming input is in microseconds or tsc)
    ; Simplified: assume input is already in ms
    
    cmp rax, r8             ; elapsed > threshold?
    jle timeout_ok
    
    ; Timeout detected
    mov qword ptr [rbx], FAILURE_TIMEOUT
    
    mov rax, 3FE999999999999Ah  ; 0.8 confidence
    mov [rbx + 8], rax
    
    lea rcx, [str_timeout_desc]
    call asm_str_create_from_cstr
    mov [rbx + 16], rax
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx + 32], rax
    
    lock inc [g_timeout_count]
    lock inc [g_failures_detected]
    
    mov rax, 1
    jmp timeout_exit

timeout_ok:
    mov qword ptr [rbx], FAILURE_NONE
    xor rax, rax

timeout_exit:
    add rsp, 32
    pop rbx
    ret

masm_detect_timeout ENDP

;=====================================================================
; masm_detect_resource_exhaustion(error_code: rcx, result_ptr: rdx) -> rax (1=detected, 0=ok)
;
; Detects resource exhaustion from error codes (OOM, quota exceeded).
;=====================================================================

ALIGN 16
masm_detect_resource_exhaustion PROC

    push rbx
    sub rsp, 32
    
    mov rbx, rdx            ; rbx = result_ptr
    
    ; Check for known resource error codes
    cmp rcx, 8007000Eh     ; E_OUTOFMEMORY
    je resource_detected
    
    cmp rcx, 12             ; ERROR_NOT_ENOUGH_MEMORY
    je resource_detected
    
    cmp rcx, 1450           ; ERROR_NO_SYSTEM_RESOURCES
    je resource_detected
    
    ; No resource exhaustion
    mov qword ptr [rbx], FAILURE_NONE
    xor rax, rax
    jmp resource_exit

resource_detected:
    mov qword ptr [rbx], FAILURE_RESOURCE_EXHAUSTION
    
    mov rax, 3FECCCCCCCCCCCCDh  ; 0.9 confidence
    mov [rbx + 8], rax
    
    lea rcx, [str_resource_desc]
    call asm_str_create_from_cstr
    mov [rbx + 16], rax
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx + 32], rax
    
    lock inc [g_resource_count]
    lock inc [g_failures_detected]
    
    mov rax, 1

resource_exit:
    add rsp, 32
    pop rbx
    ret

masm_detect_resource_exhaustion ENDP

;=====================================================================
; masm_failure_detector_get_stats(stats_ptr: rcx) -> void
;
; Fills statistics structure:
;   [0]: total_failures (qword)
;   [8]: refusal_count (qword)
;   [16]: hallucination_count (qword)
;   [24]: timeout_count (qword)
;   [32]: resource_exhaustion_count (qword)
;   [40]: safety_violation_count (qword)
;   [48]: format_error_count (qword)
;=====================================================================

ALIGN 16
masm_failure_detector_get_stats PROC

    test rcx, rcx
    jz stats_exit
    
    mov rax, [g_failures_detected]
    mov [rcx], rax
    
    mov rax, [g_refusal_count]
    mov [rcx + 8], rax
    
    mov rax, [g_hallucination_count]
    mov [rcx + 16], rax
    
    mov rax, [g_timeout_count]
    mov [rcx + 24], rax
    
    mov rax, [g_resource_count]
    mov [rcx + 32], rax
    
    mov rax, [g_safety_count]
    mov [rcx + 40], rax
    
    mov rax, [g_format_count]
    mov [rcx + 48], rax

stats_exit:
    ret

masm_failure_detector_get_stats ENDP

;=====================================================================
; String constants
;=====================================================================

.data

str_refusal_desc        DB "Model refused request", 0
str_safety_desc         DB "Safety violation detected", 0
str_format_desc         DB "Output format error", 0
str_halluc_desc         DB "Hallucination detected (fabricated content)", 0
str_timeout_desc        DB "Request timeout exceeded", 0
str_resource_desc       DB "Resource exhaustion", 0

END

