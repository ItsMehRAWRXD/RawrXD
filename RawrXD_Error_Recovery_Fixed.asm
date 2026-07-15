; RawrXD_Error_Recovery.asm
; Comprehensive error recovery and self-healing for Sovereign Engine
; Features: Retry logic, circuit breaker, fallback mechanisms, telemetry

; =============================================================================
; Error Recovery Constants
; =============================================================================

; Recovery strategies
RECOVERY_RETRY          equ 1       ; Simple retry with backoff
RECOVERY_FALLBACK       equ 2       ; Fall back to smaller model/quant
RECOVERY_CIRCUIT_BREAK  equ 3       ; Circuit breaker pattern
RECOVERY_GRACEFUL_DEGRADE equ 4     ; Reduce quality but keep running

; Retry configuration
MAX_RETRIES             equ 5
BASE_RETRY_DELAY_MS     equ 100     ; Start with 100ms
MAX_RETRY_DELAY_MS      equ 5000    ; Cap at 5 seconds
RETRY_BACKOFF_MULTIPLIER equ 2      ; Exponential backoff

; Circuit breaker states
CB_STATE_CLOSED         equ 0       ; Normal operation
CB_STATE_OPEN           equ 1       ; Failing fast
CB_STATE_HALF_OPEN      equ 2       ; Testing recovery

; Circuit breaker thresholds
CB_FAILURE_THRESHOLD    equ 5       ; Open after 5 failures
CB_SUCCESS_THRESHOLD    equ 3       ; Close after 3 successes
CB_TIMEOUT_MS           equ 30000   ; 30 second timeout

; Error codes
ERR_NONE                equ 0
ERR_OUT_OF_MEMORY       equ 0xE001
ERR_MODEL_LOAD_FAILED   equ 0xE002
ERR_INFERENCE_TIMEOUT   equ 0xE003
ERR_INVALID_INPUT       equ 0xE004
ERR_KV_CACHE_FULL       equ 0xE005
ERR_GPU_OOM             equ 0xE006
ERR_NETWORK_TIMEOUT     equ 0xE007
ERR_WORKER_DIED         equ 0xE008
ERR_NO_RESPONSE         equ 0xE009
ERR_AUTOPILOT_RECOVERY  equ 0xE00A

; =============================================================================
; Data Section
; =============================================================================
.data

; Global recovery state (128 bytes, aligned)
ALIGN 64
g_recovery_state LABEL BYTE
    retry_count             DWORD       0       ; offset 0
    last_error_code         DWORD       0       ; offset 4
    last_retry_time         QWORD       0       ; offset 8
    current_delay_ms        DWORD       0       ; offset 16
    
    cb_state                DWORD       0       ; offset 20
    failure_count           DWORD       0       ; offset 24
    success_count           DWORD       0       ; offset 28
    last_failure_time       QWORD       0       ; offset 32
    
    fallback_active         BYTE        0       ; offset 40
                            BYTE        0, 0, 0 ; padding
    fallback_model_id       DWORD       0       ; offset 44
    original_model_id       DWORD       0       ; offset 48
    
    total_requests          QWORD       0       ; offset 56
    successful_requests     QWORD       0       ; offset 64
    failed_requests         QWORD       0       ; offset 72
    recovered_requests      QWORD       0       ; offset 80
    no_response_count       QWORD       0       ; offset 88
    autopilot_recovery_count QWORD      0       ; offset 96
    
    max_retries             DWORD       0       ; offset 104
    enable_fallback         BYTE        0       ; offset 108
    enable_circuit_breaker  BYTE        0       ; offset 109
    enable_autopilot        BYTE        0       ; offset 110
                            BYTE        0       ; padding
    
    autopilot_recovery_active BYTE      0       ; offset 112
                            BYTE        0, 0, 0 ; padding
    autopilot_attempt_count DWORD       0       ; offset 116
    max_autopilot_attempts  DWORD       0       ; offset 120
    autopilot_timeout_ms    DWORD       0       ; offset 124
    
    reserved                BYTE        16 DUP(0) ; offset 128

; Error message table (for logging)
error_messages:
    db "Success", 0
    db "Out of memory", 0
    db "Model load failed", 0
    db "Inference timeout", 0
    db "Invalid input", 0
    db "KV cache full", 0
    db "GPU out of memory", 0
    db "Network timeout", 0
    db "Worker died", 0
    db "No response", 0
    db "Autopilot recovery", 0

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Recovery_Init
; Initialize error recovery system
; RCX = max_retries (0 = use default)
; RDX = enable_fallback (0/1)
; R8  = enable_circuit_breaker (0/1)
; =============================================================================
Recovery_Init PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    .endprolog
    
    ; Clear state (128 bytes)
    xor     eax, eax
    mov     rdi, OFFSET g_recovery_state
    mov     rcx, 32         ; 128 bytes / 4 = 32 dwords
    rep     stosd
    
    ; Set configuration
    cmp     ecx, 0
    jne     @F
    mov     ecx, MAX_RETRIES
@@: mov     DWORD PTR [g_recovery_state + 104], ecx      ; max_retries
    
    mov     BYTE PTR [g_recovery_state + 108], dl        ; enable_fallback
    mov     BYTE PTR [g_recovery_state + 109], r8b       ; enable_circuit_breaker
    
    ; Initialize circuit breaker as closed
    mov     DWORD PTR [g_recovery_state + 20], CB_STATE_CLOSED
    
    ; Log initialization
    call    Telemetry_LogRecoveryInit
    
    mov     rax, 1      ; Success
    pop     rdi
    pop     rbx
    ret
Recovery_Init ENDP

; =============================================================================
; Recovery_ExecuteWithRetry
; Execute operation with automatic retry logic
; RCX = function pointer to execute
; RDX = context pointer for function
; Returns: RAX = result (0 = failure after all retries)
; =============================================================================
Recovery_ExecuteWithRetry PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    .endprolog
    
    mov     rbx, rcx        ; RBX = function pointer
    mov     r12, rdx        ; R12 = context
    xor     r13, r13        ; R13 = retry counter
    
    ; Increment total requests
    inc     QWORD PTR [g_recovery_state + 56]
    
.retry_loop:
    ; Check circuit breaker
    call    Recovery_CheckCircuitBreaker
    cmp     eax, CB_STATE_OPEN
    je      .circuit_open
    
    ; Execute the function
    mov     rcx, r12
    call    rbx
    
    ; Check result
    test    rax, rax
    jnz     .success
    
    ; Function failed - handle error
    call    GetLastError
    mov     rdi, rax        ; RDI = error code
    
    ; Log failure
    mov     rcx, rdi
    mov     rdx, r13
    call    Telemetry_LogRetryFailure
    
    ; Update circuit breaker
    mov     rcx, rdi
    call    Recovery_UpdateCircuitBreakerFailure
    
    ; Check if we should retry
    inc     r13
    mov     eax, DWORD PTR [g_recovery_state + 104]  ; max_retries
    cmp     r13d, eax
    jge     .max_retries_reached
    
    ; Calculate backoff delay
    mov     ecx, r13d
    call    Recovery_CalculateBackoff
    
    ; Log retry attempt
    mov     rcx, r13
    mov     rdx, rax
    call    Telemetry_LogRetryAttempt
    
    ; Sleep with backoff
    mov     rcx, rax
    call    Sleep
    
    jmp     .retry_loop
    
.success:
    ; Update statistics
    inc     QWORD PTR [g_recovery_state + 64]     ; successful_requests
    
    ; Update circuit breaker on success
    call    Recovery_UpdateCircuitBreakerSuccess
    
    ; Log recovery if we retried
    cmp     r13, 0
    je      @F
    call    Telemetry_LogRecoverySuccess
@@: mov     rax, 1      ; Success
    jmp     .exit
    
.circuit_open:
    ; Circuit breaker is open - fail fast
    call    Telemetry_LogCircuitBreakerOpen
    xor     rax, rax    ; Failure
    jmp     .exit
    
.max_retries_reached:
    ; Try fallback if enabled
    cmp     BYTE PTR [g_recovery_state + 108], 0    ; enable_fallback
    je      .no_fallback
    
    call    Recovery_AttemptFallback
    test    rax, rax
    jnz     .success
    
.no_fallback:
    ; All retries exhausted
    inc     QWORD PTR [g_recovery_state + 72]       ; failed_requests
    call    Telemetry_LogMaxRetriesExceeded
    xor     rax, rax    ; Failure
    
.exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Recovery_ExecuteWithRetry ENDP

; =============================================================================
; Recovery_CheckCircuitBreaker
; Check if circuit breaker allows requests
; Returns: RAX = CB_STATE_*
; =============================================================================
Recovery_CheckCircuitBreaker PROC FRAME
    mov     eax, DWORD PTR [g_recovery_state + 20]  ; cb_state
    
    cmp     eax, CB_STATE_OPEN
    jne     .not_open
    
    ; Check if timeout has elapsed
    call    GetTickCount64
    mov     rcx, QWORD PTR [g_recovery_state + 32]    ; last_failure_time
    add     rcx, CB_TIMEOUT_MS
    cmp     rax, rcx
    jb      .still_open
    
    ; Timeout elapsed - transition to half-open
    mov     DWORD PTR [g_recovery_state + 20], CB_STATE_HALF_OPEN
    mov     DWORD PTR [g_recovery_state + 28], 0    ; success_count
    mov     eax, CB_STATE_HALF_OPEN
    ret
    
.still_open:
    mov     eax, CB_STATE_OPEN
    ret
    
.not_open:
    ret
Recovery_CheckCircuitBreaker ENDP

; =============================================================================
; Recovery_UpdateCircuitBreakerFailure
; Update circuit breaker on failure
; RCX = error code
; =============================================================================
Recovery_UpdateCircuitBreakerFailure PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx
    
    ; Increment failure count
    inc     DWORD PTR [g_recovery_state + 24]         ; failure_count
    
    ; Record failure time
    call    GetTickCount64
    mov     QWORD PTR [g_recovery_state + 32], rax  ; last_failure_time
    
    ; Check if we should open the circuit
    mov     eax, DWORD PTR [g_recovery_state + 24]  ; failure_count
    cmp     eax, CB_FAILURE_THRESHOLD
    jb      .done
    
    ; Open circuit breaker
    mov     DWORD PTR [g_recovery_state + 20], CB_STATE_OPEN
    call    Telemetry_LogCircuitBreakerStateChange
    
.done:
    pop     rbx
    ret
Recovery_UpdateCircuitBreakerFailure ENDP

; =============================================================================
; Recovery_UpdateCircuitBreakerSuccess
; Update circuit breaker on success
; =============================================================================
Recovery_UpdateCircuitBreakerSuccess PROC FRAME
    ; Reset failure count
    mov     DWORD PTR [g_recovery_state + 24], 0      ; failure_count
    
    ; Check if in half-open state
    cmp     DWORD PTR [g_recovery_state + 20], CB_STATE_HALF_OPEN
    jne     .done
    
    ; Increment success count
    inc     DWORD PTR [g_recovery_state + 28]         ; success_count
    
    ; Check if we should close the circuit
    mov     eax, DWORD PTR [g_recovery_state + 28]    ; success_count
    cmp     eax, CB_SUCCESS_THRESHOLD
    jb      .done
    
    ; Close circuit breaker
    mov     DWORD PTR [g_recovery_state + 20], CB_STATE_CLOSED
    call    Telemetry_LogCircuitBreakerStateChange
    
.done:
    ret
Recovery_UpdateCircuitBreakerSuccess ENDP

; =============================================================================
; Recovery_CalculateBackoff
; Calculate exponential backoff delay
; RCX = retry attempt number (0-indexed)
; Returns: RAX = delay in milliseconds
; =============================================================================
Recovery_CalculateBackoff PROC FRAME
    mov     eax, BASE_RETRY_DELAY_MS
    
    ; Calculate 2^retry_count
    mov     edx, 1
    mov     r8d, ecx
    test    r8d, r8d
    jz      .no_shift
    
.shift_loop:
    shl     edx, 1
    dec     r8d
    jnz     .shift_loop
    
.no_shift:
    ; Multiply base delay by 2^retry_count
    mul     edx
    
    ; Cap at maximum
    cmp     eax, MAX_RETRY_DELAY_MS
    jbe     @F
    mov     eax, MAX_RETRY_DELAY_MS
@@: ret
Recovery_CalculateBackoff ENDP

; =============================================================================
; Recovery_AttemptFallback
; Attempt fallback to degraded mode
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Recovery_AttemptFallback PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog
    
    ; Check if fallback already active
    cmp     BYTE PTR [g_recovery_state + 40], 1       ; fallback_active
    je      .already_active
    
    ; Save original model
    mov     eax, DWORD PTR [g_recovery_state + 48]    ; original_model_id
    test    eax, eax
    jnz     @F
    mov     DWORD PTR [g_recovery_state + 48], eax
@@: 
    ; Attempt to load fallback model (smaller/quantized)
    call    Recovery_LoadFallbackModel
    test    rax, rax
    jz      .fallback_failed
    
    ; Mark fallback as active
    mov     BYTE PTR [g_recovery_state + 40], 1       ; fallback_active
    call    Telemetry_LogFallbackActivated
    
    mov     rax, 1
    jmp     .exit
    
.already_active:
    ; Already in fallback mode
    mov     rax, 1
    jmp     .exit
    
.fallback_failed:
    xor     rax, rax
    
.exit:
    pop     rsi
    pop     rbx
    ret
Recovery_AttemptFallback ENDP

; =============================================================================
; Recovery_LoadFallbackModel
; Load a smaller/faster model for fallback
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Recovery_LoadFallbackModel PROC FRAME
    ; This would load a smaller model (e.g., 7B instead of 70B)
    ; or switch to INT8 quantization
    
    ; For now, return success (implementation depends on model loader)
    mov     rax, 1
    ret
Recovery_LoadFallbackModel ENDP

; =============================================================================
; Recovery_GetStats
; Get error recovery statistics
; RCX = pointer to stats structure
; =============================================================================
Recovery_GetStats PROC FRAME
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    .endprolog
    
    mov     rdi, rcx        ; Destination
    mov     rsi, OFFSET g_recovery_state
    
    ; Copy statistics (64 bytes)
    mov     rax, [rsi + 56]       ; total_requests
    mov     [rdi], rax
    
    mov     rax, [rsi + 64]       ; successful_requests
    mov     [rdi + 8], rax
    
    mov     rax, [rsi + 72]       ; failed_requests
    mov     [rdi + 16], rax
    
    mov     rax, [rsi + 80]       ; recovered_requests
    mov     [rdi + 24], rax
    
    mov     rax, [rsi + 88]       ; no_response_count
    mov     [rdi + 32], rax
    
    mov     rax, [rsi + 96]       ; autopilot_recovery_count
    mov     [rdi + 40], rax
    
    mov     eax, [rsi + 20]       ; cb_state
    mov     [rdi + 48], eax
    
    mov     al, [rsi + 40]        ; fallback_active
    mov     [rdi + 52], al
    
    mov     al, [rsi + 112]       ; autopilot_recovery_active
    mov     [rdi + 53], al
    
    pop     rsi
    pop     rdi
    ret
Recovery_GetStats ENDP

; =============================================================================
; Recovery_Reset
; Reset error recovery state (for testing or manual recovery)
; =============================================================================
Recovery_Reset PROC FRAME
    push    rdi
    .pushreg rdi
    .endprolog
    
    ; Reset counters but keep configuration
    mov     DWORD PTR [g_recovery_state + 0], 0       ; retry_count
    mov     DWORD PTR [g_recovery_state + 24], 0      ; failure_count
    mov     DWORD PTR [g_recovery_state + 28], 0      ; success_count
    mov     DWORD PTR [g_recovery_state + 20], CB_STATE_CLOSED
    mov     BYTE PTR [g_recovery_state + 40], 0       ; fallback_active
    mov     BYTE PTR [g_recovery_state + 112], 0      ; autopilot_recovery_active
    mov     DWORD PTR [g_recovery_state + 116], 0      ; autopilot_attempt_count
    
    call    Telemetry_LogRecoveryReset
    
    pop     rdi
    ret
Recovery_Reset ENDP

; =============================================================================
; NEW: Recovery_HandleNoResponse
; Handle "no response" scenario with autopilot recovery
; RCX = request_id
; Returns: RAX = 1 if recovery initiated, 0 if failed
; =============================================================================
Recovery_HandleNoResponse PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rbx, rcx        ; RBX = request_id
    
    ; Increment no response counter
    inc     QWORD PTR [g_recovery_state + 88]         ; no_response_count
    
    ; Log the no-response event
    mov     rcx, rbx
    mov     rdx, ERR_NO_RESPONSE
    call    Telemetry_LogNoResponse
    
    ; Check if autopilot recovery is enabled
    cmp     BYTE PTR [g_recovery_state + 110], 0      ; enable_autopilot
    je      .no_autopilot
    
    ; Check if already in autopilot recovery
    cmp     BYTE PTR [g_recovery_state + 112], 1    ; autopilot_recovery_active
    je      .already_recovering
    
    ; Enter autopilot recovery mode
    mov     BYTE PTR [g_recovery_state + 112], 1      ; autopilot_recovery_active
    inc     QWORD PTR [g_recovery_state + 96]       ; autopilot_recovery_count
    mov     DWORD PTR [g_recovery_state + 116], 1   ; autopilot_attempt_count
    
    ; Log autopilot activation
    mov     rcx, rbx
    mov     rdx, ERR_NO_RESPONSE
    call    Telemetry_LogAutopilotActivated
    
    ; Attempt immediate retry with shorter timeout
    mov     rax, 1      ; Success - recovery initiated
    jmp     .exit
    
.no_autopilot:
    ; Autopilot not enabled - just fail
    xor     rax, rax
    jmp     .exit
    
.already_recovering:
    ; Already recovering - check if we should give up
    mov     eax, DWORD PTR [g_recovery_state + 116]   ; autopilot_attempt_count
    cmp     eax, DWORD PTR [g_recovery_state + 120] ; max_autopilot_attempts
    jge     .give_up
    
    ; Increment attempt count and continue
    inc     DWORD PTR [g_recovery_state + 116]
    mov     rax, 1      ; Success - still trying
    jmp     .exit
    
.give_up:
    ; Too many attempts - exit autopilot mode
    mov     BYTE PTR [g_recovery_state + 112], 0      ; autopilot_recovery_active
    mov     DWORD PTR [g_recovery_state + 116], 0     ; autopilot_attempt_count
    xor     rax, rax    ; Failure
    
.exit:
    pop     rdi
    pop     rbx
    ret
Recovery_HandleNoResponse ENDP

; =============================================================================
; NEW: Recovery_IsAutopilotRecovery
; Check if autopilot is currently in recovery mode
; Returns: RAX = 1 if active, 0 if not
; =============================================================================
Recovery_IsAutopilotRecovery PROC FRAME
    movzx   eax, BYTE PTR [g_recovery_state + 112]  ; autopilot_recovery_active
    ret
Recovery_IsAutopilotRecovery ENDP

; =============================================================================
; NEW: Recovery_AcknowledgeAutopilot
; Acknowledge autopilot recovery completion
; =============================================================================
Recovery_AcknowledgeAutopilot PROC FRAME
    ; Clear autopilot recovery state
    mov     BYTE PTR [g_recovery_state + 112], 0      ; autopilot_recovery_active
    mov     DWORD PTR [g_recovery_state + 116], 0     ; autopilot_attempt_count
    
    ; Log successful recovery
    call    Telemetry_LogAutopilotCompleted
    ret
Recovery_AcknowledgeAutopilot ENDP

; =============================================================================
; NEW: Recovery_GetRetryDelay
; Get current retry delay with exponential backoff
; Returns: RAX = delay in milliseconds
; =============================================================================
Recovery_GetRetryDelay PROC FRAME
    mov     ecx, DWORD PTR [g_recovery_state + 0]     ; retry_count
    call    Recovery_CalculateBackoff
    ret
Recovery_GetRetryDelay ENDP

; =============================================================================
; NEW: Recovery_ConfigureAutopilot
; Configure autopilot behavior
; RCX = max_autopilot_attempts
; RDX = autopilot_timeout_ms
; =============================================================================
Recovery_ConfigureAutopilot PROC FRAME
    mov     DWORD PTR [g_recovery_state + 120], ecx   ; max_autopilot_attempts
    mov     DWORD PTR [g_recovery_state + 124], edx   ; autopilot_timeout_ms
    mov     BYTE PTR [g_recovery_state + 110], 1      ; enable_autopilot
    ret
Recovery_ConfigureAutopilot ENDP

; =============================================================================
; Telemetry Functions (stubs - would be implemented in telemetry module)
; =============================================================================

Telemetry_LogRecoveryInit PROC
    ret
Telemetry_LogRecoveryInit ENDP

Telemetry_LogRetryFailure PROC
    ret
Telemetry_LogRetryFailure ENDP

Telemetry_LogRetryAttempt PROC
    ret
Telemetry_LogRetryAttempt ENDP

Telemetry_LogRecoverySuccess PROC
    ret
Telemetry_LogRecoverySuccess ENDP

Telemetry_LogMaxRetriesExceeded PROC
    ret
Telemetry_LogMaxRetriesExceeded ENDP

Telemetry_LogCircuitBreakerOpen PROC
    ret
Telemetry_LogCircuitBreakerOpen ENDP

Telemetry_LogCircuitBreakerStateChange PROC
    ret
Telemetry_LogCircuitBreakerStateChange ENDP

Telemetry_LogFallbackActivated PROC
    ret
Telemetry_LogFallbackActivated ENDP

Telemetry_LogRecoveryReset PROC
    ret
Telemetry_LogRecoveryReset ENDP

Telemetry_LogNoResponse PROC
    ret
Telemetry_LogNoResponse ENDP

Telemetry_LogAutopilotActivated PROC
    ret
Telemetry_LogAutopilotActivated ENDP

Telemetry_LogAutopilotCompleted PROC
    ret
Telemetry_LogAutopilotCompleted ENDP

END
