; RawrXD_Error_Recovery.asm
; Comprehensive error recovery and self-healing for Sovereign Engine

; =============================================================================
; External Functions
; =============================================================================
EXTERNDEF GetTickCount64:PROC
EXTERNDEF Sleep:PROC
EXTERNDEF GetLastError:PROC

; =============================================================================
; Public Functions
; =============================================================================
PUBLIC Recovery_Init
PUBLIC Recovery_ExecuteWithRetry
PUBLIC Recovery_CheckCircuitBreaker
PUBLIC Recovery_GetStats
PUBLIC Recovery_Reset
PUBLIC Recovery_ShouldAttemptRequest
PUBLIC Recovery_HandleNoResponse
PUBLIC Recovery_IsAutopilotRecovery
PUBLIC Recovery_AcknowledgeAutopilot
PUBLIC Recovery_GetRetryDelay
PUBLIC Recovery_ConfigureAutopilot

; =============================================================================
; Constants
; =============================================================================
MAX_RETRY               EQU 5
BASE_DELAY_MS           EQU 100
MAX_DELAY_MS            EQU 5000
CB_FAILURE_THRESHOLD    EQU 5
CB_SUCCESS_THRESHOLD    EQU 3
CB_TIMEOUT_MS           EQU 30000
CB_STATE_CLOSED         EQU 0
CB_STATE_OPEN           EQU 1
CB_STATE_HALF_OPEN      EQU 2
ERR_NO_RESPONSE         EQU 0E009H

; =============================================================================
; Data Section
; =============================================================================
.data

; Recovery state structure (flat layout)
g_retry_count               DWORD 0
g_last_error_code           DWORD 0
g_last_retry_time           QWORD 0
g_current_delay_ms          DWORD 0
g_cb_state                  DWORD 0
g_failure_count             DWORD 0
g_success_count             DWORD 0
g_last_failure_time         QWORD 0
g_fallback_active           BYTE  0
g_fallback_model_id         DWORD 0
g_original_model_id         DWORD 0
g_total_requests            QWORD 0
g_successful_requests       QWORD 0
g_failed_requests           QWORD 0
g_recovered_requests        QWORD 0
g_no_response_count         QWORD 0
g_autopilot_recovery_count  QWORD 0
g_max_retries               DWORD 5
g_enable_fallback           BYTE  0
g_enable_circuit_breaker    BYTE  0
g_enable_autopilot          BYTE  0
g_autopilot_recovery_active BYTE  0
g_autopilot_attempt_count   DWORD 0
g_max_autopilot_attempts    DWORD 3
g_autopilot_timeout_ms      DWORD 5000

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Recovery_Init
; RCX = max_retries, RDX = enable_fallback, R8 = enable_circuit_breaker
; =============================================================================
Recovery_Init PROC
    push    rbx
    push    rdi
    
    ; Clear all state
    xor     eax, eax
    mov     rdi, OFFSET g_retry_count
    mov     rcx, 128
    rep     stosb
    
    ; Set configuration
    cmp     ecx, 0
    jne     set_max_retry
    mov     ecx, MAX_RETRY
set_max_retry:
    mov     g_max_retries, ecx
    mov     g_enable_fallback, dl
    mov     g_enable_circuit_breaker, r8b
    mov     g_cb_state, CB_STATE_CLOSED
    
    mov     rax, 1
    pop     rdi
    pop     rbx
    ret
Recovery_Init ENDP

; =============================================================================
; Recovery_ExecuteWithRetry
; RCX = function pointer, RDX = context
; =============================================================================
Recovery_ExecuteWithRetry PROC
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    
    mov     rbx, rcx
    mov     r12, rdx
    xor     r13, r13
    
    inc     g_total_requests
    
retry_loop:
    call    Recovery_CheckCircuitBreaker
    cmp     eax, CB_STATE_OPEN
    je      circuit_open
    
    mov     rcx, r12
    call    rbx
    
    test    rax, rax
    jnz     success
    
    call    GetLastError
    mov     r14, rax
    inc     g_failure_count
    call    GetTickCount64
    mov     g_last_failure_time, rax
    
    mov     eax, g_failure_count
    cmp     eax, CB_FAILURE_THRESHOLD
    jb      check_retry
    mov     g_cb_state, CB_STATE_OPEN
    
check_retry:
    inc     r13
    mov     eax, g_max_retries
    cmp     r13d, eax
    jge     max_retries
    
    mov     ecx, r13d
    call    Recovery_CalculateBackoff
    mov     r15, rax
    
    mov     rcx, r15
    call    Sleep
    jmp     retry_loop
    
success:
    inc     g_successful_requests
    mov     g_failure_count, 0
    cmp     g_cb_state, CB_STATE_HALF_OPEN
    jne     done_success
    inc     g_success_count
    mov     eax, g_success_count
    cmp     eax, CB_SUCCESS_THRESHOLD
    jb      done_success
    mov     g_cb_state, CB_STATE_CLOSED
    
done_success:
    mov     rax, 1
    jmp     exit_func
    
circuit_open:
    xor     rax, rax
    jmp     exit_func
    
max_retries:
    inc     g_failed_requests
    xor     rax, rax
    
exit_func:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
Recovery_ExecuteWithRetry ENDP

; =============================================================================
; Recovery_CheckCircuitBreaker
; =============================================================================
Recovery_CheckCircuitBreaker PROC
    mov     eax, g_cb_state
    cmp     eax, CB_STATE_OPEN
    jne     not_open
    
    call    GetTickCount64
    mov     rcx, g_last_failure_time
    add     rcx, CB_TIMEOUT_MS
    cmp     rax, rcx
    jb      still_open
    
    mov     g_cb_state, CB_STATE_HALF_OPEN
    mov     g_success_count, 0
    mov     rax, CB_STATE_HALF_OPEN
    ret
    
still_open:
    mov     rax, CB_STATE_OPEN
    ret
    
not_open:
    ret
Recovery_CheckCircuitBreaker ENDP

; =============================================================================
; Recovery_CalculateBackoff
; RCX = retry count
; =============================================================================
Recovery_CalculateBackoff PROC
    mov     eax, BASE_DELAY_MS
    mov     edx, 1
    mov     r8d, ecx
    test    r8d, r8d
    jz      no_shift
    
shift_loop:
    shl     edx, 1
    dec     r8d
    jnz     shift_loop
    
no_shift:
    mul     edx
    cmp     eax, MAX_DELAY_MS
    jbe     done_backoff
    mov     eax, MAX_DELAY_MS
    
done_backoff:
    ret
Recovery_CalculateBackoff ENDP

; =============================================================================
; Recovery_GetStats
; RCX = pointer to stats buffer (64 bytes)
; =============================================================================
Recovery_GetStats PROC
    push    rdi
    push    rsi
    
    mov     rdi, rcx
    mov     rsi, OFFSET g_total_requests
    
    movsq
    movsq
    movsq
    movsq
    movsq
    movsq
    
    mov     eax, g_cb_state
    mov     [rdi], eax
    add     rdi, 4
    
    movzx   eax, g_fallback_active
    mov     [rdi], al
    inc     rdi
    
    movzx   eax, g_autopilot_recovery_active
    mov     [rdi], al
    
    pop     rsi
    pop     rdi
    ret
Recovery_GetStats ENDP

; =============================================================================
; Recovery_Reset
; =============================================================================
Recovery_Reset PROC
    mov     g_retry_count, 0
    mov     g_failure_count, 0
    mov     g_success_count, 0
    mov     g_cb_state, CB_STATE_CLOSED
    mov     g_fallback_active, 0
    mov     g_autopilot_recovery_active, 0
    mov     g_autopilot_attempt_count, 0
    mov     rax, 1
    ret
Recovery_Reset ENDP

; =============================================================================
; Recovery_ShouldAttemptRequest
; Check if request should be attempted (circuit breaker)
; Returns: RAX = 1 if should attempt, 0 if should reject
; =============================================================================
Recovery_ShouldAttemptRequest PROC
    call    Recovery_CheckCircuitBreaker
    cmp     eax, CB_STATE_CLOSED
    sete    al
    movzx   rax, al
    ret
Recovery_ShouldAttemptRequest ENDP

; =============================================================================
; Recovery_HandleNoResponse
; RCX = request_id
; =============================================================================
Recovery_HandleNoResponse PROC
    push    rbx
    
    mov     rbx, rcx
    inc     g_no_response_count
    
    cmp     g_enable_autopilot, 0
    je      no_autopilot
    
    cmp     g_autopilot_recovery_active, 1
    je      already_recovering
    
    mov     g_autopilot_recovery_active, 1
    inc     g_autopilot_recovery_count
    mov     g_autopilot_attempt_count, 1
    mov     rax, 1
    jmp     exit_no_response
    
already_recovering:
    mov     eax, g_autopilot_attempt_count
    cmp     eax, g_max_autopilot_attempts
    jge     give_up
    inc     g_autopilot_attempt_count
    mov     rax, 1
    jmp     exit_no_response
    
give_up:
    mov     g_autopilot_recovery_active, 0
    mov     g_autopilot_attempt_count, 0
    xor     rax, rax
    jmp     exit_no_response
    
no_autopilot:
    xor     rax, rax
    
exit_no_response:
    pop     rbx
    ret
Recovery_HandleNoResponse ENDP

; =============================================================================
; Recovery_IsAutopilotRecovery
; =============================================================================
Recovery_IsAutopilotRecovery PROC
    movzx   rax, g_autopilot_recovery_active
    ret
Recovery_IsAutopilotRecovery ENDP

; =============================================================================
; Recovery_AcknowledgeAutopilot
; =============================================================================
Recovery_AcknowledgeAutopilot PROC
    mov     g_autopilot_recovery_active, 0
    mov     g_autopilot_attempt_count, 0
    ret
Recovery_AcknowledgeAutopilot ENDP

; =============================================================================
; Recovery_GetRetryDelay
; =============================================================================
Recovery_GetRetryDelay PROC
    mov     ecx, g_retry_count
    call    Recovery_CalculateBackoff
    ret
Recovery_GetRetryDelay ENDP

; =============================================================================
; Recovery_ConfigureAutopilot
; RCX = max_autopilot_attempts, RDX = autopilot_timeout_ms
; =============================================================================
Recovery_ConfigureAutopilot PROC
    mov     g_max_autopilot_attempts, ecx
    mov     g_autopilot_timeout_ms, edx
    mov     g_enable_autopilot, 1
    ret
Recovery_ConfigureAutopilot ENDP

; =============================================================================
; Telemetry Stubs
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
