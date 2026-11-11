; RawrXD_Recovery_Telemetry.asm
; Telemetry integration for Error Recovery System
; Exports RecoveryStats to sovereign_metrics_collector

; =============================================================================
; External Functions
; =============================================================================
EXTERNDEF GetTickCount64:PROC
EXTERNDEF Telemetry_LogMetric:PROC
EXTERNDEF Telemetry_LogEvent:PROC

; =============================================================================
; Public Functions
; =============================================================================
PUBLIC RecoveryTelemetry_Init
PUBLIC RecoveryTelemetry_ExportStats
PUBLIC RecoveryTelemetry_LogCircuitBreakerChange
PUBLIC RecoveryTelemetry_LogAutopilotActivation
PUBLIC RecoveryTelemetry_LogNoResponse
PUBLIC RecoveryTelemetry_LogRecoverySuccess

; =============================================================================
; Constants
; =============================================================================
METRIC_TYPE_GAUGE     EQU 0
METRIC_TYPE_COUNTER   EQU 1
METRIC_TYPE_HISTOGRAM EQU 2

EVENT_LEVEL_INFO      EQU 0
EVENT_LEVEL_WARNING   EQU 1
EVENT_LEVEL_ERROR     EQU 2

; Metric IDs for recovery system
METRIC_RECOVERY_TOTAL_REQUESTS       EQU 1000
METRIC_RECOVERY_SUCCESSFUL_REQUESTS  EQU 1001
METRIC_RECOVERY_FAILED_REQUESTS      EQU 1002
METRIC_RECOVERY_RECOVERED_REQUESTS   EQU 1003
METRIC_RECOVERY_NO_RESPONSE_COUNT    EQU 1004
METRIC_RECOVERY_AUTOPILOT_COUNT      EQU 1005
METRIC_RECOVERY_CIRCUIT_STATE        EQU 1006
METRIC_RECOVERY_FALLBACK_ACTIVE      EQU 1007
METRIC_RECOVERY_AUTOPILOT_ACTIVE     EQU 1008
METRIC_RECOVERY_RETRY_DELAY_MS       EQU 1009

; Event IDs
EVENT_CIRCUIT_BREAKER_CHANGE         EQU 2000
EVENT_AUTOPILOT_ACTIVATED            EQU 2001
EVENT_AUTOPILOT_COMPLETED            EQU 2002
EVENT_NO_RESPONSE_DETECTED           EQU 2003
EVENT_RECOVERY_SUCCESS               EQU 2004

; =============================================================================
; Data Section
; =============================================================================
.data

; Circuit breaker state names for logging
cb_state_closed     db "CLOSED", 0
cb_state_open       db "OPEN", 0
cb_state_half_open  db "HALF_OPEN", 0
cb_state_names      DQ cb_state_closed, cb_state_open, cb_state_half_open

; Event message templates
event_msg_cb_change     db "Circuit breaker state changed: %s -> %s", 0
event_msg_autopilot     db "Autopilot recovery activated for request %llu", 0
event_msg_no_response   db "No response detected for request %llu", 0
event_msg_recovery      db "Request recovered after %d retry attempts", 0

; Metric names (for Prometheus export)
metric_name_total_requests      db "recovery_total_requests", 0
metric_name_successful          db "recovery_successful_requests", 0
metric_name_failed              db "recovery_failed_requests", 0
metric_name_recovered           db "recovery_recovered_requests", 0
metric_name_no_response         db "recovery_no_response_count", 0
metric_name_autopilot           db "recovery_autopilot_count", 0
metric_name_circuit_state       db "recovery_circuit_state", 0
metric_name_fallback_active     db "recovery_fallback_active", 0
metric_name_autopilot_active    db "recovery_autopilot_active", 0

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; RecoveryTelemetry_Init
; Initialize recovery telemetry system
; =============================================================================
RecoveryTelemetry_Init PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    ; Register all recovery metrics with the telemetry system
    ; Metric: total_requests
    mov     ecx, METRIC_RECOVERY_TOTAL_REQUESTS
    lea     rdx, metric_name_total_requests
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: successful_requests
    mov     ecx, METRIC_RECOVERY_SUCCESSFUL_REQUESTS
    lea     rdx, metric_name_successful
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: failed_requests
    mov     ecx, METRIC_RECOVERY_FAILED_REQUESTS
    lea     rdx, metric_name_failed
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: recovered_requests
    mov     ecx, METRIC_RECOVERY_RECOVERED_REQUESTS
    lea     rdx, metric_name_recovered
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: no_response_count
    mov     ecx, METRIC_RECOVERY_NO_RESPONSE_COUNT
    lea     rdx, metric_name_no_response
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: autopilot_count
    mov     ecx, METRIC_RECOVERY_AUTOPILOT_COUNT
    lea     rdx, metric_name_autopilot
    mov     r8d, METRIC_TYPE_COUNTER
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: circuit_state (gauge)
    mov     ecx, METRIC_RECOVERY_CIRCUIT_STATE
    lea     rdx, metric_name_circuit_state
    mov     r8d, METRIC_TYPE_GAUGE
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: fallback_active (gauge)
    mov     ecx, METRIC_RECOVERY_FALLBACK_ACTIVE
    lea     rdx, metric_name_fallback_active
    mov     r8d, METRIC_TYPE_GAUGE
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    ; Metric: autopilot_active (gauge)
    mov     ecx, METRIC_RECOVERY_AUTOPILOT_ACTIVE
    lea     rdx, metric_name_autopilot_active
    mov     r8d, METRIC_TYPE_GAUGE
    xor     r9d, r9d
    call    Telemetry_RegisterMetric
    
    mov     rax, 1      ; Success
    pop     rbx
    ret
RecoveryTelemetry_Init ENDP

; =============================================================================
; RecoveryTelemetry_ExportStats
; Export RecoveryStats to telemetry system
; RCX = pointer to RecoveryStats structure
; =============================================================================
RecoveryTelemetry_ExportStats PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog
    
    mov     rbx, rcx        ; RBX = RecoveryStats pointer
    
    ; Export total_requests
    mov     ecx, METRIC_RECOVERY_TOTAL_REQUESTS
    mov     rdx, [rbx + 0]      ; total_requests
    call    Telemetry_UpdateCounter
    
    ; Export successful_requests
    mov     ecx, METRIC_RECOVERY_SUCCESSFUL_REQUESTS
    mov     rdx, [rbx + 8]      ; successful_requests
    call    Telemetry_UpdateCounter
    
    ; Export failed_requests
    mov     ecx, METRIC_RECOVERY_FAILED_REQUESTS
    mov     rdx, [rbx + 16]     ; failed_requests
    call    Telemetry_UpdateCounter
    
    ; Export recovered_requests
    mov     ecx, METRIC_RECOVERY_RECOVERED_REQUESTS
    mov     rdx, [rbx + 24]     ; recovered_requests
    call    Telemetry_UpdateCounter
    
    ; Export no_response_count
    mov     ecx, METRIC_RECOVERY_NO_RESPONSE_COUNT
    mov     rdx, [rbx + 32]     ; no_response_count
    call    Telemetry_UpdateCounter
    
    ; Export autopilot_recovery_count
    mov     ecx, METRIC_RECOVERY_AUTOPILOT_COUNT
    mov     rdx, [rbx + 40]     ; autopilot_recovery_count
    call    Telemetry_UpdateCounter
    
    ; Export cb_state (gauge)
    mov     ecx, METRIC_RECOVERY_CIRCUIT_STATE
    mov     edx, [rbx + 48]     ; cb_state
    call    Telemetry_UpdateGauge
    
    ; Export fallback_active (gauge)
    mov     ecx, METRIC_RECOVERY_FALLBACK_ACTIVE
    movzx   edx, BYTE PTR [rbx + 52]    ; fallback_active
    call    Telemetry_UpdateGauge
    
    ; Export autopilot_recovery_active (gauge)
    mov     ecx, METRIC_RECOVERY_AUTOPILOT_ACTIVE
    movzx   edx, BYTE PTR [rbx + 53]    ; autopilot_recovery_active
    call    Telemetry_UpdateGauge
    
    pop     rsi
    pop     rbx
    ret
RecoveryTelemetry_ExportStats ENDP

; =============================================================================
; RecoveryTelemetry_LogCircuitBreakerChange
; Log circuit breaker state change event
; RCX = old_state
; RDX = new_state
; =============================================================================
RecoveryTelemetry_LogCircuitBreakerChange PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    sub     rsp, 256
    .allocstack 256
    .endprolog
    
    mov     rbx, rcx        ; RBX = old_state
    mov     rdi, rdx        ; RDI = new_state
    
    ; Format event message
    lea     r8, [rsp + 128]     ; Buffer for formatted message
    
    ; Get state names
    lea     rax, cb_state_names
    mov     rcx, [rax + rbx * 8]    ; Old state name
    mov     rdx, [rax + rdi * 8]    ; New state name
    
    ; Log structured event
    mov     ecx, EVENT_CIRCUIT_BREAKER_CHANGE
    mov     edx, EVENT_LEVEL_WARNING
    lea     r8, event_msg_cb_change
    mov     r9, rcx             ; Old state name
    mov     [rsp + 32], rdx     ; New state name
    call    Telemetry_LogEvent
    
    add     rsp, 256
    pop     rdi
    pop     rbx
    ret
RecoveryTelemetry_LogCircuitBreakerChange ENDP

; =============================================================================
; RecoveryTelemetry_LogAutopilotActivation
; Log autopilot activation event
; RCX = request_id
; =============================================================================
RecoveryTelemetry_LogAutopilotActivation PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx        ; RBX = request_id
    
    ; Log structured event
    mov     ecx, EVENT_AUTOPILOT_ACTIVATED
    mov     edx, EVENT_LEVEL_WARNING
    lea     r8, event_msg_autopilot
    mov     r9, rbx
    call    Telemetry_LogEvent
    
    pop     rbx
    ret
RecoveryTelemetry_LogAutopilotActivation ENDP

; =============================================================================
; RecoveryTelemetry_LogNoResponse
; Log no response detected event
; RCX = request_id
; =============================================================================
RecoveryTelemetry_LogNoResponse PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx        ; RBX = request_id
    
    ; Log structured event
    mov     ecx, EVENT_NO_RESPONSE_DETECTED
    mov     edx, EVENT_LEVEL_ERROR
    lea     r8, event_msg_no_response
    mov     r9, rbx
    call    Telemetry_LogEvent
    
    pop     rbx
    ret
RecoveryTelemetry_LogNoResponse ENDP

; =============================================================================
; RecoveryTelemetry_LogRecoverySuccess
; Log successful recovery event
; RCX = retry_count
; =============================================================================
RecoveryTelemetry_LogRecoverySuccess PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     ebx, ecx        ; RBX = retry_count
    
    ; Log structured event
    mov     ecx, EVENT_RECOVERY_SUCCESS
    mov     edx, EVENT_LEVEL_INFO
    lea     r8, event_msg_recovery
    mov     r9d, ebx
    call    Telemetry_LogEvent
    
    pop     rbx
    ret
RecoveryTelemetry_LogRecoverySuccess ENDP

; =============================================================================
; Stubs for telemetry system functions (to be linked with actual implementation)
; =============================================================================
Telemetry_RegisterMetric PROC
    mov     rax, 1
    ret
Telemetry_RegisterMetric ENDP

Telemetry_UpdateCounter PROC
    ret
Telemetry_UpdateCounter ENDP

Telemetry_UpdateGauge PROC
    ret
Telemetry_UpdateGauge ENDP

Telemetry_LogEvent PROC
    ret
Telemetry_LogEvent ENDP

END
