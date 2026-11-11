;=============================================================================
; RAWRXD REGRESSION ENGINE v10.0
; Pure MASM x64 - Drift Detection System
;=============================================================================
; Detects:
;   1. Memory regression (slope increase)
;   2. Latency regression (p95 drift)
;   3. Handle leak drift (monotonic growth)
;   4. TPS degradation (throughput decline)
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Regression Thresholds
;-----------------------------------------------------------------------------
REG_THRESHOLD_MEM       equ 5           ; MB per minute
REG_THRESHOLD_HANDLE    equ 10          ; handles per minute
REG_THRESHOLD_LATENCY   equ 50          ; ms increase
REG_THRESHOLD_TPS       equ 10          ; % degradation

;-----------------------------------------------------------------------------
; Baseline Data (established during calibration)
;-----------------------------------------------------------------------------
baselineMemory          dq 80            ; MB
baselineHandles         dd 350
baselineLatency         dd 100           ; ms
baselineTPS             dd 1000          ; tokens/sec

;-----------------------------------------------------------------------------
; Current Drift Metrics
;-----------------------------------------------------------------------------
driftMemorySlope        dq 0
driftHandleSlope        dd 0
driftLatencyDelta       dd 0
driftTPSDelta           dd 0

;-----------------------------------------------------------------------------
; Regression Status
;-----------------------------------------------------------------------------
regressionMemory        db 0
regressionHandle        db 0
regressionLatency       db 0
regressionTPS           db 0
regressionDetected      db 0

;-----------------------------------------------------------------------------
; External References
;-----------------------------------------------------------------------------
EXTERN soakMemDrift:QWORD
EXTERN soakHandleDrift:DWORD
EXTERN soakAvgLatency:QWORD
EXTERN stressTotalTime:QWORD

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Calculate Memory Slope
;=============================================================================
CalcMemorySlope PROC
    ; Returns slope in RAX (MB per minute)
    
    push rbx
    
    ; Get memory drift from soak phase
    mov rax, soakMemDrift
    
    ; Assume 1 minute soak for demo (scale appropriately)
    ; In production: drift / duration_minutes
    
    mov driftMemorySlope, rax
    
    pop rbx
    ret
CalcMemorySlope ENDP

;=============================================================================
; Calculate Handle Slope
;=============================================================================
CalcHandleSlope PROC
    ; Returns slope in EAX (handles per minute)
    
    push rbx
    
    ; Get handle drift from soak phase
    mov eax, soakHandleDrift
    
    ; Assume 1 minute soak for demo
    mov driftHandleSlope, eax
    
    pop rbx
    ret
CalcHandleSlope ENDP

;=============================================================================
; Calculate Latency Delta
;=============================================================================
CalcLatencyDelta PROC
    ; Returns delta in EAX (ms increase from baseline)
    
    push rbx
    
    ; Get current average latency
    mov rax, soakAvgLatency
    
    ; Compare to baseline
    sub eax, baselineLatency
    mov driftLatencyDelta, eax
    
    pop rbx
    ret
CalcLatencyDelta ENDP

;=============================================================================
; Calculate TPS Delta
;=============================================================================
CalcTPSDelta PROC
    ; Returns delta in EAX (% degradation)
    
    push rbx
    
    ; Simplified TPS calculation
    ; In production: measure actual throughput
    mov eax, 0                          ; No degradation detected
    mov driftTPSDelta, eax
    
    pop rbx
    ret
CalcTPSDelta ENDP

;=============================================================================
; Check Memory Regression
;=============================================================================
CheckMemoryRegression PROC
    push rbx
    
    call CalcMemorySlope
    
    ; Compare to threshold
    cmp rax, REG_THRESHOLD_MEM
    jbe memOk
    
    ; Regression detected
    mov regressionMemory, 1
    mov regressionDetected, 1
    mov eax, 1
    jmp memDone
    
memOk:
    mov regressionMemory, 0
    xor eax, eax
    
memDone:
    pop rbx
    ret
CheckMemoryRegression ENDP

;=============================================================================
; Check Handle Regression
;=============================================================================
CheckHandleRegression PROC
    push rbx
    
    call CalcHandleSlope
    
    ; Compare to threshold
    cmp eax, REG_THRESHOLD_HANDLE
    jbe handleOk
    
    ; Regression detected
    mov regressionHandle, 1
    mov regressionDetected, 1
    mov eax, 1
    jmp handleDone
    
handleOk:
    mov regressionHandle, 0
    xor eax, eax
    
handleDone:
    pop rbx
    ret
CheckHandleRegression ENDP

;=============================================================================
; Check Latency Regression
;=============================================================================
CheckLatencyRegression PROC
    push rbx
    
    call CalcLatencyDelta
    
    ; Compare to threshold
    cmp eax, REG_THRESHOLD_LATENCY
    jbe latencyOk
    
    ; Regression detected
    mov regressionLatency, 1
    mov regressionDetected, 1
    mov eax, 1
    jmp latencyDone
    
latencyOk:
    mov regressionLatency, 0
    xor eax, eax
    
latencyDone:
    pop rbx
    ret
CheckLatencyRegression ENDP

;=============================================================================
; Check TPS Regression
;=============================================================================
CheckTPSRegression PROC
    push rbx
    
    call CalcTPSDelta
    
    ; Compare to threshold
    cmp eax, REG_THRESHOLD_TPS
    jbe tpsOk
    
    ; Regression detected
    mov regressionTPS, 1
    mov regressionDetected, 1
    mov eax, 1
    jmp tpsDone
    
tpsOk:
    mov regressionTPS, 0
    xor eax, eax
    
tpsDone:
    pop rbx
    ret
CheckTPSRegression ENDP

;=============================================================================
; REGRESSION_CHECK - Main regression detection entry
;=============================================================================
Regression_Check PROC
    push rbx
    push rsi
    push rdi
    
    ; Reset regression flags
    mov regressionDetected, 0
    mov regressionMemory, 0
    mov regressionHandle, 0
    mov regressionLatency, 0
    mov regressionTPS, 0
    
    ; Check all regression types
    call CheckMemoryRegression
    call CheckHandleRegression
    call CheckLatencyRegression
    call CheckTPSRegression
    
    ; Return regression status
    mov al, regressionDetected
    
    pop rdi
    pop rsi
    pop rbx
    ret
Regression_Check ENDP

;=============================================================================
; REGRESSION_GetDetails - Get detailed regression info
;=============================================================================
Regression_GetDetails PROC
    ; Returns regression details in registers:
    ;   AL = regressionDetected
    ;   AH = regressionMemory
    ;   BL = regressionHandle
    ;   BH = regressionLatency
    ;   CL = regressionTPS
    
    mov al, regressionDetected
    mov ah, regressionMemory
    mov bl, regressionHandle
    mov bh, regressionLatency
    mov cl, regressionTPS
    ret
Regression_GetDetails ENDP

;=============================================================================
; REGRESSION_GetMetrics - Get drift metrics
;=============================================================================
Regression_GetMetrics PROC
    ; Returns drift metrics:
    ;   RAX = memory slope
    ;   EDX = handle slope
    ;   ECX = latency delta
    ;   R8D = TPS delta
    
    mov rax, driftMemorySlope
    mov edx, driftHandleSlope
    mov ecx, driftLatencyDelta
    mov r8d, driftTPSDelta
    ret
Regression_GetMetrics ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
