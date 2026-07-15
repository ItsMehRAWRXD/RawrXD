;=============================================================================
; RAWRXD ESI ENGINE v10.0
; Pure MASM x64 - Enterprise Stability Index
;=============================================================================
; Formula:
;   ESI = (WSI * 40) + (TrendMomentum * 25) + (RegressionPenalty * 20) + (Consistency * 15)
;   All divided by 100
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; ESI Weights (fixed-point: 100 = 1.0)
;-----------------------------------------------------------------------------
WEIGHT_WSI          dd 40
WEIGHT_TREND        dd 25
WEIGHT_REGRESSION   dd 20
WEIGHT_CONSISTENCY  dd 15

;-----------------------------------------------------------------------------
; Component Scores (0-100)
;-----------------------------------------------------------------------------
componentWSI        dd 0
componentTrend      dd 0
componentRegression dd 0
componentConsistency dd 0

;-----------------------------------------------------------------------------
; Final ESI Score
;-----------------------------------------------------------------------------
esiFinalScore       dd 0

;-----------------------------------------------------------------------------
; Trend Data (simulated historical)
;-----------------------------------------------------------------------------
wsiHistory          dd 10 dup(85)     ; Last 10 WSI scores
wsiHistoryCount     dd 10
wsiHistoryIndex     dd 0

;-----------------------------------------------------------------------------
; Regression Penalty Data
;-----------------------------------------------------------------------------
regressionMemorySlope   dd 0
regressionHandleSlope   dd 0
regressionLatencyDrift  dd 0

;-----------------------------------------------------------------------------
; Consistency Data
;-----------------------------------------------------------------------------
wsiStdDev           dd 0

;-----------------------------------------------------------------------------
; External References
;-----------------------------------------------------------------------------
EXTERN wsiFinalScore:DWORD
EXTERN regressionDetected:BYTE
EXTERN soakMemDrift:QWORD
EXTERN soakHandleDrift:DWORD

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Calculate Simple Average
;=============================================================================
CalcAverage PROC
    ; RCX = array pointer
    ; EDX = count
    ; Returns average in EAX
    
    push rbx
    push rsi
    
    test edx, edx
    jz avgZero
    
    xor eax, eax
    mov rsi, rcx
    mov ebx, edx
    
sumLoop:
    add eax, [rsi]
    add rsi, 4
    dec ebx
    jnz sumLoop
    
    ; Divide by count
    mov ecx, edx
    xor edx, edx
    div ecx
    
    jmp avgDone
    
avgZero:
    xor eax, eax
    
avgDone:
    pop rsi
    pop rbx
    ret
CalcAverage ENDP

;=============================================================================
; Calculate Trend Momentum
;=============================================================================
CalcTrendMomentum PROC
    ; Returns trend score (0-100) in EAX
    ; Trend = 100 - |current - average| / 100
    
    push rbx
    
    ; Get current WSI
    mov ebx, wsiFinalScore
    
    ; Calculate historical average
    lea rcx, wsiHistory
    mov edx, wsiHistoryCount
    call CalcAverage
    
    ; Calculate absolute difference
    sub ebx, eax
    jns trendPositive
    neg ebx
    
trendPositive:
    ; Trend score = 100 - difference
    mov eax, 100
    sub eax, ebx
    
    ; Clamp to 0-100
    test eax, eax
    jns trendOk
    xor eax, eax
    
trendOk:
    cmp eax, 100
    jbe trendDone
    mov eax, 100
    
trendDone:
    pop rbx
    ret
CalcTrendMomentum ENDP

;=============================================================================
; Calculate Regression Penalty
;=============================================================================
CalcRegressionPenalty PROC
    ; Returns penalty score (0-100, higher = worse) in EAX
    
    push rbx
    
    ; Check if regression detected
    cmp regressionDetected, 0
    je noRegression
    
    ; Calculate penalty based on drift metrics
    ; Penalty = (mem_slope * 30 + handle_slope * 20 + latency * 50) / 100
    
    ; Memory drift component
    mov eax, dword ptr soakMemDrift
    imul eax, 30
    mov ebx, eax
    
    ; Handle drift component
    mov eax, soakHandleDrift
    imul eax, 20
    add ebx, eax
    
    ; Latency component (simplified)
    mov eax, 10                         ; Assume 10% latency drift
    imul eax, 50
    add ebx, eax
    
    ; Divide by 100
    mov eax, ebx
    mov ecx, 100
    xor edx, edx
    div ecx
    
    ; Clamp to 0-100
    cmp eax, 100
    jbe regOk
    mov eax, 100
    jmp regDone
    
noRegression:
    xor eax, eax
    
regOk:
regDone:
    pop rbx
    ret
CalcRegressionPenalty ENDP

;=============================================================================
; Calculate Consistency Score
;=============================================================================
CalcConsistency PROC
    ; Returns consistency score (0-100) in EAX
    ; Consistency = 100 - StdDev(WSI_history)
    
    push rbx
    push rsi
    push rdi
    
    ; Calculate average
    lea rcx, wsiHistory
    mov edx, wsiHistoryCount
    call CalcAverage
    mov ebx, eax                        ; EBX = average
    
    ; Calculate variance sum
    lea rsi, wsiHistory
    mov ecx, wsiHistoryCount
    xor edi, edi                        ; EDI = variance sum
    
varianceLoop:
    mov eax, [rsi]
    sub eax, ebx
    imul eax, eax                       ; Square the difference
    add edi, eax
    add rsi, 4
    dec ecx
    jnz varianceLoop
    
    ; Calculate variance = sum / count
    mov eax, edi
    mov ecx, wsiHistoryCount
    xor edx, edx
    div ecx
    
    ; Calculate standard deviation (simplified: sqrt via approximation)
    ; For now, use variance directly as proxy
    mov ebx, eax
    
    ; Consistency = 100 - StdDev
    mov eax, 100
    sub eax, ebx
    
    ; Clamp to 0-100
    test eax, eax
    jns consOk
    xor eax, eax
    
consOk:
    cmp eax, 100
    jbe consDone
    mov eax, 100
    
consDone:
    pop rdi
    pop rsi
    pop rbx
    ret
CalcConsistency ENDP

;=============================================================================
; ESI_COMPUTE - Calculate Enterprise Stability Index
;=============================================================================
ESI_Compute PROC
    push rbx
    push rsi
    push rdi
    
    ;-------------------------------------------------------------------------
    ; Component 1: WSI (40%)
    ;-------------------------------------------------------------------------
    mov eax, wsiFinalScore
    mov componentWSI, eax
    
    ; Apply weight: WSI * 40
    imul eax, 40
    mov ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Component 2: Trend Momentum (25%)
    ;-------------------------------------------------------------------------
    call CalcTrendMomentum
    mov componentTrend, eax
    
    ; Apply weight: Trend * 25
    imul eax, 25
    add ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Component 3: Regression Penalty (20%)
    ;-------------------------------------------------------------------------
    call CalcRegressionPenalty
    mov componentRegression, eax
    
    ; Apply weight: (100 - Regression) * 20
    ; Note: We invert because penalty reduces score
    mov ecx, 100
    sub ecx, eax
    imul ecx, 20
    add ebx, ecx
    
    ;-------------------------------------------------------------------------
    ; Component 4: Consistency (15%)
    ;-------------------------------------------------------------------------
    call CalcConsistency
    mov componentConsistency, eax
    
    ; Apply weight: Consistency * 15
    imul eax, 15
    add ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Final ESI = weighted sum / 100
    ;-------------------------------------------------------------------------
    mov eax, ebx
    mov ecx, 100
    xor edx, edx
    div ecx
    
    ; Clamp to 0-100
    cmp eax, 100
    jbe esiOk
    mov eax, 100
    
esiOk:
    mov esiFinalScore, eax
    
    pop rdi
    pop rsi
    pop rbx
    ret
ESI_Compute ENDP

;=============================================================================
; ESI_GetComponentScores - Get individual component scores
;=============================================================================
ESI_GetComponentScores PROC
    ; Returns component scores in registers:
    ;   EAX = WSI component
    ;   EDX = Trend component
    ;   ECX = Regression component
    ;   R8D = Consistency component
    
    mov eax, componentWSI
    mov edx, componentTrend
    mov ecx, componentRegression
    mov r8d, componentConsistency
    ret
ESI_GetComponentScores ENDP

;=============================================================================
; ESI_UpdateHistory - Add current WSI to history
;=============================================================================
ESI_UpdateHistory PROC
    push rbx
    
    ; Get current index
    mov eax, wsiHistoryIndex
    mov ebx, eax
    
    ; Store current WSI
    lea rcx, wsiHistory
    mov edx, wsiFinalScore
    mov [rcx + rbx*4], edx
    
    ; Increment index (wrap around)
    inc ebx
    cmp ebx, wsiHistoryCount
    jb indexOk
    xor ebx, ebx
    
indexOk:
    mov wsiHistoryIndex, ebx
    
    pop rbx
    ret
ESI_UpdateHistory ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
