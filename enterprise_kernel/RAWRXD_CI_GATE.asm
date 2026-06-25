;=============================================================================
; RAWRXD CI GATE v10.0
; Pure MASM x64 - Governance Enforcement
;=============================================================================
; Hard Gates:
;   - WSI >= 85
;   - ESI >= 80
;   - No critical regression
;   - Memory slope < 10 MB/min
; Soft Gates (warnings):
;   - WSI 85-90
;   - ESI 80-85
;   - Minor latency drift
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Hard Gate Thresholds
;-----------------------------------------------------------------------------
GATE_WSI_HARD       equ 85
GATE_ESI_HARD       equ 80
GATE_MEM_SLOPE      equ 10
GATE_HANDLE_SLOPE   equ 20

;-----------------------------------------------------------------------------
; Soft Gate Thresholds
;-----------------------------------------------------------------------------
GATE_WSI_SOFT       equ 90
GATE_ESI_SOFT       equ 85

;-----------------------------------------------------------------------------
; Gate Status
;-----------------------------------------------------------------------------
gateWSI             db 0
gateESI             db 0
gateRegression      db 0
gateMemory          db 0
gateHandle          db 0
gateFinal           db 0

;-----------------------------------------------------------------------------
; Warning Flags
;-----------------------------------------------------------------------------
warnWSI             db 0
warnESI             db 0
warnLatency         db 0

;-----------------------------------------------------------------------------
; Status Strings
;-----------------------------------------------------------------------------
STATUS_PASS         db "PASS",0
STATUS_FAIL         db "FAIL",0
STATUS_WARN         db "WARN",0

;-----------------------------------------------------------------------------
; External References
;-----------------------------------------------------------------------------
EXTERN wsiFinalScore:DWORD
EXTERN esiFinalScore:DWORD
EXTERN regressionDetected:BYTE
EXTERN driftMemorySlope:QWORD
EXTERN driftHandleSlope:DWORD

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Evaluate WSI Gate
;=============================================================================
Gate_EvaluateWSI PROC
    push rbx
    
    mov eax, wsiFinalScore
    
    ; Check hard gate
    cmp eax, GATE_WSI_HARD
    jb wsiFail
    
    ; Check soft gate (warning)
    cmp eax, GATE_WSI_SOFT
    jae wsiPass
    
    ; Warning zone
    mov warnWSI, 1
    mov gateWSI, 1
    mov eax, 1
    jmp wsiDone
    
wsiPass:
    mov warnWSI, 0
    mov gateWSI, 1
    mov eax, 1
    jmp wsiDone
    
wsiFail:
    mov warnWSI, 0
    mov gateWSI, 0
    xor eax, eax
    
wsiDone:
    pop rbx
    ret
Gate_EvaluateWSI ENDP

;=============================================================================
; Evaluate ESI Gate
;=============================================================================
Gate_EvaluateESI PROC
    push rbx
    
    mov eax, esiFinalScore
    
    ; Check hard gate
    cmp eax, GATE_ESI_HARD
    jb esiFail
    
    ; Check soft gate (warning)
    cmp eax, GATE_ESI_SOFT
    jae esiPass
    
    ; Warning zone
    mov warnESI, 1
    mov gateESI, 1
    mov eax, 1
    jmp esiDone
    
esiPass:
    mov warnESI, 0
    mov gateESI, 1
    mov eax, 1
    jmp esiDone
    
esiFail:
    mov warnESI, 0
    mov gateESI, 0
    xor eax, eax
    
esiDone:
    pop rbx
    ret
Gate_EvaluateESI ENDP

;=============================================================================
; Evaluate Regression Gate
;=============================================================================
Gate_EvaluateRegression PROC
    push rbx
    
    ; Check if any regression detected
    cmp regressionDetected, 0
    jne regFail
    
    mov gateRegression, 1
    mov eax, 1
    jmp regDone
    
regFail:
    mov gateRegression, 0
    xor eax, eax
    
regDone:
    pop rbx
    ret
Gate_EvaluateRegression ENDP

;=============================================================================
; Evaluate Memory Gate
;=============================================================================
Gate_EvaluateMemory PROC
    push rbx
    
    mov rax, driftMemorySlope
    
    ; Check against threshold
    cmp rax, GATE_MEM_SLOPE
    ja memFail
    
    mov gateMemory, 1
    mov eax, 1
    jmp memDone
    
memFail:
    mov gateMemory, 0
    xor eax, eax
    
memDone:
    pop rbx
    ret
Gate_EvaluateMemory ENDP

;=============================================================================
; Evaluate Handle Gate
;=============================================================================
Gate_EvaluateHandle PROC
    push rbx
    
    mov eax, driftHandleSlope
    
    ; Check against threshold
    cmp eax, GATE_HANDLE_SLOPE
    ja handleFail
    
    mov gateHandle, 1
    mov eax, 1
    jmp handleDone
    
handleFail:
    mov gateHandle, 0
    xor eax, eax
    
handleDone:
    pop rbx
    ret
Gate_EvaluateHandle ENDP

;=============================================================================
; CI_EVALUATE - Main CI gate evaluation
;=============================================================================
CI_Evaluate PROC
    push rbx
    push rsi
    push rdi
    
    ; Reset gate status
    mov gateWSI, 0
    mov gateESI, 0
    mov gateRegression, 0
    mov gateMemory, 0
    mov gateHandle, 0
    mov gateFinal, 0
    
    mov warnWSI, 0
    mov warnESI, 0
    mov warnLatency, 0
    
    ; Evaluate all gates
    call Gate_EvaluateWSI
    test eax, eax
    jz ciFail
    
    call Gate_EvaluateESI
    test eax, eax
    jz ciFail
    
    call Gate_EvaluateRegression
    test eax, eax
    jz ciFail
    
    call Gate_EvaluateMemory
    test eax, eax
    jz ciFail
    
    call Gate_EvaluateHandle
    test eax, eax
    jz ciFail
    
    ; All gates passed
    mov gateFinal, 1
    mov eax, 1
    jmp ciDone
    
ciFail:
    mov gateFinal, 0
    xor eax, eax
    
ciDone:
    pop rdi
    pop rsi
    pop rbx
    ret
CI_Evaluate ENDP

;=============================================================================
; CI_GetGateStatus - Get individual gate status
;=============================================================================
CI_GetGateStatus PROC
    ; Returns gate status in registers:
    ;   AL = gateWSI
    ;   AH = gateESI
    ;   BL = gateRegression
    ;   BH = gateMemory
    ;   CL = gateHandle
    ;   CH = gateFinal
    
    mov al, gateWSI
    mov ah, gateESI
    mov bl, gateRegression
    mov bh, gateMemory
    mov cl, gateHandle
    mov ch, gateFinal
    ret
CI_GetGateStatus ENDP

;=============================================================================
; CI_GetWarnings - Get warning flags
;=============================================================================
CI_GetWarnings PROC
    ; Returns warnings in registers:
    ;   AL = warnWSI
    ;   AH = warnESI
    ;   BL = warnLatency
    
    mov al, warnWSI
    mov ah, warnESI
    mov bl, warnLatency
    ret
CI_GetWarnings ENDP

;=============================================================================
; CI_GetFinalStatus - Get final CI status string
;=============================================================================
CI_GetFinalStatus PROC
    ; Returns pointer to status string in RAX
    
    cmp gateFinal, 0
    je ciStatusFail
    
    ; Check for warnings
    cmp warnWSI, 0
    jne ciStatusWarn
    cmp warnESI, 0
    jne ciStatusWarn
    cmp warnLatency, 0
    jne ciStatusWarn
    
    ; All clear
    lea rax, STATUS_PASS
    jmp ciStatusDone
    
ciStatusWarn:
    lea rax, STATUS_WARN
    jmp ciStatusDone
    
ciStatusFail:
    lea rax, STATUS_FAIL
    
ciStatusDone:
    ret
CI_GetFinalStatus ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
