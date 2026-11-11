;=============================================================================
; RAWRXD WSI ENGINE v10.0
; Pure MASM x64 - Weighted Stability Index
;=============================================================================
; Formula:
;   WSI = (Smoke * 20 + Integration * 25 + Stress * 25 + Soak * 30) / 100
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Phase Weights (fixed-point: 100 = 1.0)
;-----------------------------------------------------------------------------
WEIGHT_SMOKE        dd 20
WEIGHT_INTEGRATION  dd 25
WEIGHT_STRESS       dd 25
WEIGHT_SOAK         dd 30

;-----------------------------------------------------------------------------
; Phase Scores (0-100)
;-----------------------------------------------------------------------------
scoreSmoke          dd 0
scoreIntegration    dd 0
scoreStress         dd 0
scoreSoak           dd 0

;-----------------------------------------------------------------------------
; Final WSI Score
;-----------------------------------------------------------------------------
wsiFinalScore       dd 0

;-----------------------------------------------------------------------------
; Phase Status (externally set by test modules)
;-----------------------------------------------------------------------------
EXTERN smokeTestsPassed:DWORD
EXTERN smokeTestsFailed:DWORD
EXTERN intTestsPassed:DWORD
EXTERN intTestsFailed:DWORD
EXTERN stressPassed:DWORD
EXTERN stressFailed:DWORD
EXTERN soakTestsPassed:DWORD
EXTERN soakTestsFailed:DWORD

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Calculate Phase Score
;=============================================================================
CalcPhaseScore PROC
    ; ECX = passed count
    ; EDX = failed count
    ; Returns score (0-100) in EAX
    
    push rbx
    
    ; Total = passed + failed
    mov eax, ecx
    add eax, edx
    test eax, eax
    jz zeroScore
    
    ; Score = (passed * 100) / total
    imul ecx, 100
    xor edx, edx
    div eax
    
    jmp calcDone
    
zeroScore:
    xor eax, eax
    
calcDone:
    pop rbx
    ret
CalcPhaseScore ENDP

;=============================================================================
; WSI_COMPUTE - Calculate Weighted Stability Index
;=============================================================================
WSI_Compute PROC
    push rbx
    push rsi
    push rdi
    
    ;-------------------------------------------------------------------------
    ; Calculate Smoke Score (20%)
    ;-------------------------------------------------------------------------
    mov ecx, smokeTestsPassed
    mov edx, smokeTestsFailed
    call CalcPhaseScore
    mov scoreSmoke, eax
    
    ; Apply weight: score * 20
    imul eax, 20
    mov ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Calculate Integration Score (25%)
    ;-------------------------------------------------------------------------
    mov ecx, intTestsPassed
    mov edx, intTestsFailed
    call CalcPhaseScore
    mov scoreIntegration, eax
    
    ; Apply weight: score * 25
    imul eax, 25
    add ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Calculate Stress Score (25%)
    ;-------------------------------------------------------------------------
    mov ecx, stressPassed
    mov edx, stressFailed
    call CalcPhaseScore
    mov scoreStress, eax
    
    ; Apply weight: score * 25
    imul eax, 25
    add ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Calculate Soak Score (30%)
    ;-------------------------------------------------------------------------
    mov ecx, soakTestsPassed
    mov edx, soakTestsFailed
    call CalcPhaseScore
    mov scoreSoak, eax
    
    ; Apply weight: score * 30
    imul eax, 30
    add ebx, eax
    
    ;-------------------------------------------------------------------------
    ; Final WSI = weighted sum / 100
    ;-------------------------------------------------------------------------
    mov eax, ebx
    mov ecx, 100
    xor edx, edx
    div ecx
    
    ; Clamp to 0-100
    cmp eax, 100
    jbe wsiOk
    mov eax, 100
    
wsiOk:
    mov wsiFinalScore, eax
    
    pop rdi
    pop rsi
    pop rbx
    ret
WSI_Compute ENDP

;=============================================================================
; WSI_GetPhaseScores - Get individual phase scores
;=============================================================================
WSI_GetPhaseScores PROC
    ; Returns phase scores in registers:
    ;   EAX = Smoke score
    ;   EDX = Integration score
    ;   ECX = Stress score
    ;   R8D = Soak score
    
    mov eax, scoreSmoke
    mov edx, scoreIntegration
    mov ecx, scoreStress
    mov r8d, scoreSoak
    ret
WSI_GetPhaseScores ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
