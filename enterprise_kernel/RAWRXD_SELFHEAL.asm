;=============================================================================
; RAWRXD SELF-HEAL ENGINE v10.0
; Pure MASM x64 - Subsystem Diagnosis & Recovery
;=============================================================================
; Maps failures to likely subsystems:
;   1 = Memory (allocator / cache layer)
;   2 = LSP (language server)
;   3 = AI Router (inference routing)
;   4 = Threading (async scheduler)
;   5 = UI (rendering layer)
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Subsystem IDs
;-----------------------------------------------------------------------------
SUBSYSTEM_MEMORY    equ 1
SUBSYSTEM_LSP       equ 2
SUBSYSTEM_AIROUTER  equ 3
SUBSYSTEM_THREADING   equ 4
SUBSYSTEM_UI        equ 5
SUBSYSTEM_UNKNOWN   equ 0

;-----------------------------------------------------------------------------
; Failure Signatures
;-----------------------------------------------------------------------------
SIG_MEMORY_DRIFT    equ 1
SIG_HANDLE_LEAK     equ 2
SIG_LATENCY_SPIKE   equ 3
SIG_THREAD_GROWTH   equ 4
SIG_UI_FREEZE       equ 5
SIG_LSP_TIMEOUT     equ 6
SIG_AI_FAIL         equ 7

;-----------------------------------------------------------------------------
; Diagnosis Results
;-----------------------------------------------------------------------------
diagnosedSubsystem  dd 0
diagnosisConfidence dd 0
failureSignature    dd 0

;-----------------------------------------------------------------------------
; External References
;-----------------------------------------------------------------------------
EXTERN regressionMemory:BYTE
EXTERN regressionHandle:BYTE
EXTERN regressionLatency:BYTE
EXTERN regressionTPS:BYTE
EXTERN driftMemorySlope:QWORD
EXTERN driftHandleSlope:DWORD
EXTERN soakThreadDrift:DWORD

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Analyze Memory Failure
;=============================================================================
Analyze_Memory PROC
    push rbx
    
    ; Check memory regression
    cmp regressionMemory, 0
    je memNoIssue
    
    ; Memory drift detected
    mov failureSignature, SIG_MEMORY_DRIFT
    mov diagnosedSubsystem, SUBSYSTEM_MEMORY
    mov diagnosisConfidence, 95
    mov eax, SUBSYSTEM_MEMORY
    jmp memDone
    
memNoIssue:
    xor eax, eax
    
memDone:
    pop rbx
    ret
Analyze_Memory ENDP

;=============================================================================
; Analyze Handle Failure
;=============================================================================
Analyze_Handle PROC
    push rbx
    
    ; Check handle leak
    cmp regressionHandle, 0
    je handleNoIssue
    
    ; Handle leak detected
    mov failureSignature, SIG_HANDLE_LEAK
    mov diagnosedSubsystem, SUBSYSTEM_MEMORY
    mov diagnosisConfidence, 90
    mov eax, SUBSYSTEM_MEMORY
    jmp handleDone
    
handleNoIssue:
    xor eax, eax
    
handleDone:
    pop rbx
    ret
Analyze_Handle ENDP

;=============================================================================
; Analyze Latency Failure
;=============================================================================
Analyze_Latency PROC
    push rbx
    
    ; Check latency regression
    cmp regressionLatency, 0
    je latencyNoIssue
    
    ; Latency spike detected
    mov failureSignature, SIG_LATENCY_SPIKE
    
    ; Determine likely subsystem based on latency characteristics
    ; For now, assume LSP or AI Router
    mov diagnosedSubsystem, SUBSYSTEM_LSP
    mov diagnosisConfidence, 70
    mov eax, SUBSYSTEM_LSP
    jmp latencyDone
    
latencyNoIssue:
    xor eax, eax
    
latencyDone:
    pop rbx
    ret
Analyze_Latency ENDP

;=============================================================================
; Analyze Thread Failure
;=============================================================================
Analyze_Thread PROC
    push rbx
    
    ; Check thread growth
    mov eax, soakThreadDrift
    cmp eax, 5
    jb threadNoIssue
    
    ; Thread growth detected
    mov failureSignature, SIG_THREAD_GROWTH
    mov diagnosedSubsystem, SUBSYSTEM_THREADING
    mov diagnosisConfidence, 85
    mov eax, SUBSYSTEM_THREADING
    jmp threadDone
    
threadNoIssue:
    xor eax, eax
    
threadDone:
    pop rbx
    ret
Analyze_Thread ENDP

;=============================================================================
; Analyze TPS Failure
;=============================================================================
Analyze_TPS PROC
    push rbx
    
    ; Check TPS regression
    cmp regressionTPS, 0
    je tpsNoIssue
    
    ; TPS degradation detected
    mov failureSignature, SIG_AI_FAIL
    mov diagnosedSubsystem, SUBSYSTEM_AIROUTER
    mov diagnosisConfidence, 80
    mov eax, SUBSYSTEM_AIROUTER
    jmp tpsDone
    
tpsNoIssue:
    xor eax, eax
    
tpsDone:
    pop rbx
    ret
Analyze_TPS ENDP

;=============================================================================
; SELFHEAL_ANALYZE - Main diagnosis entry
;=============================================================================
SelfHeal_Analyze PROC
    push rbx
    push rsi
    push rdi
    
    ; Reset diagnosis
    mov diagnosedSubsystem, SUBSYSTEM_UNKNOWN
    mov diagnosisConfidence, 0
    mov failureSignature, 0
    
    ; Analyze in priority order
    
    ; Priority 1: Memory issues
    call Analyze_Memory
    test eax, eax
    jnz healDone
    
    ; Priority 2: Handle leaks
    call Analyze_Handle
    test eax, eax
    jnz healDone
    
    ; Priority 3: Thread growth
    call Analyze_Thread
    test eax, eax
    jnz healDone
    
    ; Priority 4: Latency issues
    call Analyze_Latency
    test eax, eax
    jnz healDone
    
    ; Priority 5: TPS issues
    call Analyze_TPS
    test eax, eax
    jnz healDone
    
    ; No specific issue detected
    mov diagnosedSubsystem, SUBSYSTEM_UNKNOWN
    mov diagnosisConfidence, 100
    xor eax, eax
    
healDone:
    mov eax, diagnosedSubsystem
    
    pop rdi
    pop rsi
    pop rbx
    ret
SelfHeal_Analyze ENDP

;=============================================================================
; SELFHEAL_GetDiagnosis - Get diagnosis details
;=============================================================================
SelfHeal_GetDiagnosis PROC
    ; Returns diagnosis in registers:
    ;   EAX = diagnosedSubsystem
    ;   EDX = diagnosisConfidence
    ;   ECX = failureSignature
    
    mov eax, diagnosedSubsystem
    mov edx, diagnosisConfidence
    mov ecx, failureSignature
    ret
SelfHeal_GetDiagnosis ENDP

;=============================================================================
; SELFHEAL_GetSubsystemName - Get subsystem name string
;=============================================================================
SelfHeal_GetSubsystemName PROC
    ; Input: ECX = subsystem ID
    ; Returns: RAX = pointer to name string
    
    cmp ecx, SUBSYSTEM_MEMORY
    je nameMemory
    cmp ecx, SUBSYSTEM_LSP
    je nameLSP
    cmp ecx, SUBSYSTEM_AIROUTER
    je nameAI
    cmp ecx, SUBSYSTEM_THREADING
    je nameThread
    cmp ecx, SUBSYSTEM_UI
    je nameUI
    
    ; Unknown
    lea rax, strUnknown
    jmp nameDone
    
nameMemory:
    lea rax, strMemory
    jmp nameDone
    
nameLSP:
    lea rax, strLSP
    jmp nameDone
    
nameAI:
    lea rax, strAI
    jmp nameDone
    
nameThread:
    lea rax, strThread
    jmp nameDone
    
nameUI:
    lea rax, strUI
    
nameDone:
    ret

strMemory   db "Memory/Cache",0
strLSP      db "LSP/Language Server",0
strAI       db "AI Router",0
strThread   db "Threading/Scheduler",0
strUI       db "UI/Rendering",0
strUnknown  db "Unknown",0

SelfHeal_GetSubsystemName ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
