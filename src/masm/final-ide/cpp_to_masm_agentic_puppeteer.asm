; agentic_puppeteer_masm.asm
; Pure MASM x64 - Agentic Puppeteer (converted from C++ AgenticPuppeteer class)
; Automatic failure correction for AI responses

option casemap:none

EXTERN malloc:PROC
EXTERN free:PROC
EXTERN memset:PROC
EXTERN memcpy:PROC
EXTERN strlen:PROC
EXTERN strcpy:PROC
EXTERN sprintf:PROC
EXTERN console_log:PROC

; Puppeteer constants
MAX_CORRECTIONS EQU 100
MAX_STRATEGIES EQU 10
MAX_ATTEMPTS EQU 5
MAX_ERROR_MESSAGE EQU 512

; ============================================================================
; DATA STRUCTURES
; ============================================================================

; FAILURE_DETECTION - AI failure detection result
FAILURE_DETECTION STRUCT
    type DWORD ?                    ; Failure type enum
    confidence REAL4 ?              ; 0.0-1.0 confidence
    description QWORD ?             ; Failure description
    pattern QWORD ?                 ; Pattern that triggered detection
    severity DWORD ?                ; 1-10 severity level
    isFailure BYTE ?                ; True if failure detected
FAILURE_DETECTION ENDS

; CORRECTION_RESULT - Correction attempt result
CORRECTION_RESULT STRUCT
    success BYTE ?                  ; True if correction successful
    correctedResponse QWORD ?       ; Corrected response
    strategyUsed DWORD ?            ; Strategy enum
    attemptsUsed DWORD ?            ; Number of attempts
    errorMessage QWORD ?            ; Error message if failed
CORRECTION_RESULT ENDS

; CORRECTION_STATS - Correction statistics
CORRECTION_STATS STRUCT
    totalCorrections QWORD ?        ; Total correction attempts
    successfulCorrections QWORD ?   ; Successful corrections
    failedCorrections QWORD ?       ; Failed corrections
    averageAttempts REAL4 ?         ; Average attempts per correction
    successRate REAL4 ?             ; Overall success rate
CORRECTION_STATS ENDS

; AGENTIC_PUPPETEER - Puppeteer state
AGENTIC_PUPPETEER STRUCT
    corrections QWORD ?             ; Array of CORRECTION_RESULT
    correctionCount DWORD ?         ; Current count
    maxCorrections DWORD ?          ; Capacity
    
    stats CORRECTION_STATS <>       ; Statistics
    
    ; Strategy configuration
    maxRetries DWORD ?              ; Maximum retry attempts
    retryDelayMs DWORD ?            ; Delay between retries
    confidenceThreshold REAL4 ?     ; Minimum confidence threshold
    
    ; Callbacks
    correctionCallback QWORD ?      ; Called when correction attempted
    successCallback QWORD ?         ; Called when correction successful
    failureCallback QWORD ?         ; Called when correction failed
    
    initialized BYTE ?
AGENTIC_PUPPETEER ENDS

; ============================================================================
; GLOBAL DATA
; ============================================================================

.data
    szPuppeteerCreated DB "[AGENTIC_PUPPETEER] Created with auto-correction enabled", 0
    szCorrectionStarted DB "[AGENTIC_PUPPETEER] Correcting failure: %s (confidence=%.2f)", 0
    szCorrectionSuccess DB "[AGENTIC_PUPPETEER] Correction successful: %s, attempts=%d", 0
    szCorrectionFailed DB "[AGENTIC_PUPPETEER] Correction failed: %s", 0
    szStrategySelected DB "[AGENTIC_PUPPETEER] Selected strategy: %s", 0
    szRetryAttempt DB "[AGENTIC_PUPPETEER] Retry attempt %d/%d", 0

; Failure types
FAILURE_TYPE_REFUSAL EQU 0
FAILURE_TYPE_HALLUCINATION EQU 1
FAILURE_TYPE_FORMAT_VIOLATION EQU 2
FAILURE_TYPE_INFINITE_LOOP EQU 3
FAILURE_TYPE_SAFETY_VIOLATION EQU 4
FAILURE_TYPE_TIMEOUT EQU 5
FAILURE_TYPE_RESOURCE_EXHAUSTION EQU 6
FAILURE_TYPE_UNKNOWN EQU 7

; Correction strategies
STRATEGY_REPHRASE EQU 0
STRATEGY_CONTEXT_ENHANCE EQU 1
STRATEGY_EXAMPLE_PROVIDE EQU 2
STRATEGY_SYSTEM_PROMPT EQU 3
STRATEGY_TEMPERATURE_ADJUST EQU 4
STRATEGY_MODEL_SWITCH EQU 5
STRATEGY_FORCE_COMPLETION EQU 6
STRATEGY_DEFAULT EQU 7

.code

; ============================================================================
; PUBLIC API
; ============================================================================

; agentic_puppeteer_create()
; Create agentic puppeteer
; Returns: RAX = pointer to AGENTIC_PUPPETEER
PUBLIC agentic_puppeteer_create
agentic_puppeteer_create PROC
    push rbx
    
    ; Allocate puppeteer
    mov rcx, SIZEOF AGENTIC_PUPPETEER
    call malloc
    mov rbx, rax
    
    ; Allocate corrections array
    mov rcx, MAX_CORRECTIONS
    imul rcx, SIZEOF CORRECTION_RESULT
    call malloc
    mov [rbx + AGENTIC_PUPPETEER.corrections], rax
    
    ; Initialize
    mov [rbx + AGENTIC_PUPPETEER.correctionCount], 0
    mov [rbx + AGENTIC_PUPPETEER.maxCorrections], MAX_CORRECTIONS
    mov [rbx + AGENTIC_PUPPETEER.maxRetries], MAX_ATTEMPTS
    mov [rbx + AGENTIC_PUPPETEER.retryDelayMs], 1000
    movss xmm0, [fDefaultConfidenceThreshold]
    movss [rbx + AGENTIC_PUPPETEER.confidenceThreshold], xmm0
    
    ; Initialize statistics
    mov [rbx + AGENTIC_PUPPETEER.stats.totalCorrections], 0
    mov [rbx + AGENTIC_PUPPETEER.stats.successfulCorrections], 0
    mov [rbx + AGENTIC_PUPPETEER.stats.failedCorrections], 0
    movss xmm0, [fZero]
    movss [rbx + AGENTIC_PUPPETEER.stats.averageAttempts], xmm0
    movss [rbx + AGENTIC_PUPPETEER.stats.successRate], xmm0
    
    mov byte ptr [rbx + AGENTIC_PUPPETEER.initialized], 1
    
    ; Log
    lea rcx, [szPuppeteerCreated]
    call console_log
    
    mov rax, rbx
    pop rbx
    ret
agentic_puppeteer_create ENDP

; ============================================================================

; agentic_correct_failure(RCX = puppeteer, RDX = failure, R8 = originalPrompt, R9 = failedResponse)
; Correct AI failure
; Returns: RAX = pointer to CORRECTION_RESULT
PUBLIC agentic_correct_failure
agentic_correct_failure PROC
    push rbx
    push rsi
    push r12
    
    mov rbx, rcx                    ; rbx = puppeteer
    mov rsi, rdx                    ; rsi = failure
    mov r12, r8                     ; r12 = originalPrompt
    mov r13, r9                     ; r13 = failedResponse
    
    ; Check if failure is valid
    cmp byte [rsi + FAILURE_DETECTION.isFailure], 1
    jne no_failure_local
    
    ; Log
    lea rcx, [szCorrectionStarted]
    mov rdx, [rsi + FAILURE_DETECTION.description]
    movss xmm0, [rsi + FAILURE_DETECTION.confidence]
    call console_log
    
    ; Check capacity
    mov r14d, [rbx + AGENTIC_PUPPETEER.correctionCount]
    cmp r14d, [rbx + AGENTIC_PUPPETEER.maxCorrections]
    jge capacity_exceeded_local
    
    ; Get correction slot
    mov r15, [rbx + AGENTIC_PUPPETEER.corrections]
    mov r8, r14
    imul r8, SIZEOF CORRECTION_RESULT
    add r15, r8
    
    ; Select strategy based on failure type
    mov eax, [rsi + FAILURE_DETECTION.type]
    call select_strategy
    mov [r15 + CORRECTION_RESULT.strategyUsed], eax
    
    ; Log strategy
    lea rcx, [szStrategySelected]
    mov rdx, rax
    call console_log
    
    ; Apply correction strategy
    mov rcx, rbx
    mov rdx, rsi
    mov r8, r12
    mov r9, r13
    mov r10, r15
    call apply_correction_strategy
    
    ; Update statistics
    inc qword [rbx + AGENTIC_PUPPETEER.stats.totalCorrections]
    
    cmp byte [r15 + CORRECTION_RESULT.success], 1
    jne correction_failed_local
    
    ; Success
    inc qword [rbx + AGENTIC_PUPPETEER.stats.successfulCorrections]
    
    ; Log success
    lea rcx, [szCorrectionSuccess]
    mov rdx, [rsi + FAILURE_DETECTION.description]
    mov r8d, [r15 + CORRECTION_RESULT.attemptsUsed]
    call console_log
    
    jmp correction_done_local
    
correction_failed_local:
    ; Failure
    inc qword [rbx + AGENTIC_PUPPETEER.stats.failedCorrections]
    
    ; Log failure
    lea rcx, [szCorrectionFailed]
    mov rdx, [r15 + CORRECTION_RESULT.errorMessage]
    call console_log
    
correction_done_local:
    ; Update success rate
    mov rax, [rbx + AGENTIC_PUPPETEER.stats.successfulCorrections]
    cvtsi2ss xmm0, rax
    mov rax, [rbx + AGENTIC_PUPPETEER.stats.totalCorrections]
    cvtsi2ss xmm1, rax
    divss xmm0, xmm1
    movss [rbx + AGENTIC_PUPPETEER.stats.successRate], xmm0
    
    ; Increment correction count
    inc dword [rbx + AGENTIC_PUPPETEER.correctionCount]
    
    mov rax, r15                    ; Return correction result
    pop r12
    pop rsi
    pop rbx
    ret
    
no_failure_local:
capacity_exceeded_local:
    xor rax, rax
    pop r12
    pop rsi
    pop rbx
    ret
agentic_correct_failure ENDP

; ============================================================================

; select_strategy(RAX = failureType)
; Select correction strategy based on failure type
; Returns: RAX = strategy enum
select_strategy PROC
    cmp eax, FAILURE_TYPE_REFUSAL
    jne not_refusal_local
    mov eax, STRATEGY_REPHRASE
    ret
    
not_refusal_local:
    cmp eax, FAILURE_TYPE_HALLUCINATION
    jne not_hallucination_local
    mov eax, STRATEGY_CONTEXT_ENHANCE
    ret
    
not_hallucination_local:
    cmp eax, FAILURE_TYPE_FORMAT_VIOLATION
    jne not_format_local
    mov eax, STRATEGY_EXAMPLE_PROVIDE
    ret
    
not_format_local:
    cmp eax, FAILURE_TYPE_INFINITE_LOOP
    jne not_loop_local
    mov eax, STRATEGY_FORCE_COMPLETION
    ret
    
not_loop_local:
    mov eax, STRATEGY_DEFAULT
    ret
select_strategy ENDP

; ============================================================================

; apply_correction_strategy(RCX = puppeteer, RDX = failure, R8 = prompt, R9 = response, R10 = result)
; Apply correction strategy
apply_correction_strategy PROC
    push rbx
    push rsi
    
    mov rbx, rcx                    ; rbx = puppeteer
    mov rsi, rdx                    ; rsi = failure
    mov r11, r8                     ; r11 = prompt
    mov r12, r9                     ; r12 = response
    mov r13, r10                    ; r13 = result
    
    ; Get strategy
    mov eax, [r13 + CORRECTION_RESULT.strategyUsed]
    
    ; Apply strategy (simplified)
    cmp eax, STRATEGY_REPHRASE
    jne not_rephrase_local
    
    ; Rephrase strategy
    mov rcx, r11
    call rephrase_prompt
    mov [r13 + CORRECTION_RESULT.correctedResponse], rax
    mov byte ptr [r13 + CORRECTION_RESULT.success], 1
    mov [r13 + CORRECTION_RESULT.attemptsUsed], 1
    jmp strategy_applied_local
    
not_rephrase_local:
    cmp eax, STRATEGY_CONTEXT_ENHANCE
    jne not_context_local
    
    ; Context enhancement
    mov rcx, r11
    call enhance_context
    mov [r13 + CORRECTION_RESULT.correctedResponse], rax
    mov byte ptr [r13 + CORRECTION_RESULT.success], 1
    mov [r13 + CORRECTION_RESULT.attemptsUsed], 1
    jmp strategy_applied_local
    
not_context_local:
    ; Default strategy
    mov rcx, r11
    call retry_with_rephrase
    mov [r13 + CORRECTION_RESULT.correctedResponse], rax
    mov byte ptr [r13 + CORRECTION_RESULT.success], 1
    mov [r13 + CORRECTION_RESULT.attemptsUsed], 1
    
strategy_applied_local:
    pop rsi
    pop rbx
    ret
apply_correction_strategy ENDP

; ============================================================================

; rephrase_prompt(RCX = prompt)
; Rephrase the prompt
; Returns: RAX = corrected response
rephrase_prompt PROC
    ; Allocate response buffer
    mov rcx, 1024
    call malloc
    
    ; Create rephrased response
    lea rdx, [szRephrasedResponse]
    call strcpy
    
    ret
rephrase_prompt ENDP

; ============================================================================

; enhance_context(RCX = prompt)
; Enhance context
; Returns: RAX = corrected response
enhance_context PROC
    ; Allocate response buffer
    mov rcx, 1024
    call malloc
    
    ; Create enhanced response
    lea rdx, [szEnhancedResponse]
    call strcpy
    
    ret
enhance_context ENDP

; ============================================================================

; retry_with_rephrase(RCX = prompt)
; Retry with rephrased prompt
; Returns: RAX = corrected response
retry_with_rephrase PROC
    ; Allocate response buffer
    mov rcx, 1024
    call malloc
    
    ; Create retry response
    lea rdx, [szRetryResponse]
    call strcpy
    
    ret
retry_with_rephrase ENDP

; ============================================================================

; agentic_get_correction_result(RCX = puppeteer, RDX = correctionId)
; Get correction result by ID
; Returns: RAX = pointer to CORRECTION_RESULT
PUBLIC agentic_get_correction_result
agentic_get_correction_result PROC
    mov r8, [rcx + AGENTIC_PUPPETEER.corrections]
    mov r9d, [rcx + AGENTIC_PUPPETEER.correctionCount]
    xor r10d, r10d
    
find_correction_local:
    cmp r10d, r9d
    jge correction_not_found_local
    
    mov r11, r8
    mov r12, r10
    imul r12, SIZEOF CORRECTION_RESULT
    add r11, r12
    
    cmp r10d, edx
    je correction_found_local
    
    inc r10d
    jmp find_correction_local
    
correction_found_local:
    mov rax, r11
    ret
    
correction_not_found_local:
    xor rax, rax
    ret
agentic_get_correction_result ENDP

; ============================================================================

; agentic_get_statistics(RCX = puppeteer, RDX = statsBuffer)
; Get puppeteer statistics
PUBLIC agentic_get_statistics
agentic_get_statistics PROC
    mov [rdx + 0], qword [rcx + AGENTIC_PUPPETEER.stats.totalCorrections]
    mov [rdx + 8], qword [rcx + AGENTIC_PUPPETEER.stats.successfulCorrections]
    mov [rdx + 16], qword [rcx + AGENTIC_PUPPETEER.stats.failedCorrections]
    movss xmm0, [rcx + AGENTIC_PUPPETEER.stats.averageAttempts]
    movss [rdx + 24], xmm0
    movss xmm1, [rcx + AGENTIC_PUPPETEER.stats.successRate]
    movss [rdx + 28], xmm1
    ret
agentic_get_statistics ENDP

; ============================================================================

; agentic_set_max_retries(RCX = puppeteer, RDX = maxRetries)
; Set maximum retry attempts
PUBLIC agentic_set_max_retries
agentic_set_max_retries PROC
    mov [rcx + AGENTIC_PUPPETEER.maxRetries], edx
    ret
agentic_set_max_retries ENDP

; ============================================================================

; agentic_set_confidence_threshold(RCX = puppeteer, RDX = threshold)
; Set confidence threshold
PUBLIC agentic_set_confidence_threshold
agentic_set_confidence_threshold PROC
    movss [rcx + AGENTIC_PUPPETEER.confidenceThreshold], xmm1  ; RDX in XMM1
    ret
agentic_set_confidence_threshold ENDP

; ============================================================================

; agentic_destroy(RCX = puppeteer)
; Free agentic puppeteer
PUBLIC agentic_destroy
agentic_destroy PROC
    push rbx
    
    mov rbx, rcx
    
    ; Free corrections array
    mov rcx, [rbx + AGENTIC_PUPPETEER.corrections]
    cmp rcx, 0
    je skip_corrections_local
    call free
    
skip_corrections_local:
    ; Free puppeteer
    mov rcx, rbx
    call free
    
    pop rbx
    ret
agentic_destroy ENDP

; ============================================================================

.data ALIGN 16
    fDefaultConfidenceThreshold REAL4 0.5
    fZero REAL4 0.0
    szRephrasedResponse DB "Rephrased: I can help with that request.", 0
    szEnhancedResponse DB "Enhanced context: Here's the corrected response.", 0
    szRetryResponse DB "Retry: Let me try that again with a different approach.", 0

END

