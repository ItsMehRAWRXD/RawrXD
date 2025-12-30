; agentic_failure_detector_masm.asm
; Pure MASM x64 - Agentic Failure Detector (converted from C++ AgenticFailureDetector class)
; AI failure detection with 8 detection modes and pattern matching

option casemap:none

EXTERN malloc:PROC
EXTERN free:PROC
EXTERN memset:PROC
EXTERN memcpy:PROC
EXTERN strlen:PROC
EXTERN strcpy:PROC
EXTERN sprintf:PROC
EXTERN console_log:PROC
EXTERN strstr:PROC

; Detector constants
MAX_PATTERNS EQU 100
MAX_DETECTIONS EQU 1000
MAX_PATTERN_LENGTH EQU 256
MAX_RESPONSE_LENGTH EQU 65536

; ============================================================================
; DATA STRUCTURES
; ============================================================================

; FAILURE_PATTERN - Pattern for failure detection
FAILURE_PATTERN STRUCT
    pattern QWORD ?                 ; Pattern string
    patternLength DWORD ?           ; Pattern length
    type DWORD ?                    ; Failure type
    confidence REAL4 ?              ; Pattern confidence
    enabled BYTE ?                  ; Whether pattern is enabled
ENDS

; FAILURE_DETECTION - Detection result
FAILURE_DETECTION STRUCT
    type DWORD ?                    ; Failure type enum
    confidence REAL4 ?              ; 0.0-1.0 confidence
    description QWORD ?             ; Failure description
    pattern QWORD ?                 ; Pattern that triggered detection
    severity DWORD ?                ; 1-10 severity level
    isFailure BYTE ?                ; True if failure detected
    response QWORD ?                ; Original response
    responseLength QWORD ?          ; Response length
ENDS

; DETECTION_STATS - Detection statistics
DETECTION_STATS STRUCT
    totalDetections QWORD ?         ; Total detections
    truePositives QWORD ?           ; True positives
    falsePositives QWORD ?          ; False positives
    falseNegatives QWORD ?          ; False negatives
    accuracy REAL4 ?                ; Overall accuracy
    precision REAL4 ?               ; Precision
    recall REAL4 ?                  ; Recall
ENDS

; AGENTIC_FAILURE_DETECTOR - Detector state
AGENTIC_FAILURE_DETECTOR STRUCT
    patterns QWORD ?                ; Array of FAILURE_PATTERN
    patternCount DWORD ?            ; Current pattern count
    maxPatterns DWORD ?             ; Capacity
    
    detections QWORD ?              ; Array of FAILURE_DETECTION
    detectionCount DWORD ?          ; Current detection count
    maxDetections DWORD ?           ; Capacity
    
    stats DETECTION_STATS ?         ; Statistics
    
    ; Configuration
    confidenceThreshold REAL4 ?     ; Minimum confidence threshold
    severityThreshold DWORD ?       ; Minimum severity threshold
    
    ; Callbacks
    detectionCallback QWORD ?       ; Called when failure detected
    falsePositiveCallback QWORD ?   ; Called on false positive
    falseNegativeCallback QWORD ?   ; Called on false negative
    
    initialized BYTE ?
ENDS

; ============================================================================
; GLOBAL DATA
; ============================================================================

.data
    szDetectorCreated DB "[FAILURE_DETECTOR] Created with %d patterns", 0
    szDetectionStarted DB "[FAILURE_DETECTOR] Analyzing %d bytes of response", 0
    szFailureDetected DB "[FAILURE_DETECTOR] Failure detected: %s (type=%d, confidence=%.2f)", 0
    szNoFailure DB "[FAILURE_DETECTOR] No failure detected", 0
    szPatternAdded DB "[FAILURE_DETECTOR] Added pattern: %s (type=%d)", 0
    szStatsUpdated DB "[FAILURE_DETECTOR] Stats updated: accuracy=%.2f, precision=%.2f, recall=%.2f", 0

; Failure types
FAILURE_TYPE_REFUSAL EQU 0
FAILURE_TYPE_HALLUCINATION EQU 1
FAILURE_TYPE_FORMAT_VIOLATION EQU 2
FAILURE_TYPE_INFINITE_LOOP EQU 3
FAILURE_TYPE_SAFETY_VIOLATION EQU 4
FAILURE_TYPE_TIMEOUT EQU 5
FAILURE_TYPE_RESOURCE_EXHAUSTION EQU 6
FAILURE_TYPE_UNKNOWN EQU 7

.code

; ============================================================================
; PUBLIC API
; ============================================================================

; agentic_failure_detector_create()
; Create failure detector
; Returns: RAX = pointer to AGENTIC_FAILURE_DETECTOR
PUBLIC agentic_failure_detector_create
agentic_failure_detector_create PROC
    push rbx
    
    ; Allocate detector
    mov rcx, SIZEOF AGENTIC_FAILURE_DETECTOR
    call malloc
    mov rbx, rax
    
    ; Allocate patterns array
    mov rcx, MAX_PATTERNS
    imul rcx, SIZEOF FAILURE_PATTERN
    call malloc
    mov [rbx + AGENTIC_FAILURE_DETECTOR.patterns], rax
    
    ; Allocate detections array
    mov rcx, MAX_DETECTIONS
    imul rcx, SIZEOF FAILURE_DETECTION
    call malloc
    mov [rbx + AGENTIC_FAILURE_DETECTOR.detections], rax
    
    ; Initialize
    mov [rbx + AGENTIC_FAILURE_DETECTOR.patternCount], 0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.maxPatterns], MAX_PATTERNS
    mov [rbx + AGENTIC_FAILURE_DETECTOR.detectionCount], 0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.maxDetections], MAX_DETECTIONS
    
    movss xmm0, [fDefaultConfidenceThreshold]
    movss [rbx + AGENTIC_FAILURE_DETECTOR.confidenceThreshold], xmm0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.severityThreshold], 5
    
    ; Initialize statistics
    mov [rbx + AGENTIC_FAILURE_DETECTOR.stats.totalDetections], 0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.stats.truePositives], 0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.stats.falsePositives], 0
    mov [rbx + AGENTIC_FAILURE_DETECTOR.stats.falseNegatives], 0
    movss xmm0, [fZero]
    movss [rbx + AGENTIC_FAILURE_DETECTOR.stats.accuracy], xmm0
    movss [rbx + AGENTIC_FAILURE_DETECTOR.stats.precision], xmm0
    movss [rbx + AGENTIC_FAILURE_DETECTOR.stats.recall], xmm0
    
    ; Initialize default patterns
    mov rcx, rbx
    call initialize_default_patterns
    
    mov byte [rbx + AGENTIC_FAILURE_DETECTOR.initialized], 1
    
    ; Log
    lea rcx, [szDetectorCreated]
    mov edx, [rbx + AGENTIC_FAILURE_DETECTOR.patternCount]
    call console_log
    
    mov rax, rbx
    pop rbx

agentic_failure_detector_create ENDP

; ============================================================================

; initialize_default_patterns(RCX = detector)
; Initialize default failure patterns
initialize_default_patterns PROC
    push rbx
    push mov rbx, rcx
    
    ; Add refusal patterns
    lea rdx, [szRefusalPattern1]
    mov r8d, FAILURE_TYPE_REFUSAL
    movss xmm0, [fHighConfidence]
    call add_pattern
    
    lea rdx, [szRefusalPattern2]
    mov r8d, FAILURE_TYPE_REFUSAL
    movss xmm0, [fHighConfidence]
    call add_pattern
    
    ; Add hallucination patterns
    lea rdx, [szHallucinationPattern1]
    mov r8d, FAILURE_TYPE_HALLUCINATION
    movss xmm0, [fMediumConfidence]
    call add_pattern
    
    ; Add safety violation patterns
    lea rdx, [szSafetyPattern1]
    mov r8d, FAILURE_TYPE_SAFETY_VIOLATION
    movss xmm0, [fHighConfidence]
    call add_pattern
    
    pop rbx

initialize_default_patterns ENDP

; ============================================================================

; add_pattern(RCX = detector, RDX = pattern, R8d = type, XMM0 = confidence)
; Add failure pattern
add_pattern PROC
    push rbx
    push mov rbx, rcx                    ; rbx = detector
    mov r9, rdx                     ; r9 = pattern
    mov r10d, r8d                   ; r10d = type
    
    ; Check capacity
    mov r11d, [rbx + AGENTIC_FAILURE_DETECTOR.patternCount]
    cmp r11d, [rbx + AGENTIC_FAILURE_DETECTOR.maxPatterns]
    jge @@capacity_exceeded
    
    ; Get pattern slot
    mov r12, [rbx + AGENTIC_FAILURE_DETECTOR.patterns]
    mov r13, r11
    imul r13, SIZEOF FAILURE_PATTERN
    add r12, r13
    
    ; Store pattern
    mov rcx, r9
    call strlen
    inc rax
    call malloc
    mov [r12 + FAILURE_PATTERN.pattern], rax
    
    mov rcx, r9
    mov rdx, rax
    call strcpy
    
    mov [r12 + FAILURE_PATTERN.patternLength], eax
    mov [r12 + FAILURE_PATTERN.type], r10d
    movss [r12 + FAILURE_PATTERN.confidence], xmm0
    mov byte [r12 + FAILURE_PATTERN.enabled], 1
    
    ; Increment pattern count
    inc dword [rbx + AGENTIC_FAILURE_DETECTOR.patternCount]
    
    ; Log
    lea rcx, [szPatternAdded]
    mov rdx, r9
    mov r8d, r10d
    call console_log
@@capacity_exceeded:
    pop rbx

add_pattern ENDP

; ============================================================================

; agentic_detect_failure(RCX = detector, RDX = response, R8 = responseLength)
; Detect failures in AI response
; Returns: RAX = pointer to FAILURE_DETECTION
PUBLIC agentic_detect_failure
agentic_detect_failure PROC
    push rbx

    push rsi
    push r12
    
    mov rbx, rcx                    ; rbx = detector
    mov rsi, rdx                    ; rsi = response
    mov r12, r8                     ; r12 = responseLength
    
    ; Log
    lea rcx, [szDetectionStarted]
    mov rdx, r12
    call console_log
    
    ; Check capacity
    mov r13d, [rbx + AGENTIC_FAILURE_DETECTOR.detectionCount]
    cmp r13d, [rbx + AGENTIC_FAILURE_DETECTOR.maxDetections]
    jge @@capacity_exceeded
    
    ; Get detection slot
    mov r14, [rbx + AGENTIC_FAILURE_DETECTOR.detections]
    mov r15, r13
    imul r15, SIZEOF FAILURE_DETECTION
    add r14, r15
    
    ; Initialize detection
    mov byte [r14 + FAILURE_DETECTION.isFailure], 0
    mov [r14 + FAILURE_DETECTION.response], rsi
    mov [r14 + FAILURE_DETECTION.responseLength], r12
    
    ; Check patterns
    mov r8, [rbx + AGENTIC_FAILURE_DETECTOR.patterns]
    mov r9d, [rbx + AGENTIC_FAILURE_DETECTOR.patternCount]
    xor r10d, r10d
@@pattern_loop:
    cmp r10d, r9d
    jge @@patterns_checked
    
    mov r11, r8
    mov r12, r10
    imul r12, SIZEOF FAILURE_PATTERN
    add r11, r12
    
    ; Check if pattern enabled
    cmp byte [r11 + FAILURE_PATTERN.enabled], 1
    jne @@next_pattern
    
    ; Check pattern match
    mov rcx, rsi
    mov rdx, [r11 + FAILURE_PATTERN.pattern]
    call strstr
    cmp rax, 0
    je @@next_pattern
    
    ; Pattern matched - failure detected
    mov byte [r14 + FAILURE_DETECTION.isFailure], 1
    mov eax, [r11 + FAILURE_PATTERN.type]
    mov [r14 + FAILURE_DETECTION.type], eax
    movss xmm0, [r11 + FAILURE_PATTERN.confidence]
    movss [r14 + FAILURE_DETECTION.confidence], xmm0
    mov rax, [r11 + FAILURE_PATTERN.pattern]
    mov [r14 + FAILURE_DETECTION.pattern], rax
    
    ; Set description based on type
    mov eax, [r14 + FAILURE_DETECTION.type]
    call get_failure_description
    mov [r14 + FAILURE_DETECTION.description], rax
    
    ; Set severity based on type
    mov eax, [r14 + FAILURE_DETECTION.type]
    call get_severity_level
    mov [r14 + FAILURE_DETECTION.severity], eax
    
    ; Log detection
    lea rcx, [szFailureDetected]
    mov rdx, [r14 + FAILURE_DETECTION.description]
    mov r8d, [r14 + FAILURE_DETECTION.type]
    movss xmm0, [r14 + FAILURE_DETECTION.confidence]
    call console_log
    
    jmp @@detection_complete
@@next_pattern:
    inc r10d
    jmp @@pattern_loop
@@patterns_checked:
    ; No failure detected
    lea rcx, [szNoFailure]
    call console_log
@@detection_complete:
    ; Update statistics
    inc qword [rbx + AGENTIC_FAILURE_DETECTOR.stats.totalDetections]
    
    cmp byte [r14 + FAILURE_DETECTION.isFailure], 1
    jne @@no_failure
    
    ; True positive (simplified)
    inc qword [rbx + AGENTIC_FAILURE_DETECTOR.stats.truePositives]
    jmp @@stats_updated
@@no_failure:
    ; False negative (simplified)
    inc qword [rbx + AGENTIC_FAILURE_DETECTOR.stats.falseNegatives]
@@stats_updated:
    ; Update accuracy metrics
    mov rax, [rbx + AGENTIC_FAILURE_DETECTOR.stats.truePositives]
    cvtsi2ss xmm0, rax
    mov rax, [rbx + AGENTIC_FAILURE_DETECTOR.stats.totalDetections]
    cvtsi2ss xmm1, rax
    divss xmm0, xmm1
    movss [rbx + AGENTIC_FAILURE_DETECTOR.stats.accuracy], xmm0
    
    ; Increment detection count
    inc dword [rbx + AGENTIC_FAILURE_DETECTOR.detectionCount]
    
    mov rax, r14                    ; Return detection result

    pop rsi pop r12

    pop rbx

@@capacity_exceeded:
    xor rax, rax

    pop rsi pop r12

    pop rbx

agentic_detect_failure ENDP

; ============================================================================

; get_failure_description(RAX = failureType)
; Get failure description
; Returns: RAX = description string
get_failure_description PROC
    cmp eax, FAILURE_TYPE_REFUSAL
    jne @@not_refusal
    lea rax, [szRefusalDescription]
    ret
@@not_refusal:
    cmp eax, FAILURE_TYPE_HALLUCINATION
    jne @@not_hallucination
    lea rax, [szHallucinationDescription]
    ret
@@not_hallucination:
    cmp eax, FAILURE_TYPE_FORMAT_VIOLATION
    jne @@not_format
    lea rax, [szFormatViolationDescription]
    ret
@@not_format:
    cmp eax, FAILURE_TYPE_SAFETY_VIOLATION
    jne @@not_safety
    lea rax, [szSafetyViolationDescription]
    ret
@@not_safety:
    lea rax, [szUnknownFailureDescription]
    ret
get_failure_description ENDP

; ============================================================================

; get_severity_level(RAX = failureType)
; Get severity level
; Returns: RAX = severity level (1-10)
get_severity_level PROC
    cmp eax, FAILURE_TYPE_REFUSAL
    jne @@not_refusal
    mov eax, 3
    ret
@@not_refusal:
    cmp eax, FAILURE_TYPE_HALLUCINATION
    jne @@not_hallucination
    mov eax, 7
    ret
@@not_hallucination:
    cmp eax, FAILURE_TYPE_SAFETY_VIOLATION
    jne @@not_safety
    mov eax, 9
    ret
@@not_safety:
    mov eax, 5
    ret
get_severity_level ENDP

; ============================================================================

; agentic_get_detection(RCX = detector, RDX = detectionId)
; Get detection by ID
; Returns: RAX = pointer to FAILURE_DETECTION
PUBLIC agentic_get_detection
agentic_get_detection PROC
    mov r8, [rcx + AGENTIC_FAILURE_DETECTOR.detections]
    mov r9d, [rcx + AGENTIC_FAILURE_DETECTOR.detectionCount]
    xor r10d, r10d
@@find_detection:
    cmp r10d, r9d
    jge @@detection_not_found
    
    mov r11, r8
    mov r12, r10
    imul r12, SIZEOF FAILURE_DETECTION
    add r11, r12
    
    cmp r10d, edx
    je @@detection_found
    
    inc r10d
    jmp @@find_detection
@@detection_found:
    mov rax, r11
    ret
@@detection_not_found:
    xor rax, rax
    ret
agentic_get_detection ENDP

; ============================================================================

; agentic_get_statistics(RCX = detector, RDX = statsBuffer)
; Get detector statistics
PUBLIC agentic_get_statistics
agentic_get_statistics PROC
    mov [rdx + 0], qword [rcx + AGENTIC_FAILURE_DETECTOR.stats.totalDetections]
    mov [rdx + 8], qword [rcx + AGENTIC_FAILURE_DETECTOR.stats.truePositives]
    mov [rdx + 16], qword [rcx + AGENTIC_FAILURE_DETECTOR.stats.falsePositives]
    mov [rdx + 24], qword [rcx + AGENTIC_FAILURE_DETECTOR.stats.falseNegatives]
    movss xmm0, [rcx + AGENTIC_FAILURE_DETECTOR.stats.accuracy]
    movss [rdx + 32], xmm0
    movss xmm1, [rcx + AGENTIC_FAILURE_DETECTOR.stats.precision]
    movss [rdx + 36], xmm1
    movss xmm2, [rcx + AGENTIC_FAILURE_DETECTOR.stats.recall]
    movss [rdx + 40], xmm2
    ret
agentic_get_statistics ENDP

; ============================================================================

; agentic_set_confidence_threshold(RCX = detector, RDX = threshold)
; Set confidence threshold
PUBLIC agentic_set_confidence_threshold
agentic_set_confidence_threshold PROC
    movss [rcx + AGENTIC_FAILURE_DETECTOR.confidenceThreshold], xmm1  ; RDX in XMM1
    ret
agentic_set_confidence_threshold ENDP

; ============================================================================

; agentic_add_pattern(RCX = detector, RDX = pattern, R8d = type, XMM0 = confidence)
; Add custom pattern
PUBLIC agentic_add_pattern
agentic_add_pattern PROC
    call add_pattern
    ret
agentic_add_pattern ENDP

; ============================================================================

; agentic_destroy(RCX = detector)
; Free failure detector
PUBLIC agentic_destroy
agentic_destroy PROC
    push rbx
    push mov rbx, rcx
    
    ; Free patterns array
    mov r10, [rbx + AGENTIC_FAILURE_DETECTOR.patterns]
    mov r11d, [rbx + AGENTIC_FAILURE_DETECTOR.patternCount]
    xor r12d, r12d
@@free_patterns:
    cmp r12d, r11d
    jge @@patterns_freed
    
    mov r13, r10
    mov r14, r12
    imul r14, SIZEOF FAILURE_PATTERN
    add r13, r14
    
    mov rcx, [r13 + FAILURE_PATTERN.pattern]
    cmp rcx, 0
    je @@skip_pattern
    call free
@@skip_pattern:
    inc r12d
    jmp @@free_patterns
@@patterns_freed:
    mov rcx, [rbx + AGENTIC_FAILURE_DETECTOR.patterns]
    cmp rcx, 0
    je @@skip_patterns_array
    call free
@@skip_patterns_array:
    ; Free detections array
    mov rcx, [rbx + AGENTIC_FAILURE_DETECTOR.detections]
    cmp rcx, 0
    je @@skip_detections_array
    call free
@@skip_detections_array:
    ; Free detector
    mov rcx, rbx
    call free
    
    pop rbx

agentic_destroy ENDP

; ============================================================================

.data ALIGN 16
    fDefaultConfidenceThreshold REAL4 0.5
    fHighConfidence REAL4 0.9
    fMediumConfidence REAL4 0.7
    fZero REAL4 0.0
    
    ; Default patterns
    szRefusalPattern1 DB "I cannot", 0
    szRefusalPattern2 DB "I'm not able to", 0
    szHallucinationPattern1 DB "According to my training data", 0
    szSafetyPattern1 DB "That would be inappropriate", 0
    
    ; Failure descriptions
    szRefusalDescription DB "AI refusal to respond", 0
    szHallucinationDescription DB "AI hallucination detected", 0
    szFormatViolationDescription DB "Response format violation", 0
    szSafetyViolationDescription DB "Safety violation detected", 0
    szUnknownFailureDescription DB "Unknown failure type", 0

END





