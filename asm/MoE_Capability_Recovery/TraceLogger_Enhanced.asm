;==============================================================================
; TraceLogger_Enhanced.asm - Semantic-Aware Logging for MoE Capability Recovery
;==============================================================================
; Enhanced version that outputs expert names and capabilities in traces.
; Assemble with: ml64 TraceLogger_Enhanced.asm /link /subsystem:console /out:TraceLoggerEnhanced.dll
;==============================================================================

INCLUDE \masm64\include64\masm64rt.inc
INCLUDE ExpertRegistry.inc

;==============================================================================
; Data Section
;==============================================================================
.DATA

; Log file
logFileHandle       QWORD 0
logFilePath         BYTE "moe_trace_semantic.log", 0
logMutex            BYTE 64 DUP(0)

; Buffers
formatBuffer        BYTE 8192 DUP(0)
tempBuffer          BYTE 512 DUP(0)
capabilityBuffer    BYTE 256 DUP(0)

; Statistics
eventCounts         LABEL QWORD
routerEvents        QWORD 0
expertEvents        QWORD 0
swarmEvents         QWORD 0
ghostEvents         QWORD 0
speculativeEvents   QWORD 0
prefetchEvents      QWORD 0
latentEvents        QWORD 0
shadowEvents        QWORD 0
mergeEvents         QWORD 0
echoEvents          QWORD 0

; Expert activation frequency (for heat map)
expertActivationCount QWORD 64 DUP(0)

;==============================================================================
; Code Section
;==============================================================================
.CODE

;------------------------------------------------------------------------------
; InitializeTraceLogger
;------------------------------------------------------------------------------
InitializeTraceLogger PROC
    push rbx
    push rdi
    push rsi
    
    lea rcx, logMutex
    call InitializeCriticalSection
    
    lea rcx, logFilePath
    mov rdx, GENERIC_WRITE
    mov r8, FILE_SHARE_READ
    mov r9, OPEN_ALWAYS
    
    sub rsp, 40
    mov QWORD PTR [rsp+32], FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+40], 0
    call CreateFileA
    add rsp, 40
    
    mov logFileHandle, rax
    
    cmp rax, INVALID_HANDLE_VALUE
    je @F
    
    mov rcx, logFileHandle
    mov rdx, NULL
    mov r8, FILE_END
    sub rsp, 32
    call SetFilePointerEx
    add rsp, 32
    
    call WriteSemanticHeader
    
@@: pop rsi
    pop rdi
    pop rbx
    ret
InitializeTraceLogger ENDP

;------------------------------------------------------------------------------
; ShutdownTraceLogger
;------------------------------------------------------------------------------
ShutdownTraceLogger PROC
    push rbx
    
    call WriteExpertHeatMap
    call WriteStatistics
    
    mov rcx, logFileHandle
    cmp rcx, INVALID_HANDLE_VALUE
    je @F
    sub rsp, 32
    call CloseHandle
    add rsp, 32
    
@@: lea rcx, logMutex
    call DeleteCriticalSection
    
    pop rbx
    ret
ShutdownTraceLogger ENDP

;------------------------------------------------------------------------------
; LogExpertEventNamed - Enhanced logging with semantic expert names
; RCX = timestamp, RDX = expert_id, R8 = confidence, R9 = expert_name
;------------------------------------------------------------------------------
LogExpertEventNamed PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx        ; timestamp
    mov r13, rdx        ; expert_id
    mov r14, r8         ; confidence
    mov r15, r9         ; expert_name
    
    ; Update activation count
    lea rax, expertActivationCount
    mov rcx, r13
    inc QWORD PTR [rax + rcx * 8]
    
    lea rcx, logMutex
    call EnterCriticalSection
    
    ; Build enhanced trace line
    lea rdi, formatBuffer
    
    ; Timestamp
    mov BYTE PTR [rdi], '['
    inc rdi
    mov rax, r12
    call FormatHexQword
    mov BYTE PTR [rdi], ']'
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    ; Event type
    lea rsi, [expertEventType]
    call CopyString
    
    ; Expert ID
    lea rsi, [idLabel]
    call CopyString
    mov rax, r13
    call FormatDecimal
    
    ; Expert name (semantic)
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '('
    inc rdi
    mov rsi, r15
    call CopyString
    mov BYTE PTR [rdi], ')'
    inc rdi
    
    ; Confidence
    lea rsi, [confidenceLabel]
    call CopyString
    mov rax, r14
    call FormatDecimal
    mov BYTE PTR [rdi], '%'
    inc rdi
    
    ; Capabilities
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '['
    inc rdi
    
    GET_EXPERT_CAPS r13d, ecx
    lea rdx, capabilityBuffer
    call GetCapabilityString
    
    lea rsi, capabilityBuffer
    call CopyString
    
    mov BYTE PTR [rdi], ']'
    inc rdi
    
    ; Newline
    mov BYTE PTR [rdi], 13
    inc rdi
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 0
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    inc expertEvents
    
    ; Update specific event counters based on capabilities
    GET_EXPERT_CAPS r13d, eax
    test eax, CAP_GHOST
    jz @F
    inc ghostEvents
@@: test eax, CAP_SWARM
    jz @F
    inc swarmEvents
@@: test eax, CAP_LATENT
    jz @F
    inc latentEvents
@@: test eax, CAP_SHADOW
    jz @F
    inc shadowEvents
@@: test eax, CAP_SPECULATIVE
    jz @F
    inc speculativeEvents
@@: test eax, CAP_PREFETCH
    jz @F
    inc prefetchEvents
@@: test eax, CAP_ECHO
    jz @F
    inc echoEvents
@@: test eax, CAP_MERGE
    jz @F
    inc mergeEvents
@@:
    
    lea rcx, logMutex
    call LeaveCriticalSection
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
LogExpertEventNamed ENDP

;------------------------------------------------------------------------------
; LogExpertEventContext - Expert activation with additional context
; RCX = timestamp, RDX = expert_id, R8 = confidence, R9 = name, R10 = context
;------------------------------------------------------------------------------
LogExpertEventContext PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    
    lea rcx, logMutex
    call EnterCriticalSection
    
    lea rdi, formatBuffer
    
    ; Timestamp
    mov BYTE PTR [rdi], '['
    inc rdi
    mov rax, r12
    call FormatHexQword
    mov BYTE PTR [rdi], ']'
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    ; Expert info with name
    lea rsi, [expertEventType]
    call CopyString
    
    lea rsi, [idLabel]
    call CopyString
    mov rax, r13
    call FormatDecimal
    
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '('
    inc rdi
    mov rsi, r15
    call CopyString
    mov BYTE PTR [rdi], ')'
    inc rdi
    
    ; Confidence
    lea rsi, [confidenceLabel]
    call CopyString
    mov rax, r14
    call FormatDecimal
    mov BYTE PTR [rdi], '%'
    inc rdi
    
    ; Context
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '{'
    inc rdi
    mov rsi, r10
    call CopyString
    mov BYTE PTR [rdi], '}'
    inc rdi
    
    ; Capabilities
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '['
    inc rdi
    
    GET_EXPERT_CAPS r13d, ecx
    lea rdx, capabilityBuffer
    call GetCapabilityString
    
    lea rsi, capabilityBuffer
    call CopyString
    
    mov BYTE PTR [rdi], ']'
    inc rdi
    
    ; Newline
    mov BYTE PTR [rdi], 13
    inc rdi
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 0
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    inc expertEvents
    
    lea rcx, logMutex
    call LeaveCriticalSection
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
LogExpertEventContext ENDP

;------------------------------------------------------------------------------
; WriteSemanticHeader
;------------------------------------------------------------------------------
WriteSemanticHeader PROC
    push rbx
    push rdi
    
    lea rdi, formatBuffer
    
    lea rsi, [semanticHeader]
    call CopyString
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    pop rdi
    pop rbx
    ret
WriteSemanticHeader ENDP

;------------------------------------------------------------------------------
; WriteExpertHeatMap - Show which experts fire most often
;------------------------------------------------------------------------------
WriteExpertHeatMap PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    
    lea rdi, formatBuffer
    
    ; Header
    lea rsi, [heatMapHeader]
    call CopyString
    
    ; List all experts with activation counts
    xor r12, r12        ; Expert ID
    
.next_expert:
    cmp r12, 44
    jae .done
    
    ; Check if this expert ever fired
    lea rax, expertActivationCount
    mov r13, QWORD PTR [rax + r12 * 8]
    test r13, r13
    jz .skip
    
    ; Expert ID
    mov BYTE PTR [rdi], 13
    inc rdi
    mov BYTE PTR [rdi], 10
    inc rdi
    
    mov rax, r12
    call FormatDecimal
    
    mov BYTE PTR [rdi], ':'
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    ; Expert name
    GET_EXPERT_NAME r12d, rsi
    call CopyString
    
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '='
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    ; Activation count
    mov rax, r13
    call FormatDecimal
    
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], 'a'
    inc rdi
    mov BYTE PTR [rdi], 'c'
    inc rdi
    mov BYTE PTR [rdi], 't'
    inc rdi
    mov BYTE PTR [rdi], 'i'
    inc rdi
    mov BYTE PTR [rdi], 'v'
    inc rdi
    mov BYTE PTR [rdi], 'a'
    inc rdi
    mov BYTE PTR [rdi], 't'
    inc rdi
    mov BYTE PTR [rdi], 'i'
    inc rdi
    mov BYTE PTR [rdi], 'o'
    inc rdi
    mov BYTE PTR [rdi], 'n'
    inc rdi
    mov BYTE PTR [rdi], 's'
    inc rdi
    
.skip:
    inc r12
    jmp .next_expert
    
.done:
    mov BYTE PTR [rdi], 13
    inc rdi
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 0
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
WriteExpertHeatMap ENDP

;------------------------------------------------------------------------------
; WriteStatistics
;------------------------------------------------------------------------------
WriteStatistics PROC
    push rbx
    push rdi
    
    lea rdi, formatBuffer
    
    lea rsi, [statsHeader]
    call CopyString
    
    ; Router events
    lea rsi, [routerStatLabel]
    call CopyString
    mov rax, routerEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Expert events
    lea rsi, [expertStatLabel]
    call CopyString
    mov rax, expertEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Breakdown by capability
    lea rsi, [capabilityBreakdown]
    call CopyString
    
    ; Ghost
    lea rsi, [ghostStatLabel]
    call CopyString
    mov rax, ghostEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Swarm
    lea rsi, [swarmStatLabel]
    call CopyString
    mov rax, swarmEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Latent
    lea rsi, [latentStatLabel]
    call CopyString
    mov rax, latentEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Shadow
    lea rsi, [shadowStatLabel]
    call CopyString
    mov rax, shadowEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Speculative
    lea rsi, [speculativeStatLabel]
    call CopyString
    mov rax, speculativeEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Prefetch
    lea rsi, [prefetchStatLabel]
    call CopyString
    mov rax, prefetchEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Echo
    lea rsi, [echoStatLabel]
    call CopyString
    mov rax, echoEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    ; Merge
    lea rsi, [mergeStatLabel]
    call CopyString
    mov rax, mergeEvents
    call FormatDecimal
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 13
    inc rdi
    
    mov BYTE PTR [rdi], 0
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    pop rdi
    pop rbx
    ret
WriteStatistics ENDP

;------------------------------------------------------------------------------
; Helper: WriteLogEntry
;------------------------------------------------------------------------------
WriteLogEntry PROC
    push rbx
    push rdi
    
    mov rdi, rcx
    
    xor rax, rax
    mov rcx, -1
    repne scasb
    not rcx
    dec rcx
    mov r8, rcx
    
    mov rcx, logFileHandle
    cmp rcx, INVALID_HANDLE_VALUE
    je @F
    
    mov rdx, rdi
    sub rdx, r8
    sub rdx, 1
    
    sub rsp, 40
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    add rsp, 40
    
@@: pop rdi
    pop rbx
    ret
WriteLogEntry ENDP

;------------------------------------------------------------------------------
; Helper: FormatHexQword
;------------------------------------------------------------------------------
FormatHexQword PROC
    push rax
    push rcx
    push rdx
    
    mov rcx, 16
    
@@: rol rax, 4
    mov rdx, rax
    and rdx, 0Fh
    cmp rdx, 10
    jb @F
    add rdx, 'A' - 10 - '0'
@@: add rdx, '0'
    mov BYTE PTR [rdi], dl
    inc rdi
    dec rcx
    jnz @B
    
    pop rdx
    pop rcx
    pop rax
    ret
FormatHexQword ENDP

;------------------------------------------------------------------------------
; Helper: FormatDecimal
;------------------------------------------------------------------------------
FormatDecimal PROC
    push rax
    push rbx
    push rcx
    push rdx
    
    mov rbx, 10
    xor rcx, rcx
    
    test rax, rax
    jnz @F
    mov BYTE PTR [rdi], '0'
    inc rdi
    jmp .done
    
@@: xor rdx, rdx
    div rbx
    push rdx
    inc rcx
    test rax, rax
    jnz @B
    
.output:
    pop rax
    add al, '0'
    mov BYTE PTR [rdi], al
    inc rdi
    dec rcx
    jnz .output
    
.done:
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
FormatDecimal ENDP

;------------------------------------------------------------------------------
; Helper: CopyString
;------------------------------------------------------------------------------
CopyString PROC
    push rax
    push rsi
    push rdi
    
@@: lodsb
    test al, al
    jz @F
    stosb
    jmp @B
    
@@: pop rdi
    pop rsi
    pop rax
    ret
CopyString ENDP

;------------------------------------------------------------------------------
; Data
;------------------------------------------------------------------------------
.DATA

semanticHeader      BYTE "==============================================================================", 13, 10
                    BYTE "MoE Semantic Capability Trace Log", 13, 10
                    BYTE "Format: [TIMESTAMP] EXPERT id=N (semantic_name) confidence=X% [capabilities]", 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE 13, 10, 0

heatMapHeader       BYTE 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE "Expert Activation Heat Map", 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE 13, 10, 0

expertEventType     BYTE "EXPERT", 0
idLabel             BYTE " id=", 0
confidenceLabel     BYTE " confidence=", 0

statsHeader         BYTE 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE "Event Statistics", 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE 13, 10, 0

routerStatLabel     BYTE "Router events: ", 0
expertStatLabel     BYTE "Total expert activations: ", 0
capabilityBreakdown BYTE 13, 10
                    BYTE "By Capability:", 13, 10, 0
ghostStatLabel      BYTE "  Ghost text events: ", 0
swarmStatLabel      BYTE "  Swarm mode events: ", 0
latentStatLabel     BYTE "  Latent expert events: ", 0
shadowStatLabel     BYTE "  Shadow routing events: ", 0
speculativeStatLabel BYTE "  Speculative branch events: ", 0
prefetchStatLabel   BYTE "  Prefetch events: ", 0
echoStatLabel       BYTE "  Echo refinement events: ", 0
mergeStatLabel      BYTE "  Merge events: ", 0

bytesWritten        DWORD 0

;------------------------------------------------------------------------------
; Exports
;------------------------------------------------------------------------------
PUBLIC InitializeTraceLogger
PUBLIC ShutdownTraceLogger
PUBLIC LogExpertEventNamed
PUBLIC LogExpertEventContext

END
