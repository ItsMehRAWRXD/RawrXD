;==============================================================================
; TraceLogger.asm - Logging Infrastructure for MoE Capability Recovery
;==============================================================================
; Assemble with: ml64 TraceLogger.asm /link /subsystem:console /out:TraceLogger.dll
;==============================================================================

INCLUDE \masm64\include64\masm64rt.inc

;==============================================================================
; Data Section
;==============================================================================
.DATA

; Log file handle
logFileHandle       QWORD 0
logFilePath         BYTE "moe_trace.log", 0
logMutex            BYTE 64 DUP(0)  ; CRITICAL_SECTION structure

; Buffer for formatting
formatBuffer        BYTE 4096 DUP(0)
tempBuffer          BYTE 256 DUP(0)

; Event counters (for statistics)
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

;==============================================================================
; Code Section
;==============================================================================
.CODE

;------------------------------------------------------------------------------
; InitializeTraceLogger - Call this once at startup
;------------------------------------------------------------------------------
InitializeTraceLogger PROC
    push rbx
    push rdi
    push rsi
    
    ; Initialize critical section
    lea rcx, logMutex
    call InitializeCriticalSection
    
    ; Create/open log file
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
    
    ; If file opened successfully, seek to end for append
    cmp rax, INVALID_HANDLE_VALUE
    je @F
    
    mov rcx, logFileHandle
    mov rdx, NULL
    mov r8, FILE_END
    sub rsp, 32
    call SetFilePointerEx
    add rsp, 32
    
    ; Write header
    lea rcx, headerText
    call WriteLogHeader
    
@@: pop rsi
    pop rdi
    pop rbx
    ret
InitializeTraceLogger ENDP

;------------------------------------------------------------------------------
; ShutdownTraceLogger - Call this before exit
;------------------------------------------------------------------------------
ShutdownTraceLogger PROC
    push rbx
    
    ; Write footer
    call WriteStatistics
    
    ; Close log file
    mov rcx, logFileHandle
    cmp rcx, INVALID_HANDLE_VALUE
    je @F
    sub rsp, 32
    call CloseHandle
    add rsp, 32
    
@@: ; Delete critical section
    lea rcx, logMutex
    call DeleteCriticalSection
    
    pop rbx
    ret
ShutdownTraceLogger ENDP

;------------------------------------------------------------------------------
; LogRouterEvent - Log router entry/exit
; RCX = timestamp, RDX = router_id, R8 = message, R9 = expert_selected
;------------------------------------------------------------------------------
LogRouterEvent PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx        ; timestamp
    mov r13, rdx        ; router_id
    mov r14, r8         ; message
    mov r15, r9         ; expert_selected (may be 0 for entry)
    
    ; Enter critical section
    lea rcx, logMutex
    call EnterCriticalSection
    
    ; Format: [TIMESTAMP] ROUTER router_id=XX expert=YY msg
    lea rdi, formatBuffer
    
    ; Opening bracket and timestamp
    mov BYTE PTR [rdi], '['
    inc rdi
    
    ; Convert timestamp to hex string
    mov rax, r12
    call FormatHexQword
    
    ; Close bracket
    mov BYTE PTR [rdi], ']'
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    ; Event type
    lea rsi, [routerEventType]
    call CopyString
    
    ; Router ID
    mov rax, r13
    call FormatDecimal
    
    ; Expert (if specified)
    test r15, r15
    jz @F
    
    lea rsi, [expertLabel]
    call CopyString
    mov rax, r15
    call FormatDecimal
    
@@: ; Message
    mov rsi, r14
    call CopyString
    
    ; Newline
    mov BYTE PTR [rdi], 13
    inc rdi
    mov BYTE PTR [rdi], 10
    inc rdi
    mov BYTE PTR [rdi], 0
    
    ; Write to file
    lea rcx, formatBuffer
    call WriteLogEntry
    
    ; Update counter
    inc routerEvents
    
    ; Leave critical section
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
LogRouterEvent ENDP

;------------------------------------------------------------------------------
; LogExpertEvent - Log expert activation
; RCX = timestamp, RDX = expert_id, R8 = confidence
;------------------------------------------------------------------------------
LogExpertEvent PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    
    lea rcx, logMutex
    call EnterCriticalSection
    
    lea rdi, formatBuffer
    
    ; Format: [TIMESTAMP] EXPERT id=X confidence=Y
    mov BYTE PTR [rdi], '['
    inc rdi
    mov rax, r12
    call FormatHexQword
    mov BYTE PTR [rdi], ']'
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi
    
    lea rsi, [expertEventType]
    call CopyString
    
    lea rsi, [idLabel]
    call CopyString
    mov rax, r13
    call FormatDecimal
    
    lea rsi, [confidenceLabel]
    call CopyString
    mov rax, r14
    call FormatDecimal
    mov BYTE PTR [rdi], '%'
    inc rdi
    
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
    
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
LogExpertEvent ENDP

;------------------------------------------------------------------------------
; LogSwarmEvent - Log swarm mode activation
;------------------------------------------------------------------------------
LogSwarmEvent PROC
    ; Implementation similar to above
    inc swarmEvents
    ret
LogSwarmEvent ENDP

;------------------------------------------------------------------------------
; LogGhostEvent - Log ghost text generation
;------------------------------------------------------------------------------
LogGhostEvent PROC
    inc ghostEvents
    ret
LogGhostEvent ENDP

;------------------------------------------------------------------------------
; LogSpeculativeEvent - Log speculative execution
;------------------------------------------------------------------------------
LogSpeculativeEvent PROC
    inc speculativeEvents
    ret
LogSpeculativeEvent ENDP

;------------------------------------------------------------------------------
; LogPrefetchEvent - Log prefetch operations
;------------------------------------------------------------------------------
LogPrefetchEvent PROC
    inc prefetchEvents
    ret
LogPrefetchEvent ENDP

;------------------------------------------------------------------------------
; LogLatentEvent - Log latent expert activation
;------------------------------------------------------------------------------
LogLatentEvent PROC
    inc latentEvents
    ret
LogLatentEvent ENDP

;------------------------------------------------------------------------------
; LogShadowEvent - Log shadow routing
;------------------------------------------------------------------------------
LogShadowEvent PROC
    inc shadowEvents
    ret
LogShadowEvent ENDP

;------------------------------------------------------------------------------
; LogMergeEvent - Log merge operations
;------------------------------------------------------------------------------
LogMergeEvent PROC
    inc mergeEvents
    ret
LogMergeEvent ENDP

;------------------------------------------------------------------------------
; LogEchoEvent - Log echo/refinement
;------------------------------------------------------------------------------
LogEchoEvent PROC
    inc echoEvents
    ret
LogEchoEvent ENDP

;------------------------------------------------------------------------------
; Helper: WriteLogEntry
; RCX = pointer to null-terminated string
;------------------------------------------------------------------------------
WriteLogEntry PROC
    push rbx
    push rdi
    
    mov rdi, rcx
    
    ; Calculate length
    xor rax, rax
    mov rcx, -1
    repne scasb
    not rcx
    dec rcx
    mov r8, rcx         ; Length
    
    ; Write to file
    mov rcx, logFileHandle
    cmp rcx, INVALID_HANDLE_VALUE
    je @F
    
    mov rdx, rdi
    sub rdx, r8         ; Start of string
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
; RAX = value to format, RDI = destination buffer
;------------------------------------------------------------------------------
FormatHexQword PROC
    push rax
    push rcx
    push rdx
    
    mov rcx, 16         ; 16 hex digits
    
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
; RAX = value to format, RDI = destination buffer
;------------------------------------------------------------------------------
FormatDecimal PROC
    push rax
    push rbx
    push rcx
    push rdx
    
    mov rbx, 10
    xor rcx, rcx        ; Digit count
    
    ; Handle 0 specially
    test rax, rax
    jnz @F
    mov BYTE PTR [rdi], '0'
    inc rdi
    jmp .done
    
@@: ; Convert to decimal
.convert_loop:
    xor rdx, rdx
    div rbx
    push rdx
    inc rcx
    test rax, rax
    jnz .convert_loop
    
    ; Output digits
.output_loop:
    pop rax
    add al, '0'
    mov BYTE PTR [rdi], al
    inc rdi
    dec rcx
    jnz .output_loop
    
.done:
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
FormatDecimal ENDP

;------------------------------------------------------------------------------
; Helper: CopyString
; RSI = source, RDI = destination
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
; Helper: WriteLogHeader
;------------------------------------------------------------------------------
WriteLogHeader PROC
    push rbx
    push rdi
    
    lea rdi, formatBuffer
    
    lea rsi, [headerText]
    call CopyString
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    pop rdi
    pop rbx
    ret
WriteLogHeader ENDP

;------------------------------------------------------------------------------
; Helper: WriteStatistics
;------------------------------------------------------------------------------
WriteStatistics PROC
    push rbx
    push rdi
    
    lea rdi, formatBuffer
    
    ; Format statistics
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
    
    ; ... more stats ...
    
    mov BYTE PTR [rdi], 0
    
    lea rcx, formatBuffer
    call WriteLogEntry
    
    pop rdi
    pop rbx
    ret
WriteStatistics ENDP

;------------------------------------------------------------------------------
; Data
;------------------------------------------------------------------------------
.DATA

headerText          BYTE "==============================================================================", 13, 10
                    BYTE "MoE Capability Trace Log", 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE 13, 10, 0

routerEventType     BYTE "ROUTER ", 0
expertEventType     BYTE "EXPERT ", 0
expertLabel         BYTE " expert=", 0
idLabel             BYTE " id=", 0
confidenceLabel     BYTE " confidence=", 0

statsHeader         BYTE 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE "Event Statistics", 13, 10
                    BYTE "==============================================================================", 13, 10
                    BYTE 13, 10, 0

routerStatLabel     BYTE "Router events: ", 0
expertStatLabel     BYTE "Expert activations: ", 0

bytesWritten        DWORD 0

;------------------------------------------------------------------------------
; Exports
;------------------------------------------------------------------------------
PUBLIC InitializeTraceLogger
PUBLIC ShutdownTraceLogger
PUBLIC LogRouterEvent
PUBLIC LogExpertEvent
PUBLIC LogSwarmEvent
PUBLIC LogGhostEvent
PUBLIC LogSpeculativeEvent
PUBLIC LogPrefetchEvent
PUBLIC LogLatentEvent
PUBLIC LogShadowEvent
PUBLIC LogMergeEvent
PUBLIC LogEchoEvent

END
