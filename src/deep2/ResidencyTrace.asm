; ============================================================================
; RawrXD ResidencyTrace.asm
;
; x64 MASM
; No CRT
; No STL
; No third-party libraries
;
; Purpose:
;   Ground-truth tracing of model residency movement:
;       FILE/COLD -> RAM/WARM -> VRAM/HOT
;
; Build:
;   ml64 /c /Fo ResidencyTrace.obj ResidencyTrace.asm
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; Win64 imports
; ----------------------------------------------------------------------------

EXTERN  GetCurrentThreadId:PROC
EXTERN  QueryPerformanceCounter:PROC
EXTERN  QueryPerformanceFrequency:PROC
EXTERN  CreateFileA:PROC
EXTERN  WriteFile:PROC
EXTERN  CloseHandle:PROC

; ----------------------------------------------------------------------------
; Constants
; ----------------------------------------------------------------------------

TRACE_CAPACITY     EQU 4096
TRACE_EVENT_SIZE   EQU 128

INVALID_HANDLE     EQU -1

; Residency tiers
TIER_COLD          EQU 0
TIER_RAM           EQU 1
TIER_VRAM          EQU 2

; Operations
OP_FILE_READ       EQU 1
OP_MAP             EQU 2
OP_PREFETCH        EQU 3
OP_GPU_UPLOAD      EQU 4
OP_GPU_COMPLETE    EQU 5
OP_EVICT           EQU 6

; States
STATE_REQUESTED    EQU 1
STATE_STARTED      EQU 2
STATE_COMPLETED    EQU 3
STATE_FAILED       EQU 4

; ----------------------------------------------------------------------------
; Residency event
; ----------------------------------------------------------------------------

RESIDENCY_EVENT STRUCT

    Timestamp       QWORD ?
    Sequence        QWORD ?

    Token           DWORD ?
    Layer           DWORD ?
    TensorId        DWORD ?
    Operation       DWORD ?

    SourceTier      DWORD ?
    RequestedTier   DWORD ?
    ActualTier      DWORD ?
    State           DWORD ?

    SizeBytes       QWORD ?

    CpuAddress      QWORD ?

    VkBuffer        QWORD ?
    VkMemory        QWORD ?

    MemoryType      DWORD ?
    HeapIndex       DWORD ?

    Queue           QWORD ?
    Fence           QWORD ?

    ThreadId        DWORD ?
    Reserved        DWORD ?

RESIDENCY_EVENT ENDS

; ----------------------------------------------------------------------------
; Ring buffer
; ----------------------------------------------------------------------------

.data

ALIGN 16

gTraceWrite:
    QWORD 0

gTraceRead:
    QWORD 0

gTraceSequence:
    QWORD 0

ALIGN 16

gTraceEvents:
    BYTE (TRACE_CAPACITY * TRACE_EVENT_SIZE) DUP(0)

; QPC frequency
gQpcFrequency:
    QWORD 0

; Output file
gTraceFile:
    QWORD INVALID_HANDLE

; ----------------------------------------------------------------------------
; Static strings
; ----------------------------------------------------------------------------

szTraceFile:
    DB "rawrxd_residency.trace",0

szHeader:
    DB "RawrXD Residency Trace",13,10
    DB "======================",13,10
    DB 0

; ----------------------------------------------------------------------------
; Code
; ----------------------------------------------------------------------------

.code

; ============================================================================
; TraceInit
;
; Initializes the tracer.
;
; RCX = filename (optional, NULL uses default)
;
; Returns:
;   RAX = 1 success
;   RAX = 0 failure
; ============================================================================

TraceInit PROC

    push    rbx
    sub     rsp, 40h

    ; Query performance counter frequency
    lea     rcx, gQpcFrequency
    call    QueryPerformanceFrequency

    test    eax, eax
    jz      TraceInitFail

    ; Create output file
    mov     rdx, rcx
    lea     rcx, szTraceFile
    mov     r8d, 40000000h       ; GENERIC_WRITE
    xor     r9d, r9d             ; no sharing
    mov     rax, 2
    mov     QWORD PTR [rsp+20h], rax     ; CREATE_ALWAYS
    mov     rax, 80h
    mov     QWORD PTR [rsp+28h], rax     ; FILE_ATTRIBUTE_NORMAL
    xor     eax, eax
    mov     QWORD PTR [rsp+30h], rax
    mov     QWORD PTR [rsp+38h], rax
    call    CreateFileA

    cmp     rax, INVALID_HANDLE
    je      TraceInitFail

    mov     QWORD PTR [gTraceFile], rax

    ; Reset ring
    xor     eax, eax
    mov     QWORD PTR [gTraceWrite], rax
    mov     QWORD PTR [gTraceRead], rax
    mov     QWORD PTR [gTraceSequence], rax

    mov     eax, 1

    add     rsp, 40h
    pop     rbx
    ret

TraceInitFail:
    xor     eax, eax
    add     rsp, 40h
    pop     rbx
    ret

TraceInit ENDP

; ============================================================================
; TraceTimestamp
;
; Returns QPC in RAX.
; ============================================================================

TraceTimestamp PROC
    sub     rsp, 28h
    lea     rcx, [rsp+20h]
    call    QueryPerformanceCounter
    mov     rax, [rsp+20h]
    add     rsp, 28h
    ret
TraceTimestamp ENDP

; ============================================================================
; TraceBegin
;
; Reserves a ring slot and records the beginning of an operation.
;
; RCX = token
; RDX = layer
; R8  = tensor ID
; R9  = size bytes
;
; [rsp+28h] = source tier
; [rsp+30h] = requested tier
;
; Returns:
;   RAX = pointer to event
;   RAX = 0 if ring full
; ============================================================================

TraceBegin PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 28h

    mov     r10, rcx
    mov     r11, rdx

    ; Atomically reserve sequence number
    mov     rax, 1
    lock xadd QWORD PTR [gTraceWrite], rax

    ; RAX = old write position
    mov     rbx, rax

    ; Ring index
    and     eax, TRACE_CAPACITY-1
    imul    eax, TRACE_EVENT_SIZE
    lea     rdi, gTraceEvents
    add     rdi, rax

    ; Timestamp
    call    TraceTimestamp
    mov     [rdi].RESIDENCY_EVENT.Timestamp, rax
    mov     [rdi].RESIDENCY_EVENT.Sequence, rbx

    ; Basic metadata
    mov     [rdi].RESIDENCY_EVENT.Token, r10d
    mov     [rdi].RESIDENCY_EVENT.Layer, r11d
    mov     [rdi].RESIDENCY_EVENT.TensorId, r8d
    mov     [rdi].RESIDENCY_EVENT.SizeBytes, r9

    mov     eax, OP_PREFETCH
    mov     [rdi].RESIDENCY_EVENT.Operation, eax

    mov     eax, STATE_STARTED
    mov     [rdi].RESIDENCY_EVENT.State, eax

    mov     eax, [rsp+58h]
    mov     [rdi].RESIDENCY_EVENT.SourceTier, eax

    mov     eax, [rsp+60h]
    mov     [rdi].RESIDENCY_EVENT.RequestedTier, eax

    ; Thread
    call    GetCurrentThreadId
    mov     [rdi].RESIDENCY_EVENT.ThreadId, eax

    ; Return event pointer
    mov     rax, rdi

    add     rsp, 28h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TraceBegin ENDP

; ============================================================================
; TraceSetDestination
;
; RCX = event pointer
; RDX = actual tier
; R8  = CPU address
; R9  = VkBuffer
; [rsp+28h] = VkDeviceMemory
; [rsp+30h] = memory type
; [rsp+38h] = heap index
; ============================================================================

TraceSetDestination PROC
    mov     [rcx].RESIDENCY_EVENT.ActualTier, edx
    mov     [rcx].RESIDENCY_EVENT.CpuAddress, r8
    mov     [rcx].RESIDENCY_EVENT.VkBuffer, r9
    mov     rax, [rsp+28h]
    mov     [rcx].RESIDENCY_EVENT.VkMemory, rax
    mov     eax, [rsp+30h]
    mov     [rcx].RESIDENCY_EVENT.MemoryType, eax
    mov     eax, [rsp+38h]
    mov     [rcx].RESIDENCY_EVENT.HeapIndex, eax
    ret
TraceSetDestination ENDP

; ============================================================================
; TraceComplete
;
; RCX = event pointer
; RDX = fence
; R8  = queue
; EAX = success/nonzero
; ============================================================================

TraceComplete PROC
    mov     [rcx].RESIDENCY_EVENT.Fence, rdx
    mov     [rcx].RESIDENCY_EVENT.Queue, r8
    test    eax, eax
    jz      TraceCompleteFail
    mov     edx, STATE_COMPLETED
    mov     DWORD PTR [rcx].RESIDENCY_EVENT.State, edx
    call    TraceTimestamp
    mov     [rcx].RESIDENCY_EVENT.Timestamp, rax
    ret
TraceCompleteFail:
    mov     edx, STATE_FAILED
    mov     DWORD PTR [rcx].RESIDENCY_EVENT.State, edx
    call    TraceTimestamp
    mov     [rcx].RESIDENCY_EVENT.Timestamp, rax
    ret
TraceComplete ENDP

; ============================================================================
; TraceFlush
;
; Writes the raw event stream to disk.
; ============================================================================

TraceFlush PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 30h

    mov     rbx, gTraceFile
    cmp     rbx, INVALID_HANDLE
    je      TraceFlushDone

    mov     rsi, gTraceRead
    mov     rdi, gTraceWrite
    cmp     rsi, rdi
    je      TraceFlushDone

FlushLoop:
    mov     rax, rsi
    and     eax, TRACE_CAPACITY-1
    imul    eax, TRACE_EVENT_SIZE
    lea     rcx, gTraceEvents
    add     rcx, rax

    ; WriteFile(hFile, buffer, size, written, overlapped)
    mov     rdx, rcx
    mov     r8d, TRACE_EVENT_SIZE
    lea     r9, [rsp+20h]
    xor     eax, eax
    mov     QWORD PTR [rsp+28h], rax
    mov     rcx, rbx
    call    WriteFile

    test    eax, eax
    jz      TraceFlushDone

    inc     rsi
    cmp     rsi, rdi
    jb      FlushLoop

    mov     QWORD PTR [gTraceRead], rsi

TraceFlushDone:
    add     rsp, 30h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TraceFlush ENDP

; ============================================================================
; TraceShutdown
; ============================================================================

TraceShutdown PROC
    sub     rsp, 28h
    call    TraceFlush
    mov     rcx, gTraceFile
    cmp     rcx, INVALID_HANDLE
    je      ShutdownDone
    call    CloseHandle
ShutdownDone:
    mov     rax, INVALID_HANDLE
    mov     QWORD PTR [gTraceFile], rax
    add     rsp, 28h
    ret
TraceShutdown ENDP

END
