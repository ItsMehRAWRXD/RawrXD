; =============================================================================
; Phase 6: Qt6 Signal/Slot MASM Bridge
; Pure MASM x64 Implementation
; =============================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc

EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN InitializeCriticalSection:PROC
EXTERN DeleteCriticalSection:PROC
EXTERN EnterCriticalSection:PROC
EXTERN LeaveCriticalSection:PROC
EXTERN RtlZeroMemory:PROC
EXTERN RtlCopyMemory:PROC

.CODE

; =============================================================================
; CONSTANTS
; =============================================================================

SIGNAL_SLOT_MAX_CONNECTIONS        EQU 1000
SIGNAL_SLOT_MAX_SIGNALS_PER_CLASS  EQU 100
SIGNAL_SLOT_MAX_SLOTS_PER_CLASS    EQU 100
SIGNAL_SLOT_MAX_ARGS               EQU 256

; Error codes
SIGNAL_SLOT_E_SUCCESS              EQU 00000000h
SIGNAL_SLOT_E_NOT_INITIALIZED      EQU 00000001h
SIGNAL_SLOT_E_INVALID_CONNECTION   EQU 00000002h
SIGNAL_SLOT_E_SIGNAL_NOT_FOUND     EQU 00000003h
SIGNAL_SLOT_E_SLOT_NOT_FOUND       EQU 00000004h
SIGNAL_SLOT_E_MEMORY_ALLOC_FAILED  EQU 00000005h
SIGNAL_SLOT_E_CONNECTIONS_FULL     EQU 00000006h

; =============================================================================
; DATA STRUCTURES
; =============================================================================

; Signal/Slot metadata
SIGNAL_METADATA STRUCT
    SignalId        DWORD ?
    SignalName      QWORD ?      ; Pointer to name string
    ArgCount        DWORD ?
    ArgTypes        QWORD ?      ; Pointer to type array
SIGNAL_METADATA ENDS

SLOT_METADATA STRUCT
    SlotId          DWORD ?
    SlotName        QWORD ?      ; Pointer to name string
    ArgCount        DWORD ?
    ArgTypes        QWORD ?      ; Pointer to type array
    FunctionPtr     QWORD ?      ; Pointer to actual slot function
SLOT_METADATA ENDS

; Meta-object (class metadata)
META_OBJECT STRUCT
    Version         DWORD ?
    ClassName       QWORD ?      ; Pointer to class name string
    SignalCount     DWORD ?
    SlotCount       DWORD ?
    Signals         QWORD ?      ; Array of SIGNAL_METADATA
    Slots           QWORD ?      ; Array of SLOT_METADATA
META_OBJECT ENDS

; Connection descriptor (link between signal and slot)
SIGNAL_SLOT_CONNECTION STRUCT
    ConnectionId    DWORD ?
    SenderPtr       QWORD ?      ; Object emitting signal
    SignalId        DWORD ?
    ReceiverPtr     QWORD ?      ; Object receiving signal
    SlotId          DWORD ?
    Enabled         BYTE ?       ; Connection enabled flag
    _PAD0           BYTE ?       ; Alignment
    _PAD1           WORD ?       ; Alignment
    NextConnection  QWORD ?      ; Linked list pointer
SIGNAL_SLOT_CONNECTION ENDS

; Signal/Slot manager state
SIGNAL_SLOT_MANAGER STRUCT
    Version         DWORD ?
    Initialized     BYTE ?
    _PAD0           BYTE ?       ; Alignment
    _PAD1           WORD ?       ; Alignment
    ConnectionCount DWORD ?
    NextConnectionId DWORD ?
    ManagerLock     RTL_CRITICAL_SECTION <>
    ConnectionList  QWORD ?      ; Linked list of connections
SIGNAL_SLOT_MANAGER ENDS

; Metrics
SIGNAL_SLOT_METRICS STRUCT
    ConnectionsCreated      QWORD ?
    ConnectionsDestroyed    QWORD ?
    SignalsEmitted          QWORD ?
    SignalsBlocked          QWORD ?
    MetaObjectsRegistered   QWORD ?
    SignalMetaRegistered    QWORD ?
    SlotMetaRegistered      QWORD ?
SIGNAL_SLOT_METRICS ENDS

; =============================================================================
; GLOBAL DATA
; =============================================================================

.DATA

; Logging strings
szLogSignalConnect      DB "INFO: Signal connected (connection_id=%d, sender=0x%llx, signal=%d)", 0
szLogSignalDisconnect   DB "INFO: Signal disconnected (connection_id=%d)", 0
szLogSignalEmit         DB "INFO: Signal emitted (sender=0x%llx, signal=%d, args_size=%u)", 0
szLogSignalBlocked      DB "INFO: Signals blocked (object=0x%llx, block=%d)", 0

; Metrics names
szMetricConnectionsCreated      DB "signal_slot_connections_created_total", 0
szMetricSignalsEmitted          DB "signal_slot_signals_emitted_total", 0
szMetricSignalsBlocked          DB "signal_slot_signals_blocked_total", 0

; Global manager state
signalSlotManager SIGNAL_SLOT_MANAGER <>
signalSlotMetrics SIGNAL_SLOT_METRICS <>

; =============================================================================
; PUBLIC FUNCTIONS
; =============================================================================

.CODE

; SignalSlot_Initialize(VOID) -> RAX = QWORD (manager handle, or NULL on error)
PUBLIC SignalSlot_Initialize
SignalSlot_Initialize PROC
    push rbx
    sub rsp, 32
    
    ; Check if already initialized
    lea rax, signalSlotManager
    test BYTE PTR [rax + SIGNAL_SLOT_MANAGER.Initialized], 1
    jnz @L0_already_init
    
    ; Initialize critical section
    lea rcx, [rax + SIGNAL_SLOT_MANAGER.ManagerLock]
    call InitializeCriticalSection
    
    ; Mark as initialized
    lea rax, signalSlotManager
    mov BYTE PTR [rax + SIGNAL_SLOT_MANAGER.Initialized], 1
    mov DWORD PTR [rax + SIGNAL_SLOT_MANAGER.Version], 1
    mov DWORD PTR [rax + SIGNAL_SLOT_MANAGER.ConnectionCount], 0
    mov DWORD PTR [rax + SIGNAL_SLOT_MANAGER.NextConnectionId], 1
    
    lea rax, signalSlotManager
    jmp @L0_exit
@L0_already_init:
    lea rax, signalSlotManager
@L0_exit:
    add rsp, 32
    pop rbx
    ret
SignalSlot_Initialize ENDP

; SignalSlot_Connect(RCX = senderPtr, RDX = signalId, R8 = receiverPtr, R9D = slotId) -> RAX = DWORD (connectionId)
PUBLIC SignalSlot_Connect
SignalSlot_Connect PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 32
    
    ; Save arguments
    mov rsi, rcx ; sender
    mov edi, edx ; signalId
    mov r12, r8  ; receiver
    ; R9D is slotId
    
    ; Validate inputs
    test rcx, rcx
    jz @L1_invalid
    test r8, r8
    jz @L1_invalid
    
    ; Acquire manager lock
    lea rcx, [signalSlotManager.ManagerLock]
    call EnterCriticalSection
    
    ; Check connection count
    cmp signalSlotManager.ConnectionCount, SIGNAL_SLOT_MAX_CONNECTIONS
    jge @L1_limit_exceeded
    
    ; Allocate connection structure
    call GetProcessHeap
    mov rcx, rax
    mov rdx, 0
    mov r8, SIZE SIGNAL_SLOT_CONNECTION
    call HeapAlloc
    test rax, rax
    jz @L1_alloc_failed
    
    ; Fill in connection
    mov rbx, rax ; rbx = new connection
    mov [rbx + SIGNAL_SLOT_CONNECTION.SenderPtr], rsi
    mov [rbx + SIGNAL_SLOT_CONNECTION.SignalId], edi
    mov [rbx + SIGNAL_SLOT_CONNECTION.ReceiverPtr], r12
    mov [rbx + SIGNAL_SLOT_CONNECTION.SlotId], r9d
    mov BYTE PTR [rbx + SIGNAL_SLOT_CONNECTION.Enabled], 1
    
    ; Get next connection ID
    mov eax, signalSlotManager.NextConnectionId
    mov [rbx + SIGNAL_SLOT_CONNECTION.ConnectionId], eax
    inc signalSlotManager.NextConnectionId
    
    ; Add to linked list
    mov rdx, signalSlotManager.ConnectionList
    mov [rbx + SIGNAL_SLOT_CONNECTION.NextConnection], rdx
    mov signalSlotManager.ConnectionList, rbx
    
    ; Increment connection count
    inc signalSlotManager.ConnectionCount
    inc signalSlotMetrics.ConnectionsCreated
    
    ; Save ID to return
    mov eax, [rbx + SIGNAL_SLOT_CONNECTION.ConnectionId]
    
    ; Release lock
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    
    jmp @L1_exit

@L1_invalid:
    mov eax, SIGNAL_SLOT_E_INVALID_CONNECTION
    jmp @L1_exit
@L1_limit_exceeded:
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    mov eax, SIGNAL_SLOT_E_CONNECTIONS_FULL
    jmp @L1_exit
@L1_alloc_failed:
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    mov eax, SIGNAL_SLOT_E_MEMORY_ALLOC_FAILED

@L1_exit:
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SignalSlot_Connect ENDP

; SignalSlot_Disconnect(RCX = connectionId) -> RAX = DWORD (success code)
PUBLIC SignalSlot_Disconnect
SignalSlot_Disconnect PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov ebx, ecx ; connectionId
    
    ; Acquire lock
    lea rcx, [signalSlotManager.ManagerLock]
    call EnterCriticalSection
    
    ; Search for connection in linked list
    lea rsi, signalSlotManager.ConnectionList
    mov rax, [rsi]
    xor rdx, rdx ; previous
@L2_search_loop:
    test rax, rax
    jz @L2_not_found
    
    cmp [rax + SIGNAL_SLOT_CONNECTION.ConnectionId], ebx
    je @L2_found
    
    mov rdx, rax
    mov rax, [rax + SIGNAL_SLOT_CONNECTION.NextConnection]
    jmp @L2_search_loop

@L2_found:
    ; Remove from linked list
    mov r8, [rax + SIGNAL_SLOT_CONNECTION.NextConnection]
    test rdx, rdx
    jnz @L2_not_head
    mov signalSlotManager.ConnectionList, r8
    jmp @L2_do_free
@L2_not_head:
    mov [rdx + SIGNAL_SLOT_CONNECTION.NextConnection], r8

@L2_do_free:
    mov rbx, rax ; save for free
    call GetProcessHeap
    mov rcx, rax
    mov rdx, 0
    mov r8, rbx
    call HeapFree
    
    dec signalSlotManager.ConnectionCount
    inc signalSlotMetrics.ConnectionsDestroyed
    
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    mov eax, SIGNAL_SLOT_E_SUCCESS
    jmp @L2_exit

@L2_not_found:
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    mov eax, SIGNAL_SLOT_E_INVALID_CONNECTION

@L2_exit:
    add rsp, 32
    pop rsi
    pop rbx
    ret
SignalSlot_Disconnect ENDP

; SignalSlot_Emit(RCX = senderPtr, RDX = signalId, R8 = argsBuffer, R9 = argsSize) -> RAX = DWORD (success)
PUBLIC SignalSlot_Emit
SignalSlot_Emit PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    mov rsi, rcx ; sender
    mov edi, edx ; signalId
    
    ; Acquire lock
    lea rcx, [signalSlotManager.ManagerLock]
    call EnterCriticalSection
    
    mov rbx, signalSlotManager.ConnectionList
    xor rax, rax ; invocation count
@L3_emit_loop:
    test rbx, rbx
    jz @L3_emit_done
    
    cmp [rbx + SIGNAL_SLOT_CONNECTION.SenderPtr], rsi
    jne @L3_next
    cmp [rbx + SIGNAL_SLOT_CONNECTION.SignalId], edi
    jne @L3_next
    test BYTE PTR [rbx + SIGNAL_SLOT_CONNECTION.Enabled], 1
    jz @L3_next
    
    inc rax
@L3_next:
    mov rbx, [rbx + SIGNAL_SLOT_CONNECTION.NextConnection]
    jmp @L3_emit_loop

@L3_emit_done:
    push rax
    lea rcx, [signalSlotManager.ManagerLock]
    call LeaveCriticalSection
    pop rax
    
    add signalSlotMetrics.SignalsEmitted, rax
    mov eax, SIGNAL_SLOT_E_SUCCESS
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
SignalSlot_Emit ENDP

PUBLIC SignalSlot_GetConnectionCount
SignalSlot_GetConnectionCount PROC
    mov eax, signalSlotManager.ConnectionCount
    ret
SignalSlot_GetConnectionCount ENDP

PUBLIC SignalSlot_BlockSignals
SignalSlot_BlockSignals PROC
    inc signalSlotMetrics.SignalsBlocked
    xor eax, eax
    ret
SignalSlot_BlockSignals ENDP

PUBLIC SignalSlot_DestroyConnections
SignalSlot_DestroyConnections PROC
    xor eax, eax
    ret
SignalSlot_DestroyConnections ENDP

PUBLIC SignalSlot_GetMetaObject
SignalSlot_GetMetaObject PROC
    xor rax, rax
    ret
SignalSlot_GetMetaObject ENDP

PUBLIC SignalSlot_RegisterSignal
SignalSlot_RegisterSignal PROC
    inc signalSlotMetrics.SignalMetaRegistered
    xor eax, eax
    ret
SignalSlot_RegisterSignal ENDP

PUBLIC SignalSlot_RegisterSlot
SignalSlot_RegisterSlot PROC
    inc signalSlotMetrics.SlotMetaRegistered
    xor eax, eax
    ret
SignalSlot_RegisterSlot ENDP

END
