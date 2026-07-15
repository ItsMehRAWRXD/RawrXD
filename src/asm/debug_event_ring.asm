; ============================================================================
; debug_event_ring.asm - x64 MASM Debug Event Ring Buffer
; ============================================================================
; Purpose: Lock-free ring buffer for debug event serialization
;          Enables debugger thread to push events while GUI thread consumes
;          at 60 FPS without deadlocking.
;
; Architecture:
;   - Single Producer (Debugger Thread): DbgEvent_Push
;   - Single Consumer (GUI Thread): DbgEvent_Pop
;   - Lock-free SPSC pattern with memory barriers
;   - O(1) push and pop operations
;
; Integration:
;   - Debugger thread calls DbgEvent_Push after WaitForDebugEvent
;   - GUI thread calls DbgEvent_Pop during render loop
;   - Events serialized to ring buffer with CONTEXT data
;
; Build: ml64 /c /Zi debug_event_ring.asm
; ============================================================================

option casemap:none

; ============================================================================
; Constants
; ============================================================================

; Ring buffer size (must be power of 2)
DEBUG_EVENT_RING_SIZE    EQU 256
DEBUG_EVENT_RING_MASK    EQU (DEBUG_EVENT_RING_SIZE - 1)

; Event types
DBG_EVENT_BREAKPOINT     EQU 1
DBG_EVENT_SINGLE_STEP    EQU 2
DBG_EVENT_EXCEPTION      EQU 3
DBG_EVENT_CREATE_PROCESS EQU 4
DBG_EVENT_EXIT_PROCESS   EQU 5
DBG_EVENT_CREATE_THREAD  EQU 6
DBG_EVENT_EXIT_THREAD    EQU 7
DBG_EVENT_LOAD_DLL       EQU 8
DBG_EVENT_UNLOAD_DLL     EQU 9
DBG_EVENT_OUTPUT_STRING  EQU 10

; Context structure offsets (x64)
CTX_ContextFlags          EQU 30h
CTX_Rip                   EQU 0F8h
CTX_Rax                   EQU 78h
CTX_Rbx                   EQU 90h
CTX_Rcx                   EQU 80h
CTX_Rdx                   EQU 88h
CTX_Rsi                   EQU 0A8h
CTX_Rdi                   EQU 0B0h
CTX_Rbp                   EQU 0A0h
CTX_Rsp                   EQU 98h
CTX_R8                    EQU 0B8h
CTX_R9                    EQU 0C0h
CTX_R10                   EQU 0C8h
CTX_R11                   EQU 0D0h
CTX_R12                   EQU 0D8h
CTX_R13                   EQU 0E0h
CTX_R14                   EQU 0E8h
CTX_R15                   EQU 0F0h
CTX_EFlags                EQU 44h
CTX_Dr0                   EQU 48h
CTX_Dr1                   EQU 50h
CTX_Dr2                   EQU 58h
CTX_Dr3                   EQU 60h
CTX_Dr6                   EQU 68h
CTX_Dr7                   EQU 70h
CONTEXT_SIZE              EQU 4D0h

; ============================================================================
; Structures
; ============================================================================

; Debug event entry (512 bytes)
DEBUG_EVENT_ENTRY STRUCT
    eventType       DD ?            ; DBG_EVENT_* constant
    processId       DD ?            ; PID
    threadId        DD ?            ; TID
    reserved        DD ?            ; Padding
    exceptionCode   DQ ?            ; Exception code (if applicable)
    exceptionAddr   DQ ?            ; Exception address
    reg_rip         DQ ?            ; Instruction pointer
    reg_rax         DQ ?            ; General purpose registers
    reg_rbx         DQ ?
    reg_rcx         DQ ?
    reg_rdx         DQ ?
    reg_rsi         DQ ?
    reg_rdi         DQ ?
    reg_rbp         DQ ?
    reg_rsp         DQ ?
    reg_r8          DQ ?
    reg_r9          DQ ?
    reg_r10         DQ ?
    reg_r11         DQ ?
    reg_r12         DQ ?
    reg_r13         DQ ?
    reg_r14         DQ ?
    reg_r15         DQ ?
    reg_eflags      DQ ?            ; RFLAGS
    reg_dr0         DQ ?            ; Debug registers
    reg_dr1         DQ ?
    reg_dr2         DQ ?
    reg_dr3         DQ ?
    reg_dr6         DQ ?
    reg_dr7         DQ ?
    timestamp       DQ ?            ; RDTSC timestamp
    stackFrame0     DQ ?            ; First 4 stack frames
    stackFrame1     DQ ?
    stackFrame2     DQ ?
    stackFrame3     DQ ?
    auxData         DB 64 DUP(?)    ; Auxiliary data (module name, etc.)
DEBUG_EVENT_ENTRY ENDS

; Ring buffer control
DEBUG_EVENT_RING STRUCT
    events          DEBUG_EVENT_ENTRY DEBUG_EVENT_RING_SIZE DUP(<>)
    head            DQ ?            ; Producer index (write position)
    tail            DQ ?            ; Consumer index (read position)
    count           DQ ?            ; Current event count
    overflowCount   DQ ?            ; Events dropped due to full buffer
    _padding        DQ ?            ; Cache line alignment
DEBUG_EVENT_RING ENDS

; ============================================================================
; External APIs
; ============================================================================

EXTERN GetTickCount64:PROC
EXTERN ReadProcessMemory:PROC

; ============================================================================
; Data Section
; ============================================================================

.data

ALIGN 16
g_debugEventRing   DEBUG_EVENT_RING <>
g_ringInitialized   DB 0

; Statistics
g_eventsPushed      DQ 0
g_eventsPopped      DQ 0
g_eventsDropped     DQ 0

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; DbgEvent_Init
; ============================================================================
; Initialize the debug event ring buffer.
; Must be called before any push/pop operations.
;
; Parameters: None
; Returns: RAX = 1 success, 0 failure
; ============================================================================

ALIGN 16
DbgEvent_Init PROC
    
    ; Check if already initialized
    cmp     byte ptr [g_ringInitialized], 1
    je      L_already_init
    
    ; Clear the ring buffer
    lea     rdi, [g_debugEventRing]
    mov     rcx, SIZEOF DEBUG_EVENT_RING
    xor     eax, eax
    rep     stosb
    
    ; Initialize head/tail to 0
    lea     rdi, [g_debugEventRing]
    mov     qword ptr [rdi + DEBUG_EVENT_RING.head], 0
    mov     qword ptr [rdi + DEBUG_EVENT_RING.tail], 0
    mov     qword ptr [rdi + DEBUG_EVENT_RING.count], 0
    mov     qword ptr [rdi + DEBUG_EVENT_RING.overflowCount], 0
    
    ; Mark as initialized
    mov     byte ptr [g_ringInitialized], 1
    
    ; Clear statistics
    mov     qword ptr [g_eventsPushed], 0
    mov     qword ptr [g_eventsPopped], 0
    mov     qword ptr [g_eventsDropped], 0
    
L_already_init:
    mov     rax, 1
    ret

DbgEvent_Init ENDP

; ============================================================================
; DbgEvent_Push
; ============================================================================
; Push a debug event into the ring buffer (Producer).
; Called from debugger thread after WaitForDebugEvent.
;
; Parameters:
;   RCX = eventType (DBG_EVENT_*)
;   RDX = processId
;   R8  = threadId
;   R9  = pContext (pointer to CONTEXT structure, can be 0)
;   Stack[28h] = exceptionCode (optional)
;   Stack[30h] = exceptionAddr (optional)
; Returns: RAX = 1 success, 0 buffer full
; ============================================================================

ALIGN 16
DbgEvent_Push PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov     rbx, rcx                ; eventType
    mov     rsi, rdx                ; processId
    mov     rdi, r8                 ; threadId
    mov     r12, r9                 ; pContext
    
    ; Get ring buffer pointer
    lea     rax, [g_debugEventRing]
    
    ; Check if buffer is full
    mov     rcx, [rax + DEBUG_EVENT_RING.count]
    cmp     rcx, DEBUG_EVENT_RING_SIZE
    jae     L_buffer_full
    
    ; Get head index
    mov     rcx, [rax + DEBUG_EVENT_RING.head]
    and     rcx, DEBUG_EVENT_RING_MASK
    
    ; Calculate event pointer
    imul    rcx, SIZEOF DEBUG_EVENT_ENTRY
    lea     rdx, [rax + DEBUG_EVENT_RING.events]
    add     rdx, rcx
    
    ; Fill event structure
    mov     dword ptr [rdx + DEBUG_EVENT_ENTRY.eventType], ebx
    mov     dword ptr [rdx + DEBUG_EVENT_ENTRY.processId], esi
    mov     dword ptr [rdx + DEBUG_EVENT_ENTRY.threadId], edi
    
    ; Copy CONTEXT if provided
    test    r12, r12
    jz      L_no_context
    
    ; Copy registers from CONTEXT
    mov     rax, [r12 + CTX_Rip]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rip], rax
    mov     rax, [r12 + CTX_Rax]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rax], rax
    mov     rax, [r12 + CTX_Rbx]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rbx], rax
    mov     rax, [r12 + CTX_Rcx]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rcx], rax
    mov     rax, [r12 + CTX_Rdx]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rdx], rax
    mov     rax, [r12 + CTX_Rsi]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rsi], rax
    mov     rax, [r12 + CTX_Rdi]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rdi], rax
    mov     rax, [r12 + CTX_Rbp]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rbp], rax
    mov     rax, [r12 + CTX_Rsp]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_rsp], rax
    mov     rax, [r12 + CTX_R8]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r8], rax
    mov     rax, [r12 + CTX_R9]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r9], rax
    mov     rax, [r12 + CTX_R10]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r10], rax
    mov     rax, [r12 + CTX_R11]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r11], rax
    mov     rax, [r12 + CTX_R12]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r12], rax
    mov     rax, [r12 + CTX_R13]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r13], rax
    mov     rax, [r12 + CTX_R14]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r14], rax
    mov     rax, [r12 + CTX_R15]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_r15], rax
    mov     rax, [r12 + CTX_EFlags]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_eflags], rax
    mov     rax, [r12 + CTX_Dr0]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr0], rax
    mov     rax, [r12 + CTX_Dr1]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr1], rax
    mov     rax, [r12 + CTX_Dr2]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr2], rax
    mov     rax, [r12 + CTX_Dr3]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr3], rax
    mov     rax, [r12 + CTX_Dr6]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr6], rax
    mov     rax, [r12 + CTX_Dr7]
    mov     [rdx + DEBUG_EVENT_ENTRY.reg_dr7], rax
    
L_no_context:
    ; Get exception code and address from stack
    mov     rax, [rsp + 28h + 28h]      ; exceptionCode
    mov     [rdx + DEBUG_EVENT_ENTRY.exceptionCode], rax
    mov     rax, [rsp + 28h + 30h]      ; exceptionAddr
    mov     [rdx + DEBUG_EVENT_ENTRY.exceptionAddr], rax
    
    ; Get timestamp
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rdx + DEBUG_EVENT_ENTRY.timestamp], rax
    
    ; Memory barrier (ensure all writes complete before incrementing head)
    mfence
    
    ; Increment head and count
    lea     rax, [g_debugEventRing]
    lock inc qword ptr [rax + DEBUG_EVENT_RING.head]
    lock inc qword ptr [rax + DEBUG_EVENT_RING.count]
    lock inc qword ptr [g_eventsPushed]
    
    mov     rax, 1
    jmp     L_done
    
L_buffer_full:
    lock inc qword ptr [g_debugEventRing.overflowCount]
    lock inc qword ptr [g_eventsDropped]
    xor     rax, rax
    
L_done:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

DbgEvent_Push ENDP

; ============================================================================
; DbgEvent_Pop
; ============================================================================
; Pop a debug event from the ring buffer (Consumer).
; Called from GUI thread during render loop.
;
; Parameters:
;   RCX = pOutEvent (pointer to DEBUG_EVENT_ENTRY to fill)
; Returns: RAX = 1 event popped, 0 buffer empty
; ============================================================================

ALIGN 16
DbgEvent_Pop PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov     rbx, rcx                ; pOutEvent
    
    ; Check if initialized
    cmp     byte ptr [g_ringInitialized], 0
    je      L_empty
    
    ; Get ring buffer pointer
    lea     rax, [g_debugEventRing]
    
    ; Check if buffer is empty
    mov     rcx, [rax + DEBUG_EVENT_RING.count]
    test    rcx, rcx
    jz      L_empty
    
    ; Get tail index
    mov     rcx, [rax + DEBUG_EVENT_RING.tail]
    and     rcx, DEBUG_EVENT_RING_MASK
    
    ; Calculate event pointer
    imul    rcx, SIZEOF DEBUG_EVENT_ENTRY
    lea     rsi, [rax + DEBUG_EVENT_RING.events]
    add     rsi, rcx
    
    ; Copy event to output buffer
    mov     rdi, rbx                ; destination
    mov     rcx, SIZEOF DEBUG_EVENT_ENTRY
    rep     movsb
    
    ; Memory barrier
    mfence
    
    ; Increment tail and decrement count
    lea     rax, [g_debugEventRing]
    lock inc qword ptr [rax + DEBUG_EVENT_RING.tail]
    lock dec qword ptr [rax + DEBUG_EVENT_RING.count]
    lock inc qword ptr [g_eventsPopped]
    
    mov     rax, 1
    jmp     L_done
    
L_empty:
    xor     rax, rax
    
L_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret

DbgEvent_Pop ENDP

; ============================================================================
; DbgEvent_Peek
; ============================================================================
; Peek at the next event without removing it.
;
; Parameters:
;   RCX = pOutEvent (pointer to DEBUG_EVENT_ENTRY to fill)
; Returns: RAX = 1 event available, 0 buffer empty
; ============================================================================

ALIGN 16
DbgEvent_Peek PROC
    
    ; Check if initialized
    cmp     byte ptr [g_ringInitialized], 0
    je      L_empty
    
    ; Get ring buffer pointer
    lea     rax, [g_debugEventRing]
    
    ; Check if buffer is empty
    mov     rcx, [rax + DEBUG_EVENT_RING.count]
    test    rcx, rcx
    jz      L_empty
    
    ; Get tail index
    mov     rcx, [rax + DEBUG_EVENT_RING.tail]
    and     rcx, DEBUG_EVENT_RING_MASK
    
    ; Calculate event pointer
    imul    rcx, SIZEOF DEBUG_EVENT_ENTRY
    lea     rsi, [rax + DEBUG_EVENT_RING.events]
    add     rsi, rcx
    
    ; Copy event to output buffer
    mov     rdi, rcx                ; destination (from param)
    mov     rcx, SIZEOF DEBUG_EVENT_ENTRY
    rep     movsb
    
    mov     rax, 1
    ret
    
L_empty:
    xor     rax, rax
    ret

DbgEvent_Peek ENDP

; ============================================================================
; DbgEvent_GetCount
; ============================================================================
; Get the current number of events in the buffer.
;
; Parameters: None
; Returns: RAX = event count
; ============================================================================

ALIGN 16
DbgEvent_GetCount PROC
    
    lea     rax, [g_debugEventRing]
    mov     rax, [rax + DEBUG_EVENT_RING.count]
    ret

DbgEvent_GetCount ENDP

; ============================================================================
; DbgEvent_GetStats
; ============================================================================
; Get statistics about the ring buffer.
;
; Parameters: None
; Returns:
;   RAX = events pushed
;   RCX = events popped
;   RDX = events dropped
;   R8  = overflow count
; ============================================================================

ALIGN 16
DbgEvent_GetStats PROC
    
    mov     rax, [g_eventsPushed]
    mov     rcx, [g_eventsPopped]
    mov     rdx, [g_eventsDropped]
    lea     r8, [g_debugEventRing]
    mov     r8, [r8 + DEBUG_EVENT_RING.overflowCount]
    ret

DbgEvent_GetStats ENDP

; ============================================================================
; DbgEvent_Clear
; ============================================================================
; Clear all events from the buffer.
;
; Parameters: None
; Returns: RAX = 1 success
; ============================================================================

ALIGN 16
DbgEvent_Clear PROC
    
    lea     rax, [g_debugEventRing]
    mov     qword ptr [rax + DEBUG_EVENT_RING.head], 0
    mov     qword ptr [rax + DEBUG_EVENT_RING.tail], 0
    mov     qword ptr [rax + DEBUG_EVENT_RING.count], 0
    mov     rax, 1
    ret

DbgEvent_Clear ENDP

; ============================================================================
; DbgEvent_WalkStack
; ============================================================================
; Walk the call stack and store first 4 frames in the event.
; Called from debugger thread after capturing CONTEXT.
;
; Parameters:
;   RCX = hProcess
;   RDX = pEvent (pointer to DEBUG_EVENT_ENTRY)
;   R8  = startRBP (from CONTEXT.Rbp)
; Returns: RAX = number of frames captured
; ============================================================================

ALIGN 16
DbgEvent_WalkStack PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 38h
    .allocstack 38h
    .endprolog
    
    mov     rbx, rcx                ; hProcess
    mov     rsi, rdx                ; pEvent
    mov     rdi, r8                 ; startRBP
    
    ; Clear stack frames in event
    mov     qword ptr [rsi + DEBUG_EVENT_ENTRY.stackFrame0], 0
    mov     qword ptr [rsi + DEBUG_EVENT_ENTRY.stackFrame1], 0
    mov     qword ptr [rsi + DEBUG_EVENT_ENTRY.stackFrame2], 0
    mov     qword ptr [rsi + DEBUG_EVENT_ENTRY.stackFrame3], 0
    
    ; Walk RBP chain
    xor     ecx, ecx                ; frame count
    
L_walk:
    cmp     ecx, 4
    jae     L_done
    
    ; Read [RBP] (previous RBP) and [RBP+8] (return address)
    lea     r8, [rsp + 20h]         ; buffer for 16 bytes
    mov     qword ptr [rsp + 28h], 16
    mov     rcx, rbx
    mov     rdx, rdi
    call    ReadProcessMemory
    test    rax, rax
    jz      L_done
    
    ; Store return address
    mov     rax, [rsp + 28h]        ; return address at +8
    cmp     ecx, 0
    je      L_frame0
    cmp     ecx, 1
    je      L_frame1
    cmp     ecx, 2
    je      L_frame2
    jmp     L_frame3
    
L_frame0:
    mov     [rsi + DEBUG_EVENT_ENTRY.stackFrame0], rax
    jmp     L_next
L_frame1:
    mov     [rsi + DEBUG_EVENT_ENTRY.stackFrame1], rax
    jmp     L_next
L_frame2:
    mov     [rsi + DEBUG_EVENT_ENTRY.stackFrame2], rax
    jmp     L_next
L_frame3:
    mov     [rsi + DEBUG_EVENT_ENTRY.stackFrame3], rax
    
L_next:
    ; Move to previous frame
    mov     rdi, [rsp + 20h]        ; previous RBP
    test    rdi, rdi
    jz      L_done
    
    inc     ecx
    jmp     L_walk
    
L_done:
    mov     rax, rcx
    
    add     rsp, 38h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

DbgEvent_WalkStack ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC DbgEvent_Init
PUBLIC DbgEvent_Push
PUBLIC DbgEvent_Pop
PUBLIC DbgEvent_Peek
PUBLIC DbgEvent_GetCount
PUBLIC DbgEvent_GetStats
PUBLIC DbgEvent_Clear
PUBLIC DbgEvent_WalkStack

END
