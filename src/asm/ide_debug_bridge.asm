; ============================================================================
; ide_debug_bridge.asm - x64 MASM IDE Debug Event Consumer
; ============================================================================
; Purpose: Bridge between debugger thread and IDE UI thread
;          Consumes debug events from ring buffer and updates UI state
;
; Architecture:
;   - Runs on GUI thread (60 FPS render loop)
;   - Polls ring buffer for new events
;   - Updates editor state (current line, breakpoints, call stack)
;   - Triggers UI redraw when debug state changes
;
; Integration:
;   - Call IDE_DebugInit during IDE startup
;   - Call IDE_DebugPoll during render loop
;   - Call IDE_DebugRender to draw debug overlays
;
; Build: ml64 /c /Zi ide_debug_bridge.asm
; ============================================================================

option casemap:none

; ============================================================================
; Constants
; ============================================================================

; Debug state flags
DEBUG_STATE_HALTED        EQU 01h
DEBUG_STATE_RUNNING       EQU 02h
DEBUG_STATE_STEPPING      EQU 04h
DEBUG_STATE_BREAKPOINT    EQU 08h
DEBUG_STATE_EXCEPTION     EQU 10h

; UI colors (COLORREF: 0x00BBGGRR)
COLOR_BP_ENABLED          EQU 00FF0000h    ; Red
COLOR_BP_DISABLED         EQU 00808080h    ; Gray
COLOR_CURRENT_LINE        EQU 00FFFF00h    ; Cyan
COLOR_CALLSTACK           EQU 0000FF00h    ; Green
COLOR_EXCEPTION           EQU 000000FFh    ; Blue

; Max call stack depth
MAX_CALLSTACK_DEPTH       EQU 32

; ============================================================================
; Structures
; ============================================================================

; Breakpoint info
BREAKPOINT_INFO STRUCT
    address        DQ ?            ; Address of breakpoint
    lineNumber     DD ?            ; Source line (if known)
    enabled        DB ?            ; 1 = enabled, 0 = disabled
    hitCount       DD ?            ; Number of times hit
    bpType         DB ?            ; 0 = software, 1 = hardware
    _pad           DB 2 DUP(?)
BREAKPOINT_INFO ENDS

; Call stack frame
CALLSTACK_FRAME STRUCT
    address        DQ ?            ; Return address
    symbolName     DB 64 DUP(?)     ; Symbol name (if resolved)
    moduleName     DB 64 DUP(?)    ; Module name
    sourceFile     DB 256 DUP(?)   ; Source file path
    lineNumber     DD ?            ; Line number
    _pad           DD ?
CALLSTACK_FRAME ENDS

; Debug UI state
DEBUG_UI_STATE STRUCT
    flags          DD ?            ; DEBUG_STATE_* flags
    currentAddress DQ ?            ; Current RIP
    currentLine    DD ?            ; Current source line
    currentFile    DB 512 DUP(?)   ; Current source file
    exceptionCode  DQ ?            ; Last exception code
    exceptionAddr  DQ ?            ; Exception address
    callStackDepth DD ?            ; Number of frames
    callStack      CALLSTACK_FRAME MAX_CALLSTACK_DEPTH DUP(<>)
    bpCount        DD ?            ; Number of breakpoints
    breakpoints    BREAKPOINT_INFO 64 DUP(<>)
    lastEventTime  DQ ?            ; RDTSC of last event
    _pad           DQ ?
DEBUG_UI_STATE ENDS

; ============================================================================
; External APIs
; ============================================================================

EXTERN DbgEvent_Pop:PROC
EXTERN DbgEvent_GetCount:PROC
EXTERN DbgEvent_Clear:PROC
EXTERN DbgEvent_Init:PROC

; Win32 GDI for rendering
EXTERN CreatePen:PROC
EXTERN CreateSolidBrush:PROC
EXTERN SelectObject:PROC
EXTERN DeleteObject:PROC
EXTERN Rectangle:PROC
EXTERN SetTextColor:PROC
EXTERN SetBkColor:PROC
EXTERN TextOutA:PROC
EXTERN GetTickCount64:PROC

; ============================================================================
; Data Section
; ============================================================================

.data

ALIGN 16
g_debugUIState    DEBUG_UI_STATE <>
g_initialized     DB 0

; Statistics
g_eventsProcessed DQ 0
g_framesRendered  DQ 0

; Temporary event buffer (for pop)
ALIGN 16
g_tempEvent       DB 512 DUP(?)

; UI strings
szBreakpoint      DB "[BP]", 0
szCurrentLine     DB "->", 0
szException       DB "EXCEPTION", 0
szCallStack       DB "Call Stack:", 0
szHalted          DB "HALTED", 0
szRunning         DB "RUNNING", 0
szStepping        DB "STEPPING", 0

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; IDE_DebugInit
; ============================================================================
; Initialize the debug UI bridge.
; Must be called during IDE startup before any debug operations.
;
; Parameters: None
; Returns: RAX = 1 success, 0 failure
; ============================================================================

ALIGN 16
IDE_DebugInit PROC
    
    ; Check if already initialized
    cmp     byte ptr [g_initialized], 1
    je      L_already_init
    
    ; Initialize ring buffer
    call    DbgEvent_Init
    test    rax, rax
    jz      L_fail
    
    ; Clear UI state
    lea     rdi, [g_debugUIState]
    mov     rcx, SIZEOF DEBUG_UI_STATE
    xor     eax, eax
    rep     stosb
    
    ; Set initial state to running
    lea     rax, [g_debugUIState]
    mov     dword ptr [rax + DEBUG_UI_STATE.flags], DEBUG_STATE_RUNNING
    
    ; Mark as initialized
    mov     byte ptr [g_initialized], 1
    
L_already_init:
    mov     rax, 1
    ret
    
L_fail:
    xor     rax, rax
    ret

IDE_DebugInit ENDP

; ============================================================================
; IDE_DebugPoll
; ============================================================================
; Poll for new debug events and update UI state.
; Call this during the render loop (60 FPS).
;
; Parameters: None
; Returns: RAX = number of events processed
; ============================================================================

ALIGN 16
IDE_DebugPoll PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    
    xor     ebx, ebx                ; event count
    
    ; Check if initialized
    cmp     byte ptr [g_initialized], 0
    je      L_done
    
L_poll_loop:
    ; Pop event from ring buffer
    lea     rcx, [g_tempEvent]
    call    DbgEvent_Pop
    test    rax, rax
    jz      L_done
    
    inc     ebx
    
    ; Process event based on type
    mov     eax, dword ptr [g_tempEvent]    ; eventType
    
    cmp     eax, 1                  ; DBG_EVENT_BREAKPOINT
    je      L_on_breakpoint
    cmp     eax, 2                  ; DBG_EVENT_SINGLE_STEP
    je      L_on_single_step
    cmp     eax, 3                  ; DBG_EVENT_EXCEPTION
    je      L_on_exception
    cmp     eax, 4                  ; DBG_EVENT_CREATE_PROCESS
    je      L_on_create_process
    cmp     eax, 5                  ; DBG_EVENT_EXIT_PROCESS
    je      L_on_exit_process
    
    ; Unknown event type, continue polling
    jmp     L_poll_loop
    
L_on_breakpoint:
    ; Update UI state for breakpoint hit
    lea     rsi, [g_tempEvent]
    lea     rdi, [g_debugUIState]
    
    ; Set flags
    mov     dword ptr [rdi + DEBUG_UI_STATE.flags], DEBUG_STATE_HALTED or DEBUG_STATE_BREAKPOINT
    
    ; Copy current address
    mov     rax, [rsi + 16]         ; rip
    mov     [rdi + DEBUG_UI_STATE.currentAddress], rax
    
    ; Copy exception info
    mov     rax, [rsi + 8]          ; exceptionCode
    mov     [rdi + DEBUG_UI_STATE.exceptionCode], rax
    mov     rax, [rsi + 16]          ; exceptionAddr (same as rip for breakpoint)
    mov     [rdi + DEBUG_UI_STATE.exceptionAddr], rax
    
    ; Copy timestamp
    mov     rax, [rsi + 208]        ; timestamp
    mov     [rdi + DEBUG_UI_STATE.lastEventTime], rax
    
    jmp     L_poll_loop
    
L_on_single_step:
    ; Update UI state for single step
    lea     rsi, [g_tempEvent]
    lea     rdi, [g_debugUIState]
    
    ; Set flags
    mov     dword ptr [rdi + DEBUG_UI_STATE.flags], DEBUG_STATE_HALTED or DEBUG_STATE_STEPPING
    
    ; Copy current address
    mov     rax, [rsi + 16]         ; rip
    mov     [rdi + DEBUG_UI_STATE.currentAddress], rax
    
    ; Copy timestamp
    mov     rax, [rsi + 208]        ; timestamp
    mov     [rdi + DEBUG_UI_STATE.lastEventTime], rax
    
    jmp     L_poll_loop
    
L_on_exception:
    ; Update UI state for exception
    lea     rsi, [g_tempEvent]
    lea     rdi, [g_debugUIState]
    
    ; Set flags
    mov     dword ptr [rdi + DEBUG_UI_STATE.flags], DEBUG_STATE_HALTED or DEBUG_STATE_EXCEPTION
    
    ; Copy current address
    mov     rax, [rsi + 16]         ; rip
    mov     [rdi + DEBUG_UI_STATE.currentAddress], rax
    
    ; Copy exception info
    mov     rax, [rsi + 8]          ; exceptionCode
    mov     [rdi + DEBUG_UI_STATE.exceptionCode], rax
    mov     rax, [rsi + 16]          ; exceptionAddr
    mov     [rdi + DEBUG_UI_STATE.exceptionAddr], rax
    
    ; Copy timestamp
    mov     rax, [rsi + 208]        ; timestamp
    mov     [rdi + DEBUG_UI_STATE.lastEventTime], rax
    
    jmp     L_poll_loop
    
L_on_create_process:
    ; Process started, set state to running
    lea     rdi, [g_debugUIState]
    mov     dword ptr [rdi + DEBUG_UI_STATE.flags], DEBUG_STATE_RUNNING
    jmp     L_poll_loop
    
L_on_exit_process:
    ; Process exited, clear state
    lea     rdi, [g_debugUIState]
    mov     dword ptr [rdi + DEBUG_UI_STATE.flags], 0
    jmp     L_poll_loop
    
L_done:
    ; Update statistics
    lock add qword ptr [g_eventsProcessed], rbx
    
    mov     rax, rbx
    
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret

IDE_DebugPoll ENDP

; ============================================================================
; IDE_DebugGetCurrentLine
; ============================================================================
; Get the current source line (for highlighting).
;
; Parameters: None
; Returns: RAX = current line number (0 if not available)
; ============================================================================

ALIGN 16
IDE_DebugGetCurrentLine PROC
    
    lea     rax, [g_debugUIState]
    mov     eax, [rax + DEBUG_UI_STATE.currentLine]
    ret

IDE_DebugGetCurrentLine ENDP

; ============================================================================
; IDE_DebugGetCurrentAddress
; ============================================================================
; Get the current instruction pointer.
;
; Parameters: None
; Returns: RAX = current RIP
; ============================================================================

ALIGN 16
IDE_DebugGetCurrentAddress PROC
    
    lea     rax, [g_debugUIState]
    mov     rax, [rax + DEBUG_UI_STATE.currentAddress]
    ret

IDE_DebugGetCurrentAddress ENDP

; ============================================================================
; IDE_DebugGetState
; ============================================================================
; Get the current debug state flags.
;
; Parameters: None
; Returns: RAX = DEBUG_STATE_* flags
; ============================================================================

ALIGN 16
IDE_DebugGetState PROC
    
    lea     rax, [g_debugUIState]
    mov     eax, [rax + DEBUG_UI_STATE.flags]
    ret

IDE_DebugGetState ENDP

; ============================================================================
; IDE_DebugGetCallStack
; ============================================================================
; Get the call stack frames.
;
; Parameters:
;   RCX = pOutFrames (pointer to array of CALLSTACK_FRAME)
;   RDX = maxFrames
; Returns: RAX = number of frames copied
; ============================================================================

ALIGN 16
IDE_DebugGetCallStack PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog
    
    mov     rbx, rdx                ; maxFrames
    mov     rdi, rcx                ; pOutFrames
    
    ; Get current call stack depth
    lea     rax, [g_debugUIState]
    mov     ecx, [rax + DEBUG_UI_STATE.callStackDepth]
    
    ; Limit to maxFrames
    cmp     ecx, ebx
    cmovg   ecx, ebx
    
    ; Copy frames
    test    ecx, ecx
    jz      L_done
    
    lea     rsi, [rax + DEBUG_UI_STATE.callStack]
    mov     edx, SIZEOF CALLSTACK_FRAME
    imul    edx, ecx
    rep     movsb
    
L_done:
    mov     rax, rcx
    
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

IDE_DebugGetCallStack ENDP

; ============================================================================
; IDE_DebugSetBreakpoint
; ============================================================================
; Add a breakpoint to the UI state.
;
; Parameters:
;   RCX = address
;   RDX = lineNumber (optional, 0 if unknown)
; Returns: RAX = breakpoint index (0-63), -1 if full
; ============================================================================

ALIGN 16
IDE_DebugSetBreakpoint PROC
    
    lea     rax, [g_debugUIState]
    mov     ecx, [rax + DEBUG_UI_STATE.bpCount]
    
    ; Check if full
    cmp     ecx, 64
    jae     L_full
    
    ; Calculate breakpoint index
    imul    ecx, SIZEOF BREAKPOINT_INFO
    lea     rdx, [rax + DEBUG_UI_STATE.breakpoints]
    add     rdx, rcx
    
    ; Set address
    mov     [rdx + BREAKPOINT_INFO.address], rcx
    
    ; Set line number (from param)
    mov     [rdx + BREAKPOINT_INFO.lineNumber], edx
    
    ; Set enabled
    mov     byte ptr [rdx + BREAKPOINT_INFO.enabled], 1
    
    ; Set type (software = 0)
    mov     byte ptr [rdx + BREAKPOINT_INFO.bpType], 0
    
    ; Increment count
    lea     rax, [g_debugUIState]
    inc     dword ptr [rax + DEBUG_UI_STATE.bpCount]
    
    ; Return index
    mov     eax, ecx
    shr     eax, 5                  ; divide by SIZEOF BREAKPOINT_INFO
    ret
    
L_full:
    mov     rax, -1
    ret

IDE_DebugSetBreakpoint ENDP

; ============================================================================
; IDE_DebugClearBreakpoint
; ============================================================================
; Remove a breakpoint from the UI state.
;
; Parameters:
;   RCX = breakpoint index (0-63)
; Returns: RAX = 1 success, 0 failure
; ============================================================================

ALIGN 16
IDE_DebugClearBreakpoint PROC
    
    lea     rax, [g_debugUIState]
    mov     ecx, [rax + DEBUG_UI_STATE.bpCount]
    
    ; Validate index
    cmp     ecx, 64
    jae     L_fail
    
    ; Calculate breakpoint pointer
    imul    ecx, SIZEOF BREAKPOINT_INFO
    lea     rdx, [rax + DEBUG_UI_STATE.breakpoints]
    add     rdx, rcx
    
    ; Clear enabled flag
    mov     byte ptr [rdx + BREAKPOINT_INFO.enabled], 0
    
    mov     rax, 1
    ret
    
L_fail:
    xor     rax, rax
    ret

IDE_DebugClearBreakpoint ENDP

; ============================================================================
; IDE_DebugGetBreakpoints
; ============================================================================
; Get all breakpoints.
;
; Parameters:
;   RCX = pOutBp (pointer to array of BREAKPOINT_INFO)
;   RDX = maxCount
; Returns: RAX = number of breakpoints copied
; ============================================================================

ALIGN 16
IDE_DebugGetBreakpoints PROC frame
    
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog
    
    mov     rbx, rdx                ; maxCount
    mov     rdi, rcx                ; pOutBp
    
    ; Get breakpoint count
    lea     rax, [g_debugUIState]
    mov     ecx, [rax + DEBUG_UI_STATE.bpCount]
    
    ; Limit to maxCount
    cmp     ecx, ebx
    cmovg   ecx, ebx
    
    ; Copy breakpoints
    test    ecx, ecx
    jz      L_done
    
    lea     rsi, [rax + DEBUG_UI_STATE.breakpoints]
    mov     edx, SIZEOF BREAKPOINT_INFO
    imul    edx, ecx
    rep     movsb
    
L_done:
    mov     rax, rcx
    
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

IDE_DebugGetBreakpoints ENDP

; ============================================================================
; IDE_DebugContinue
; ============================================================================
; Signal the debugger to continue execution.
;
; Parameters: None
; Returns: RAX = 1 success
; ============================================================================

ALIGN 16
IDE_DebugContinue PROC
    
    lea     rax, [g_debugUIState]
    mov     dword ptr [rax + DEBUG_UI_STATE.flags], DEBUG_STATE_RUNNING
    mov     rax, 1
    ret

IDE_DebugContinue ENDP

; ============================================================================
; IDE_DebugStep
; ============================================================================
; Signal the debugger to single step.
;
; Parameters: None
; Returns: RAX = 1 success
; ============================================================================

ALIGN 16
IDE_DebugStep PROC
    
    lea     rax, [g_debugUIState]
    mov     dword ptr [rax + DEBUG_UI_STATE.flags], DEBUG_STATE_STEPPING
    mov     rax, 1
    ret

IDE_DebugStep ENDP

; ============================================================================
; IDE_DebugStop
; ============================================================================
; Signal the debugger to stop.
;
; Parameters: None
; Returns: RAX = 1 success
; ============================================================================

ALIGN 16
IDE_DebugStop PROC
    
    lea     rax, [g_debugUIState]
    mov     dword ptr [rax + DEBUG_UI_STATE.flags], DEBUG_STATE_HALTED
    mov     rax, 1
    ret

IDE_DebugStop ENDP

; ============================================================================
; IDE_DebugGetStats
; ============================================================================
; Get debug statistics.
;
; Parameters: None
; Returns:
;   RAX = events processed
;   RCX = frames rendered
; ============================================================================

ALIGN 16
IDE_DebugGetStats PROC
    
    mov     rax, [g_eventsProcessed]
    mov     rcx, [g_framesRendered]
    ret

IDE_DebugGetStats ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC IDE_DebugInit
PUBLIC IDE_DebugPoll
PUBLIC IDE_DebugGetCurrentLine
PUBLIC IDE_DebugGetCurrentAddress
PUBLIC IDE_DebugGetState
PUBLIC IDE_DebugGetCallStack
PUBLIC IDE_DebugSetBreakpoint
PUBLIC IDE_DebugClearBreakpoint
PUBLIC IDE_DebugGetBreakpoints
PUBLIC IDE_DebugContinue
PUBLIC IDE_DebugStep
PUBLIC IDE_DebugStop
PUBLIC IDE_DebugGetStats

END
