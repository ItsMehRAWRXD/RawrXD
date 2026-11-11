; ============================================================================
; input_handler.asm - x64 MASM Input Event Queue for Win32 IDE
; ============================================================================
; Architecture: x64 MASM, Windows x64 calling convention
; Purpose: High-performance input event queue for editor keystroke handling.
;          Prevents GUI thread blocking during complex operations.
;          Implements lock-free SPSC (Single Producer Single Consumer) queue.
;
; Features:
;   - WM_CHAR capture for printable characters
;   - WM_KEYDOWN capture for control keys (backspace, enter, arrows)
;   - Lock-free event queue (SPSC pattern)
;   - Direct integration with editor.asm gap buffer
;   - Zero-allocation hot path
;
; Build: ml64 /c /Zi input_handler.asm
; Link: Link with editor.asm and gui_dispatch_bridge.asm
; ============================================================================

option casemap:none

; ============================================================================
;                         CONSTANTS
; ============================================================================

; Queue size (must be power of 2)
INPUT_QUEUE_SIZE      EQU     1024
INPUT_QUEUE_MASK      EQU     INPUT_QUEUE_SIZE - 1

; Event types
INPUT_EVENT_CHAR       EQU     1       ; Printable character
INPUT_EVENT_KEYDOWN    EQU     2       ; Control key
INPUT_EVENT_KEYUP      EQU     3       ; Key release (for modifiers)

; Virtual key codes
VK_BACK               EQU     08h      ; Backspace
VK_TAB                EQU     09h      ; Tab
VK_RETURN             EQU     0Dh      ; Enter
VK_SHIFT              EQU     10h      ; Shift
VK_CONTROL            EQU     11h      ; Ctrl
VK_MENU               EQU     12h      ; Alt
VK_ESCAPE             EQU     1Bh      ; Escape
VK_PRIOR              EQU     21h      ; Page Up
VK_NEXT               EQU     22h      ; Page Down
VK_END                EQU     23h      ; End
VK_HOME               EQU     24h      ; Home
VK_LEFT               EQU     25h      ; Left arrow
VK_UP                 EQU     26h      ; Up arrow
VK_RIGHT              EQU     27h      ; Right arrow
VK_DOWN               EQU     28h      ; Down arrow
VK_DELETE             EQU     2Eh      ; Delete

; Modifier flags
MODIFIER_SHIFT        EQU     01h
MODIFIER_CTRL         EQU     02h
MODIFIER_ALT          EQU     04h

; ============================================================================
;                         STRUCTURES
; ============================================================================

; Input event structure (16 bytes)
INPUT_EVENT STRUCT
    eventType        DD ?        ; INPUT_EVENT_CHAR, INPUT_EVENT_KEYDOWN, etc.
    keyCode          DD ?        ; Character code or virtual key code
    modifiers        DQ ?        ; Modifier flags (Shift, Ctrl, Alt)
    timestamp        DQ ?        ; GetTickCount64() timestamp
INPUT_EVENT ENDS

; Input queue structure (circular buffer)
INPUT_QUEUE STRUCT
    events           INPUT_EVENT INPUT_QUEUE_SIZE dup(<>)  ; Event buffer
    head             DQ ?        ; Producer index (write position)
    tail             DQ ?        ; Consumer index (read position)
    count            DQ ?        ; Current event count (for polling)
    _padding         DQ ?        ; Cache line alignment
INPUT_QUEUE ENDS

; Text buffer structure (for editor integration)
TEXT_BUFFER STRUCT
    pBuffer          DQ ?        ; Pointer to buffer memory
    bufferSize       DQ ?        ; Total allocated size
    contentLength    DQ ?        ; Current content length
    cursorPos        DQ ?        ; Cursor position (0-based)
    selectionStart   DQ ?        ; Selection start (-1 if no selection)
    selectionEnd     DQ ?        ; Selection end
    lineCount        DQ ?        ; Number of lines
    flags            DQ ?        ; Buffer flags (modified, read-only, etc.)
TEXT_BUFFER ENDS

; Buffer flags
BUFFER_FLAG_MODIFIED     EQU     01h
BUFFER_FLAG_READONLY     EQU     02h
BUFFER_FLAG_UNDO_AVAIL   EQU     04h

; ============================================================================
;                         EXTERNAL API
; ============================================================================

EXTERN GetTickCount64:PROC
EXTERN GetKeyState:PROC
EXTERN PostMessageA:PROC
EXTERN SendMessageA:PROC

; External editor functions (from editor.asm)
EXTERN Editor_InsertChar:PROC
EXTERN Editor_DeleteChar:PROC
EXTERN Editor_MoveCursor:PROC
EXTERN Editor_InsertNewline:PROC
EXTERN Editor_Backspace:PROC

; ============================================================================
;                         DATA
; ============================================================================

.data

; Global input queue (single instance)
ALIGN 16
g_inputQueue     INPUT_QUEUE <>
g_textBuffer     TEXT_BUFFER <>

; Modifier state tracking
g_shiftPressed   DB 0
g_ctrlPressed    DB 0
g_altPressed     DB 0

; Event processing state
g_lastEventTime  DQ 0
g_repeatCount    DD 0
g_lastKeyCode    DD 0

; Statistics
g_eventsQueued   DQ 0
g_eventsProcessed DQ 0
g_queueOverflows DQ 0

; Debug strings
szQueueOverflow   DB "[INPUT] Queue overflow, event dropped", 13, 10, 0
szEventQueued     DB "[INPUT] Event queued: type=%d, key=%d", 13, 10, 0

; ============================================================================
;                         CODE
; ============================================================================

.code

; ============================================================================
; Input_Init
; ============================================================================
; Initializes the input queue and text buffer structures.
; Must be called before any input processing.
;
; Parameters: None
; Returns: RAX = 1 on success, 0 on failure
; ============================================================================

ALIGN 16
Input_Init PROC
    
    ; Clear the queue structure
    lea     rdi, [g_inputQueue]
    mov     rcx, SIZEOF INPUT_QUEUE
    xor     eax, eax
    rep     stosb
    
    ; Initialize head/tail to 0
    lea     rdi, [g_inputQueue]
    mov     qword ptr [rdi + INPUT_QUEUE.head], 0
    mov     qword ptr [rdi + INPUT_QUEUE.tail], 0
    mov     qword ptr [rdi + INPUT_QUEUE.count], 0
    
    ; Initialize text buffer
    lea     rdi, [g_textBuffer]
    mov     qword ptr [rdi + TEXT_BUFFER.pBuffer], 0
    mov     qword ptr [rdi + TEXT_BUFFER.bufferSize], 0
    mov     qword ptr [rdi + TEXT_BUFFER.contentLength], 0
    mov     qword ptr [rdi + TEXT_BUFFER.cursorPos], 0
    mov     qword ptr [rdi + TEXT_BUFFER.selectionStart], -1
    mov     qword ptr [rdi + TEXT_BUFFER.selectionEnd], -1
    mov     qword ptr [rdi + TEXT_BUFFER.lineCount], 1
    mov     qword ptr [rdi + TEXT_BUFFER.flags], 0
    
    ; Clear modifier states
    mov     byte ptr [g_shiftPressed], 0
    mov     byte ptr [g_ctrlPressed], 0
    mov     byte ptr [g_altPressed], 0
    
    ; Clear statistics
    mov     qword ptr [g_eventsQueued], 0
    mov     qword ptr [g_eventsProcessed], 0
    mov     qword ptr [g_queueOverflows], 0
    
    ; Return success
    mov     rax, 1
    ret

Input_Init ENDP

; ============================================================================
; Input_QueueEvent
; ============================================================================
; Queues an input event (called from WM_CHAR/WM_KEYDOWN handlers).
; Lock-free SPSC queue - only called from GUI thread (producer).
;
; Parameters:
;   RCX = eventType (INPUT_EVENT_CHAR, INPUT_EVENT_KEYDOWN, etc.)
;   RDX = keyCode (character or virtual key code)
;   R8  = modifiers (Shift, Ctrl, Alt flags)
; Returns: RAX = 1 if queued, 0 if queue full
; ============================================================================

ALIGN 16
Input_QueueEvent PROC
    
    ; Preserve non-volatile registers
    push    rbx
    push    rsi
    sub     rsp, 28h            ; Shadow space + alignment
    
    mov     ebx, ecx            ; Save eventType
    mov     esi, edx            ; Save keyCode
    mov     r8, r8              ; modifiers already in r8
    
    ; Get current queue state
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.head]
    mov     rdx, [rax + INPUT_QUEUE.tail]
    
    ; Check if queue is full (head - tail == QUEUE_SIZE)
    sub     rcx, rdx
    cmp     rcx, INPUT_QUEUE_SIZE
    jae     L_queue_full
    
    ; Get timestamp
    call    GetTickCount64
    mov     r9, rax             ; timestamp
    
    ; Calculate write position (head AND MASK)
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.head]
    and     rcx, INPUT_QUEUE_MASK
    
    ; Write event to buffer
    lea     rdi, [rax + INPUT_QUEUE.events]
    imul    rcx, SIZEOF INPUT_EVENT
    add     rdi, rcx
    
    mov     [rdi + INPUT_EVENT.eventType], ebx
    mov     [rdi + INPUT_EVENT.keyCode], esi
    mov     [rdi + INPUT_EVENT.modifiers], r8
    mov     [rdi + INPUT_EVENT.timestamp], r9
    
    ; Increment head (atomic store)
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.head]
    inc     rcx
    mov     [rax + INPUT_QUEUE.head], rcx
    
    ; Increment count (for polling)
    lock inc qword ptr [rax + INPUT_QUEUE.count]
    
    ; Update statistics
    inc qword ptr [g_eventsQueued]
    
    ; Return success
    mov     rax, 1
    jmp     L_done
    
L_queue_full:
    ; Queue overflow - drop event
    inc qword ptr [g_queueOverflows]
    xor     rax, rax            ; Return 0 (failure)
    
L_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret

Input_QueueEvent ENDP

; ============================================================================
; Input_ProcessEvents
; ============================================================================
; Processes all pending events in the queue (called from editor idle loop).
; Consumer side of SPSC queue.
;
; Parameters: None
; Returns: RAX = number of events processed
; ============================================================================

ALIGN 16
Input_ProcessEvents PROC
    
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 28h
    
    xor     ebx, ebx            ; Event counter
    
    ; Get queue state
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.tail]
    mov     rdx, [rax + INPUT_QUEUE.head]
    
    ; Check if queue is empty
    cmp     rcx, rdx
    jae     L_done_empty
    
L_process_loop:
    ; Check if we've caught up to head
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.tail]
    mov     rdx, [rax + INPUT_QUEUE.head]
    cmp     rcx, rdx
    jae     L_done
    
    ; Calculate read position (tail AND MASK)
    mov     rcx, [rax + INPUT_QUEUE.tail]
    and     rcx, INPUT_QUEUE_MASK
    
    ; Read event from buffer
    lea     rdi, [rax + INPUT_QUEUE.events]
    imul    rcx, SIZEOF INPUT_EVENT
    add     rdi, rcx
    
    ; Extract event data
    mov     esi, [rdi + INPUT_EVENT.eventType]
    mov     eax, [rdi + INPUT_EVENT.keyCode]
    mov     r8, [rdi + INPUT_EVENT.modifiers]
    
    ; Increment tail
    lea     rax, [g_inputQueue]
    mov     rcx, [rax + INPUT_QUEUE.tail]
    inc     rcx
    mov     [rax + INPUT_QUEUE.tail], rcx
    
    ; Decrement count
    lock dec qword ptr [rax + INPUT_QUEUE.count]
    
    ; Dispatch event based on type
    cmp     esi, INPUT_EVENT_CHAR
    je      L_dispatch_char
    cmp     esi, INPUT_EVENT_KEYDOWN
    je      L_dispatch_keydown
    jmp     L_process_loop
    
L_dispatch_char:
    ; Character input - call editor insert
    ; RCX = keyCode (character)
    ; RDX = modifiers
    mov     ecx, eax            ; Character
    mov     rdx, r8             ; Modifiers
    
    ; Check for Ctrl+V (paste) - handle specially
    test    r8, MODIFIER_CTRL
    jz     L_insert_char
    cmp     eax, 'V'
    je      L_handle_paste
    
L_insert_char:
    ; Call Editor_InsertChar
    call    Editor_InsertChar
    inc     ebx
    jmp     L_process_loop
    
L_handle_paste:
    ; TODO: Implement clipboard paste
    jmp     L_process_loop
    
L_dispatch_keydown:
    ; Control key input
    ; RCX = keyCode (virtual key)
    ; RDX = modifiers
    
    mov     ecx, eax            ; Virtual key code
    mov     rdx, r8             ; Modifiers
    
    ; Dispatch based on key code
    cmp     eax, VK_BACK
    je      L_handle_backspace
    cmp     eax, VK_RETURN
    je      L_handle_return
    cmp     eax, VK_DELETE
    je      L_handle_delete
    cmp     eax, VK_LEFT
    je      L_handle_left
    cmp     eax, VK_RIGHT
    je      L_handle_right
    cmp     eax, VK_UP
    je      L_handle_up
    cmp     eax, VK_DOWN
    je      L_handle_down
    cmp     eax, VK_HOME
    je      L_handle_home
    cmp     eax, VK_END
    je      L_handle_end
    cmp     eax, VK_TAB
    je      L_handle_tab
    jmp     L_process_loop
    
L_handle_backspace:
    call    Editor_Backspace
    inc     ebx
    jmp     L_process_loop
    
L_handle_return:
    call    Editor_InsertNewline
    inc     ebx
    jmp     L_process_loop
    
L_handle_delete:
    call    Editor_DeleteChar
    inc     ebx
    jmp     L_process_loop
    
L_handle_left:
    ; Editor_MoveCursor(direction, modifiers)
    mov     ecx, 0              ; Direction: left
    mov     rdx, r8             ; Modifiers
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_right:
    mov     ecx, 1              ; Direction: right
    mov     rdx, r8
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_up:
    mov     ecx, 2              ; Direction: up
    mov     rdx, r8
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_down:
    mov     ecx, 3              ; Direction: down
    mov     rdx, r8
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_home:
    mov     ecx, 4              ; Direction: home
    mov     rdx, r8
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_end:
    mov     ecx, 5              ; Direction: end
    mov     rdx, r8
    call    Editor_MoveCursor
    inc     ebx
    jmp     L_process_loop
    
L_handle_tab:
    ; Insert tab character (or handle indent)
    mov     ecx, 09h            ; Tab character
    call    Editor_InsertChar
    inc     ebx
    jmp     L_process_loop
    
L_done_empty:
    xor     rax, rax
    jmp     L_exit
    
L_done:
    mov     rax, rbx            ; Return count
    add     qword ptr [g_eventsProcessed], rbx
    
L_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    pop     rbx
    ret

Input_ProcessEvents ENDP

; ============================================================================
; Input_OnChar
; ============================================================================
; Called from WM_CHAR handler in GUI message loop.
; Queues character input events.
;
; Parameters:
;   RCX = wParam (character code)
;   RDX = lParam (key data)
; Returns: RAX = 1 if handled, 0 if not
; ============================================================================

ALIGN 16
Input_OnChar PROC
    
    push    rbx
    sub     rsp, 28h
    
    mov     ebx, ecx            ; Save character
    
    ; Get current modifier state
    xor     r8, r8              ; Clear modifiers
    
    ; Check Shift
    mov     eax, VK_SHIFT
    call    GetKeyState
    test    ax, 8000h
    jz      L_check_ctrl
    or      r8, MODIFIER_SHIFT
    
L_check_ctrl:
    mov     eax, VK_CONTROL
    call    GetKeyState
    test    ax, 8000h
    jz      L_check_alt
    or      r8, MODIFIER_CTRL
    
L_check_alt:
    mov     eax, VK_MENU
    call    GetKeyState
    test    ax, 8000h
    jz      L_queue_event
    or      r8, MODIFIER_ALT
    
L_queue_event:
    ; Queue the event
    mov     ecx, INPUT_EVENT_CHAR
    mov     edx, ebx            ; Character code
    ; r8 already has modifiers
    call    Input_QueueEvent
    
    mov     rax, 1              ; Return handled
    
    add     rsp, 28h
    pop     rbx
    ret

Input_OnChar ENDP

; ============================================================================
; Input_OnKeyDown
; ============================================================================
; Called from WM_KEYDOWN handler in GUI message loop.
; Queues control key events.
;
; Parameters:
;   RCX = wParam (virtual key code)
;   RDX = lParam (key data)
; Returns: RAX = 1 if handled, 0 if not
; ============================================================================

ALIGN 16
Input_OnKeyDown PROC
    
    push    rbx
    sub     rsp, 28h
    
    mov     ebx, ecx            ; Save virtual key code
    
    ; Filter: only handle navigation/editing keys
    cmp     ebx, VK_BACK
    je      L_handle_key
    cmp     ebx, VK_RETURN
    je      L_handle_key
    cmp     ebx, VK_DELETE
    je      L_handle_key
    cmp     ebx, VK_LEFT
    je      L_handle_key
    cmp     ebx, VK_RIGHT
    je      L_handle_key
    cmp     ebx, VK_UP
    je      L_handle_key
    cmp     ebx, VK_DOWN
    je      L_handle_key
    cmp     ebx, VK_HOME
    je      L_handle_key
    cmp     ebx, VK_END
    je      L_handle_key
    cmp     ebx, VK_TAB
    je      L_handle_key
    
    ; Not a key we handle
    xor     rax, rax
    jmp     L_exit
    
L_handle_key:
    ; Get current modifier state
    xor     r8, r8              ; Clear modifiers
    
    ; Check Shift
    mov     eax, VK_SHIFT
    call    GetKeyState
    test    ax, 8000h
    jz      L_check_ctrl_key
    or      r8, MODIFIER_SHIFT
    
L_check_ctrl_key:
    mov     eax, VK_CONTROL
    call    GetKeyState
    test    ax, 8000h
    jz      L_check_alt_key
    or      r8, MODIFIER_CTRL
    
L_check_alt_key:
    mov     eax, VK_MENU
    call    GetKeyState
    test    ax, 8000h
    jz      L_queue_key_event
    or      r8, MODIFIER_ALT
    
L_queue_key_event:
    ; Queue the event
    mov     ecx, INPUT_EVENT_KEYDOWN
    mov     edx, ebx            ; Virtual key code
    ; r8 already has modifiers
    call    Input_QueueEvent
    
    mov     rax, 1              ; Return handled
    
L_exit:
    add     rsp, 28h
    pop     rbx
    ret

Input_OnKeyDown ENDP

; ============================================================================
; Input_GetStats
; ============================================================================
; Returns input queue statistics.
;
; Parameters: None
; Returns:
;   RAX = events queued
;   RCX = events processed
;   RDX = queue overflows
; ============================================================================

ALIGN 16
Input_GetStats PROC
    
    mov     rax, [g_eventsQueued]
    mov     rcx, [g_eventsProcessed]
    mov     rdx, [g_queueOverflows]
    ret

Input_GetStats ENDP

; ============================================================================
; Input_ResetStats
; ============================================================================
; Resets input queue statistics.
;
; Parameters: None
; Returns: None
; ============================================================================

ALIGN 16
Input_ResetStats PROC
    
    mov     qword ptr [g_eventsQueued], 0
    mov     qword ptr [g_eventsProcessed], 0
    mov     qword ptr [g_queueOverflows], 0
    ret

Input_ResetStats ENDP

; ============================================================================
; Input_GetBufferState
; ============================================================================
; Returns current text buffer state (for editor integration).
;
; Parameters: None
; Returns:
;   RAX = pointer to TEXT_BUFFER structure
; ============================================================================

ALIGN 16
Input_GetBufferState PROC
    
    lea     rax, [g_textBuffer]
    ret

Input_GetBufferState ENDP

; ============================================================================
; Input_SetBufferPointer
; ============================================================================
; Sets the text buffer pointer (called by editor.asm during initialization).
;
; Parameters:
;   RCX = pointer to buffer memory
;   RDX = buffer size
; Returns: RAX = 1 on success
; ============================================================================

ALIGN 16
Input_SetBufferPointer PROC
    
    lea     rax, [g_textBuffer]
    mov     [rax + TEXT_BUFFER.pBuffer], rcx
    mov     [rax + TEXT_BUFFER.bufferSize], rdx
    mov     qword ptr [rax + TEXT_BUFFER.contentLength], 0
    mov     qword ptr [rax + TEXT_BUFFER.cursorPos], 0
    mov     qword ptr [rax + TEXT_BUFFER.selectionStart], -1
    mov     qword ptr [rax + TEXT_BUFFER.selectionEnd], -1
    mov     qword ptr [rax + TEXT_BUFFER.lineCount], 1
    mov     qword ptr [rax + TEXT_BUFFER.flags], 0
    
    mov     rax, 1
    ret

Input_SetBufferPointer ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC Input_Init
PUBLIC Input_QueueEvent
PUBLIC Input_ProcessEvents
PUBLIC Input_OnChar
PUBLIC Input_OnKeyDown
PUBLIC Input_GetStats
PUBLIC Input_ResetStats
PUBLIC Input_GetBufferState
PUBLIC Input_SetBufferPointer

END
