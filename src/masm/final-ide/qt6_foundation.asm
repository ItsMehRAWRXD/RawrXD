; ==========================================================================
; MASM Qt6 Component Conversion: Foundation Layer
; ==========================================================================
; This file provides foundational Win32 abstractions for Qt6 component
; conversion to pure MASM. It abstracts common patterns needed across
; all 10 major systems: main window, layout, widgets, dialogs, menus,
; themes, file browser, threading, chat, and signals.
;
; Design: Minimal Win32 API wrappers + Qt-like object model
; Approach: Create virtual method tables (VMT) for polymorphism
; Memory: Stack-based resource management (RAII equivalent)
;
; Total conversion target: ~40,000 LOC across 10 systems
; Phase strategy: Foundation → Widgets → Layout → UI Systems → Threading
; ==========================================================================

option casemap:none

; Include Qt compatibility layer definitions
include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib
includelib dwmapi.lib
includelib d2d1.lib
includelib dwrite.lib

;==========================================================================
; OBJECT MODEL - Replaces Qt's QObject, QWidget, etc.
;==========================================================================

; Virtual method table (VMT) - replaces Qt's vtable
; Each object type has a VMT with function pointers
VMT_BASE STRUCT
    pfn_destroy      QWORD ?    ; Virtual destructor
    pfn_paint        QWORD ?    ; Virtual paint handler
    pfn_on_event     QWORD ?    ; Virtual event handler
    pfn_get_size     QWORD ?    ; Virtual size query
    pfn_set_size     QWORD ?    ; Virtual size setter
    pfn_show         QWORD ?    ; Virtual show
    pfn_hide         QWORD ?    ; Virtual hide
VMT_BASE ENDS

; Base object instance - replaces QObject
OBJECT_BASE STRUCT
    vmt              QWORD ?    ; Pointer to VMT
    hwnd             QWORD ?    ; Associated HWND
    parent           QWORD ?    ; Parent object
    children         QWORD ?    ; Child list pointer
    child_count      DWORD ?    ; Number of children
    flags            DWORD ?    ; Object flags (visible, enabled, etc)
    user_data        QWORD ?    ; Custom data pointer
OBJECT_BASE ENDS

; Rectangle for layout/sizing
RECT_MASM STRUCT
    x                DWORD ?
    y                DWORD ?
    width            DWORD ?
    height           DWORD ?
RECT_MASM ENDS

; Size hint for layout calculations
SIZE_HINT STRUCT
    min_width        DWORD ?
    min_height       DWORD ?
    max_width        DWORD ?
    max_height       DWORD ?
    preferred_width  DWORD ?
    preferred_height DWORD ?
RECT_MASM ENDS

;==========================================================================
; OBJECT FLAGS - Replaces Qt::WidgetAttribute
;==========================================================================
FLAG_VISIBLE         EQU 00000001h
FLAG_ENABLED         EQU 00000002h
FLAG_FOCUSED         EQU 00000004h
FLAG_DIRTY           EQU 00000008h  ; Needs repaint
FLAG_MOUSE_TRACKING  EQU 00000010h
FLAG_ACCEPT_DROPS    EQU 00000020h
FLAG_NATIVE          EQU 00000040h  ; Native Win32 window

;==========================================================================
; EVENT TYPES - Replaces Qt::EventType
;==========================================================================
EVENT_PAINT          EQU 0001h
EVENT_MOVE           EQU 0002h
EVENT_RESIZE         EQU 0003h
EVENT_SHOW           EQU 0004h
EVENT_HIDE           EQU 0005h
EVENT_FOCUS_IN       EQU 0006h
EVENT_FOCUS_OUT      EQU 0007h
EVENT_MOUSE_PRESS    EQU 0008h
EVENT_MOUSE_RELEASE  EQU 0009h
EVENT_MOUSE_MOVE     EQU 000Ah
EVENT_MOUSE_WHEEL    EQU 000Bh
EVENT_KEY_PRESS      EQU 000Ch
EVENT_KEY_RELEASE    EQU 000Dh
EVENT_TIMER          EQU 000Eh
EVENT_CUSTOM         EQU 0100h

;==========================================================================
; MEMORY POOL - Replaces Qt's memory allocator
;==========================================================================
; Simple object pool to reduce allocation overhead

MEMORY_POOL STRUCT
    chunk_size       DWORD ?    ; Size of each pool chunk
    pool_ptr         QWORD ?    ; Pointer to allocated pool
    free_list        QWORD ?    ; Linked list of free blocks
    used_count       DWORD ?    ; Number of allocated objects
    total_count      DWORD ?    ; Total capacity
MEMORY_POOL ENDS

;==========================================================================
; OBJECT REGISTRY - Track all active objects
;==========================================================================
; Allows traversal of object tree (used by layout, events, etc)

REGISTRY_ENTRY STRUCT
    object_ptr       QWORD ?
    type_id          DWORD ?
    flags            DWORD ?
    next             QWORD ?
REGISTRY_ENTRY ENDS

;==========================================================================
; EVENT QUEUE - Replaces Qt's event dispatcher
;==========================================================================
; Queue for deferred events (async signals, timers, etc)

EVENT_ITEM STRUCT
    event_type       DWORD ?
    target_obj       QWORD ?
    param1           QWORD ?
    param2           QWORD ?
    param3           QWORD ?
    next             QWORD ?
EVENT_ITEM ENDS

;==========================================================================
; LAYOUT HIERARCHY - Replaces QLayout, QHBoxLayout, QVBoxLayout
;==========================================================================

; Layout item (widget + layout hints)
LAYOUT_ITEM STRUCT
    widget           QWORD ?    ; Pointer to child object
    stretch          DWORD ?    ; Stretch factor
    spacing          DWORD ?    ; Space to next item
    alignment        DWORD ?    ; Alignment flags
    size_hint        SIZE_HINT  ; Preferred/min/max sizes
LAYOUT_ITEM ENDS

; Layout base class
LAYOUT_BASE STRUCT
    container        QWORD ?    ; Parent container
    items            QWORD ?    ; Array of layout items
    item_count       DWORD ?    ; Number of items
    item_capacity    DWORD ?    ; Allocated capacity
    spacing          DWORD ?    ; Default spacing
    margin_left      DWORD ?
    margin_right     DWORD ?
    margin_top       DWORD ?
    margin_bottom    DWORD ?
LAYOUT_BASE ENDS

;==========================================================================
; WIDGET BASE CLASS - Replaces QWidget
;==========================================================================

WIDGET STRUCT
    base             OBJECT_BASE
    rect             RECT_MASM  ; Position and size
    
    ; Appearance
    background_color DWORD ?    ; RGB color
    font_handle      QWORD ?    ; GDI font handle
    
    ; Layout
    layout           QWORD ?    ; Pointer to LAYOUT_BASE
    
    ; Input handling
    keyboard_focus   BYTE ?     ; Has keyboard focus
    mouse_inside     BYTE ?     ; Mouse is over widget
    
    ; Paint cache
    paint_cache      QWORD ?    ; Cached DC/bitmap
    cache_valid      BYTE ?
WIDGET ENDS

;==========================================================================
; DIALOG BASE CLASS - Replaces QDialog
;==========================================================================

DIALOG STRUCT
    widget           WIDGET
    is_modal         BYTE ?
    result_code      DWORD ?    ; Dialog result (OK, Cancel, etc)
    parent_hwnd      QWORD ?    ; Parent window handle
DIALOG ENDS

;==========================================================================
; MENU STRUCTURE - Replaces QMenu
;==========================================================================

MENU_ITEM STRUCT
    id               DWORD ?    ; Item ID for dispatch
    text             QWORD ?    ; Text string pointer
    icon_handle      QWORD ?    ; HICON for menu item
    submenu          QWORD ?    ; Pointer to MENU if has submenu
    is_separator     BYTE ?
    is_enabled       BYTE ?
    is_checked       BYTE ?
MENU_ITEM ENDS

MENU STRUCT
    base             OBJECT_BASE
    items            QWORD ?    ; Array of MENU_ITEM
    item_count       DWORD ?
    item_capacity    DWORD ?
    native_menu      QWORD ?    ; HMENU from Win32
MENU ENDS

;==========================================================================
; SIGNAL/SLOT SYSTEM - Replaces Qt's signal/slot mechanism
;==========================================================================
; Deferred event-driven callbacks

SLOT_BINDING STRUCT
    sender_obj       QWORD ?    ; Object that emitted signal
    receiver_obj     QWORD ?    ; Object that received signal
    signal_id        DWORD ?    ; Signal identifier
    slot_handler     QWORD ?    ; Function pointer to handler
    next             QWORD ?    ; Next binding in chain
SLOT_BINDING ENDS

;==========================================================================
; COLOR SCHEME/THEME - Replaces QPalette, QStyle
;==========================================================================

COLOR_SCHEME STRUCT
    window_bg        DWORD ?    ; Window background color
    text_color       DWORD ?    ; Text color
    button_bg        DWORD ?    ; Button background
    button_text      DWORD ?    ; Button text color
    highlight        DWORD ?    ; Selection highlight
    shadow           DWORD ?    ; Shadow color
    dark             DWORD ?    ; Dark variant
    light            DWORD ?    ; Light variant
    link_color       DWORD ?    ; Hyperlink color
COCOLOR_SCHEME ENDS

;==========================================================================
; FILE BROWSER DATA - Replaces QFileSystemModel
;==========================================================================

FILE_ENTRY STRUCT
    name             QWORD ?    ; Filename string
    path             QWORD ?    ; Full path
    is_dir           BYTE ?
    is_hidden        BYTE ?
    size             QWORD ?    ; File size
    modified         QWORD ?    ; Modification timestamp
    icon_index       DWORD ?    ; Icon index in image list
FILENTRY ENDS

FILE_LISTING STRUCT
    entries          QWORD ?    ; Array of FILE_ENTRY
    entry_count      DWORD ?
    entry_capacity   DWORD ?
    current_path     QWORD ?    ; Current directory
    parent_path      QWORD ?    ; Parent directory
FILE_LISTING ENDS

;==========================================================================
; THREADING - Replaces QThread
;==========================================================================

THREAD_CONTEXT STRUCT
    thread_handle    QWORD ?    ; HANDLE from CreateThread
    thread_id        DWORD ?
    function         QWORD ?    ; Thread entry function
    param            QWORD ?    ; Parameter to thread
    is_running       BYTE ?
    should_exit      BYTE ?
    exit_code        DWORD ?
THREAD_CONTEXT ENDS

;==========================================================================
; CHAT PANEL STRUCTURES - Custom for agent chat integration
;==========================================================================

CHAT_MESSAGE STRUCT
    timestamp        QWORD ?    ; Milliseconds since epoch
    type             BYTE ?     ; 1=user, 2=assistant, 3=system
    text             QWORD ?    ; Message text
    tokens           DWORD ?    ; Token count
    model_name       QWORD ?    ; Model used
CHAT_MESSAGE ENDS

CHAT_HISTORY STRUCT
    messages         QWORD ?    ; Array of CHAT_MESSAGE
    msg_count        DWORD ?
    msg_capacity     DWORD ?
    session_id       QWORD ?    ; Session identifier
    created_time     QWORD ?    ; Session creation time
CHAT_HISTORY ENDS

;==========================================================================
; GLOBAL COMPONENT REGISTRY
;==========================================================================

.data
    ; Object registry
    g_registry_root  QWORD 0    ; Root of object tree
    g_registry_count DWORD 0
    
    ; Memory pool
    g_widget_pool    MEMORY_POOL <>
    g_dialog_pool    MEMORY_POOL <>
    
    ; Event queue
    g_event_queue    QWORD 0    ; Head of event queue
    g_event_lock     QWORD 0    ; SRWLOCK for thread safety
    
    ; Slot bindings
    g_slot_bindings  QWORD 0    ; Head of bindings chain
    
    ; Default theme
    g_default_theme  COLOR_SCHEME <>
    
    ; Main window handle
    g_main_hwnd      QWORD 0
    
    ; Message strings
    sz_masm_class    BYTE "MASM_WIDGET_CLASS", 0
    sz_main_window   BYTE "MASM_MAIN_WINDOW", 0

;==========================================================================
; INITIALIZATION & CLEANUP
;==========================================================================

PUBLIC qt_foundation_init
qt_foundation_init PROC
    ; Initialize memory pools, event queue, window classes, default theme
    ; Return: RAX = 0 (success) or error code
    
    push rbx
    push r12
    sub rsp, 32
    
    ; Initialize widget memory pool (100 widgets * sizeof(WIDGET) pre-allocated)
    lea rax, [rel g_widget_pool]
    mov qword ptr [rax + MEMORY_POOL.chunk_size], 512  ; Approximate WIDGET size
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0      ; Will allocate on first use
    mov qword ptr [rax + MEMORY_POOL.free_list], 0
    mov dword ptr [rax + MEMORY_POOL.used_count], 0
    mov dword ptr [rax + MEMORY_POOL.total_count], 100
    
    ; Initialize dialog memory pool
    lea rax, [rel g_dialog_pool]
    mov qword ptr [rax + MEMORY_POOL.chunk_size], 256  ; Approximate DIALOG size
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0
    mov qword ptr [rax + MEMORY_POOL.free_list], 0
    mov dword ptr [rax + MEMORY_POOL.used_count], 0
    mov dword ptr [rax + MEMORY_POOL.total_count], 50
    
    ; Initialize event queue and lock
    mov qword ptr [rel g_event_queue], 0
    mov qword ptr [rel g_event_lock], 0
    
    ; Initialize slot bindings chain
    mov qword ptr [rel g_slot_bindings], 0
    
    ; Initialize default color scheme
    lea rax, [rel g_default_theme]
    mov dword ptr [rax + COLOR_SCHEME.window_bg], 0xF0F0F0    ; Light gray
    mov dword ptr [rax + COLOR_SCHEME.text_color], 0x000000    ; Black
    mov dword ptr [rax + COLOR_SCHEME.button_bg], 0xE0E0E0     ; Medium gray
    mov dword ptr [rax + COLOR_SCHEME.button_text], 0x000000   ; Black
    mov dword ptr [rax + COLOR_SCHEME.highlight], 0x0078D4     ; Windows blue
    mov dword ptr [rax + COLOR_SCHEME.shadow], 0x808080        ; Medium gray
    mov dword ptr [rax + COLOR_SCHEME.dark], 0x696969          ; Dark gray
    mov dword ptr [rax + COLOR_SCHEME.light], 0xFFFFFF         ; White
    mov dword ptr [rax + COLOR_SCHEME.link_color], 0x0563C1    ; Link blue
    
    ; Clear registry
    mov qword ptr [rel g_registry_root], 0
    mov dword ptr [rel g_registry_count], 0
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop r12
    pop rbx
    ret
qt_foundation_init ENDP

PUBLIC qt_foundation_cleanup
qt_foundation_cleanup PROC
    ; Clean up all objects, free pools, cleanup queues
    ; Return: RAX = 0 (success)
    
    push rbx
    push r12
    sub rsp, 32
    
    ; Walk registry root and destroy all objects recursively
    mov rax, [rel g_registry_root]
    test rax, rax
    jz .cleanup_pools
    
.cleanup_objects:
    ; RCX = current object to destroy
    mov rcx, rax
    call object_destroy
    
    ; Get next from registry (simplified - in production, walk registry list)
    xor rax, rax
    
.cleanup_pools:
    ; Clear memory pool pointers (will be freed when process exits)
    mov qword ptr [rel g_widget_pool + MEMORY_POOL.pool_ptr], 0
    mov qword ptr [rel g_dialog_pool + MEMORY_POOL.pool_ptr], 0
    
    ; Clear event queue
    mov qword ptr [rel g_event_queue], 0
    mov qword ptr [rel g_slot_bindings], 0
    mov dword ptr [rel g_registry_count], 0
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop r12
    pop rbx
    ret
qt_foundation_cleanup ENDP

;==========================================================================
; OBJECT CREATION/DESTRUCTION
;==========================================================================

PUBLIC object_create
object_create PROC
    ; Create a new object
    ; RCX = type ID (1=WIDGET, 2=DIALOG, 3=MENU, etc.)
    ; RDX = parent (optional, can be NULL)
    ; Return: RAX = object pointer
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; Save type ID
    mov rbx, rdx                ; Save parent
    
    ; For WIDGET types (type = 1)
    cmp r12, 1
    jne .try_dialog
    
    ; Allocate WIDGET from widget pool (256 bytes typical)
    mov rax, 256
    call malloc                 ; RCX = size → RAX = ptr or 0
    test rax, rax
    jz .create_error
    
    ; Initialize WIDGET structure
    mov rcx, rax                ; Object pointer
    mov qword ptr [rcx + OBJECT_BASE.vmt], 0      ; Will set in subclass
    mov qword ptr [rcx + OBJECT_BASE.hwnd], 0
    mov qword ptr [rcx + OBJECT_BASE.parent], rbx ; Set parent
    mov qword ptr [rcx + OBJECT_BASE.children], 0
    mov dword ptr [rcx + OBJECT_BASE.child_count], 0
    mov dword ptr [rcx + OBJECT_BASE.flags], FLAG_VISIBLE | FLAG_ENABLED
    jmp .add_to_registry
    
.try_dialog:
    cmp r12, 2
    jne .try_menu
    
    ; Allocate DIALOG (320 bytes typical)
    mov rax, 320
    call malloc
    test rax, rax
    jz .create_error
    
    mov rcx, rax
    mov qword ptr [rcx + OBJECT_BASE.parent], rbx
    mov dword ptr [rcx + OBJECT_BASE.flags], FLAG_VISIBLE
    jmp .add_to_registry
    
.try_menu:
    cmp r12, 3
    jne .create_error
    
    ; Allocate MENU (256 bytes typical)
    mov rax, 256
    call malloc
    test rax, rax
    jz .create_error
    
    mov rcx, rax
    mov qword ptr [rcx + OBJECT_BASE.parent], rbx
    mov qword ptr [rcx + MENU.items], 0
    mov dword ptr [rcx + MENU.item_count], 0
    mov dword ptr [rcx + MENU.item_capacity], 0
    jmp .add_to_registry
    
.add_to_registry:
    ; Add to registry (simplified - in production use linked list)
    mov rbx, [rel g_registry_root]
    mov [rel g_registry_root], rax        ; New root
    mov qword ptr [rax + 0], rbx          ; Link previous root
    inc dword ptr [rel g_registry_count]
    
    add rsp, 32
    pop r12
    pop rbx
    ret
    
.create_error:
    xor eax, eax                ; Return NULL on allocation failure
    add rsp, 32
    pop r12
    pop rbx
    ret
object_create ENDP

PUBLIC object_destroy
object_destroy PROC
    ; Destroy an object and its children
    ; RCX = object pointer
    ; Return: RAX = 0 (success)
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; Save object pointer
    test r12, r12
    jz .destroy_ok              ; NULL pointer is OK
    
    ; Recursively destroy children
    mov rbx, [r12 + OBJECT_BASE.children]
.destroy_loop:
    test rbx, rbx
    jz .destroy_self
    
    mov rcx, rbx
    mov rbx, [rbx + 0]          ; Get next sibling (simplified)
    call object_destroy         ; Recursively destroy
    jmp .destroy_loop
    
.destroy_self:
    ; Call virtual destructor if VMT exists
    mov rax, [r12 + OBJECT_BASE.vmt]
    test rax, rax
    jz .free_memory
    
    mov rbx, [rax + VMT_BASE.pfn_destroy]
    test rbx, rbx
    jz .free_memory
    
    mov rcx, r12
    call rbx                    ; Call destructor
    
.free_memory:
    ; Free object memory
    mov rcx, r12
    call free
    
.destroy_ok:
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
object_destroy ENDP

;==========================================================================
; EVENT HANDLING
;==========================================================================

PUBLIC post_event
post_event PROC
    ; Post event to queue for deferred processing
    ; RCX = target object
    ; RDX = event type
    ; R8 = param1
    ; R9 = param2
    ; Return: RAX = 0 (success)
    
    push rbx
    push r12
    sub rsp, 32
    
    ; Allocate EVENT_ITEM structure (64 bytes)
    mov rax, 64
    call malloc
    test rax, rax
    jz .post_error
    
    mov r12, rax                ; R12 = new event item
    mov [r12 + 0], rcx          ; target object
    mov [r12 + 8], rdx          ; event_type
    mov [r12 + 16], r8          ; param1
    mov [r12 + 24], r9          ; param2
    mov qword ptr [r12 + 32], 0 ; next = NULL
    
    ; Add to queue (simplified locking)
.lock_retry:
    mov eax, 1
    xchg [rel g_event_lock], rax
    test rax, rax
    jnz .lock_retry
    
    ; Find tail and link
    mov rax, [rel g_event_queue]
    test rax, rax
    jnz .find_tail
    mov [rel g_event_queue], r12
    jmp .unlock
    
.find_tail:
    mov rbx, rax
.tail_loop:
    mov rcx, [rbx + 32]
    test rcx, rcx
    jz .at_tail
    mov rbx, rcx
    jmp .tail_loop
.at_tail:
    mov [rbx + 32], r12
    
.unlock:
    mov qword ptr [rel g_event_lock], 0
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
    
.post_error:
    mov eax, 1
    add rsp, 32
    pop r12
    pop rbx
    ret
post_event ENDP

PUBLIC process_events
process_events PROC
    ; Process all queued events
    ; Return: RAX = number of events processed
    
    push rbx
    push r12
    push r13
    sub rsp, 32
    
    xor r13, r13                ; Event counter
    
    ; Acquire lock
.lock_retry:
    mov eax, 1
    xchg [rel g_event_lock], rax
    test rax, rax
    jnz .lock_retry
    
    mov r12, [rel g_event_queue]
    mov qword ptr [rel g_event_queue], 0 ; Clear queue
    
.unlock_queue:
    mov qword ptr [rel g_event_lock], 0
    
    ; Process all events (now unlocked, safe to dispatch)
.process_loop:
    test r12, r12
    jz .done
    
    mov rbx, r12
    mov r12, [r12 + 32]         ; Get next
    
    ; Dispatch event
    ; RBX points to EVENT_ITEM with: target, event_type, param1, param2
    mov rcx, [rbx + 0]          ; target object
    test rcx, rcx
    jz .skip_dispatch
    
    mov rax, [rcx + OBJECT_BASE.vmt]
    test rax, rax
    jz .skip_dispatch
    
    mov rax, [rax + VMT_BASE.pfn_on_event]
    test rax, rax
    jz .skip_dispatch
    
    mov rdx, [rbx + 8]          ; event_type
    mov r8, [rbx + 16]          ; param1
    mov r9, [rbx + 24]          ; param2
    call rax                    ; Call event handler
    
.skip_dispatch:
    mov rcx, rbx
    call free                   ; Free event item
    inc r13                      ; Increment counter
    jmp .process_loop
    
.done:
    mov rax, r13
    add rsp, 32
    pop r13
    pop r12
    pop rbx
    ret
process_events ENDP

;==========================================================================
; SIGNAL/SLOT BINDING
;==========================================================================

PUBLIC connect_signal
connect_signal PROC
    ; Connect a signal to a slot
    ; RCX = sender object
    ; RDX = signal ID
    ; R8 = receiver object
    ; R9 = slot handler function
    ; Return: RAX = 0 (success)
    
    push rbx
    sub rsp, 32
    
    ; Allocate SLOT_BINDING structure (64 bytes)
    mov rax, 64
    call malloc
    test rax, rax
    jz .connect_error
    
    mov rbx, rax                ; RBX = new binding
    mov [rbx + SLOT_BINDING.sender_obj], rcx
    mov [rbx + SLOT_BINDING.receiver_obj], r8
    mov [rbx + SLOT_BINDING.signal_id], rdx
    mov [rbx + SLOT_BINDING.slot_handler], r9
    
    ; Link to bindings list
    mov rax, [rel g_slot_bindings]
    mov [rbx + SLOT_BINDING.next], rax
    mov [rel g_slot_bindings], rbx
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop rbx
    ret
    
.connect_error:
    mov eax, 1                  ; Return error
    add rsp, 32
    pop rbx
    ret
connect_signal ENDP

PUBLIC emit_signal
emit_signal PROC
    ; Emit a signal and call all connected slots
    ; RCX = sender object
    ; RDX = signal ID
    ; R8 = param1 (signal data)
    ; Return: RAX = number of slots called
    
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 32
    
    mov r12, rcx                ; sender
    mov r13, rdx                ; signal_id
    mov r14, r8                 ; param1
    xor r13, r13                ; slot count
    
    ; Walk slot bindings chain
    mov rbx, [rel g_slot_bindings]
    
.find_bindings:
    test rbx, rbx
    jz .emit_done
    
    ; Check if this binding matches
    mov rax, [rbx + SLOT_BINDING.sender_obj]
    cmp rax, r12
    jne .next_binding
    
    mov rax, [rbx + SLOT_BINDING.signal_id]
    cmp rax, r13
    jne .next_binding
    
    ; Found matching binding, call it
    mov rcx, [rbx + SLOT_BINDING.receiver_obj]
    mov rdx, r14                ; param1
    mov rax, [rbx + SLOT_BINDING.slot_handler]
    call rax                    ; Call slot handler
    inc r13                      ; Count calls
    
.next_binding:
    mov rbx, [rbx + SLOT_BINDING.next]
    jmp .find_bindings
    
.emit_done:
    mov rax, r13                ; Return call count
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
emit_signal ENDP

;==========================================================================
; WIDGET GEOMETRY MANAGEMENT
;==========================================================================

PUBLIC widget_set_geometry
widget_set_geometry PROC
    ; Set widget position and size
    ; RCX = widget pointer
    ; RDX = x position
    ; R8 = y position
    ; R9 = width
    ; [RSP+40] = height
    ; Return: RAX = 0 (success)
    
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    mov eax, [rbx + OBJECT_BASE.flags]
    or eax, FLAG_DIRTY
    mov [rbx + OBJECT_BASE.flags], eax
    
    ; Store geometry (simplified - would store in WIDGET.rect)
    ; In production:
    ; - Store x, y, width, height in widget structure
    ; - If native window (FLAG_NATIVE): call SetWindowPos
    ; - If has layout: trigger layout recalculation
    ; - Post paint events to self and children
    
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
widget_set_geometry ENDP

PUBLIC widget_get_geometry
widget_get_geometry PROC
    ; Get widget geometry
    ; RCX = widget pointer
    ; RDX = RECT_MASM output pointer
    ; Return: RAX = pointer to filled RECT_MASM
    
    push rbx
    sub rsp, 32
    
    mov rbx, rdx
    
    ; Return zeros (simplified - would read from WIDGET.rect)
    mov dword ptr [rbx + RECT_MASM.x], 0
    mov dword ptr [rbx + RECT_MASM.y], 0
    mov dword ptr [rbx + RECT_MASM.width], 0
    mov dword ptr [rbx + RECT_MASM.height], 0
    
    mov rax, rdx
    add rsp, 32
    pop rbx
    ret
widget_get_geometry ENDP

;==========================================================================
; THEME/COLOR MANAGEMENT
;==========================================================================

PUBLIC set_color_scheme
set_color_scheme PROC
    ; Set global color scheme
    ; RCX = COLOR_SCHEME pointer
    ; Return: RAX = 0 (success)
    
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    lea rax, [rel g_default_theme]
    
    ; Copy all color values
    mov ecx, [rbx + COLOR_SCHEME.window_bg]
    mov [rax + COLOR_SCHEME.window_bg], ecx
    mov ecx, [rbx + COLOR_SCHEME.text_color]
    mov [rax + COLOR_SCHEME.text_color], ecx
    mov ecx, [rbx + COLOR_SCHEME.button_bg]
    mov [rax + COLOR_SCHEME.button_bg], ecx
    mov ecx, [rbx + COLOR_SCHEME.button_text]
    mov [rax + COLOR_SCHEME.button_text], ecx
    mov ecx, [rbx + COLOR_SCHEME.highlight]
    mov [rax + COLOR_SCHEME.highlight], ecx
    mov ecx, [rbx + COLOR_SCHEME.shadow]
    mov [rax + COLOR_SCHEME.shadow], ecx
    mov ecx, [rbx + COLOR_SCHEME.dark]
    mov [rax + COLOR_SCHEME.dark], ecx
    mov ecx, [rbx + COLOR_SCHEME.light]
    mov [rax + COLOR_SCHEME.light], ecx
    mov ecx, [rbx + COLOR_SCHEME.link_color]
    mov [rax + COLOR_SCHEME.link_color], ecx
    
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
set_color_scheme ENDP

PUBLIC get_color_scheme
get_color_scheme PROC
    ; Get current color scheme
    ; Return: RAX = pointer to COLOR_SCHEME
    
    lea rax, [rip + g_default_theme]
    ret
get_color_scheme ENDP

;==========================================================================
; FILE OPERATIONS - Support for file browser
;==========================================================================

PUBLIC enumerate_files
enumerate_files PROC
    ; Enumerate files in directory
    ; RCX = directory path
    ; RDX = FILE_LISTING output pointer
    ; Return: RAX = error code
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; Directory path
    mov rbx, rdx                ; Output pointer
    
    ; Initialize FILE_LISTING
    mov qword ptr [rbx + FILE_LISTING.entries], 0
    mov dword ptr [rbx + FILE_LISTING.entry_count], 0
    mov dword ptr [rbx + FILE_LISTING.entry_capacity], 100
    mov qword ptr [rbx + FILE_LISTING.current_path], r12
    
    ; In production: Use Win32 FindFile APIs
    ; - FindFirstFile(path, out WIN32_FIND_DATA)
    ; - Loop: FindNextFile(...) and populate entries
    ; - FindClose(handle)
    
    xor eax, eax                ; Return success (simplified)
    add rsp, 32
    pop r12
    pop rbx
    ret
enumerate_files ENDP

;==========================================================================
; THREADING UTILITIES
;==========================================================================

PUBLIC create_thread
create_thread PROC
    ; Create a new thread
    ; RCX = function pointer
    ; RDX = parameter
    ; Return: RAX = THREAD_CONTEXT pointer
    
    push rbx
    sub rsp, 32
    
    ; Allocate THREAD_CONTEXT structure (96 bytes)
    mov rax, 96
    call malloc
    test rax, rax
    jz .thread_error
    
    mov rbx, rax                ; RBX = context
    mov [rbx + THREAD_CONTEXT.function], rcx
    mov [rbx + THREAD_CONTEXT.param], rdx
    mov byte ptr [rbx + THREAD_CONTEXT.is_running], 1
    mov byte ptr [rbx + THREAD_CONTEXT.should_exit], 0
    mov dword ptr [rbx + THREAD_CONTEXT.exit_code], 0
    mov qword ptr [rbx + THREAD_CONTEXT.thread_handle], 0
    mov dword ptr [rbx + THREAD_CONTEXT.thread_id], 0
    
    ; In production: Call CreateThread(
    ;   NULL,           ; Security
    ;   0,              ; Stack size
    ;   rcx,            ; Start address
    ;   rdx,            ; Parameter
    ;   0,              ; Flags
    ;   &thread_id      ; Thread ID output
    ; )
    
    mov rax, rbx
    add rsp, 32
    pop rbx
    ret
    
.thread_error:
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
create_thread ENDP

PUBLIC wait_thread
wait_thread PROC
    ; Wait for thread to complete
    ; RCX = THREAD_CONTEXT pointer
    ; Return: RAX = thread exit code
    
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    
    ; In production:
    ; 1. WaitForSingleObject(rbx->thread_handle, INFINITE)
    ; 2. GetExitCodeThread(rbx->thread_handle, &exit_code)
    ; 3. CloseHandle(rbx->thread_handle)
    
    mov eax, [rbx + THREAD_CONTEXT.exit_code]
    
    add rsp, 32
    pop rbx
    ret
wait_thread ENDP

;==========================================================================
; CHAT INTEGRATION
;==========================================================================

PUBLIC create_chat_history
create_chat_history PROC
    ; Create new chat history
    ; Return: RAX = CHAT_HISTORY pointer
    
    push rbx
    push r12
    sub rsp, 32
    
    ; Allocate CHAT_HISTORY structure (96 bytes)
    mov rax, 96
    call malloc
    test rax, rax
    jz .chat_alloc_error
    
    mov r12, rax                ; R12 = history
    
    ; Allocate message array (100 messages * 64 bytes = 6400 bytes)
    mov rcx, 6400
    call malloc
    test rax, rax
    jz .chat_array_error
    
    mov [r12 + CHAT_HISTORY.messages], rax
    mov dword ptr [r12 + CHAT_HISTORY.msg_count], 0
    mov dword ptr [r12 + CHAT_HISTORY.msg_capacity], 100
    
    ; Get current timestamp
    ; In production: GetSystemTimeAsFileTime or similar
    mov qword ptr [r12 + CHAT_HISTORY.created_time], 0
    mov qword ptr [r12 + CHAT_HISTORY.session_id], 0
    
    mov rax, r12
    add rsp, 32
    pop r12
    pop rbx
    ret
    
.chat_array_error:
    ; Free history if array allocation failed
    mov rcx, r12
    call free
    
.chat_alloc_error:
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
create_chat_history ENDP

PUBLIC add_chat_message
add_chat_message PROC
    ; Add message to chat history
    ; RCX = CHAT_HISTORY pointer
    ; RDX = CHAT_MESSAGE pointer
    ; Return: RAX = 0 (success), 1 (full)
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; History
    mov rbx, rdx                ; Message
    
    ; Check capacity
    mov eax, [r12 + CHAT_HISTORY.msg_count]
    mov ecx, [r12 + CHAT_HISTORY.msg_capacity]
    cmp eax, ecx
    jge .msg_full
    
    ; Calculate offset: count * sizeof(CHAT_MESSAGE) = count * 64
    mov eax, [r12 + CHAT_HISTORY.msg_count]
    shl eax, 6                  ; Multiply by 64
    
    ; Get message array pointer
    mov rcx, [r12 + CHAT_HISTORY.messages]
    add rcx, rax                ; Point to next slot
    
    ; Copy message
    mov rax, [rbx + CHAT_MESSAGE.timestamp]
    mov [rcx + CHAT_MESSAGE.timestamp], rax
    mov al, [rbx + CHAT_MESSAGE.type]
    mov [rcx + CHAT_MESSAGE.type], al
    mov rax, [rbx + CHAT_MESSAGE.text]
    mov [rcx + CHAT_MESSAGE.text], rax
    mov eax, [rbx + CHAT_MESSAGE.tokens]
    mov [rcx + CHAT_MESSAGE.tokens], eax
    mov rax, [rbx + CHAT_MESSAGE.model_name]
    mov [rcx + CHAT_MESSAGE.model_name], rax
    
    ; Increment count
    inc dword ptr [r12 + CHAT_HISTORY.msg_count]
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop r12
    pop rbx
    ret
    
.msg_full:
    mov eax, 1                  ; Return failure (full)
    add rsp, 32
    pop r12
    pop rbx
    ret
add_chat_message ENDP

.end
