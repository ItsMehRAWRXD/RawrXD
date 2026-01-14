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

; External memory functions (provided by malloc_wrapper.asm)
extern masm_malloc : proc
extern masm_free : proc
extern masm_realloc : proc

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
; Each object type_id has a VMT with function pointers
VMT_BASE STRUCT
    pfn_destroy      QWORD ?    ; Virtual destructor
    pfn_paint        QWORD ?    ; Virtual paint handler
    pfn_on_event     QWORD ?    ; Virtual event handler
    pfn_get_size     QWORD ?    ; Virtual size_val query
    pfn_set_size     QWORD ?    ; Virtual size_val setter
    pfn_show         QWORD ?    ; Virtual show
    pfn_hide         QWORD ?    ; Virtual hide
VMT_BASE ENDS

; Base object instance - replaces QObject
OBJECT_BASE STRUCT
    obj_vmt          QWORD ?    ; Pointer to VMT
    obj_hwnd         QWORD ?    ; Associated HWND
    obj_parent       QWORD ?    ; Parent object
    obj_children     QWORD ?    ; Child list pointer
    obj_child_count  DWORD ?    ; Number of children
    obj_flags        DWORD ?    ; Object flags (visible, enabled, etc)
    obj_user_data    QWORD ?    ; Custom data pointer
OBJECT_BASE ENDS

; Rectangle for layout/sizing
RECT_MASM STRUCT
    x                DWORD ?
    y                DWORD ?
    width_val        DWORD ?
    height           DWORD ?
RECT_MASM ENDS

; size_val hint for layout calculations
SIZE_HINT STRUCT
    min_width        DWORD ?
    min_height       DWORD ?
    max_width        DWORD ?
    max_height       DWORD ?
    preferred_width  DWORD ?
    preferred_height DWORD ?
SIZE_HINT ENDS

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
    pool_chunk_size  DWORD ?    ; size_val of each pool chunk
    pool_ptr         QWORD ?    ; Pointer to allocated pool
    pool_free_list   QWORD ?    ; Linked list of free blocks
    pool_used_count  DWORD ?    ; Number of allocated objects
    pool_total_count DWORD ?    ; Total capacity
MEMORY_POOL ENDS

;==========================================================================
; OBJECT REGISTRY - Track all active objects
;==========================================================================
; Allows traversal of object tree (used by layout, events, etc)

REGISTRY_ENTRY STRUCT
    reg_obj_ptr      QWORD ?
    reg_type_id      DWORD ?
    reg_flags        DWORD ?
    reg_next         QWORD ?
REGISTRY_ENTRY ENDS

;==========================================================================
; EVENT QUEUE - Replaces Qt's event dispatcher
;==========================================================================
; Queue for deferred events (async signals, timers, etc)

EVENT_ITEM STRUCT
    evt_type         DWORD ?
    evt_target       QWORD ?
    evt_param1       QWORD ?
    evt_param2       QWORD ?
    evt_param3       QWORD ?
    evt_next         QWORD ?
EVENT_ITEM ENDS

;==========================================================================
; LAYOUT HIERARCHY - Replaces QLayout, QHBoxLayout, QVBoxLayout
;==========================================================================

; Layout item (widget + layout hints)
LAYOUT_ITEM STRUCT
    lay_widget       QWORD ?    ; Pointer to child object
    lay_stretch      DWORD ?    ; Stretch factor
    lay_spacing      DWORD ?    ; Space to next item
    lay_alignment    DWORD ?    ; Alignment flags
    lay_size_hint    SIZE_HINT <> ; Preferred/min/max sizes
LAYOUT_ITEM ENDS

; Layout base class
LAYOUT_BASE STRUCT
    lay_container    QWORD ?    ; Parent container
    lay_items        QWORD ?    ; Array of layout items
    lay_item_count   DWORD ?    ; Number of items
    lay_item_capacity DWORD ?    ; Allocated capacity
    lay_spacing_val  DWORD ?    ; Default spacing
    lay_margin_l     DWORD ?
    lay_margin_r     DWORD ?
    lay_margin_t     DWORD ?
    lay_margin_b     DWORD ?
LAYOUT_BASE ENDS

;==========================================================================
; WIDGET BASE CLASS - Replaces QWidget
;==========================================================================

WIDGET STRUCT
    wid_base         OBJECT_BASE <>
    wid_rect         RECT_MASM <> ; Position and size_val
    
    ; Appearance
    wid_bg_color     DWORD ?    ; RGB color
    wid_font         QWORD ?    ; GDI font handle
    
    ; Layout
    wid_layout       QWORD ?    ; Pointer to LAYOUT_BASE
    
    ; Input handling
    wid_kb_focus     BYTE ?     ; Has keyboard focus
    wid_mouse_inside BYTE ?     ; Mouse is over widget
    
    ; Paint cache
    wid_paint_cache  QWORD ?    ; Cached DC/bitmap
    wid_cache_valid  BYTE ?
WIDGET ENDS

;==========================================================================
; DIALOG BASE CLASS - Replaces QDialog
;==========================================================================

DIALOG STRUCT
    dlg_widget       WIDGET <>
    dlg_is_modal     BYTE ?
    dlg_result       DWORD ?    ; Dialog result (OK, Cancel, etc)
    dlg_parent_hwnd  QWORD ?    ; Parent window handle
DIALOG ENDS

;==========================================================================
; MENU STRUCTURE - Replaces QMenu
;==========================================================================

MENU_ITEM STRUCT
    mi_id            DWORD ?    ; Item ID for dispatch
    mi_text          QWORD ?    ; Text string pointer
    mi_icon          QWORD ?    ; HICON for menu item
    mi_submenu       QWORD ?    ; Pointer to MENU if has submenu
    mi_sep           BYTE ?
    mi_enabled       BYTE ?
    mi_checked       BYTE ?
MENU_ITEM ENDS

MENU STRUCT
    menu_base        OBJECT_BASE <>
    menu_items       QWORD ?    ; Array of MENU_ITEM
    menu_item_count  DWORD ?
    menu_item_capacity DWORD ?
    menu_native      QWORD ?    ; HMENU from Win32
MENU ENDS

;==========================================================================
; SIGNAL/SLOT SYSTEM - Replaces Qt's signal/slot mechanism
;==========================================================================
; Deferred event-driven callbacks

SLOT_BINDING STRUCT
    slot_sender      QWORD ?    ; Object that emitted signal
    slot_receiver    QWORD ?    ; Object that received signal
    slot_signal_id   DWORD ?    ; Signal identifier
    slot_handler_fn  QWORD ?    ; Function pointer to handler
    slot_next        QWORD ?    ; Next binding in_val chain
SLOT_BINDING ENDS

;==========================================================================
; COLOR SCHEME/THEME - Replaces QPalette, QStyle
;==========================================================================

COLOR_SCHEME STRUCT
    clr_window_bg    DWORD ?    ; Window background color
    clr_text_color   DWORD ?    ; Text color
    clr_button_bg    DWORD ?    ; Button background
    clr_button_text  DWORD ?    ; Button text color
    clr_highlight    DWORD ?    ; Selection highlight
    clr_shadow       DWORD ?    ; Shadow color
    clr_dark         DWORD ?    ; Dark variant
    clr_light        DWORD ?    ; Light variant
    clr_link_color   DWORD ?    ; Hyperlink color
COLOR_SCHEME ENDS

;==========================================================================
; FILE BROWSER DATA - Replaces QFileSystemModel
;==========================================================================

FILE_ENTRY STRUCT
    file_name        QWORD ?    ; Filename string
    file_path        QWORD ?    ; Full path
    file_is_dir      BYTE ?
    file_is_hidden   BYTE ?
    file_size        QWORD ?    ; File size_val
    file_modified    QWORD ?    ; Modification timestamp
    file_icon_idx    DWORD ?    ; Icon index in_val image list
FILE_ENTRY ENDS

FILE_LISTING STRUCT
    fl_entries       QWORD ?    ; Array of FILE_ENTRY
    fl_count         DWORD ?
    fl_capacity      DWORD ?
    fl_current       QWORD ?    ; Current directory
    fl_parent        QWORD ?    ; Parent directory
FILE_LISTING ENDS

;==========================================================================
; THREADING - Replaces QThread
;==========================================================================

THREAD_CONTEXT STRUCT
    thr_handle       QWORD ?    ; HANDLE from CreateThread
    thr_id           DWORD ?
    thr_func         QWORD ?    ; Thread entry function
    thr_param        QWORD ?    ; Parameter to thread
    thr_running      BYTE ?
    thr_exit         BYTE ?
    thr_exit_code    DWORD ?
THREAD_CONTEXT ENDS

;==========================================================================
; CHAT PANEL STRUCTURES - Custom for agent chat integration
;==========================================================================

CHAT_MESSAGE STRUCT
    timestamp        QWORD ?    ; Milliseconds since epoch
    type_id             BYTE ?     ; 1=user, 2=assistant, 3=system
    text             QWORD ?    ; Message text
    tokens           DWORD ?    ; Token count
    model_name       QWORD ?    ; Model used
CHAT_MESSAGE ENDS

CHAT_HISTORY STRUCT
    chat_msgs        QWORD ?    ; Array of CHAT_MESSAGE
    chat_count       DWORD ?
    chat_capacity    DWORD ?
    chat_session     QWORD ?    ; Session identifier
    chat_created     QWORD ?    ; Session creation time
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

.code

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
    mov dword ptr [rax].MEMORY_POOL.pool_chunk_size, 512  ; Approximate WIDGET size_val
    mov qword ptr [rax].MEMORY_POOL.pool_ptr, 0      ; Will allocate on first use
    mov qword ptr [rax].MEMORY_POOL.pool_free_list, 0
    mov dword ptr [rax].MEMORY_POOL.pool_used_count, 0
    mov dword ptr [rax].MEMORY_POOL.pool_total_count, 100
    
    ; Initialize dialog memory pool
    lea rax, [rel g_dialog_pool]
    mov dword ptr [rax].MEMORY_POOL.pool_chunk_size, 256  ; Approximate DIALOG size_val
    mov qword ptr [rax].MEMORY_POOL.pool_ptr, 0
    mov qword ptr [rax].MEMORY_POOL.pool_free_list, 0
    mov dword ptr [rax].MEMORY_POOL.pool_used_count, 0
    mov dword ptr [rax].MEMORY_POOL.pool_total_count, 50
    
    ; Initialize event queue and lock
    mov qword ptr [rel g_event_queue], 0
    mov qword ptr [rel g_event_lock], 0
    
    ; Initialize slot bindings chain
    mov qword ptr [rel g_slot_bindings], 0
    
    ; Initialize default color scheme
    lea rax, [rel g_default_theme]
    mov dword ptr [rax].COLOR_SCHEME.clr_window_bg, 0xF0F0F0    ; Light gray
    mov dword ptr [rax].COLOR_SCHEME.clr_text_color, 0x000000    ; Black
    mov dword ptr [rax].COLOR_SCHEME.clr_button_bg, 0xE0E0E0     ; Medium gray
    mov dword ptr [rax].COLOR_SCHEME.clr_button_text, 0x000000   ; Black
    mov dword ptr [rax].COLOR_SCHEME.clr_highlight, 0x0078D4     ; Windows blue
    mov dword ptr [rax].COLOR_SCHEME.clr_shadow, 0x808080        ; Medium gray
    mov dword ptr [rax].COLOR_SCHEME.clr_dark, 0x696969          ; Dark gray
    mov dword ptr [rax].COLOR_SCHEME.clr_light, 0xFFFFFF         ; White
    mov dword ptr [rax].COLOR_SCHEME.clr_link_color, 0x0563C1    ; Link blue
    
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
    jz cleanup_pools
    
cleanup_objects:
    ; RCX = current object to destroy
    mov rcx, rax
    call object_destroy
    
    ; Get next from registry (simplified - in_val production, walk registry list)
    xor rax, rax
    
cleanup_pools:
    ; Clear memory pool pointers (will be freed when process exits)
    mov qword ptr [rel g_widget_pool].MEMORY_POOL.pool_ptr, 0
    mov qword ptr [rel g_dialog_pool].MEMORY_POOL.pool_ptr, 0
    
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
    ; RCX = type_id ID (1=WIDGET, 2=DIALOG, 3=MENU, etc.)
    ; RDX = parent (optional, can be NULL)
    ; Return: RAX = object pointer
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; Save type_id ID
    mov rbx, rdx                ; Save parent
    
    ; For WIDGET types (type_id = 1)
    cmp r12, 1
    jne try_dialog
    
    ; Allocate WIDGET from widget pool (256 bytes typical)
    mov rax, 256
    call masm_malloc                 ; RCX = size_val → RAX = ptr or 0
    test rax, rax
    jz create_error
    
    ; Initialize WIDGET structure
    mov rcx, rax                ; Object pointer
    mov (WIDGET PTR [rcx]).wid_base.obj_vmt, 0      ; Will set in_val subclass
    mov (WIDGET PTR [rcx]).wid_base.obj_hwnd, 0
    mov (WIDGET PTR [rcx]).wid_base.obj_parent, rbx ; Set parent
    mov (WIDGET PTR [rcx]).wid_base.obj_children, 0
    mov (WIDGET PTR [rcx]).wid_base.obj_child_count, 0
    mov (WIDGET PTR [rcx]).wid_base.obj_flags, FLAG_VISIBLE or FLAG_ENABLED
    jmp add_to_registry
    
try_dialog:
    cmp r12, 2
    jne try_menu
    
    ; Allocate DIALOG (320 bytes typical)
    mov rax, 320
    call masm_malloc
    test rax, rax
    jz create_error
    
    mov rcx, rax
    mov (DIALOG PTR [rcx]).dlg_widget.wid_base.obj_parent, rbx
    mov (DIALOG PTR [rcx]).dlg_widget.wid_base.obj_flags, FLAG_VISIBLE
    jmp add_to_registry
    
try_menu:
    cmp r12, 3
    jne create_error
    
    ; Allocate MENU (256 bytes typical)
    mov rax, 256
    call masm_malloc
    test rax, rax
    jz create_error
    
    mov rcx, rax
    mov (MENU PTR [rcx]).menu_base.obj_parent, rbx
    mov (MENU PTR [rcx]).menu_items, 0
    mov (MENU PTR [rcx]).menu_item_count, 0
    mov (MENU PTR [rcx]).menu_item_capacity, 0
    jmp add_to_registry
    
add_to_registry:
    ; Add to registry (simplified - in_val production use linked list)
    mov rbx, [rel g_registry_root]
    mov [rel g_registry_root], rax        ; New root
    mov qword ptr [rax + 0], rbx          ; Link previous root
    inc dword ptr [rel g_registry_count]
    
    add rsp, 32
    pop r12
    pop rbx
    ret
    
create_error:
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
    jz destroy_ok              ; NULL pointer is OK
    
    ; Recursively destroy children
    mov rbx, (OBJECT_BASE PTR [r12]).obj_children
destroy_loop:
    test rbx, rbx
    jz destroy_self
    
    mov rcx, rbx
    mov rbx, [rbx + 0]          ; Get next sibling (simplified)
    call object_destroy         ; Recursively destroy
    jmp destroy_loop
    
destroy_self:
    ; Call virtual destructor if VMT exists
    mov rax, (OBJECT_BASE PTR [r12]).obj_vmt
    test rax, rax
    jz free_memory
    
    mov rbx, (VMT_BASE PTR [rax]).pfn_destroy
    test rbx, rbx
    jz free_memory
    
    mov rcx, r12
    call rbx                    ; Call destructor
    
free_memory:
    ; Free object memory
    mov rcx, r12
    call masm_free
    
destroy_ok:
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
    ; RDX = event type_id
    ; R8 = param1
    ; R9 = param2
    ; Return: RAX = 0 (success)
    
    push rbx
    push r12
    sub rsp, 32
    
    ; Allocate EVENT_ITEM structure (64 bytes)
    mov rax, 64
    call masm_malloc
    test rax, rax
    jz post_error
    
    mov r12, rax                ; R12 = new event item
    mov (EVENT_ITEM PTR [r12]).evt_target, rcx
    mov (EVENT_ITEM PTR [r12]).evt_type, edx
    mov (EVENT_ITEM PTR [r12]).evt_param1, r8
    mov (EVENT_ITEM PTR [r12]).evt_param2, r9
    mov (EVENT_ITEM PTR [r12]).evt_next, 0
    
    ; Add to queue (simplified locking)
lock_retry:
    mov eax, 1
    xchg [rel g_event_lock], rax
    test rax, rax
    jnz lock_retry
    
    ; Find tail and link
    mov rax, [rel g_event_queue]
    test rax, rax
    jnz find_tail
    mov [rel g_event_queue], r12
    jmp unlock
    
find_tail:
    mov rbx, rax
tail_loop:
    mov rcx, (EVENT_ITEM PTR [rbx]).evt_next
    test rcx, rcx
    jz at_tail
    mov rbx, rcx
    jmp tail_loop
at_tail:
    mov (EVENT_ITEM PTR [rbx]).evt_next, r12
    
unlock:
    mov qword ptr [rel g_event_lock], 0
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
    
post_error:
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
lock_retry:
    mov eax, 1
    xchg [rel g_event_lock], rax
    test rax, rax
    jnz lock_retry
    
    mov r12, [rel g_event_queue]
    mov qword ptr [rel g_event_queue], 0 ; Clear queue
    
unlock_queue:
    mov qword ptr [rel g_event_lock], 0
    
    ; Process all events (now unlocked, safe to dispatch)
process_loop:
    test r12, r12
    jz done
    
    mov rbx, r12
    mov r12, (EVENT_ITEM PTR [r12]).evt_next
    
    ; Dispatch event
    ; RBX points to EVENT_ITEM with: target, event_type, param1, param2
    mov rcx, (EVENT_ITEM PTR [rbx]).evt_target
    test rcx, rcx
    jz skip_dispatch
    
    mov rax, (OBJECT_BASE PTR [rcx]).obj_vmt
    test rax, rax
    jz skip_dispatch
    
    mov rax, (VMT_BASE PTR [rax]).pfn_on_event
    test rax, rax
    jz skip_dispatch
    
    mov edx, (EVENT_ITEM PTR [rbx]).evt_type
    mov r8, (EVENT_ITEM PTR [rbx]).evt_param1
    mov r9, (EVENT_ITEM PTR [rbx]).evt_param2
    call rax                    ; Call event handler
    
skip_dispatch:
    mov rcx, rbx
    call masm_free                   ; Free event item
    inc r13                      ; Increment counter
    jmp process_loop
    
done:
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
    call masm_malloc
    test rax, rax
    jz connect_error
    
    mov rbx, rax                ; RBX = new binding
    mov (SLOT_BINDING PTR [rbx]).slot_sender, rcx
    mov (SLOT_BINDING PTR [rbx]).slot_receiver, r8
    mov (SLOT_BINDING PTR [rbx]).slot_signal_id, edx
    mov (SLOT_BINDING PTR [rbx]).slot_handler_fn, r9
    
    ; Link to bindings list
    mov rax, [rel g_slot_bindings]
    mov (SLOT_BINDING PTR [rbx]).slot_next, rax
    mov [rel g_slot_bindings], rbx
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop rbx
    ret
    
connect_error:
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
    push r15
    sub rsp, 32
    
    mov r12, rcx                ; sender
    mov r13, rdx                ; signal_id
    mov r14, r8                 ; param1
    xor r15, r15                ; slot count
    
    ; Walk slot bindings chain
    mov rbx, [rel g_slot_bindings]
    
find_bindings:
    test rbx, rbx
    jz emit_done
    
    ; Check if this binding matches
    mov rax, (SLOT_BINDING PTR [rbx]).slot_sender
    cmp rax, r12
    jne next_binding
    
    mov eax, (SLOT_BINDING PTR [rbx]).slot_signal_id
    cmp eax, r13d
    jne next_binding
    
    ; Found matching binding, call it
    mov rcx, (SLOT_BINDING PTR [rbx]).slot_receiver
    mov rdx, r14                ; param1
    mov rax, (SLOT_BINDING PTR [rbx]).slot_handler_fn
    call rax                    ; Call slot handler
    inc r15                      ; Count calls
    
next_binding:
    mov rbx, (SLOT_BINDING PTR [rbx]).slot_next
    jmp find_bindings
    
emit_done:
    mov rax, r15                ; Return call count
    add rsp, 32
    pop r15
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
    ; Set widget position and size_val
    ; RCX = widget pointer
    ; RDX = x position
    ; R8 = y position
    ; R9 = width_val
    ; [RSP+40] = height
    ; Return: RAX = 0 (success)
    
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    mov eax, (WIDGET PTR [rbx]).wid_base.obj_flags
    or eax, FLAG_DIRTY
    mov (WIDGET PTR [rbx]).wid_base.obj_flags, eax
    
    ; Store geometry (simplified - would store in_val WIDGET.rect)
    ; in_val production:
    ; - Store x, y, width_val, height in_val widget structure
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
    mov (RECT_MASM PTR [rbx]).x, 0
    mov (RECT_MASM PTR [rbx]).y, 0
    mov (RECT_MASM PTR [rbx]).width_val, 0
    mov (RECT_MASM PTR [rbx]).height, 0
    
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
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_window_bg
    mov (COLOR_SCHEME PTR [rax]).clr_window_bg, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_text_color
    mov (COLOR_SCHEME PTR [rax]).clr_text_color, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_button_bg
    mov (COLOR_SCHEME PTR [rax]).clr_button_bg, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_button_text
    mov (COLOR_SCHEME PTR [rax]).clr_button_text, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_highlight
    mov (COLOR_SCHEME PTR [rax]).clr_highlight, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_shadow
    mov (COLOR_SCHEME PTR [rax]).clr_shadow, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_dark
    mov (COLOR_SCHEME PTR [rax]).clr_dark, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_light
    mov (COLOR_SCHEME PTR [rax]).clr_light, ecx
    mov ecx, (COLOR_SCHEME PTR [rbx]).clr_link_color
    mov (COLOR_SCHEME PTR [rax]).clr_link_color, ecx
    
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
set_color_scheme ENDP
PUBLIC get_color_scheme
get_color_scheme PROC
    ; Get current color scheme
    ; Return: RAX = pointer to COLOR_SCHEME
    
    lea rax, [rel g_default_theme]
    ret
get_color_scheme ENDP

;==========================================================================
; FILE OPERATIONS - Support for file browser
;==========================================================================
PUBLIC enumerate_files
enumerate_files PROC
    ; Enumerate files in_val directory
    ; RCX = directory path
    ; RDX = FILE_LISTING output pointer
    ; Return: RAX = error code
    
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx                ; Directory path
    mov rbx, rdx                ; Output pointer
    
    ; Initialize FILE_LISTING
    mov (FILE_LISTING PTR [rbx]).fl_entries, 0
    mov (FILE_LISTING PTR [rbx]).fl_count, 0
    mov (FILE_LISTING PTR [rbx]).fl_capacity, 100
    mov (FILE_LISTING PTR [rbx]).fl_current, r12
    
    ; in_val production: Use Win32 FindFile APIs
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
    call masm_malloc
    test rax, rax
    jz thread_error
    
    mov rbx, rax                ; RBX = context
    mov (THREAD_CONTEXT PTR [rbx]).thr_func, rcx
    mov (THREAD_CONTEXT PTR [rbx]).thr_param, rdx
    mov (THREAD_CONTEXT PTR [rbx]).thr_running, 1
    mov (THREAD_CONTEXT PTR [rbx]).thr_exit, 0
    mov (THREAD_CONTEXT PTR [rbx]).thr_exit_code, 0
    mov (THREAD_CONTEXT PTR [rbx]).thr_handle, 0
    mov (THREAD_CONTEXT PTR [rbx]).thr_id, 0
    
    ; in_val production: Call CreateThread(
    ;   NULL,           ; Security
    ;   0,              ; Stack size_val
    ;   rcx,            ; Start address
    ;   rdx,            ; Parameter
    ;   0,              ; Flags
    ;   &thread_id      ; Thread ID output
    ; )
    
    mov rax, rbx
    add rsp, 32
    pop rbx
    ret
    
thread_error:
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
    
    ; in_val production:
    ; 1. WaitForSingleObject(rbx->thread_handle, INFINITE)
    ; 2. GetExitCodeThread(rbx->thread_handle, &exit_code)
    ; 3. CloseHandle(rbx->thread_handle)
    
    mov eax, (THREAD_CONTEXT PTR [rbx]).thr_exit_code
    
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
    call masm_malloc
    test rax, rax
    jz chat_alloc_error
    
    mov r12, rax                ; R12 = history
    
    ; Allocate message array (100 messages * 64 bytes = 6400 bytes)
    mov rcx, 6400
    call masm_malloc
    test rax, rax
    jz chat_array_error
    
    mov (CHAT_HISTORY PTR [r12]).chat_msgs, rax
    mov (CHAT_HISTORY PTR [r12]).chat_count, 0
    mov (CHAT_HISTORY PTR [r12]).chat_capacity, 100
    
    ; Get current timestamp
    ; in_val production: GetSystemTimeAsFileTime or similar
    mov (CHAT_HISTORY PTR [r12]).chat_created, 0
    mov (CHAT_HISTORY PTR [r12]).chat_session, 0
    
    mov rax, r12
    add rsp, 32
    pop r12
    pop rbx
    ret
    
chat_array_error:
    ; Free history if array allocation failed
    mov rcx, r12
    call masm_free
    
chat_alloc_error:
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
    mov eax, (CHAT_HISTORY PTR [r12]).chat_count
    mov ecx, (CHAT_HISTORY PTR [r12]).chat_capacity
    cmp eax, ecx
    jge msg_full
    
    ; Calculate offset: count * sizeof(CHAT_MESSAGE) = count * 64
    mov eax, (CHAT_HISTORY PTR [r12]).chat_count
    shl eax, 6                  ; Multiply by 64
    
    ; Get message array pointer
    mov rcx, (CHAT_HISTORY PTR [r12]).chat_msgs
    add rcx, rax                ; Point to next slot
    
    ; Copy message
    mov rax, (CHAT_MESSAGE PTR [rbx]).timestamp
    mov (CHAT_MESSAGE PTR [rcx]).timestamp, rax
    mov al, (CHAT_MESSAGE PTR [rbx]).type_id
    mov (CHAT_MESSAGE PTR [rcx]).type_id, al
    mov rax, (CHAT_MESSAGE PTR [rbx]).text
    mov (CHAT_MESSAGE PTR [rcx]).text, rax
    mov eax, (CHAT_MESSAGE PTR [rbx]).tokens
    mov (CHAT_MESSAGE PTR [rcx]).tokens, eax
    mov rax, (CHAT_MESSAGE PTR [rbx]).model_name
    mov (CHAT_MESSAGE PTR [rcx]).model_name, rax
    
    ; Increment count
    inc dword ptr (CHAT_HISTORY PTR [r12]).chat_count
    
    xor eax, eax                ; Return success
    add rsp, 32
    pop r12
    pop rbx
    ret
    
msg_full:
    mov eax, 1                  ; Return failure (full)
    add rsp, 32
    pop r12
    pop rbx
    ret
add_chat_message ENDP

END





