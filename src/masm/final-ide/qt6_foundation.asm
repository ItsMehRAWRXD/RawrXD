; ==========================================================================
; MASM Qt6 Component Conversion: Foundation Layer (CLEAN)
; ==========================================================================
; This file provides foundational Win32 abstractions for Qt6 component
; conversion to pure MASM. Rewritten to avoid MASM syntax errors.
;
; ==========================================================================

option casemap:none

; External memory functions (provided by malloc_wrapper.asm)
EXTERN malloc:PROC
EXTERN free:PROC
EXTERN realloc:PROC

; Include Qt compatibility layer definitions
include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

;==========================================================================
; SIMPLE STRUCT DEFINITIONS (All fields have unique names)
;==========================================================================

; Base object instance
OBJECT_BASE STRUCT
    obj_vmt          QWORD ?    ; Pointer to VMT
    obj_hwnd         QWORD ?    ; Associated HWND
    obj_parent       QWORD ?    ; Parent object
    obj_children     QWORD ?    ; Child list pointer
    obj_child_count  DWORD ?    ; Number of children
    obj_flags        DWORD ?    ; Object flags
    obj_user_data    QWORD ?    ; Custom data pointer
OBJECT_BASE ENDS

; Memory pool
MEMORY_POOL STRUCT
    pool_chunk_size  DWORD ?    ; size_val of each pool chunk
    pool_ptr         QWORD ?    ; Pointer to allocated pool
    pool_free_list   QWORD ?    ; Linked list of free blocks
    pool_used_count  DWORD ?    ; Number of allocated objects
    pool_total_count DWORD ?    ; Total capacity
MEMORY_POOL ENDS

; Event queue item
EVENT_ITEM STRUCT
    evt_type         DWORD ?
    evt_target       QWORD ?
    evt_param1       QWORD ?
    evt_param2       QWORD ?
    evt_param3       QWORD ?
    evt_next         QWORD ?
EVENT_ITEM ENDS

; Slot binding
SLOT_BINDING STRUCT
    slot_sender      QWORD ?    ; Object that emitted signal
    slot_receiver    QWORD ?    ; Object that received signal
    slot_signal_id   DWORD ?    ; Signal identifier
    slot_handler_fn  QWORD ?    ; Function pointer to handler
    slot_next        QWORD ?    ; Next binding in chain
SLOT_BINDING ENDS

; Color scheme
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
; FLAGS AND CONSTANTS
;==========================================================================
FLAG_VISIBLE         EQU 00000001h
FLAG_ENABLED         EQU 00000002h
FLAG_FOCUSED         EQU 00000004h
FLAG_DIRTY           EQU 00000008h
FLAG_MOUSE_TRACKING  EQU 00000010h
FLAG_ACCEPT_DROPS    EQU 00000020h
FLAG_NATIVE          EQU 00000040h

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
; GLOBAL DATA
;==========================================================================

.data
    ; Object registry
    g_registry_root  QWORD 0    ; Root of object tree
    g_registry_count DWORD 0
    
    ; Memory pools
    g_widget_pool    MEMORY_POOL <>
    g_dialog_pool    MEMORY_POOL <>
    
    ; Event queue
    g_event_queue    QWORD 0    ; Head of event queue
    g_event_lock     QWORD 0    ; Lock for thread safety
    
    ; Slot bindings
    g_slot_bindings  QWORD 0    ; Head of bindings chain
    
    ; Default theme
    g_default_theme  COLOR_SCHEME <>
    
    ; Main window handle
    g_main_hwnd      QWORD 0

.code

;==========================================================================
; INITIALIZATION & CLEANUP
;==========================================================================

PUBLIC qt_foundation_init
qt_foundation_init PROC
    push rbx
    push r12
    sub rsp, 32
    
    ; Initialize widget memory pool
    lea rax, [g_widget_pool]
    mov dword ptr [rax + MEMORY_POOL.pool_chunk_size], 512
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0
    mov qword ptr [rax + MEMORY_POOL.pool_free_list], 0
    mov dword ptr [rax + MEMORY_POOL.pool_used_count], 0
    mov dword ptr [rax + MEMORY_POOL.pool_total_count], 100
    
    ; Initialize dialog memory pool
    lea rax, [g_dialog_pool]
    mov dword ptr [rax + MEMORY_POOL.pool_chunk_size], 256
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0
    mov qword ptr [rax + MEMORY_POOL.pool_free_list], 0
    mov dword ptr [rax + MEMORY_POOL.pool_used_count], 0
    mov dword ptr [rax + MEMORY_POOL.pool_total_count], 50
    
    ; Initialize event queue
    mov qword ptr [g_event_queue], 0
    mov qword ptr [g_event_lock], 0
    
    ; Initialize slot bindings
    mov qword ptr [g_slot_bindings], 0
    
    ; Initialize default color scheme
    lea rax, [g_default_theme]
    mov dword ptr [rax + COLOR_SCHEME.clr_window_bg], 0F0F0F0h
    mov dword ptr [rax + COLOR_SCHEME.clr_text_color], 000000h
    mov dword ptr [rax + COLOR_SCHEME.clr_button_bg], 0E0E0E0h
    mov dword ptr [rax + COLOR_SCHEME.clr_button_text], 000000h
    mov dword ptr [rax + COLOR_SCHEME.clr_highlight], 0078D4h
    mov dword ptr [rax + COLOR_SCHEME.clr_shadow], 808080h
    mov dword ptr [rax + COLOR_SCHEME.clr_dark], 696969h
    mov dword ptr [rax + COLOR_SCHEME.clr_light], 0FFFFFFh
    mov dword ptr [rax + COLOR_SCHEME.clr_link_color], 0563C1h
    
    ; Clear registry
    mov qword ptr [g_registry_root], 0
    mov dword ptr [g_registry_count], 0
    
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
qt_foundation_init ENDP

PUBLIC qt_foundation_cleanup
qt_foundation_cleanup PROC
    push rbx
    push r12
    sub rsp, 32
    
    mov rax, [g_registry_root]
    test rax, rax
    jz cleanup_pools
    
    mov rcx, rax
    call object_destroy
    
cleanup_pools:
    lea rax, [g_widget_pool]
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0
    
    lea rax, [g_dialog_pool]
    mov qword ptr [rax + MEMORY_POOL.pool_ptr], 0
    
    mov qword ptr [g_event_queue], 0
    mov qword ptr [g_slot_bindings], 0
    mov dword ptr [g_registry_count], 0
    
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
qt_foundation_cleanup ENDP

;==========================================================================
; OBJECT OPERATIONS
;==========================================================================

PUBLIC object_create
object_create PROC
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx
    mov rbx, rdx
    
    mov rax, 256
    call malloc
    test rax, rax
    jz create_error
    
    mov rcx, rax
    mov qword ptr [rcx + OBJECT_BASE.obj_vmt], 0
    mov qword ptr [rcx + OBJECT_BASE.obj_hwnd], 0
    mov qword ptr [rcx + OBJECT_BASE.obj_parent], rbx
    mov qword ptr [rcx + OBJECT_BASE.obj_children], 0
    mov dword ptr [rcx + OBJECT_BASE.obj_child_count], 0
    mov dword ptr [rcx + OBJECT_BASE.obj_flags], FLAG_VISIBLE or FLAG_ENABLED
    
    mov rbx, [g_registry_root]
    mov [g_registry_root], rax
    inc dword ptr [g_registry_count]
    
    add rsp, 32
    pop r12
    pop rbx
    ret

create_error:
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
object_create ENDP

PUBLIC object_destroy
object_destroy PROC
    push rbx
    push r12
    sub rsp, 32
    
    mov r12, rcx
    test r12, r12
    jz destroy_ok
    
    mov rbx, [r12 + OBJECT_BASE.obj_children]
destroy_loop:
    test rbx, rbx
    jz destroy_self
    
    mov rcx, rbx
    mov rbx, [rbx + 0]
    call object_destroy
    jmp destroy_loop
    
destroy_self:
    mov rax, [r12 + OBJECT_BASE.obj_vmt]
    test rax, rax
    jz destroy_free
    
destroy_free:
    mov rcx, r12
    call free
    
destroy_ok:
    xor eax, eax
    add rsp, 32
    pop r12
    pop rbx
    ret
object_destroy ENDP

;==========================================================================
; EVENT OPERATIONS
;==========================================================================

PUBLIC post_event
post_event PROC
    push rbx
    push r12
    sub rsp, 32
    
    mov rax, 64
    call malloc
    test rax, rax
    jz post_error
    
    mov r12, rax
    mov qword ptr [r12 + EVENT_ITEM.evt_target], rcx
    mov dword ptr [r12 + EVENT_ITEM.evt_type], edx
    mov qword ptr [r12 + EVENT_ITEM.evt_param1], r8
    mov qword ptr [r12 + EVENT_ITEM.evt_param2], r9
    mov qword ptr [r12 + EVENT_ITEM.evt_next], 0
    
    mov rax, [g_event_queue]
    test rax, rax
    jnz find_tail
    mov [g_event_queue], r12
    jmp post_ok
    
find_tail:
    mov rbx, rax
tail_loop:
    mov rcx, [rbx + EVENT_ITEM.evt_next]
    test rcx, rcx
    jz at_tail
    mov rbx, rcx
    jmp tail_loop
at_tail:
    mov [rbx + EVENT_ITEM.evt_next], r12
    
post_ok:
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
    push rbx
    push r12
    push r13
    sub rsp, 32
    
    xor r13, r13
    mov r12, [g_event_queue]
    mov qword ptr [g_event_queue], 0
    
process_loop:
    test r12, r12
    jz done
    
    mov rbx, r12
    mov r12, [r12 + EVENT_ITEM.evt_next]
    
    mov rcx, [rbx + EVENT_ITEM.evt_target]
    test rcx, rcx
    jz skip_dispatch
    
    mov rax, [rcx + OBJECT_BASE.obj_vmt]
    test rax, rax
    jz skip_dispatch
    
skip_dispatch:
    mov rcx, rbx
    call free
    inc r13
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
; SIGNAL/SLOT OPERATIONS
;==========================================================================

PUBLIC connect_signal
connect_signal PROC
    push rbx
    sub rsp, 32
    
    mov rax, 64
    call malloc
    test rax, rax
    jz connect_error
    
    mov rbx, rax
    mov qword ptr [rbx + SLOT_BINDING.slot_sender], rcx
    mov qword ptr [rbx + SLOT_BINDING.slot_receiver], r8
    mov dword ptr [rbx + SLOT_BINDING.slot_signal_id], edx
    mov qword ptr [rbx + SLOT_BINDING.slot_handler_fn], r9
    
    mov rax, [g_slot_bindings]
    mov qword ptr [rbx + SLOT_BINDING.slot_next], rax
    mov [g_slot_bindings], rbx
    
    xor eax, eax
    add rsp, 32
    pop rbx
    ret

connect_error:
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
connect_signal ENDP

PUBLIC emit_signal
emit_signal PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    
    mov r12, rcx
    mov r13d, edx
    mov r14, r8
    xor r15, r15
    
    mov rbx, [g_slot_bindings]
    
find_bindings:
    test rbx, rbx
    jz emit_done
    
    mov rax, [rbx + SLOT_BINDING.slot_sender]
    cmp rax, r12
    jne next_binding
    
    mov eax, [rbx + SLOT_BINDING.slot_signal_id]
    cmp eax, r13d
    jne next_binding
    
    mov rcx, [rbx + SLOT_BINDING.slot_receiver]
    mov rdx, r14
    mov rax, [rbx + SLOT_BINDING.slot_handler_fn]
    call rax
    inc r15
    
next_binding:
    mov rbx, [rbx + SLOT_BINDING.slot_next]
    jmp find_bindings
    
emit_done:
    mov rax, r15
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
emit_signal ENDP

;==========================================================================
; THEME OPERATIONS
;==========================================================================

PUBLIC get_color_scheme
get_color_scheme PROC
    lea rax, [g_default_theme]
    ret
get_color_scheme ENDP

PUBLIC set_color_scheme
set_color_scheme PROC
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    lea rax, [g_default_theme]
    
    mov ecx, [rbx + COLOR_SCHEME.clr_window_bg]
    mov [rax + COLOR_SCHEME.clr_window_bg], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_text_color]
    mov [rax + COLOR_SCHEME.clr_text_color], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_button_bg]
    mov [rax + COLOR_SCHEME.clr_button_bg], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_button_text]
    mov [rax + COLOR_SCHEME.clr_button_text], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_highlight]
    mov [rax + COLOR_SCHEME.clr_highlight], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_shadow]
    mov [rax + COLOR_SCHEME.clr_shadow], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_dark]
    mov [rax + COLOR_SCHEME.clr_dark], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_light]
    mov [rax + COLOR_SCHEME.clr_light], ecx
    mov ecx, [rbx + COLOR_SCHEME.clr_link_color]
    mov [rax + COLOR_SCHEME.clr_link_color], ecx
    
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
set_color_scheme ENDP

END
