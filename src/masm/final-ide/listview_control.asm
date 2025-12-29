; ============================================================================
; List View Control System for RawrXD Pure MASM IDE
; ============================================================================
; Phase 3 Critical Blocker #3 - Blocks file browser, model lists
; ============================================================================
; Provides WC_LISTVIEW wrapper for list displays
; ============================================================================

include windows.inc
include kernel32.inc
include user32.inc
include comctl32.inc

.DATA

; ============================================================================
; List View Structures
; ============================================================================

LISTVIEW_ITEM STRUCT
    text            QWORD ?     ; Item text
    icon_index      DWORD ?     ; Icon index
    user_data       QWORD ?     ; Custom user data
    is_selected     BYTE ?      ; Selection state
    padding         BYTE 7 DUP(?)
LISTVIEW_ITEM ENDS

LISTVIEW_COLUMN STRUCT
    title           QWORD ?     ; Column header text
    width           DWORD ?     ; Column width in pixels
    format          DWORD ?     ; LVCFMT_LEFT, LVCFMT_RIGHT, etc.
    subitem_index   DWORD ?     ; Subitem index
    user_data       QWORD ?     ; Custom user data
LISTVIEW_COLUMN ENDS

LISTVIEW_CONTROL STRUCT
    hwnd            QWORD ?     ; List view window handle
    parent_hwnd     QWORD ?     ; Parent window handle
    items           QWORD ?     ; Array of LISTVIEW_ITEM pointers
    item_count      DWORD ?     ; Number of items
    columns         QWORD ?     ; Array of LISTVIEW_COLUMN pointers
    column_count    DWORD ?     ; Number of columns
    on_selection_changed QWORD ? ; Selection change callback
    user_data       QWORD ?     ; Custom user data
LISTVIEW_CONTROL ENDS

; ============================================================================
; List View Constants
; ============================================================================
MAX_LISTVIEW_ITEMS     EQU 1024
MAX_LISTVIEW_COLUMNS   EQU 16

.CODE

; ============================================================================
; CreateListView: Create list view control
; Parameters:
;   rcx = parent HWND
;   rdx = x position
;   r8d = y position
;   r9d = width
;   stack: [rsp+40] = height
;   stack: [rsp+48] = on_selection_changed callback (optional)
;   stack: [rsp+56] = user_data (optional)
; Returns:
;   rax = LISTVIEW_CONTROL pointer or NULL
; ============================================================================
CreateListView PROC FRAME
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    .PUSHREG rbx
    .PUSHREG rsi
    .PUSHREG rdi
    
    ; Allocate stack space
    sub rsp, 30h
    .ALLOCSTACK 30h
    
    .ENDPROLOG
    
    ; Save parameters
    mov [rsp+20h], rcx  ; parent_hwnd
    mov [rsp+28h], rdx  ; x
    mov [rsp+2Ch], r8d  ; y
    mov [rsp+30h], r9d  ; width
    
    ; Allocate LISTVIEW_CONTROL structure
    mov rcx, sizeof(LISTVIEW_CONTROL)
    call malloc
    test rax, rax
    jz allocation_failed
    
    mov rbx, rax  ; rbx = listview_control pointer
    
    ; Initialize structure
    mov rcx, [rsp+20h]  ; parent_hwnd
    mov [rbx+LISTVIEW_CONTROL.parent_hwnd], rcx
    mov [rbx+LISTVIEW_CONTROL.item_count], 0
    mov [rbx+LISTVIEW_CONTROL.column_count], 0
    
    ; Set callbacks if provided
    mov rcx, [rsp+58h]  ; on_selection_changed
    test rcx, rcx
    jz no_selection_callback
    mov [rbx+LISTVIEW_CONTROL.on_selection_changed], rcx
    
no_selection_callback:
    mov rcx, [rsp+60h]  ; user_data
    test rcx, rcx
    jz no_user_data
    mov [rbx+LISTVIEW_CONTROL.user_data], rcx
    
no_user_data:
    ; Allocate items array
    mov rcx, MAX_LISTVIEW_ITEMS * 8  ; QWORD pointers
    call malloc
    test rax, rax
    jz items_allocation_failed
    
    mov [rbx+LISTVIEW_CONTROL.items], rax
    
    ; Initialize items array to NULL
    mov rdi, rax
    mov rcx, MAX_LISTVIEW_ITEMS
    xor rax, rax
    rep stosq
    
    ; Allocate columns array
    mov rcx, MAX_LISTVIEW_COLUMNS * 8  ; QWORD pointers
    call malloc
    test rax, rax
    jz columns_allocation_failed
    
    mov [rbx+LISTVIEW_CONTROL.columns], rax
    
    ; Initialize columns array to NULL
    mov rdi, rax
    mov rcx, MAX_LISTVIEW_COLUMNS
    xor rax, rax
    rep stosq
    
    ; Create list view window
    mov rcx, [rsp+20h]  ; parent_hwnd
    mov rdx, [rsp+28h]  ; x
    mov r8d, [rsp+2Ch]  ; y
    mov r9d, [rsp+30h]  ; width
    mov r10d, [rsp+48h] ; height
    call CreateListViewWindow
    test rax, rax
    jz window_creation_failed
    
    mov [rbx+LISTVIEW_CONTROL.hwnd], rax
    
    ; Return success
    mov rax, rbx
    jmp listview_created
    
allocation_failed:
    xor rax, rax
    jmp listview_created
    
items_allocation_failed:
    mov rcx, rbx
    call free
    xor rax, rax
    jmp listview_created
    
columns_allocation_failed:
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    call free
    mov rcx, rbx
    call free
    xor rax, rax
    jmp listview_created
    
window_creation_failed:
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    call free
    mov rcx, [rbx+LISTVIEW_CONTROL.columns]
    call free
    mov rcx, rbx
    call free
    xor rax, rax
    
listview_created:
    ; Cleanup stack and return
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    ret
CreateListView ENDP

; ============================================================================
; CreateListViewWindow: Create WC_LISTVIEW window
; Parameters:
;   rcx = parent HWND
;   rdx = x
;   r8d = y
;   r9d = width
;   r10d = height
; Returns:
;   rax = list view HWND or NULL
; ============================================================================
CreateListViewWindow PROC
    ; Create list view
    ; rcx = parent HWND, rdx = x, r8d = y, r9d = width, r10d = height
    push rbx
    push rsi
    push rdi
    sub rsp, 80 ; shadow space + stack args + alignment
    
    mov rbx, rcx ; parent
    mov rsi, rdx ; x
    mov rdi, r8  ; y
    ; r9 = width
    ; r10 = height
    
    mov qword ptr [rsp+58h], 0 ; lpParam
    mov qword ptr [rsp+50h], 0 ; hMenu
    mov [rsp+48h], rbx         ; parent_hwnd
    mov [rsp+40h], r10         ; height
    mov [rsp+38h], r9          ; width
    mov [rsp+30h], rdi         ; y
    mov [rsp+28h], rsi         ; x
    mov qword ptr [rsp+20h], WS_CHILD or WS_VISIBLE or LVS_REPORT or LVS_SINGLESEL
    
    xor rcx, rcx               ; dwExStyle
    lea rdx, [WC_LISTVIEW]     ; lpClassName
    xor r8, r8                 ; lpWindowName
    mov r9d, WS_CHILD or WS_VISIBLE or LVS_REPORT or LVS_SINGLESEL ; dwStyle
    call CreateWindowExA
    
    add rsp, 80
    pop rdi
    pop rsi
    pop rbx
    ret
CreateListViewWindow ENDP

; ============================================================================
; AddColumn: Add column to list view
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = column title
;   r8d = width
;   r9d = format (LVCFMT_LEFT, etc.)
;   stack: [rsp+40] = user_data (optional)
; Returns:
;   rax = column index or -1 if failed
; ============================================================================
AddColumn PROC FRAME
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    .PUSHREG rbx
    .PUSHREG rsi
    .PUSHREG rdi
    
    ; Allocate stack space
    sub rsp, 20h
    .ALLOCSTACK 20h
    
    .ENDPROLOG
    
    mov rbx, rcx  ; listview_control
    mov rsi, rdx  ; title
    
    ; Check if we have space for more columns
    mov eax, [rbx+LISTVIEW_CONTROL.column_count]
    cmp eax, MAX_LISTVIEW_COLUMNS
    jge too_many_columns
    
    ; Allocate LISTVIEW_COLUMN structure
    mov rcx, sizeof(LISTVIEW_COLUMN)
    call malloc
    test rax, rax
    jz column_allocation_failed
    
    mov rdi, rax  ; rdi = listview_column
    
    ; Initialize column
    mov [rdi+LISTVIEW_COLUMN.title], rsi
    mov [rdi+LISTVIEW_COLUMN.width], r8d
    mov [rdi+LISTVIEW_COLUMN.format], r9d
    mov eax, [rbx+LISTVIEW_CONTROL.column_count]
    mov [rdi+LISTVIEW_COLUMN.subitem_index], eax
    
    mov rcx, [rsp+48h]  ; user_data
    test rcx, rcx
    jz no_column_user_data
    mov [rdi+LISTVIEW_COLUMN.user_data], rcx
    
no_column_user_data:
    ; Add to columns array
    mov rcx, [rbx+LISTVIEW_CONTROL.columns]
    mov edx, [rbx+LISTVIEW_CONTROL.column_count]
    mov [rcx+rdx*8], rdi
    
    ; Increment column count
    inc [rbx+LISTVIEW_CONTROL.column_count]
    
    ; Add column to control
    mov rcx, rbx
    mov rdx, rdi
    call AddColumnToControl
    test rax, rax
    jz add_column_failed
    
    ; Return column index
    mov eax, [rbx+LISTVIEW_CONTROL.column_count]
    dec eax
    jmp add_column_success
    
too_many_columns:
    mov eax, -1
    jmp add_column_success
    
column_allocation_failed:
    mov eax, -1
    jmp add_column_success
    
add_column_failed:
    ; Remove from array and free
    mov rcx, [rbx+LISTVIEW_CONTROL.columns]
    mov edx, [rbx+LISTVIEW_CONTROL.column_count]
    dec edx
    mov qword ptr [rcx+rdx*8], 0
    dec [rbx+LISTVIEW_CONTROL.column_count]
    
    mov rcx, rdi
    call free
    mov eax, -1
    
add_column_success:
    ; Cleanup stack and return
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
AddColumn ENDP

; ============================================================================
; AddColumnToControl: Add column to WC_LISTVIEW
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = LISTVIEW_COLUMN pointer
; Returns:
;   rax = 1 if success, 0 if failed
; ============================================================================
AddColumnToControl PROC
    mov rbx, rcx  ; listview_control
    mov rsi, rdx  ; listview_column
    
    ; Prepare LVCOLUMN structure
    sub rsp, sizeof(LVCOLUMN) + 20h ; shadow space + struct
    
    ; Initialize LVCOLUMN
    mov dword ptr [rsp+20h].LVCOLUMN.dwMask, LVCF_TEXT or LVCF_WIDTH or LVCF_FMT or LVCF_SUBITEM
    mov eax, [rsi+LISTVIEW_COLUMN.format]
    mov [rsp+20h].LVCOLUMN.fmt, eax
    mov eax, [rsi+LISTVIEW_COLUMN.width]
    mov [rsp+20h].LVCOLUMN.cx_, eax
    mov rax, [rsi+LISTVIEW_COLUMN.title]
    mov [rsp+20h].LVCOLUMN.pszText, rax
    mov eax, [rsi+LISTVIEW_COLUMN.subitem_index]
    mov [rsp+20h].LVCOLUMN.iSubItem, eax
    
    ; Send LVM_INSERTCOLUMN message
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov edx, [rsi+LISTVIEW_COLUMN.subitem_index]
    lea r8, [rsp+20h]  ; LVCOLUMN pointer
    mov r9, LVM_INSERTCOLUMN
    call SendMessageA
    
    add rsp, sizeof(LVCOLUMN) + 20h
    
    cmp eax, -1
    je insert_failed
    
    mov rax, 1
    ret
    
insert_failed:
    xor rax, rax
    ret
AddColumnToControl ENDP

; ============================================================================
; AddItem: Add item to list view
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = item text
;   r8 = icon_index (optional)
;   r9 = user_data (optional)
; Returns:
;   rax = item index or -1 if failed
; ============================================================================
AddItem PROC
    mov rbx, rcx  ; listview_control
    mov rsi, rdx  ; text
    
    ; Check if we have space for more items
    mov eax, [rbx+LISTVIEW_CONTROL.item_count]
    cmp eax, MAX_LISTVIEW_ITEMS
    jge too_many_items
    
    ; Allocate LISTVIEW_ITEM structure
    mov rcx, sizeof(LISTVIEW_ITEM)
    call malloc
    test rax, rax
    jz item_allocation_failed
    
    mov rdi, rax  ; rdi = listview_item
    
    ; Initialize item
    mov [rdi+LISTVIEW_ITEM.text], rsi
    mov [rdi+LISTVIEW_ITEM.icon_index], r8d
    mov [rdi+LISTVIEW_ITEM.user_data], r9
    mov [rdi+LISTVIEW_ITEM.is_selected], 0
    
    ; Add to items array
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov edx, [rbx+LISTVIEW_CONTROL.item_count]
    mov [rcx+rdx*8], rdi
    
    ; Increment item count
    inc [rbx+LISTVIEW_CONTROL.item_count]
    
    ; Add item to control
    mov rcx, rbx
    mov rdx, rdi
    call AddItemToControl
    test rax, rax
    jz add_item_failed
    
    ; Return item index
    mov eax, [rbx+LISTVIEW_CONTROL.item_count]
    dec eax
    jmp add_item_success
    
too_many_items:
    mov eax, -1
    jmp add_item_success
    
item_allocation_failed:
    mov eax, -1
    jmp add_item_success
    
add_item_failed:
    ; Remove from array and free
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov edx, [rbx+LISTVIEW_CONTROL.item_count]
    dec edx
    mov qword ptr [rcx+rdx*8], 0
    dec [rbx+LISTVIEW_CONTROL.item_count]
    
    mov rcx, rdi
    call free
    mov eax, -1
    
add_item_success:
    ret
AddItem ENDP

; ============================================================================
; AddItemToControl: Add item to WC_LISTVIEW
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = LISTVIEW_ITEM pointer
; Returns:
;   rax = 1 if success, 0 if failed
; ============================================================================
AddItemToControl PROC
    mov rbx, rcx  ; listview_control
    mov rsi, rdx  ; listview_item
    
    ; Prepare LVITEM structure
    sub rsp, sizeof(LVITEM) + 20h ; shadow space + struct
    
    ; Initialize LVITEM
    mov dword ptr [rsp+20h].LVITEM.dwMask, LVIF_TEXT
    mov eax, [rbx+LISTVIEW_CONTROL.item_count]
    dec eax
    mov [rsp+20h].LVITEM.iItem, eax
    mov [rsp+20h].LVITEM.iSubItem, 0
    mov rax, [rsi+LISTVIEW_ITEM.text]
    mov [rsp+20h].LVITEM.pszText, rax
    mov [rsp+20h].LVITEM.cchTextMax, 260
    
    mov eax, [rsi+LISTVIEW_ITEM.icon_index]
    test eax, eax
    jz no_icon
    
    or dword ptr [rsp+20h].LVITEM.dwMask, LVIF_IMAGE
    mov [rsp+20h].LVITEM.iImage, eax
    
no_icon:
    ; Send LVM_INSERTITEM message
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_INSERTITEM
    xor r8, r8
    lea r9, [rsp+20h]  ; LVITEM pointer
    call SendMessageA
    
    add rsp, sizeof(LVITEM) + 20h
    
    cmp eax, -1
    je insert_failed
    
    mov rax, 1
    ret
    
insert_failed:
    xor rax, rax
    ret
AddItemToControl ENDP

; ============================================================================
; GetSelectedItem: Get selected item index
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
; Returns:
;   rax = item index or -1 if none
; ============================================================================
GetSelectedItem PROC
    mov rbx, rcx
    
    ; Get selection from control
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_GETNEXTITEM
    mov r8, -1  ; start from -1
    mov r9, LVNI_SELECTED
    call SendMessageA
    
    ret
GetSelectedItem ENDP

; ============================================================================
; SetSelectedItem: Set selected item
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = item index
; Returns:
;   rax = 1 if success, 0 if failed
; ============================================================================
SetSelectedItem PROC
    mov rbx, rcx
    mov esi, edx  ; item index
    
    ; Validate index
    cmp esi, [rbx+LISTVIEW_CONTROL.item_count]
    jge invalid_index
    test esi, esi
    jl invalid_index
    
    ; Prepare LVITEM for state change
    sub rsp, sizeof(LVITEM) + 20h
    
    ; Clear current selection
    mov dword ptr [rsp+20h].LVITEM.dwMask, LVIF_STATE
    mov dword ptr [rsp+20h].LVITEM.state, 0
    mov dword ptr [rsp+20h].LVITEM.stateMask, LVIS_SELECTED
    
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_SETITEMSTATE
    mov r8, -1  ; all items
    lea r9, [rsp+20h]
    call SendMessageA
    
    ; Set new selection
    mov dword ptr [rsp+20h].LVITEM.state, LVIS_SELECTED
    
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_SETITEMSTATE
    mov r8, rsi
    lea r9, [rsp+20h]
    call SendMessageA
    
    add rsp, sizeof(LVITEM) + 20h
    
    ; Update item selection state
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov rdi, [rcx+rsi*8]
    test rdi, rdi
    jz item_not_found
    
    mov [rdi+LISTVIEW_ITEM.is_selected], 1
    
    ; Call selection changed callback if provided
    mov rcx, [rbx+LISTVIEW_CONTROL.on_selection_changed]
    test rcx, rcx
    jz no_callback
    
    ; Call callback: rcx = listview_control, rdx = item_index
    mov rcx, rbx
    mov edx, esi
    call [rbx+LISTVIEW_CONTROL.on_selection_changed]
    
no_callback:
    mov rax, 1
    ret
    
invalid_index:
    xor rax, rax
    ret
    
item_not_found:
    mov rax, 1
    ret
SetSelectedItem ENDP

; ============================================================================
; RemoveItem: Remove item from list view
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = item index
; Returns:
;   rax = 1 if success, 0 if failed
; ============================================================================
RemoveItem PROC
    mov rbx, rcx
    mov esi, edx  ; item index
    
    ; Validate index
    cmp esi, [rbx+LISTVIEW_CONTROL.item_count]
    jge invalid_index
    test esi, esi
    jl invalid_index
    
    ; Remove item from control
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_DELETEITEM
    mov r8, esi
    call SendMessageA
    
    ; Get item pointer
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov rdi, [rcx+rsi*8]
    test rdi, rdi
    jz item_already_removed
    
    ; Free item structure
    mov rcx, rdi
    call free
    
    ; Shift items array
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov edx, esi
    inc edx
    
shift_items:
    cmp edx, [rbx+LISTVIEW_CONTROL.item_count]
    jge shift_done
    
    mov rax, [rcx+rdx*8]
    mov [rcx+rdx*8-8], rax
    inc edx
    jmp shift_items
    
shift_done:
    ; Clear last entry
    mov edx, [rbx+LISTVIEW_CONTROL.item_count]
    dec edx
    mov qword ptr [rcx+rdx*8], 0
    
    ; Decrement item count
    dec [rbx+LISTVIEW_CONTROL.item_count]
    
    mov rax, 1
    ret
    
invalid_index:
    xor rax, rax
    ret
    
item_already_removed:
    mov rax, 1
    ret
RemoveItem ENDP

; ============================================================================
; ClearItems: Remove all items from list view
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
; Returns:
;   rax = 1 if success
; ============================================================================
ClearItems PROC
    mov rbx, rcx
    
    ; Remove all items from control
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    mov rdx, LVM_DELETEALLITEMS
    mov r8, 0
    call SendMessageA
    
    ; Free all item structures
    mov eax, [rbx+LISTVIEW_CONTROL.item_count]
    test eax, eax
    jz no_items
    
    mov esi, eax
    dec esi
    
free_items_loop:
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    mov rdi, [rcx+rsi*8]
    test rdi, rdi
    jz skip_item
    
    push rcx
    push rsi
    mov rcx, rdi
    call free
    pop rsi
    pop rcx
    
    mov qword ptr [rcx+rsi*8], 0
    
skip_item:
    dec esi
    jns free_items_loop
    
no_items:
    mov [rbx+LISTVIEW_CONTROL.item_count], 0
    mov rax, 1
    ret
ClearItems ENDP

; ============================================================================
; OnListViewSelectionChanged: Handle LVN_ITEMCHANGED notification
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
;   rdx = notification HWND
;   r8 = notification code
; Returns:
;   rax = 1 if handled, 0 if not
; ============================================================================
OnListViewSelectionChanged PROC
    mov rbx, rcx  ; listview_control
    
    ; Get selected item
    mov rcx, rbx
    call GetSelectedItem
    
    cmp eax, -1
    je no_selection
    
    ; Update selection state
    mov rcx, rbx
    mov edx, eax
    call SetSelectedItem
    
no_selection:
    mov rax, 1
    ret
OnListViewSelectionChanged ENDP

; ============================================================================
; DestroyListView: Cleanup list view
; Parameters:
;   rcx = LISTVIEW_CONTROL pointer
; Returns:
;   rax = 1 if success
; ============================================================================
DestroyListView PROC
    mov rbx, rcx
    
    ; Clear all items
    mov rcx, rbx
    call ClearItems
    
    ; Destroy list view window
    mov rcx, [rbx+LISTVIEW_CONTROL.hwnd]
    test rcx, rcx
    jz no_window
    
    call DestroyWindow
    
no_window:
    ; Free items array
    mov rcx, [rbx+LISTVIEW_CONTROL.items]
    test rcx, rcx
    jz no_items_array
    
    call free
    
no_items_array:
    ; Free columns array
    mov rcx, [rbx+LISTVIEW_CONTROL.columns]
    test rcx, rcx
    jz no_columns_array
    
    call free
    
no_columns_array:
    ; Free list view structure
    mov rcx, rbx
    call free
    
    mov rax, 1
    ret
DestroyListView ENDP

END