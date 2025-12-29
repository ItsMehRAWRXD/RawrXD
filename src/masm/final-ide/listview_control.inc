; ============================================================================
; ListView Control Include File
; ============================================================================
; Constants and structures for listview_control.asm
; ============================================================================

; ListView Functions
EXTERN CreateListView:PROC
EXTERN AddItem:PROC
EXTERN SetSelectedItem:PROC
EXTERN GetSelectedItem:PROC
EXTERN RemoveItem:PROC
EXTERN ClearItems:PROC
EXTERN DestroyListView:PROC
EXTERN OnItemSelectionChanged:PROC

; ListView Structures
LISTVIEW_COLUMN STRUCT
    title           QWORD ?
    title_len       DWORD ?
    width           DWORD ?
    alignment       DWORD ?
    user_data       QWORD ?
LISTVIEW_COLUMN ENDS

LISTVIEW_ITEM STRUCT
    text            QWORD ?
    text_len        DWORD ?
    image_index     DWORD ?
    user_data       QWORD ?
    is_selected     BYTE ?
    padding         BYTE 7 DUP(?)
LISTVIEW_ITEM ENDS

LISTVIEW_CONTROL STRUCT
    hwnd            QWORD ?
    parent_hwnd     QWORD ?
    columns         QWORD ?
    column_count    DWORD ?
    items           QWORD ?
    item_count      DWORD ?
    selected_item   DWORD ?
    on_selection_changed QWORD ?
    user_data       QWORD ?
LISTVIEW_CONTROL ENDS

; ListView Constants
MAX_LISTVIEW_COLUMNS   EQU 8
MAX_LISTVIEW_ITEMS     EQU 1024