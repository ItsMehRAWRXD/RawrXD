;==============================================================================
; dynamic_pane_manager.asm - Real-time Drag & Drop Pane System
; Allows users to drag panes anywhere while IDE is running
;==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

; Win64 externs (explicit to avoid missing prototypes)
EXTERN SetCapture:PROC
EXTERN ReleaseCapture:PROC
EXTERN SetWindowPos:PROC
EXTERN DestroyWindow:PROC
EXTERN CreateWindowExA:PROC
EXTERN SetLayeredWindowAttributes:PROC
EXTERN CreateFileA:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetPaneRect:PROC

; External globals referenced
EXTERN g_hInstance:QWORD
EXTERN szGhostClass:BYTE

PUBLIC DragPane_Init, DragPane_StartDrag, DragPane_HandleDrop
PUBLIC DragPane_SaveLayout, DragPane_LoadLayout, DragPane_CreateDockZones

;==============================================================================
; DOCK ZONES
;==============================================================================
DOCK_NONE           equ 0
DOCK_LEFT           equ 1
DOCK_RIGHT          equ 2
DOCK_TOP            equ 3
DOCK_BOTTOM         equ 4
DOCK_CENTER         equ 5
DOCK_TAB            equ 6

;==============================================================================
; DRAG STATE
;==============================================================================
DRAG_STATE STRUCT
    Active          DWORD   ?       ; Is drag in progress
    SourcePane      QWORD   ?       ; Pane being dragged
    MouseX          DWORD   ?       ; Current mouse position
    MouseY          DWORD   ?
    StartX          DWORD   ?       ; Drag start position
    StartY          DWORD   ?
    GhostWindow     QWORD   ?       ; Transparent drag preview
    TargetZone      DWORD   ?       ; Current drop zone
    TargetPane      QWORD   ?       ; Target pane for docking
DRAG_STATE ENDS

;==============================================================================
; DOCK ZONE
;==============================================================================
DOCK_ZONE STRUCT
    ZoneType        DWORD   ?       ; DOCK_*
    X               DWORD   ?       ; Zone rectangle
    Y               DWORD   ?
    ZoneW           DWORD   ?
    ZoneH           DWORD   ?
    TargetPane      QWORD   ?       ; Pane this zone belongs to
    Highlighted     DWORD   ?       ; Visual feedback
DOCK_ZONE ENDS

;==============================================================================
; DATA
;==============================================================================
.data
    g_dragState         DRAG_STATE <>
    g_dockZones         DOCK_ZONE 32 dup(<>)
    g_zoneCount         DWORD   0
    g_layoutFile        db "ide_layout.cfg", 0
    
    ; Visual feedback colors
    HIGHLIGHT_COLOR     equ 0080FF80h    ; Semi-transparent blue
    GHOST_COLOR         equ 40404040h    ; Semi-transparent gray

    ; Win32 constants (explicit for MASM64)
    SWP_NOSIZE          equ 0001h
    SWP_NOMOVE          equ 0002h
    SWP_NOZORDER        equ 0004h
    SWP_NOREDRAW        equ 0008h
    SWP_NOACTIVATE      equ 0010h
    SWP_SHOWWINDOW      equ 0040h
    SWP_HIDEWINDOW      equ 0080h
    SWP_NOOWNERZORDER   equ 0200h

    WS_POPUP            equ 80000000h
    WS_VISIBLE          equ 10000000h

    WS_EX_LAYERED       equ 00080000h
    WS_EX_TOPMOST       equ 00000008h
    WS_EX_TOOLWINDOW    equ 00000080h

    LWA_ALPHA           equ 00000002h

    GENERIC_WRITE       equ 40000000h
    GENERIC_READ        equ 80000000h
    CREATE_ALWAYS       equ 2
    OPEN_EXISTING       equ 3
    INVALID_HANDLE_VALUE equ -1

.data?
    g_savedLayouts      BYTE 4096 dup(?)  ; Layout configuration buffer

;==============================================================================
; CODE
;==============================================================================
.code

;==============================================================================
; DragPane_Init - Initialize drag & drop system
;==============================================================================
ALIGN 16
DragPane_Init PROC
    ; Clear drag state
    lea     rdi, g_dragState
    xor     eax, eax
    mov     ecx, SIZEOF DRAG_STATE
    rep     stosb
    
    ; Load saved layout if exists
    call    DragPane_LoadLayout
    
    mov     eax, 1
    ret
DragPane_Init ENDP

;==============================================================================
; DragPane_StartDrag - Begin dragging a pane
; rcx = pane structure, edx = mouse X, r8d = mouse Y
;==============================================================================
ALIGN 16
DragPane_StartDrag PROC USES rbx
    ; Set drag state
    mov     g_dragState.Active, 1
    mov     g_dragState.SourcePane, rcx
    mov     g_dragState.MouseX, edx
    mov     g_dragState.MouseY, r8d
    mov     g_dragState.StartX, edx
    mov     g_dragState.StartY, r8d
    mov     g_dragState.TargetZone, DOCK_NONE
    mov     g_dragState.TargetPane, 0
    
    ; Create ghost window for visual feedback
    call    CreateGhostWindow
    mov     g_dragState.GhostWindow, rax
    
    ; Create dock zones for all visible panes
    call    DragPane_CreateDockZones
    
    ; Capture mouse
    mov     rcx, g_mainWindow
    sub     rsp, 32
    call    SetCapture
    add     rsp, 32
    
    mov     eax, 1
    ret
DragPane_StartDrag ENDP

;==============================================================================
; DragPane_HandleMouseMove - Update drag state during mouse movement
; edx = mouse X, r8d = mouse Y
;==============================================================================
ALIGN 16
DragPane_HandleMouseMove PROC USES rbx r12
    cmp     g_dragState.Active, 0
    je      move_done
    
    ; Update mouse position
    mov     g_dragState.MouseX, edx
    mov     g_dragState.MouseY, r8d
    
    ; Move ghost window
    mov     rcx, g_dragState.GhostWindow
    test    rcx, rcx
    jz      check_zones
    
    ; Position ghost at mouse cursor (Win64 calling convention)
    ; SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags)
    mov     rcx, g_dragState.GhostWindow    ; hWnd
    xor     rdx, rdx                        ; hWndInsertAfter = 0
    mov     r8d, g_dragState.MouseX         ; X
    mov     r9d, g_dragState.MouseY         ; Y
    sub     rsp, 32                         ; shadow space
    mov     dword ptr [rsp+20h], 200        ; cx
    mov     dword ptr [rsp+28h], 100        ; cy
    mov     dword ptr [rsp+30h], SWP_NOSIZE or SWP_NOZORDER or SWP_NOACTIVATE ; uFlags
    call    SetWindowPos
    add     rsp, 32
    
check_zones:
    ; Check which dock zone mouse is over
    call    FindDockZone
    mov     ebx, eax        ; ebx = zone index or -1
    
    ; Update visual feedback
    cmp     ebx, -1
    je      clear_highlight
    
    ; Highlight target zone
    mov     eax, ebx
    imul    rax, rax, SIZEOF DOCK_ZONE
    lea     rcx, [g_dockZones + rax]
    mov     (DOCK_ZONE PTR [rcx]).Highlighted, 1
    mov     eax, (DOCK_ZONE PTR [rcx]).ZoneType
    mov     g_dragState.TargetZone, eax
    mov     rax, (DOCK_ZONE PTR [rcx]).TargetPane
    mov     g_dragState.TargetPane, rax
    jmp     move_done
    
clear_highlight:
    ; Clear all highlights
    call    ClearAllHighlights
    mov     g_dragState.TargetZone, DOCK_NONE
    mov     g_dragState.TargetPane, 0
    
move_done:
    ret
DragPane_HandleMouseMove ENDP

;==============================================================================
; DragPane_HandleDrop - Complete the drag operation
;==============================================================================
ALIGN 16
DragPane_HandleDrop PROC USES rbx r12 r13
    cmp     g_dragState.Active, 0
    je      drop_done
    
    ; Get drop target
    mov     ebx, g_dragState.TargetZone
    mov     r12, g_dragState.TargetPane
    mov     r13, g_dragState.SourcePane
    
    ; Release mouse capture
    sub     rsp, 32
    call    ReleaseCapture
    add     rsp, 32
    
    ; Destroy ghost window
    mov     rcx, g_dragState.GhostWindow
    test    rcx, rcx
    jz      perform_dock
    sub     rsp, 32
    call    DestroyWindow
    add     rsp, 32
    
perform_dock:
    ; Perform docking based on target zone
    cmp     ebx, DOCK_NONE
    je      cancel_drop
    
    cmp     ebx, DOCK_LEFT
    je      dock_left
    cmp     ebx, DOCK_RIGHT
    je      dock_right
    cmp     ebx, DOCK_TOP
    je      dock_top
    cmp     ebx, DOCK_BOTTOM
    je      dock_bottom
    cmp     ebx, DOCK_CENTER
    je      dock_center
    cmp     ebx, DOCK_TAB
    je      dock_tab
    jmp     cancel_drop
    
dock_left:
    mov     rcx, r13        ; source pane
    mov     rdx, r12        ; target pane
    mov     r8d, DOCK_LEFT
    call    PerformDocking
    jmp     drop_complete
    
dock_right:
    mov     rcx, r13
    mov     rdx, r12
    mov     r8d, DOCK_RIGHT
    call    PerformDocking
    jmp     drop_complete
    
dock_top:
    mov     rcx, r13
    mov     rdx, r12
    mov     r8d, DOCK_TOP
    call    PerformDocking
    jmp     drop_complete
    
dock_bottom:
    mov     rcx, r13
    mov     rdx, r12
    mov     r8d, DOCK_BOTTOM
    call    PerformDocking
    jmp     drop_complete
    
dock_center:
    mov     rcx, r13
    mov     rdx, r12
    mov     r8d, DOCK_CENTER
    call    PerformDocking
    jmp     drop_complete
    
dock_tab:
    mov     rcx, r13
    mov     rdx, r12
    call    CreateTabGroup
    jmp     drop_complete
    
cancel_drop:
    ; Return pane to original position
    mov     rcx, r13
    call    RestoreOriginalPosition
    
drop_complete:
    ; Clear drag state
    lea     rdi, g_dragState
    xor     eax, eax
    mov     ecx, SIZEOF DRAG_STATE
    rep     stosb
    
    ; Clear highlights
    call    ClearAllHighlights
    
    ; Save new layout
    call    DragPane_SaveLayout
    
    ; Refresh layout
    call    PaneSystem_RefreshLayout
    
drop_done:
    mov     eax, 1
    ret
DragPane_HandleDrop ENDP

;==============================================================================
; DragPane_CreateDockZones - Create drop zones around all panes
;==============================================================================
ALIGN 16
DragPane_CreateDockZones PROC USES rbx r12 r13
    mov     g_zoneCount, 0
    
    ; Create zones for each visible pane
    mov     rbx, 0
    
create_zones_loop:
    cmp     rbx, MAX_PANES
    jge     zones_done
    
    ; Check if pane is visible
    mov     rax, rbx
    imul    rax, rax, SIZEOF PANE_INFO
    lea     rcx, [g_panes + rax]
    cmp     (PANE_INFO PTR [rcx]).Visible, 0
    je      next_pane
    
    ; Create dock zones around this pane
    call    CreatePaneZones
    
next_pane:
    inc     rbx
    jmp     create_zones_loop
    
zones_done:
    ret
DragPane_CreateDockZones ENDP

;==============================================================================
; Helper functions (minimal implementations)
;==============================================================================
; (Preserve early stub implementations under distinct names for reference)
CreatePaneZones_stub PROC
    ret
CreatePaneZones_stub ENDP

AddDockZone_stub PROC
    mov eax, 1
    ret
AddDockZone_stub ENDP

FindDockZone_stub PROC
    mov eax, -1
    ret
FindDockZone_stub ENDP

PerformDocking_stub PROC
    ret
PerformDocking_stub ENDP

CreateGhostWindow_stub PROC
    xor rax, rax
    ret
CreateGhostWindow_stub ENDP

ClearAllHighlights_stub PROC
    ret
ClearAllHighlights_stub ENDP

CreateTabGroup_stub PROC
    ret
CreateTabGroup_stub ENDP

RestoreOriginalPosition_stub PROC
    ret
RestoreOriginalPosition_stub ENDP

DragPane_SaveLayout_stub PROC
    mov eax, 1
    ret
DragPane_SaveLayout_stub ENDP

DragPane_LoadLayout_stub PROC
    mov eax, 1
    ret
DragPane_LoadLayout_stub ENDP

; External references
EXTERN g_mainWindow:QWORD
EXTERN g_panes:BYTE
EXTERN PaneSystem_RefreshLayout:PROC
EXTERN g_paneList:QWORD
EXTERN g_paneCount:DWORD
MAX_PANES EQU 32

; Pane structure
PANE_INFO STRUCT
    Visible     DWORD   ?
    X           DWORD   ?
    Y           DWORD   ?
    PaneW       DWORD   ?
    PaneH       DWORD   ?
PANE_INFO ENDS

; IDE pane structure (used by alternate routines)
IDE_PANE STRUCT
    Visible     DWORD   ?
    X           DWORD   ?
    Y           DWORD   ?
    W           DWORD   ?
    H           DWORD   ?
IDE_PANE ENDS

; Alternate zone creation routine (v2a)
DragPane_CreateDockZones_v2a PROC USES rbx r12
    
create_zones_loop_v2:
    cmp     rbx, MAX_PANES
    jge     zones_done_v2
    
    ; Check if pane is visible
    mov     rax, rbx
    imul    rax, rax, SIZEOF PANE_INFO
    lea     rcx, [g_panes + rax]
    cmp     (PANE_INFO PTR [rcx]).Visible, 0
    je      next_pane_v2
    
    ; Create 5 dock zones around this pane (left, right, top, bottom, center)
    call    CreatePaneZones
    
next_pane_v2:
    inc     rbx
    jmp     create_zones_loop_v2
    
zones_done_v2:
    mov     g_zoneCount, r12d
    ret
DragPane_CreateDockZones_v2a ENDP

;==============================================================================
; CreatePaneZones - Create dock zones for a single pane
; rcx = pane pointer
;==============================================================================
CreatePaneZones_basic PROC USES rbx r12
    mov     rbx, rcx        ; pane pointer
    mov     r12d, g_zoneCount
    
    ; Get pane rectangle
    mov     eax, (PANE_INFO PTR [rbx]).X
    mov     edx, (PANE_INFO PTR [rbx]).Y
    mov     r8d, (PANE_INFO PTR [rbx]).PaneW
    mov     r9d, (PANE_INFO PTR [rbx]).PaneH
    
    ; Create left zone
    call    AddDockZone
    
    ; Create right zone  
    add     eax, r8d
    sub     eax, 20
    call    AddDockZone
    
    ; Create top zone
    mov     eax, (PANE_INFO PTR [rbx]).X
    call    AddDockZone
    
    ; Create bottom zone
    add     edx, r9d
    sub     edx, 20
    call    AddDockZone
    
    ; Create center zone
    mov     eax, (PANE_INFO PTR [rbx]).X
    add     eax, 20
    mov     edx, (PANE_INFO PTR [rbx]).Y
    add     edx, 20
    call    AddDockZone
    
    ret
CreatePaneZones_basic ENDP

;==============================================================================
; AddDockZone - Add a dock zone to the list
;==============================================================================
AddDockZone_basic PROC
    mov     eax, 1
    ret
AddDockZone_basic ENDP

;==============================================================================
; FindDockZone - Find which zone mouse is over
;==============================================================================
FindDockZone_basic PROC
    mov     eax, -1
    ret
FindDockZone_basic ENDP

;==============================================================================
; PerformDocking - Execute the docking operation
;==============================================================================
PerformDocking_basic PROC
    ret
PerformDocking_basic ENDP

;==============================================================================
; CreateGhostWindow - Create transparent drag preview
;==============================================================================
CreateGhostWindow_basic PROC
    xor     rax, rax
    ret
CreateGhostWindow_basic ENDP

;==============================================================================
; ClearAllHighlights - Remove visual feedback
;==============================================================================
ClearAllHighlights_basic PROC
    ret
ClearAllHighlights_basic ENDP

;==============================================================================
; CreateTabGroup - Create tabbed pane group
;==============================================================================
CreateTabGroup_basic PROC
    ret
CreateTabGroup_basic ENDP

;==============================================================================
; RestoreOriginalPosition - Cancel drag operation
;==============================================================================
RestoreOriginalPosition_basic PROC
    ret
RestoreOriginalPosition_basic ENDP

;==============================================================================
; DragPane_SaveLayout - Save current layout to file
;==============================================================================
DragPane_SaveLayout_basic PROC
    mov     eax, 1
    ret
DragPane_SaveLayout_basic ENDP

;==============================================================================
; DragPane_LoadLayout - Load layout from file
;==============================================================================
DragPane_LoadLayout_basic PROC
    mov     eax, 1
    ret
DragPane_LoadLayout_basic ENDP

; External references
EXTERN g_mainWindow:QWORD
EXTERN g_panes:BYTE
EXTERN PaneSystem_RefreshLayout:PROC
MAX_PANES EQU 32

; Pane structure (minimal)
PANE_INFO STRUCT
    Visible     DWORD   ?
    X           DWORD   ?
    Y           DWORD   ?
    PaneW       DWORD   ?
    PaneH       DWORD   ?
PANE_INFO ENDS

; Define alternate zone creation routine (kept for reference)
DragPane_CreateDockZones_v2 PROC USES rcx r12
    mov     rcx, g_paneList
    test    rcx, rcx
    jz      zones_done
    
zone_loop:
    ; Get pane rectangle
    push rcx
    push call    GetPaneRect      ; Returns rect in rax
    pop mov
    pop rcx     r12, rax         ; r12 = pane rect
    
    ; Create 5 dock zones around this pane
    call    CreatePaneZones
    
    ; Next pane
    mov     rcx, [rcx + 8]   ; Next pane in list
    test    rcx, rcx
    jnz     zone_loop
    
zones_done:
    ret
DragPane_CreateDockZones_v2 ENDP

;==============================================================================
; CreatePaneZones - Create dock zones for a single pane
; rcx = pane, r12 = pane rect
;==============================================================================
ALIGN 16
CreatePaneZones PROC USES rbx r13 r14
    mov     r13, rcx         ; r13 = pane
    mov     r14d, g_zoneCount ; r14 = current zone index
    
    ; Left zone
    call    AddDockZone
    mov     eax, DOCK_LEFT
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, eax
    mov     eax, [r12]       ; x
    sub     eax, 20
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     eax, [r12 + 4]   ; y
    mov     (DOCK_ZONE PTR [rbx]).Y, eax
    mov     dword ptr (DOCK_ZONE PTR [rbx]).ZoneW, 20
    mov     eax, [r12 + 12]  ; height
    mov     dword ptr (DOCK_ZONE PTR [rbx]).ZoneH, eax
    mov     qword ptr [rbx+20h], r13
    
    ; Right zone
    call    AddDockZone
    mov     eax, DOCK_RIGHT
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, eax
    mov     eax, [r12]       ; x
    add     eax, [r12 + 8]   ; + width
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     eax, [r12 + 4]   ; y
    mov     (DOCK_ZONE PTR [rbx]).Y, eax
    mov     dword ptr (DOCK_ZONE PTR [rbx]).ZoneW, 20
    mov     eax, [r12 + 12]  ; height
    mov     dword ptr (DOCK_ZONE PTR [rbx]).ZoneH, eax
    mov     qword ptr [rbx+20h], r13
    
    ; Top zone
    call    AddDockZone
    mov     eax, DOCK_TOP
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, eax
    mov     eax, [r12]       ; x
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     eax, [r12 + 4]   ; y
    sub     eax, 20
    mov     (DOCK_ZONE PTR [rbx]).Y, eax
    mov     eax, [r12 + 8]   ; width
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, eax
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, 20
    mov     qword ptr (DOCK_ZONE PTR [rbx]).TargetPane, r13
    
    ; Bottom zone
    call    AddDockZone
    mov     eax, DOCK_BOTTOM
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, eax
    mov     eax, [r12]       ; x
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     eax, [r12 + 4]   ; y
    add     eax, [r12 + 12]  ; + height
    mov     (DOCK_ZONE PTR [rbx]).Y, eax
    mov     eax, [r12 + 8]   ; width
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, eax
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, 20
    mov     qword ptr (DOCK_ZONE PTR [rbx]).TargetPane, r13
    
    ; Center zone (for tabbing)
    call    AddDockZone
    mov     eax, DOCK_TAB
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, eax
    mov     eax, [r12]       ; x
    add     eax, 20
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     eax, [r12 + 4]   ; y
    add     eax, 20
    mov     (DOCK_ZONE PTR [rbx]).Y, eax
    mov     eax, [r12 + 8]   ; width
    sub     eax, 40
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, eax
    mov     eax, [r12 + 12]  ; height
    sub     eax, 40
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, eax
    mov     (DOCK_ZONE PTR [rbx]).TargetPane, r13
    
    ret
CreatePaneZones ENDP

;==============================================================================
; Helper Functions
;==============================================================================

; AddDockZone - Add new dock zone, returns pointer in rbx
ALIGN 16
AddDockZone PROC
    mov     eax, g_zoneCount
    cmp     eax, 32
    jae     add_failed
    
    imul    rax, rax, SIZEOF DOCK_ZONE
    lea     rbx, [g_dockZones + rax]
    inc     g_zoneCount
    
    ; Clear zone
    push rdi

    push rcx
    push mov     rdi, rbx
    xor     eax, eax
    mov     ecx, SIZEOF DOCK_ZONE
    rep     stosb

    pop rcx
    pop add
    pop rdi_failed:
    xor     rbx, rbx
    ret
AddDockZone ENDP

; FindDockZone - Find zone containing mouse position
; Returns zone index in eax or -1 if none
ALIGN 16
FindDockZone PROC USES rbx rcx rdx
    mov     edx, g_dragState.MouseX
    mov     r8d, g_dragState.MouseY
    xor     eax, eax         ; zone index
    
find_loop:
    cmp     eax, g_zoneCount
    jae     not_found
    
    ; Check if point is in zone
    imul    rbx, rax, SIZEOF DOCK_ZONE
    lea     rbx, [g_dockZones + rbx]
    
    ; Check X bounds
    mov     ecx, (DOCK_ZONE PTR [rbx]).X
    cmp     edx, ecx
    jl      next_zone
    add     ecx, (DOCK_ZONE PTR [rbx]).ZoneW
    cmp     edx, ecx
    jge     next_zone
    
    ; Check Y bounds
    mov     ecx, (DOCK_ZONE PTR [rbx]).Y
    cmp     r8d, ecx
    jl      next_zone
    add     ecx, (DOCK_ZONE PTR [rbx]).ZoneH
    cmp     r8d, ecx
    jge     next_zone
    
    ; Found zone
    ret
    
next_zone:
    inc     eax
    jmp     find_loop
    
not_found:
    mov     eax, -1
    ret
FindDockZone ENDP

; ClearAllHighlights - Remove visual feedback from all zones
ALIGN 16
ClearAllHighlights PROC USES rax rbx
    xor     eax, eax
    
clear_loop:
    cmp     eax, g_zoneCount
    jae     clear_done
    
    imul    rbx, rax, SIZEOF DOCK_ZONE
    lea     rbx, [g_dockZones + rbx]
    mov     (DOCK_ZONE PTR [rbx]).Highlighted, 0
    
    inc     eax
    jmp     clear_loop
    
clear_done:
    ret
ClearAllHighlights ENDP

; CreateGhostWindow - Create transparent drag preview
ALIGN 16
CreateGhostWindow_alt PROC
    ; Create layered window for transparency (Win64 calling convention)
    ; CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight,
    ;                 hWndParent, hMenu, hInstance, lpParam)
    mov     ecx, WS_EX_LAYERED or WS_EX_TOPMOST or WS_EX_TOOLWINDOW ; dwExStyle
    lea     rdx, szGhostClass       ; lpClassName
    lea     r8,  szGhostClass       ; lpWindowName
    mov     r9d, WS_POPUP or WS_VISIBLE ; dwStyle
    sub     rsp, 32
    mov     dword ptr [rsp+20h], 0      ; x
    mov     dword ptr [rsp+28h], 0      ; y
    mov     dword ptr [rsp+30h], 200    ; nWidth
    mov     dword ptr [rsp+38h], 100    ; nHeight
    mov     qword ptr  [rsp+40h], 0     ; hWndParent
    mov     qword ptr  [rsp+48h], 0     ; hMenu
    mov     rax, g_hInstance
    mov     qword ptr  [rsp+50h], rax ; hInstance
    mov     qword ptr  [rsp+58h], 0     ; lpParam
    call    CreateWindowExA
    add     rsp, 32

    ; Set transparency if created
    test    rax, rax
    jz      ghost_done

    mov     rcx, rax              ; hWnd
    xor     edx, edx              ; crKey (unused when using LWA_ALPHA)
    mov     r8d, 128              ; bAlpha
    mov     r9d, LWA_ALPHA        ; dwFlags
    sub     rsp, 32
    call    SetLayeredWindowAttributes
    add     rsp, 32

ghost_done:
    ret
CreateGhostWindow_alt ENDP

;==============================================================================
; Layout Management
;==============================================================================

; DragPane_SaveLayout - Save current pane layout to file
ALIGN 16
DragPane_SaveLayout_basic2 PROC
    ; Implementation would serialize pane positions to file
    mov     eax, 1
    ret
DragPane_SaveLayout_basic2 ENDP

; DragPane_LoadLayout - Load saved pane layout
ALIGN 16
DragPane_LoadLayout_basic2 PROC
    ; Implementation would restore pane positions from file
    mov     eax, 1
    ret
DragPane_LoadLayout_basic2 ENDP

;==============================================================================
; Docking Operations
;==============================================================================

; PerformDocking - Execute the docking operation
; rcx = source pane, rdx = target pane, r8d = dock type
ALIGN 16
PerformDocking PROC
    ; Implementation would rearrange pane hierarchy
    mov     eax, 1
    ret
PerformDocking ENDP

; CreateTabGroup - Create tabbed pane group
; rcx = source pane, rdx = target pane
ALIGN 16
CreateTabGroup PROC
    ; Implementation would create tab container
    mov     eax, 1
    ret
CreateTabGroup ENDP

; RestoreOriginalPosition - Cancel drag operation
; rcx = pane
ALIGN 16
RestoreOriginalPosition PROC
    ; Implementation would restore pane to start position
    mov     eax, 1
    ret
RestoreOriginalPosition ENDP

;==============================================================================
; External Dependencies (to be implemented elsewhere)
;==============================================================================

; External procedures that need to be implemented:
; - GetPaneRect: Get pane rectangle coordinates
; - PaneSystem_RefreshLayout: Refresh the entire layout
; - g_paneList: Global pane list head
; - g_mainWindow: Main window handle
; - g_hInstance: Application instance
; - szGhostClass: Ghost window class name

; Additional zone creation routine based on pane list
DragPane_CreateDockZones_v3 PROC USES rbx r12 r13
    xor     ebx, ebx        ; pane index
    
create_zones_loop_v3:
    cmp     ebx, g_paneCount
    jge     zones_done_v3
    
    ; Get pane structure
    mov     eax, ebx
    imul    rax, rax, SIZEOF IDE_PANE
    lea     r12, [g_panes + rax]
    
    ; Skip if not visible
    cmp     (IDE_PANE PTR [r12]).Visible, 0
    je      next_pane_zones_v3
    
    ; Create 5 zones around this pane (left, right, top, bottom, center)
    mov     rcx, r12
    mov     edx, DOCK_LEFT
    call    CreateZoneForPane
    
    mov     rcx, r12
    mov     edx, DOCK_RIGHT
    call    CreateZoneForPane
    
    mov     rcx, r12
    mov     edx, DOCK_TOP
    call    CreateZoneForPane
    
    mov     rcx, r12
    mov     edx, DOCK_BOTTOM
    call    CreateZoneForPane
    
    mov     rcx, r12
    mov     edx, DOCK_CENTER
    call    CreateZoneForPane
    
next_pane_zones_v3:
    inc     ebx
    jmp     create_zones_loop_v3
    
zones_done_v3:
    ret
DragPane_CreateDockZones_v3 ENDP

;==============================================================================
; CreateZoneForPane - Create a dock zone for a specific pane and position
; rcx = pane structure, edx = zone type
;==============================================================================
ALIGN 16
CreateZoneForPane PROC USES rbx
    mov     eax, g_zoneCount
    cmp     eax, 32
    jge     zone_create_done
    
    ; Get zone structure
    imul    rax, rax, SIZEOF DOCK_ZONE
    lea     rbx, [g_dockZones + rax]
    
    ; Set zone type and target pane
    mov     (DOCK_ZONE PTR [rbx]).ZoneType, edx
    mov     (DOCK_ZONE PTR [rbx]).TargetPane, rcx
    mov     (DOCK_ZONE PTR [rbx]).Highlighted, 0
    
    ; Calculate zone rectangle based on type
    mov     eax, (IDE_PANE PTR [rcx]).X
    mov     r8d, (IDE_PANE PTR [rcx]).Y
    mov     r9d, (IDE_PANE PTR [rcx]).W
    mov     r10d, (IDE_PANE PTR [rcx]).H
    
    cmp     edx, DOCK_LEFT
    je      zone_left
    cmp     edx, DOCK_RIGHT
    je      zone_right
    cmp     edx, DOCK_TOP
    je      zone_top
    cmp     edx, DOCK_BOTTOM
    je      zone_bottom
    cmp     edx, DOCK_CENTER
    je      zone_center
    jmp     zone_create_done
    
zone_left:
    ; Left edge zone (20px wide)
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     (DOCK_ZONE PTR [rbx]).Y, r8d
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, 20
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, r10d
    jmp     zone_complete
    
zone_right:
    ; Right edge zone
    add     eax, r9d
    sub     eax, 20
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     (DOCK_ZONE PTR [rbx]).Y, r8d
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, 20
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, r10d
    jmp     zone_complete
    
zone_top:
    ; Top edge zone
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     (DOCK_ZONE PTR [rbx]).Y, r8d
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, r9d
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, 20
    jmp     zone_complete
    
zone_bottom:
    ; Bottom edge zone
    add     r8d, r10d
    sub     r8d, 20
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     (DOCK_ZONE PTR [rbx]).Y, r8d
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, r9d
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, 20
    jmp     zone_complete
    
zone_center:
    ; Center zone (for tabbing)
    add     eax, 20
    add     r8d, 20
    sub     r9d, 40
    sub     r10d, 40
    mov     (DOCK_ZONE PTR [rbx]).X, eax
    mov     (DOCK_ZONE PTR [rbx]).Y, r8d
    mov     (DOCK_ZONE PTR [rbx]).ZoneW, r9d
    mov     (DOCK_ZONE PTR [rbx]).ZoneH, r10d
    
zone_complete:
    inc     g_zoneCount
    
zone_create_done:
    ret
CreateZoneForPane ENDP

;==============================================================================
; DragPane_SaveLayout - Save current layout to file
;==============================================================================
ALIGN 16
DragPane_SaveLayout PROC USES rbx r12
    ; Create/open layout file
    lea     rcx, g_layoutFile
    mov     edx, GENERIC_WRITE
    mov     r8d, CREATE_ALWAYS
    sub     rsp, 32
    call    CreateFileA
    add     rsp, 32
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      save_fail
    mov     r12, rax        ; file handle
    
    ; Write pane count
    mov     rcx, r12
    lea     rdx, g_paneCount
    mov     r8d, 4
    lea     r9, [rsp + 32]  ; bytes written
    push    0               ; overlapped
    sub     rsp, 32
    call    WriteFile
    add     rsp, 40
    
    ; Write each pane's layout data
    xor     ebx, ebx
    
save_pane_loop:
    cmp     ebx, g_paneCount
    jge     save_complete
    
    ; Write pane structure
    mov     eax, ebx
    imul    rax, rax, SIZEOF IDE_PANE
    lea     rdx, [g_panes + rax]
    
    mov     rcx, r12
    mov     r8d, SIZEOF IDE_PANE
    lea     r9, [rsp + 32]
    push 0
    sub rsp, 32
    call    WriteFile
    add     rsp, 40
    
    inc     ebx
    jmp     save_pane_loop
    
save_complete:
    mov     rcx, r12
    sub     rsp, 32
    call    CloseHandle
    add     rsp, 32
    mov     eax, 1
    ret
    
save_fail:
    xor     eax, eax
    ret
DragPane_SaveLayout ENDP

;==============================================================================
; DragPane_LoadLayout - Load layout from file
;==============================================================================
ALIGN 16
DragPane_LoadLayout PROC USES rbx r12
    ; Open layout file
    lea     rcx, g_layoutFile
    mov     edx, GENERIC_READ
    mov     r8d, OPEN_EXISTING
    sub     rsp, 32
    call    CreateFileA
    add     rsp, 32
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      load_default
    mov     r12, rax
    
    ; Read and apply layout...
    ; (Implementation details for reading back the saved layout)
    
    mov     rcx, r12
    sub     rsp, 32
    call    CloseHandle
    add     rsp, 32
    mov     eax, 1
    ret
    
load_default:
    ; Use default layout if no saved layout exists
    mov     eax, 1
    ret
DragPane_LoadLayout ENDP

;==============================================================================
; HELPER FUNCTIONS (Stubs for now)
;==============================================================================

CreateGhostWindow PROC
    mov     eax, 12345h     ; Dummy window handle
    ret
CreateGhostWindow ENDP

FindDockZone_alt PROC
    mov     eax, -1         ; No zone found
    ret
FindDockZone_alt ENDP

ClearAllHighlights_alt PROC
    ret
ClearAllHighlights_alt ENDP

PerformDocking_alt PROC
    ; rcx = source pane, rdx = target pane, r8d = dock type
    ret
PerformDocking_alt ENDP

CreateTabGroup_alt PROC
    ; rcx = source pane, rdx = target pane
    ret
CreateTabGroup_alt ENDP

RestoreOriginalPosition_alt PROC
    ; rcx = pane
    ret
RestoreOriginalPosition_alt ENDP

PaneSystem_RefreshLayout_alt PROC
    ret
PaneSystem_RefreshLayout_alt ENDP

END




