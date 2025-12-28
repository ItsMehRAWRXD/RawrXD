;==============================================================================
; ide_pane_system.asm - Core IDE Pane Management System
; Manages all IDE panes, docking, resizing, and plugin integration
;==============================================================================

option casemap:none

include windows.inc
include plugin_abi.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

PUBLIC PaneSystem_Init, PaneSystem_RegisterPane, PaneSystem_LoadPlugins
PUBLIC PaneSystem_CreateLayout, PaneSystem_HandleResize, PaneSystem_GetPane

;==============================================================================
; PANE TYPES
;==============================================================================
PANE_TYPE_EXPLORER      equ 1
PANE_TYPE_EDITOR        equ 2
PANE_TYPE_TERMINAL      equ 3
PANE_TYPE_CHAT          equ 4
PANE_TYPE_OUTPUT        equ 5
PANE_TYPE_PROPERTIES    equ 6
PANE_TYPE_MINIMAP       equ 7
PANE_TYPE_TABS          equ 8
PANE_TYPE_STATUSBAR     equ 9
PANE_TYPE_TOOLBAR       equ 10

;==============================================================================
; PANE STRUCTURE
;==============================================================================
IDE_PANE STRUCT
    PaneID          DWORD   ?       ; Unique pane identifier
    PaneType        DWORD   ?       ; PANE_TYPE_*
    hWnd            QWORD   ?       ; Window handle
    X               DWORD   ?       ; Position
    Y               DWORD   ?
    Width           DWORD   ?       ; Size
    Height          DWORD   ?
    MinWidth        DWORD   ?       ; Constraints
    MinHeight       DWORD   ?
    Dockable        DWORD   ?       ; Can be docked/undocked
    Visible         DWORD   ?       ; Visibility state
    PluginHandle    QWORD   ?       ; Plugin that owns this pane
    CreateFunc      QWORD   ?       ; Creation function
    UpdateFunc      QWORD   ?       ; Update function
    DestroyFunc     QWORD   ?       ; Cleanup function
    NamePtr         QWORD   ?       ; Pane display name
IDE_PANE ENDS

;==============================================================================
; DATA
;==============================================================================
.data
    g_paneCount         DWORD   0
    g_mainWindow        QWORD   0
    g_layoutInitialized DWORD   0
    
    ; Default pane names
    szExplorer          db "File Explorer", 0
    szEditor            db "Code Editor", 0
    szTerminal          db "Terminal", 0
    szChat              db "AI Chat", 0
    szOutput            db "Output", 0
    szProperties        db "Properties", 0
    szMinimap           db "Minimap", 0
    szTabs              db "Editor Tabs", 0
    szStatusBar         db "Status Bar", 0
    szToolbar           db "Toolbar", 0

.data?
    g_panes             IDE_PANE 32 dup(<>)  ; Max 32 panes
    g_clientRect        RECT <>

;==============================================================================
; CODE
;==============================================================================
.code

;==============================================================================
; PaneSystem_Init - Initialize the pane management system
; rcx = main window handle
;==============================================================================
ALIGN 16
PaneSystem_Init PROC
    mov     g_mainWindow, rcx
    mov     g_paneCount, 0
    mov     g_layoutInitialized, 0
    
    ; Register core IDE panes
    call    RegisterCorePanes
    
    mov     eax, 1
    ret
PaneSystem_Init ENDP

;==============================================================================
; RegisterCorePanes - Register built-in IDE panes
;==============================================================================
ALIGN 16
RegisterCorePanes PROC USES rbx
    ; File Explorer (Left)
    mov     ecx, PANE_TYPE_EXPLORER
    lea     rdx, szExplorer
    mov     r8, OFFSET CreateExplorerPane
    mov     r9, OFFSET UpdateExplorerPane
    push    OFFSET DestroyExplorerPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ; Code Editor (Center)
    mov     ecx, PANE_TYPE_EDITOR
    lea     rdx, szEditor
    mov     r8, OFFSET CreateEditorPane
    mov     r9, OFFSET UpdateEditorPane
    push    OFFSET DestroyEditorPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ; Terminal (Bottom)
    mov     ecx, PANE_TYPE_TERMINAL
    lea     rdx, szTerminal
    mov     r8, OFFSET CreateTerminalPane
    mov     r9, OFFSET UpdateTerminalPane
    push    OFFSET DestroyTerminalPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ; AI Chat (Right)
    mov     ecx, PANE_TYPE_CHAT
    lea     rdx, szChat
    mov     r8, OFFSET CreateChatPane
    mov     r9, OFFSET UpdateChatPane
    push    OFFSET DestroyChatPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ; Editor Tabs (Top of editor)
    mov     ecx, PANE_TYPE_TABS
    lea     rdx, szTabs
    mov     r8, OFFSET CreateTabsPane
    mov     r9, OFFSET UpdateTabsPane
    push    OFFSET DestroyTabsPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ; Status Bar (Bottom)
    mov     ecx, PANE_TYPE_STATUSBAR
    lea     rdx, szStatusBar
    mov     r8, OFFSET CreateStatusPane
    mov     r9, OFFSET UpdateStatusPane
    push    OFFSET DestroyStatusPane
    sub     rsp, 32
    call    PaneSystem_RegisterPane
    add     rsp, 40
    
    ret
RegisterCorePanes ENDP

;==============================================================================
; PaneSystem_RegisterPane - Register a new pane
; ecx = pane type, rdx = name, r8 = create func, r9 = update func, [rsp+40] = destroy func
;==============================================================================
ALIGN 16
PaneSystem_RegisterPane PROC
    mov     eax, g_paneCount
    cmp     eax, 32
    jge     register_fail
    
    ; Calculate pane structure offset
    imul    rax, rax, SIZEOF IDE_PANE
    lea     rdi, [g_panes + rax]
    
    ; Fill pane structure
    mov     (IDE_PANE PTR [rdi]).PaneID, eax
    mov     (IDE_PANE PTR [rdi]).PaneType, ecx
    mov     (IDE_PANE PTR [rdi]).hWnd, 0
    mov     (IDE_PANE PTR [rdi]).Dockable, 1
    mov     (IDE_PANE PTR [rdi]).Visible, 1
    mov     (IDE_PANE PTR [rdi]).PluginHandle, 0
    mov     (IDE_PANE PTR [rdi]).CreateFunc, r8
    mov     (IDE_PANE PTR [rdi]).UpdateFunc, r9
    mov     rax, [rsp + 40]  ; destroy func from stack
    mov     (IDE_PANE PTR [rdi]).DestroyFunc, rax
    mov     (IDE_PANE PTR [rdi]).NamePtr, rdx
    
    inc     g_paneCount
    mov     eax, 1
    ret
    
register_fail:
    xor     eax, eax
    ret
PaneSystem_RegisterPane ENDP

;==============================================================================
; PaneSystem_CreateLayout - Create the IDE layout with all panes
;==============================================================================
ALIGN 16
PaneSystem_CreateLayout PROC USES rbx r12 r13
    ; Get client area
    mov     rcx, g_mainWindow
    lea     rdx, g_clientRect
    sub     rsp, 32
    call    GetClientRect
    add     rsp, 32
    
    ; Calculate layout dimensions
    mov     eax, g_clientRect.right
    mov     ebx, g_clientRect.bottom
    
    ; Layout: Explorer(200) | Editor+Tabs | Chat(300)
    ;         Terminal(150) spans bottom
    ;         StatusBar(25) at very bottom
    
    mov     r12d, 200      ; Explorer width
    mov     r13d, 300      ; Chat width
    
    ; Create all panes
    xor     ecx, ecx       ; pane index
    
create_pane_loop:
    cmp     ecx, g_paneCount
    jge     layout_done
    
    ; Get pane structure
    mov     eax, ecx
    imul    rax, rax, SIZEOF IDE_PANE
    lea     rdi, [g_panes + rax]
    
    ; Calculate position based on pane type
    mov     edx, (IDE_PANE PTR [rdi]).PaneType
    
    cmp     edx, PANE_TYPE_EXPLORER
    je      position_explorer
    cmp     edx, PANE_TYPE_EDITOR
    je      position_editor
    cmp     edx, PANE_TYPE_TERMINAL
    je      position_terminal
    cmp     edx, PANE_TYPE_CHAT
    je      position_chat
    cmp     edx, PANE_TYPE_TABS
    je      position_tabs
    cmp     edx, PANE_TYPE_STATUSBAR
    je      position_statusbar
    jmp     next_pane
    
position_explorer:
    mov     (IDE_PANE PTR [rdi]).X, 0
    mov     (IDE_PANE PTR [rdi]).Y, 0
    mov     (IDE_PANE PTR [rdi]).Width, r12d
    mov     eax, ebx
    sub     eax, 175      ; Leave space for terminal + status
    mov     (IDE_PANE PTR [rdi]).Height, eax
    jmp     create_pane_window
    
position_editor:
    mov     (IDE_PANE PTR [rdi]).X, r12d
    mov     (IDE_PANE PTR [rdi]).Y, 30    ; Below tabs
    mov     eax, g_clientRect.right
    sub     eax, r12d     ; - explorer width
    sub     eax, r13d     ; - chat width
    mov     (IDE_PANE PTR [rdi]).Width, eax
    mov     eax, ebx
    sub     eax, 205      ; Leave space for terminal + status + tabs
    mov     (IDE_PANE PTR [rdi]).Height, eax
    jmp     create_pane_window
    
position_terminal:
    mov     (IDE_PANE PTR [rdi]).X, 0
    mov     eax, ebx
    sub     eax, 175
    mov     (IDE_PANE PTR [rdi]).Y, eax
    mov     eax, g_clientRect.right
    sub     eax, r13d     ; Leave space for chat
    mov     (IDE_PANE PTR [rdi]).Width, eax
    mov     (IDE_PANE PTR [rdi]).Height, 150
    jmp     create_pane_window
    
position_chat:
    mov     eax, g_clientRect.right
    sub     eax, r13d
    mov     (IDE_PANE PTR [rdi]).X, eax
    mov     (IDE_PANE PTR [rdi]).Y, 0
    mov     (IDE_PANE PTR [rdi]).Width, r13d
    mov     eax, ebx
    sub     eax, 25       ; Leave space for status bar
    mov     (IDE_PANE PTR [rdi]).Height, eax
    jmp     create_pane_window
    
position_tabs:
    mov     (IDE_PANE PTR [rdi]).X, r12d
    mov     (IDE_PANE PTR [rdi]).Y, 0
    mov     eax, g_clientRect.right
    sub     eax, r12d     ; - explorer width
    sub     eax, r13d     ; - chat width
    mov     (IDE_PANE PTR [rdi]).Width, eax
    mov     (IDE_PANE PTR [rdi]).Height, 30
    jmp     create_pane_window
    
position_statusbar:
    mov     (IDE_PANE PTR [rdi]).X, 0
    mov     eax, ebx
    sub     eax, 25
    mov     (IDE_PANE PTR [rdi]).Y, eax
    mov     eax, g_clientRect.right
    mov     (IDE_PANE PTR [rdi]).Width, eax
    mov     (IDE_PANE PTR [rdi]).Height, 25
    jmp     create_pane_window
    
create_pane_window:
    ; Call pane's create function
    mov     rax, (IDE_PANE PTR [rdi]).CreateFunc
    test    rax, rax
    jz      next_pane
    
    push    rcx
    push    rdi
    mov     rcx, rdi      ; Pass pane structure
    sub     rsp, 32
    call    rax
    add     rsp, 32
    pop     rdi
    pop     rcx
    
    ; Store returned window handle
    mov     (IDE_PANE PTR [rdi]).hWnd, rax
    
next_pane:
    inc     ecx
    jmp     create_pane_loop
    
layout_done:
    mov     g_layoutInitialized, 1
    mov     eax, 1
    ret
PaneSystem_CreateLayout ENDP

;==============================================================================
; PaneSystem_LoadPlugins - Load and integrate plugin panes
;==============================================================================
ALIGN 16
PaneSystem_LoadPlugins PROC
    ; Initialize plugin loader
    sub     rsp, 32
    call    PluginLoaderInit
    add     rsp, 32
    
    ; Plugin panes will register themselves via callbacks
    ; This is handled by the plugin system automatically
    
    mov     eax, 1
    ret
PaneSystem_LoadPlugins ENDP

;==============================================================================
; PaneSystem_HandleResize - Handle main window resize
;==============================================================================
ALIGN 16
PaneSystem_HandleResize PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 32
    
    ; Recalculate layout
    call    PaneSystem_CreateLayout
    
    ; Update all pane windows
    xor     ebx, ebx
resize_loop:
    cmp     ebx, g_paneCount
    jge     resize_done
    
    mov     eax, ebx
    imul    rax, rax, SIZEOF IDE_PANE
    lea     rdi, [g_panes + rax]
    
    mov     rcx, (IDE_PANE PTR [rdi]).hWnd
    test    rcx, rcx
    jz      next_resize
    
    ; MoveWindow(hWnd, X, Y, Width, Height, bRepaint)
    mov     edx, (IDE_PANE PTR [rdi]).X
    mov     r8d, (IDE_PANE PTR [rdi]).Y
    mov     r9d, (IDE_PANE PTR [rdi]).Width
    push    1               ; bRepaint
    push    (IDE_PANE PTR [rdi]).Height
    sub     rsp, 32
    call    MoveWindow
    add     rsp, 48
    
next_resize:
    inc     ebx
    jmp     resize_loop
    
resize_done:
    add     rsp, 32
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PaneSystem_HandleResize ENDP

;==============================================================================
; PANE CREATION FUNCTIONS (Non-simplified)
;==============================================================================

EXTERN hwnd_file_tree:QWORD
EXTERN hwnd_editor:QWORD
EXTERN hwnd_terminal:QWORD
EXTERN hwnd_chat:QWORD
EXTERN hwnd_status:QWORD

CreateExplorerPane PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    call    ide_init_file_tree
    mov     rax, hwnd_file_tree
    leave
    ret
CreateExplorerPane ENDP

CreateEditorPane PROC
    mov     rax, hwnd_editor
    ret
CreateEditorPane ENDP

CreateTerminalPane PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    mov     ecx, 1 ; PowerShell
    call    terminal_start_shell
    mov     rax, hwnd_terminal
    leave
    ret
CreateTerminalPane ENDP

CreateChatPane PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    call    agent_chat_init
    mov     rax, hwnd_chat
    leave
    ret
CreateChatPane ENDP

CreateTabsPane PROC
    ; Tabs are currently integrated into editor host in ui_masm.asm
    xor     rax, rax
    ret
CreateTabsPane ENDP

CreateStatusPane PROC
    mov     rax, hwnd_status
    ret
CreateStatusPane ENDP

; Update and Destroy stubs
UpdateExplorerPane PROC
    ret
UpdateExplorerPane ENDP

UpdateEditorPane PROC
    ret
UpdateEditorPane ENDP

UpdateTerminalPane PROC
    ret
UpdateTerminalPane ENDP

UpdateChatPane PROC
    ret
UpdateChatPane ENDP

UpdateTabsPane PROC
    ret
UpdateTabsPane ENDP

UpdateStatusPane PROC
    ret
UpdateStatusPane ENDP

DestroyExplorerPane PROC
    ret
DestroyExplorerPane ENDP

DestroyEditorPane PROC
    ret
DestroyEditorPane ENDP

DestroyTerminalPane PROC
    ret
DestroyTerminalPane ENDP

DestroyChatPane PROC
    ret
DestroyChatPane ENDP

DestroyTabsPane PROC
    ret
DestroyTabsPane ENDP

DestroyStatusPane PROC
    ret
DestroyStatusPane ENDP

;==============================================================================
; PaneSystem_GetPane - Get pane by type
; ecx = pane type
; Returns: RAX = pane structure pointer or 0
;==============================================================================
ALIGN 16
PaneSystem_GetPane PROC
    xor     edx, edx      ; index
    
search_pane:
    cmp     edx, g_paneCount
    jge     pane_not_found
    
    mov     eax, edx
    imul    rax, rax, SIZEOF IDE_PANE
    lea     rdi, [g_panes + rax]
    
    cmp     (IDE_PANE PTR [rdi]).PaneType, ecx
    je      pane_found
    
    inc     edx
    jmp     search_pane
    
pane_found:
    mov     rax, rdi
    ret
    
pane_not_found:
    xor     rax, rax
    ret
PaneSystem_GetPane ENDP

END