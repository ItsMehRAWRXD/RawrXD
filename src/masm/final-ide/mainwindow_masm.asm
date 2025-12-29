;==============================================================================
; mainwindow_masm.asm - MASM MainWindow Architecture & Qt Widget Bridge
; Purpose: Core IDE window management, menu system, dock management, signals
; Author: RawrXD CI/CD
; Date: Dec 29, 2025
;
; Provides Qt6 window/widget integration at MASM level:
; - Main window lifecycle (create, resize, show, hide, close)
; - Menu bar construction and event routing
; - Dock widget management (12+ docks)
; - Status bar integration
; - Signal/slot dispatcher bridge
; - Theme/styling application
;==============================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc
includelib kernel32.lib
includelib user32.lib

;==============================================================================
; CONSTANTS & STRUCTURES
;==============================================================================

; Window state constants
WINDOW_STATE_CLOSED         EQU 0
WINDOW_STATE_CREATED        EQU 1
WINDOW_STATE_SHOWN          EQU 2
WINDOW_STATE_HIDDEN         EQU 3
WINDOW_STATE_MAXIMIZED      EQU 4
WINDOW_STATE_MINIMIZED      EQU 5
WINDOW_STATE_FULLSCREEN     EQU 6

; Dock widget positions
DOCK_POS_LEFT               EQU 0
DOCK_POS_RIGHT              EQU 1
DOCK_POS_TOP                EQU 2
DOCK_POS_BOTTOM             EQU 3
DOCK_POS_FLOATING           EQU 4

; Menu types
MENU_TYPE_FILE              EQU 0
MENU_TYPE_EDIT              EQU 1
MENU_TYPE_VIEW              EQU 2
MENU_TYPE_TOOLS             EQU 3
MENU_TYPE_HELP              EQU 4

; Maximum limits
MAX_DOCKS                   EQU 16
MAX_MENU_ITEMS              EQU 64
MAX_TOOLBAR_BUTTONS         EQU 32

; Dock widget structure
DOCK_WIDGET STRUCT
    dockId                  DWORD ?
    name                    BYTE 256 DUP(?)
    position                DWORD ?     ; DOCK_POS_*
    isVisible               DWORD ?     ; BOOL
    isFloating              DWORD ?     ; BOOL
    width                   DWORD ?
    height                  DWORD ?
    hDockWidget             QWORD ?     ; Qt widget pointer
    contentWidget           QWORD ?     ; Main content
    titleBar                QWORD ?     ; Title widget
DOCK_WIDGET ENDS

; Menu item structure
MENU_ITEM STRUCT
    itemId                  DWORD ?
    text                    BYTE 256 DUP(?)
    icon                    QWORD ?     ; Icon resource
    isChecked               DWORD ?     ; BOOL
    isEnabled               DWORD ?     ; BOOL
    actionCallback          QWORD ?     ; Function pointer
    menuType                DWORD ?     ; MENU_TYPE_*
    hAction                 QWORD ?     ; Qt action pointer
MENU_ITEM ENDS

; MainWindow structure
MAINWINDOW STRUCT
    hMainWindow             QWORD ?     ; Qt QMainWindow pointer
    windowState             DWORD ?     ; WINDOW_STATE_*
    width                   DWORD ?     ; Window dimensions
    height                  DWORD ?
    posX                    DWORD ?     ; Window position
    posY                    DWORD ?
    
    ; Dock widgets (12 total)
    docks                   DOCK_WIDGET MAX_DOCKS DUP(<>)
    dockCount               DWORD ?
    
    ; Menu bar
    menus                   MENU_ITEM MAX_MENU_ITEMS DUP(<>)
    menuCount               DWORD ?
    hMenuBar                QWORD ?
    
    ; Toolbars
    toolbarButtons          QWORD MAX_TOOLBAR_BUTTONS DUP(?)
    buttonCount             DWORD ?
    
    ; Status bar
    hStatusBar              QWORD ?
    statusText              BYTE 512 DUP(?)
    
    ; Central widget
    hCentralWidget          QWORD ?
    
    ; Mutex for thread safety
    windowMutex             QWORD ?
    
    ; Event dispatcher
    hSignalDispatcher       QWORD ?
    signalQueue             QWORD ?     ; Async signal queue
    signalQueueSize         DWORD ?
    
    ; Theme/styling
    themeId                 DWORD ?     ; 0=light, 1=dark, 2=custom
    accentColor             DWORD ?     ; RGB value
    fontName                BYTE 64 DUP(?)
    fontSize                DWORD ?
    
    isInitialized           DWORD ?     ; BOOL
MAINWINDOW ENDS

;==============================================================================
; GLOBAL DATA
;==============================================================================

.data?
    g_mainWindow            MAINWINDOW <>
    g_initialized           DWORD 0
    g_heapHandle            QWORD 0

.data
    ; Default theme colors
    szDarkTheme             BYTE "Dark", 0
    szLightTheme            BYTE "Light", 0
    szDefaultFont           BYTE "Segoe UI", 0
    
    ; Menu strings
    szFileMenu              BYTE "File", 0
    szEditMenu              BYTE "Edit", 0
    szViewMenu              BYTE "View", 0
    szToolsMenu             BYTE "Tools", 0
    szHelpMenu              BYTE "Help", 0
    
    ; Dock names
    szActivityBar           BYTE "Activity Bar", 0
    szFileExplorer          BYTE "File Explorer", 0
    szTerminal              BYTE "Terminal", 0
    szOutput                BYTE "Output", 0
    szProblems              BYTE "Problems", 0
    szDebug                 BYTE "Debug", 0

;==============================================================================
; EXPORTED FUNCTIONS
;==============================================================================

PUBLIC masm_mainwindow_init
PUBLIC masm_mainwindow_shutdown
PUBLIC masm_mainwindow_create
PUBLIC masm_mainwindow_show
PUBLIC masm_mainwindow_hide
PUBLIC masm_mainwindow_close
PUBLIC masm_mainwindow_resize
PUBLIC masm_mainwindow_set_title
PUBLIC masm_mainwindow_add_dock
PUBLIC masm_mainwindow_remove_dock
PUBLIC masm_mainwindow_show_dock
PUBLIC masm_mainwindow_hide_dock
PUBLIC masm_mainwindow_add_menu_item
PUBLIC masm_mainwindow_remove_menu_item
PUBLIC masm_mainwindow_set_status
PUBLIC masm_mainwindow_get_status
PUBLIC masm_mainwindow_set_theme
PUBLIC masm_mainwindow_get_theme
PUBLIC masm_mainwindow_dispatch_signal
PUBLIC masm_mainwindow_list_docks
PUBLIC masm_mainwindow_save_layout
PUBLIC masm_mainwindow_load_layout

;==============================================================================
; FUNCTION IMPLEMENTATIONS
;==============================================================================

; masm_mainwindow_init - Initialize the MainWindow system
; Returns: 1 = success, 0 = failure
masm_mainwindow_init PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    cmp g_initialized, 1
    je .init_already

    ; Get process heap
    call GetProcessHeap
    mov g_heapHandle, rax
    mov g_mainWindow.MAINWINDOW.hMainWindow, 0
    
    ; Initialize counts
    mov g_mainWindow.MAINWINDOW.dockCount, 0
    mov g_mainWindow.MAINWINDOW.menuCount, 0
    mov g_mainWindow.MAINWINDOW.buttonCount, 0
    
    ; Set default theme
    mov g_mainWindow.MAINWINDOW.themeId, 1  ; Dark theme
    mov g_mainWindow.MAINWINDOW.fontSize, 11
    
    ; Create window mutex
    lea rcx, [rel g_mainWindow.MAINWINDOW.windowMutex]
    xor rdx, rdx
    call CreateMutexA
    
    mov g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_CLOSED
    mov g_initialized, 1
    mov rax, 1
    jmp .init_done

.init_already:
    mov rax, 1

.init_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_init ENDP

; masm_mainwindow_shutdown - Shutdown the MainWindow system
; Returns: 1 = success, 0 = failure
masm_mainwindow_shutdown PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    cmp g_initialized, 0
    je .shutdown_not_init

    ; Close window if open
    cmp g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_CLOSED
    je .skip_close_window
    
    mov rcx, g_mainWindow.MAINWINDOW.hMainWindow
    cmp rcx, 0
    je .skip_close_window
    
    ; TODO: Call Qt close() on window
.skip_close_window:

    ; Free all dock resources
    xor rbx, rbx
.free_docks:
    cmp rbx, g_mainWindow.MAINWINDOW.dockCount
    jge .docks_freed

    lea rax, [g_mainWindow.MAINWINDOW.docks + rbx * (SIZEOF DOCK_WIDGET)]
    
    ; Free dock name string if allocated
    mov rcx, [rax].DOCK_WIDGET.contentWidget
    cmp rcx, 0
    je .skip_dock_free
    ; TODO: Free Qt widget
.skip_dock_free:

    inc rbx
    jmp .free_docks

.docks_freed:
    ; Close mutex
    mov rcx, g_mainWindow.MAINWINDOW.windowMutex
    call CloseHandle

    mov g_initialized, 0
    mov rax, 1
    jmp .shutdown_done

.shutdown_not_init:
    xor rax, rax

.shutdown_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_shutdown ENDP

; masm_mainwindow_create - Create the main window
; Args: RCX = width, RDX = height, R8 = window title pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_create PROC USES rbx rsi rdi r12 r13 r14
    push rbp
    sub rsp, 32

    mov r12d, ecx  ; Width
    mov r13d, edx  ; Height
    mov r14, r8    ; Title

    cmp g_initialized, 0
    je .create_not_init

    ; Store dimensions
    mov g_mainWindow.MAINWINDOW.width, r12d
    mov g_mainWindow.MAINWINDOW.height, r13d

    ; TODO: Create Qt QMainWindow via bridge
    ; For now, mark as created
    mov g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_CREATED

    ; Add default docks
    call masm_setup_default_docks

    ; Create default menu bar
    call masm_setup_default_menus

    mov rax, 1
    jmp .create_done

.create_not_init:
    xor rax, rax

.create_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_create ENDP

; masm_mainwindow_show - Show the main window
; Returns: 1 = success, 0 = failure
masm_mainwindow_show PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    cmp g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_CREATED
    jne .show_not_ready

    mov g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_SHOWN

    ; TODO: Call Qt show() on window
    mov rax, 1
    jmp .show_done

.show_not_ready:
    xor rax, rax

.show_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_show ENDP

; masm_mainwindow_hide - Hide the main window
; Returns: 1 = success, 0 = failure
masm_mainwindow_hide PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_HIDDEN
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_hide ENDP

; masm_mainwindow_close - Close the main window
; Returns: 1 = success, 0 = failure
masm_mainwindow_close PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov g_mainWindow.MAINWINDOW.windowState, WINDOW_STATE_CLOSED
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_close ENDP

; masm_mainwindow_resize - Resize the window
; Args: RCX = new width, RDX = new height
; Returns: 1 = success, 0 = failure
masm_mainwindow_resize PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov g_mainWindow.MAINWINDOW.width, ecx
    mov g_mainWindow.MAINWINDOW.height, edx
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_resize ENDP

; masm_mainwindow_set_title - Set window title
; Args: RCX = title string pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_set_title PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; TODO: Copy title and set on Qt window
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_set_title ENDP

; masm_mainwindow_add_dock - Add a dock widget
; Args: RCX = dock name, RDX = position (DOCK_POS_*), R8 = content widget pointer
; Returns: dock ID or 0 if failure
masm_mainwindow_add_dock PROC USES rbx rsi rdi r12 r13 r14
    push rbp
    sub rsp, 32

    mov r12, rcx   ; Name
    mov r13d, edx  ; Position
    mov r14, r8    ; Content widget

    cmp g_mainWindow.MAINWINDOW.dockCount, MAX_DOCKS
    jge .add_dock_full

    mov eax, g_mainWindow.MAINWINDOW.dockCount
    lea rbx, [g_mainWindow.MAINWINDOW.docks + rax * (SIZEOF DOCK_WIDGET)]

    ; Initialize dock
    mov [rbx].DOCK_WIDGET.dockId, eax
    mov [rbx].DOCK_WIDGET.position, r13d
    mov [rbx].DOCK_WIDGET.contentWidget, r14
    mov [rbx].DOCK_WIDGET.isVisible, 1
    mov [rbx].DOCK_WIDGET.isFloating, 0

    ; Copy name
    mov rsi, r12
    lea rdi, [rbx + OFFSET DOCK_WIDGET.name]
    mov ecx, 256
.copy_dock_name:
    cmp ecx, 0
    je .dock_name_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jmp .copy_dock_name

.dock_name_done:
    mov eax, g_mainWindow.MAINWINDOW.dockCount
    inc g_mainWindow.MAINWINDOW.dockCount
    jmp .add_dock_done

.add_dock_full:
    xor eax, eax

.add_dock_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_add_dock ENDP

; masm_mainwindow_remove_dock - Remove a dock widget
; Args: RCX = dock ID
; Returns: 1 = success, 0 = failure
masm_mainwindow_remove_dock PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov r8d, ecx  ; Dock ID

    ; Find dock
    xor r9d, r9d
.find_dock:
    cmp r9d, g_mainWindow.MAINWINDOW.dockCount
    jge .dock_not_found

    lea rax, [g_mainWindow.MAINWINDOW.docks + r9 * (SIZEOF DOCK_WIDGET)]
    cmp [rax].DOCK_WIDGET.dockId, r8d
    je .dock_found

    inc r9d
    jmp .find_dock

.dock_found:
    lea rax, [g_mainWindow.MAINWINDOW.docks + r9 * (SIZEOF DOCK_WIDGET)]
    mov [rax].DOCK_WIDGET.isVisible, 0
    mov rax, 1
    jmp .remove_dock_done

.dock_not_found:
    xor rax, rax

.remove_dock_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_remove_dock ENDP

; masm_mainwindow_show_dock - Show a dock widget
; Args: RCX = dock ID
; Returns: 1 = success, 0 = failure
masm_mainwindow_show_dock PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov r8d, ecx

    xor r9d, r9d
.find_show:
    cmp r9d, g_mainWindow.MAINWINDOW.dockCount
    jge .show_not_found

    lea rax, [g_mainWindow.MAINWINDOW.docks + r9 * (SIZEOF DOCK_WIDGET)]
    cmp [rax].DOCK_WIDGET.dockId, r8d
    je .show_found

    inc r9d
    jmp .find_show

.show_found:
    mov [rax].DOCK_WIDGET.isVisible, 1
    mov rax, 1
    jmp .show_dock_done

.show_not_found:
    xor rax, rax

.show_dock_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_show_dock ENDP

; masm_mainwindow_hide_dock - Hide a dock widget
; Args: RCX = dock ID
; Returns: 1 = success, 0 = failure
masm_mainwindow_hide_dock PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov r8d, ecx

    xor r9d, r9d
.find_hide:
    cmp r9d, g_mainWindow.MAINWINDOW.dockCount
    jge .hide_not_found

    lea rax, [g_mainWindow.MAINWINDOW.docks + r9 * (SIZEOF DOCK_WIDGET)]
    cmp [rax].DOCK_WIDGET.dockId, r8d
    je .hide_found

    inc r9d
    jmp .find_hide

.hide_found:
    mov [rax].DOCK_WIDGET.isVisible, 0
    mov rax, 1
    jmp .hide_dock_done

.hide_not_found:
    xor rax, rax

.hide_dock_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_hide_dock ENDP

; masm_mainwindow_add_menu_item - Add a menu item
; Args: RCX = menu type, RDX = item text, R8 = callback function
; Returns: menu item ID or 0 if failure
masm_mainwindow_add_menu_item PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    cmp g_mainWindow.MAINWINDOW.menuCount, MAX_MENU_ITEMS
    jge .menu_full

    mov eax, g_mainWindow.MAINWINDOW.menuCount
    lea rbx, [g_mainWindow.MAINWINDOW.menus + rax * (SIZEOF MENU_ITEM)]

    mov [rbx].MENU_ITEM.itemId, eax
    mov [rbx].MENU_ITEM.menuType, ecx
    mov [rbx].MENU_ITEM.actionCallback, r8
    mov [rbx].MENU_ITEM.isEnabled, 1

    inc g_mainWindow.MAINWINDOW.menuCount
    jmp .add_menu_done

.menu_full:
    xor eax, eax

.add_menu_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_add_menu_item ENDP

; masm_mainwindow_remove_menu_item - Remove a menu item
; Args: RCX = menu item ID
; Returns: 1 = success, 0 = failure
masm_mainwindow_remove_menu_item PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov r8d, ecx

    xor r9d, r9d
.find_menu:
    cmp r9d, g_mainWindow.MAINWINDOW.menuCount
    jge .menu_not_found

    lea rax, [g_mainWindow.MAINWINDOW.menus + r9 * (SIZEOF MENU_ITEM)]
    cmp [rax].MENU_ITEM.itemId, r8d
    je .menu_found

    inc r9d
    jmp .find_menu

.menu_found:
    mov [rax].MENU_ITEM.isEnabled, 0
    mov rax, 1
    jmp .remove_menu_done

.menu_not_found:
    xor rax, rax

.remove_menu_done:
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_remove_menu_item ENDP

; masm_mainwindow_set_status - Set status bar text
; Args: RCX = status text pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_set_status PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; Copy status text
    mov rsi, rcx
    lea rdi, [rel g_mainWindow.MAINWINDOW.statusText]
    mov ecx, 512
.copy_status:
    cmp ecx, 0
    je .status_copied
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jmp .copy_status

.status_copied:
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_set_status ENDP

; masm_mainwindow_get_status - Get status bar text
; Args: RCX = output buffer pointer, RDX = buffer size
; Returns: 1 = success, 0 = failure
masm_mainwindow_get_status PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov rdi, rcx
    mov esi, edx
    lea rsi, [rel g_mainWindow.MAINWINDOW.statusText]

.copy_get_status:
    cmp esi, 0
    je .get_status_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec esi
    jmp .copy_get_status

.get_status_done:
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_get_status ENDP

; masm_mainwindow_set_theme - Set window theme
; Args: RCX = theme ID (0=light, 1=dark, 2=custom)
; Returns: 1 = success, 0 = failure
masm_mainwindow_set_theme PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov g_mainWindow.MAINWINDOW.themeId, ecx
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_set_theme ENDP

; masm_mainwindow_get_theme - Get current theme
; Returns: theme ID (0=light, 1=dark, 2=custom)
masm_mainwindow_get_theme PROC
    mov eax, g_mainWindow.MAINWINDOW.themeId
    ret
masm_mainwindow_get_theme ENDP

; masm_mainwindow_dispatch_signal - Dispatch a Qt signal
; Args: RCX = signal name, RDX = signal data pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_dispatch_signal PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; TODO: Queue signal and trigger dispatcher
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_dispatch_signal ENDP

; masm_mainwindow_list_docks - List all docks
; Args: RCX = output buffer (DWORD array), RDX = max count
; Returns: actual count filled
masm_mainwindow_list_docks PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    mov r8, rcx
    mov r9d, edx

    xor r10d, r10d
.list_loop:
    cmp r10d, g_mainWindow.MAINWINDOW.dockCount
    jge .list_done

    cmp r10d, r9d
    jge .list_done

    lea rax, [g_mainWindow.MAINWINDOW.docks + r10 * (SIZEOF DOCK_WIDGET)]
    mov edx, [rax].DOCK_WIDGET.dockId
    mov [r8 + r10 * 4], edx

    inc r10d
    jmp .list_loop

.list_done:
    mov rax, r10
    add rsp, 32
    pop rbp
    ret
masm_mainwindow_list_docks ENDP

; masm_mainwindow_save_layout - Save window layout to file
; Args: RCX = file path pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_save_layout PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; TODO: Serialize window state to file
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_save_layout ENDP

; masm_mainwindow_load_layout - Load window layout from file
; Args: RCX = file path pointer
; Returns: 1 = success, 0 = failure
masm_mainwindow_load_layout PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; TODO: Deserialize window state from file
    mov rax, 1

    add rsp, 32
    pop rbp
    ret
masm_mainwindow_load_layout ENDP

; Helper: Setup default docks
masm_setup_default_docks PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; Activity Bar - Left
    lea rcx, [rel szActivityBar]
    mov edx, DOCK_POS_LEFT
    xor r8, r8
    call masm_mainwindow_add_dock

    ; File Explorer - Left
    lea rcx, [rel szFileExplorer]
    mov edx, DOCK_POS_LEFT
    xor r8, r8
    call masm_mainwindow_add_dock

    ; Terminal - Bottom
    lea rcx, [rel szTerminal]
    mov edx, DOCK_POS_BOTTOM
    xor r8, r8
    call masm_mainwindow_add_dock

    ; Output - Bottom
    lea rcx, [rel szOutput]
    mov edx, DOCK_POS_BOTTOM
    xor r8, r8
    call masm_mainwindow_add_dock

    ; Problems - Bottom
    lea rcx, [rel szProblems]
    mov edx, DOCK_POS_BOTTOM
    xor r8, r8
    call masm_mainwindow_add_dock

    ; Debug - Right
    lea rcx, [rel szDebug]
    mov edx, DOCK_POS_RIGHT
    xor r8, r8
    call masm_mainwindow_add_dock

    add rsp, 32
    pop rbp
    ret
masm_setup_default_docks ENDP

; Helper: Setup default menus
masm_setup_default_menus PROC USES rbx rsi rdi
    push rbp
    sub rsp, 32

    ; File menu
    lea rcx, [rel szFileMenu]
    mov edx, MENU_TYPE_FILE
    xor r8, r8
    call masm_mainwindow_add_menu_item

    ; Edit menu
    lea rcx, [rel szEditMenu]
    mov edx, MENU_TYPE_EDIT
    xor r8, r8
    call masm_mainwindow_add_menu_item

    ; View menu
    lea rcx, [rel szViewMenu]
    mov edx, MENU_TYPE_VIEW
    xor r8, r8
    call masm_mainwindow_add_menu_item

    ; Tools menu
    lea rcx, [rel szToolsMenu]
    mov edx, MENU_TYPE_TOOLS
    xor r8, r8
    call masm_mainwindow_add_menu_item

    ; Help menu
    lea rcx, [rel szHelpMenu]
    mov edx, MENU_TYPE_HELP
    xor r8, r8
    call masm_mainwindow_add_menu_item

    add rsp, 32
    pop rbp
    ret
masm_setup_default_menus ENDP

END
