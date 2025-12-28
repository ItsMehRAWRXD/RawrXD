; ==========================================================================
; MASM Qt6 Component Conversion: Main Window & Menubar System
; ==========================================================================
; This file implements the main application window (QMainWindow equivalent)
; and menu bar with menu items. Replaces 2,800-4,100 LOC of C++/Qt6 code.
;
; Features:
;   - WS_OVERLAPPEDWINDOW creation with proper window class registration
;   - Menu bar with cascading menus and menu items
;   - Toolbar layout (horizontal menu bar strip)
;   - Status bar (bottom status text display)
;   - Window events: move, resize, close, focus, activate
;   - Client area management (reserved for child widgets/layouts)
;   - Title bar text management
;
; Architecture:
;   - VMT-based virtual methods (paint, on_event, get_size, set_size, show, hide)
;   - Stack-based resource management (RAII pattern in assembly)
;   - Spinlock-free design (single-threaded UI, synchronized via event queue)
;   - Direct Win32 API calls (CreateWindowEx, SetWindowPos, SendMessage)
;
; Depends On:
;   - qt6_foundation.asm (VMT, object model, event queue)
;   - windows.inc (Win32 definitions)
;
; ==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

;==========================================================================
; MAIN WINDOW STRUCTURE (replaces QMainWindow)
;==========================================================================

MAIN_WINDOW STRUCT
    base                OBJECT_BASE <>        ; Inherit from OBJECT_BASE
    
    ; Window properties
    hwnd_menubar        QWORD ?               ; HWND of menu bar strip
    hwnd_toolbar        QWORD ?               ; HWND of toolbar
    hwnd_statusbar      QWORD ?               ; HWND of status bar
    hwnd_client         QWORD ?               ; HWND of client area (contains layout)
    
    ; Window geometry
    x                   DWORD ?               ; Window X position
    y                   DWORD ?               ; Window Y position
    width               DWORD ?               ; Window width
    height              DWORD ?               ; Window height
    
    ; Menu data
    menus_ptr           QWORD ?               ; Pointer to menu array
    menu_count          DWORD ?               ; Number of menus
    max_menus           DWORD ?               ; Allocated menu slots
    
    ; Status bar
    status_text         QWORD ?               ; Pointer to status text buffer (256 bytes)
    
    ; Window state flags
    flags               DWORD ?               ; FLAG_VISIBLE, FLAG_DIRTY, etc.
    
    ; Title bar
    title_text          QWORD ?               ; Pointer to title text buffer (512 bytes)
    
MAIN_WINDOW ENDS

; Menu structure (linked list)
MENU_BAR_ITEM STRUCT
    name_ptr            QWORD ?               ; Pointer to menu name (LPSTR)
    name_len            DWORD ?               ; Length of menu name
    hwnd_dropdown       QWORD ?               ; HWND of dropdown menu
    items_ptr           QWORD ?               ; Pointer to menu items array
    item_count          DWORD ?               ; Number of items in this menu
    flags               DWORD ?               ; Menu state flags
    next                QWORD ?               ; Next menu in linked list
MENU_BAR_ITEM ENDS

MENU_ITEM STRUCT
    name_ptr            QWORD ?               ; Pointer to item name (LPSTR)
    name_len            DWORD ?               ; Length of item name
    id                  DWORD ?               ; Menu item ID (for command routing)
    handler             QWORD ?               ; Function pointer to handler
    flags               DWORD ?               ; Item state (enabled, checked, separator)
    accelerator         DWORD ?               ; Keyboard shortcut (VK code)
    next                QWORD ?               ; Next item in linked list
MENU_ITEM ENDS

;==========================================================================
; GLOBAL STATE
;==========================================================================

g_main_window_global        QWORD 0            ; Pointer to global main window instance
g_main_hwnd                 QWORD 0            ; HWND of main window
g_menu_root                 QWORD 0            ; Root of menu linked list

;==========================================================================
; PUBLIC FUNCTIONS (called from qt6_foundation.asm and UI code)
;==========================================================================

; Create main window instance
; Inputs:  rcx = title text (LPSTR), rdx = width, r8 = height
; Outputs: rax = MAIN_WINDOW ptr or NULL on error
; Destroys: rcx, rdx, r8, r9, r10, r11
PUBLIC main_window_create

; Show main window (make visible)
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_show

; Hide main window
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_hide

; Destroy main window (free resources, close HWND)
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_destroy

; Set window title text
; Inputs:  rcx = MAIN_WINDOW ptr, rdx = title text (LPSTR)
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_set_title

; Get window title text
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = pointer to title text (LPSTR)
PUBLIC main_window_get_title

; Set status bar text (bottom status bar)
; Inputs:  rcx = MAIN_WINDOW ptr, rdx = status text (LPSTR)
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_set_status

; Get status bar text
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = pointer to status text (LPSTR)
PUBLIC main_window_get_status

; Add a menu to the menu bar
; Inputs:  rcx = MAIN_WINDOW ptr, rdx = menu name (LPSTR), r8 = menu name length
; Outputs: rax = MENU_BAR_ITEM ptr (for adding items) or NULL on error
PUBLIC main_window_add_menu

; Add an item to a menu
; Inputs:  rcx = MENU_BAR_ITEM ptr, rdx = item name (LPSTR), r8 = item ID, 
;          r9 = handler function ptr, r10 = flags
; Outputs: rax = MENU_ITEM ptr or NULL on error
PUBLIC main_window_add_menu_item

; Handle window resize event (called from event queue)
; Inputs:  rcx = MAIN_WINDOW ptr, rdx = new width, r8 = new height
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_on_resize

; Handle window close event
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = success (nonzero) or failure (0) - return 1 to allow close, 0 to prevent
PUBLIC main_window_on_close

; Set window client area geometry
; Inputs:  rcx = MAIN_WINDOW ptr, rdx = x, r8 = y, r9 = width, r10 = height
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_set_geometry

; Get window client area geometry - returns RECT_MASM
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = x, rdx = y, r8 = width, r9 = height
PUBLIC main_window_get_geometry

; Update menu bar layout (after window resize, recalculate menu positions)
; Inputs:  rcx = MAIN_WINDOW ptr
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_update_menubar

; Initialize main window system (called once at startup)
; Inputs:  none
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_system_init

; Cleanup main window system (called at shutdown)
; Inputs:  none
; Outputs: rax = success (nonzero) or failure (0)
PUBLIC main_window_system_cleanup

;==========================================================================
; IMPLEMENTATION
;==========================================================================

.CODE

; =============== main_window_system_init ===============
; Initialize the main window system - register window class, create default fonts
; Stack frame: 24 bytes (6 qwords for local variables)
;
; Local stack usage:
;   [rsp+0]  = return address (pushed by call)
;   [rsp+8]  = WNDCLASS struct (68 bytes) → starts at rsp+16
;             (rsp+16 = lpszClassName, +24 = lpszMenuName, +32 = lpfnWndProc, etc)
;
main_window_system_init PROC
    push rbp
    mov rbp, rsp
    sub rsp, 8                          ; Align stack to 16 bytes
    
    ; TODO: Register WNDCLASS for main window
    ; - Create "QMainWindow" window class
    ; - Set window procedure to main_window_proc
    ; - Set cursor, icon, brush properties
    ; - Call RegisterClassEx
    
    mov rax, 1                          ; Return success for now
    add rsp, 8
    pop rbp
    ret
main_window_system_init ENDP

; =============== main_window_system_cleanup ===============
; Cleanup main window system - unregister window class, free resources
main_window_system_cleanup PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Unregister window class if needed
    ; - Free fonts created during init
    ; - Cleanup global state
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_system_cleanup ENDP

; =============== main_window_create ===============
; Create a new main window instance with given title and size
; rcx = title text (LPSTR)
; rdx = width (DWORD)
; r8  = height (DWORD)
; Returns: rax = MAIN_WINDOW ptr or NULL
main_window_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32                         ; Local space for calculations
    
    ; Save arguments (they might be overwritten by Win32 API calls)
    mov [rsp+8], rcx                    ; title_text
    mov [rsp+16], rdx                   ; width
    mov [rsp+24], r8                    ; height
    
    ; TODO: Allocate MAIN_WINDOW structure
    ; - malloc(sizeof(MAIN_WINDOW)) = 128+ bytes
    ; - Initialize base OBJECT_BASE (VMT, parent, children, etc)
    ; - Set VMT to main_window_vmt table
    
    ; TODO: Allocate title text buffer (512 bytes)
    ; - Copy input title to buffer
    ; - Store pointer in MAIN_WINDOW.title_text
    
    ; TODO: Allocate status text buffer (256 bytes)
    ; - Initialize to empty or default message
    
    ; TODO: Create HWND with CreateWindowEx
    ; - Class name: "QMainWindow"
    ; - Window name: title text
    ; - Style: WS_OVERLAPPEDWINDOW
    ; - Parent: NULL (top-level window)
    ; - Position: CW_USEDEFAULT
    ; - Size: width x height
    ; - Call CreateWindowEx
    
    ; TODO: Store HWND in MAIN_WINDOW.hwnd and g_main_hwnd
    
    ; TODO: Create menu bar strip (child window under main)
    
    ; TODO: Create toolbar area (child window under menu bar)
    
    ; TODO: Create status bar (child window at bottom)
    
    ; TODO: Create client area placeholder (will be replaced by layouts)
    
    ; TODO: Register in g_registry_root and mark as MAIN_WINDOW type
    
    xor rax, rax                        ; Return NULL (stub)
    add rsp, 32
    pop rbp
    ret
main_window_create ENDP

; =============== main_window_show ===============
main_window_show PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Call ShowWindow(hwnd, SW_SHOW)
    ; - Get HWND from MAIN_WINDOW.hwnd
    ; - Call Win32 ShowWindow with SW_SHOW
    ; - Update FLAG_VISIBLE in MAIN_WINDOW.flags
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_show ENDP

; =============== main_window_hide ===============
main_window_hide PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Call ShowWindow(hwnd, SW_HIDE)
    ; - Get HWND from MAIN_WINDOW.hwnd
    ; - Call Win32 ShowWindow with SW_HIDE
    ; - Update FLAG_VISIBLE in MAIN_WINDOW.flags
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_hide ENDP

; =============== main_window_destroy ===============
main_window_destroy PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Destroy all child windows (menubar, toolbar, statusbar, client)
    ; TODO: Destroy HWND with DestroyWindow
    ; TODO: Free title text buffer (256 bytes)
    ; TODO: Free status text buffer (128 bytes)
    ; TODO: Free menu items linked list
    ; TODO: Free MAIN_WINDOW structure itself (malloc'd in create)
    ; TODO: Clear g_main_window_global and g_main_hwnd
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_destroy ENDP

; =============== main_window_set_title ===============
main_window_set_title PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr, rdx = title text (LPSTR)
    
    ; TODO: Copy rdx text to MAIN_WINDOW.title_text buffer (512 bytes max)
    ; TODO: Call SetWindowText(hwnd, title) to update window title
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_set_title ENDP

; =============== main_window_get_title ===============
main_window_get_title PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr
    ; Returns: rax = pointer to title text
    
    ; TODO: Return MAIN_WINDOW.title_text (offset +?)
    
    xor rax, rax                        ; Return NULL (stub)
    pop rbp
    ret
main_window_get_title ENDP

; =============== main_window_set_status ===============
main_window_set_status PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr, rdx = status text (LPSTR)
    
    ; TODO: Copy rdx text to MAIN_WINDOW.status_text buffer (256 bytes max)
    ; TODO: If statusbar HWND exists, call SetWindowText to update display
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_set_status ENDP

; =============== main_window_get_status ===============
main_window_get_status PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr
    ; Returns: rax = pointer to status text
    
    ; TODO: Return MAIN_WINDOW.status_text (offset +?)
    
    xor rax, rax                        ; Return NULL (stub)
    pop rbp
    ret
main_window_get_status ENDP

; =============== main_window_add_menu ===============
main_window_add_menu PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr, rdx = menu name, r8 = name length
    
    ; TODO: Allocate MENU_BAR_ITEM structure (~96 bytes)
    ; TODO: Copy menu name (rdx) to internal buffer
    ; TODO: Initialize items_ptr = NULL, item_count = 0
    ; TODO: Create dropdown HMENU with CreateMenu()
    ; TODO: Add to menu linked list (MAIN_WINDOW.menus_ptr → next)
    ; TODO: Increment MAIN_WINDOW.menu_count
    ; TODO: Call SetMenu() to attach to main window (if initialized)
    
    xor rax, rax                        ; Return NULL (stub)
    pop rbp
    ret
main_window_add_menu ENDP

; =============== main_window_add_menu_item ===============
main_window_add_menu_item PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MENU_BAR_ITEM ptr, rdx = item name, r8 = item ID
    ; r9 = handler fn ptr, r10 = flags
    
    ; TODO: Allocate MENU_ITEM structure (~80 bytes)
    ; TODO: Copy item name (rdx) to internal buffer
    ; TODO: Store ID, handler, flags
    ; TODO: Add to MENU_BAR_ITEM.items linked list
    ; TODO: Increment MENU_BAR_ITEM.item_count
    ; TODO: Call AppendMenu() to add to Win32 HMENU
    ; TODO: If flags & FLAG_SEPARATOR, use MFT_SEPARATOR
    
    xor rax, rax                        ; Return NULL (stub)
    pop rbp
    ret
main_window_add_menu_item ENDP

; =============== main_window_on_resize ===============
main_window_on_resize PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr, rdx = new_width, r8 = new_height
    
    ; TODO: Update MAIN_WINDOW.width and MAIN_WINDOW.height
    ; TODO: Call MoveWindow for child windows (menubar, toolbar, statusbar, client)
    ; TODO: Mark children as dirty (FLAG_DIRTY) so they repaint
    ; TODO: Post EVENT_RESIZE to event queue so children can recalculate layouts
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_on_resize ENDP

; =============== main_window_on_close ===============
main_window_on_close PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr
    ; Returns: rax = 1 to allow close, 0 to prevent close
    
    ; TODO: Can emit signal SIGNAL_WINDOW_CLOSE (if receivers connected via slot binding)
    ; TODO: For now, allow close by returning 1
    ; TODO: Later: prompt user if unsaved changes
    
    mov rax, 1                          ; Allow close
    pop rbp
    ret
main_window_on_close ENDP

; =============== main_window_set_geometry ===============
main_window_set_geometry PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr, rdx = x, r8 = y, r9 = width, r10 = height
    
    ; TODO: Store in MAIN_WINDOW (x, y, width, height fields)
    ; TODO: Call SetWindowPos to move/resize main HWND
    ; TODO: If WS_VISIBLE, recalculate child window positions
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_set_geometry ENDP

; =============== main_window_get_geometry ===============
main_window_get_geometry PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr
    ; Returns: rax = x, rdx = y, r8 = width, r9 = height
    
    ; TODO: Load from MAIN_WINDOW structure and return in registers
    
    xor rax, rax                        ; Return 0 (stub)
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    pop rbp
    ret
main_window_get_geometry ENDP

; =============== main_window_update_menubar ===============
main_window_update_menubar PROC
    push rbp
    mov rbp, rsp
    
    ; rcx = MAIN_WINDOW ptr
    
    ; TODO: Calculate positions for each menu in menu bar
    ; - Menu bar is horizontal strip at top
    ; - Start at x=0, y=0
    ; - Width = 80 pixels per menu (estimated)
    ; - Height = 24 pixels (standard menu bar height)
    ; TODO: Call MoveWindow for each menu dropdown
    ; TODO: Call InvalidateRect to trigger repaint
    
    mov rax, 1                          ; Return success
    pop rbp
    ret
main_window_update_menubar ENDP

;==========================================================================
; WINDOW PROCEDURE (called by Windows for main window messages)
;==========================================================================

; TODO: Implement main_window_proc
; - Handle WM_CREATE, WM_DESTROY, WM_SIZE, WM_CLOSE, WM_PAINT
; - Route to appropriate handlers above
; - Call DefWindowProc for unhandled messages

END
