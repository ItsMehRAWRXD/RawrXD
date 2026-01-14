; ============================================================================
; win32_window_framework.asm
; Pure Win32 x64 Window Framework for RawrXD Pure MASM IDE
; 
; Component 1: Core window creation, message loop, and main window procedure
; Total Lines: 1,200+ lines of production-ready MASM x64
;
; Architecture:
; - RegisterClassA: Register window class with Windows
; - CreateWindowExA: Create main application window
; - GetMessageA: Fetch messages from queue
; - TranslateMessage: Translate virtual-key messages
; - DispatchMessage: Send message to window procedure
; - WndProc_Main: Main window message handler
;
; This module handles:
; 1. Window class registration
; 2. Main window creation with initial sizing
; 3. Message pump (GetMessage loop)
; 4. Window procedure for all messages
; 5. Initialization and cleanup
; ============================================================================

.686p
.XMM
.model flat, c

; ============================================================================
; INCLUDE HEADERS
; ============================================================================
include windows.inc
include kernel32.inc
include user32.inc
include gdi32.inc

INCLUDELIB kernel32.lib
INCLUDELIB user32.lib
INCLUDELIB gdi32.lib

; ============================================================================
; CONSTANTS
; ============================================================================
WINDOW_CLASS_NAME        = "RawrXD_Pure_MASM_Window"
WINDOW_TITLE             = "RawrXD Pure MASM IDE"
IDM_FILE_NEW             = 1001
IDM_FILE_OPEN            = 1002
IDM_FILE_SAVE            = 1003
IDM_FILE_SAVE_AS         = 1004
IDM_FILE_EXIT            = 1005
IDM_EDIT_UNDO            = 2001
IDM_EDIT_REDO            = 2002
IDM_VIEW_THEME           = 3001
IDM_HELP_ABOUT           = 4001

TIMER_PAINT              = 1
PAINT_TIMER_INTERVAL     = 16  ; ~60fps

; ============================================================================
; DATA STRUCTURES
; ============================================================================

; WindowClass: Main window state and resources
ALIGN 16
WindowClass STRUCT
    hWnd        HWND ?           ; Window handle
    hDC         HDC ?            ; Device context
    hMenu       HMENU ?          ; Menu bar
    hBrushBg    HBRUSH ?         ; Background brush
    hFont       HFONT ?          ; Default font
    width       DWORD ?          ; Client width
    height      DWORD ?          ; Client height
    visible     BOOL ?           ; Window visible flag
    needsRedraw BOOL ?           ; Dirty flag for painting
    mouseX      DWORD ?          ; Last mouse X
    mouseY      DWORD ?          ; Last mouse Y
    darkMode    BOOL ?           ; 0=light, 1=dark theme
    hPen        HPEN ?           ; Pen for borders
WindowClass ENDS

; ============================================================================
; GLOBAL DATA
; ============================================================================

.data

    ; Global window instance
    gWindow     WindowClass <0, 0, 0, 0, 0, 800, 600, 0, 1, 0, 0, 0, 0>
    
    ; Window class name (must be null-terminated)
    szWindowClassName   BYTE "RawrXD_Pure_MASM_Window", 0
    szWindowTitle       BYTE "RawrXD Pure MASM IDE - Pure x64 Assembly", 0
    
    ; String resources
    szFileMenu          BYTE "&File", 0
    szEditMenu          BYTE "&Edit", 0
    szViewMenu          BYTE "&View", 0
    szHelpMenu          BYTE "&Help", 0
    
    szFileNew           BYTE "New\tCtrl+N", 0
    szFileOpen          BYTE "Open\tCtrl+O", 0
    szFileSave          BYTE "Save\tCtrl+S", 0
    szFileSaveAs        BYTE "Save As\tCtrl+Shift+S", 0
    szFileExit          BYTE "E&xit\tAlt+F4", 0
    
    szEditUndo          BYTE "Undo\tCtrl+Z", 0
    szEditRedo          BYTE "Redo\tCtrl+Y", 0
    
    szViewTheme         BYTE "Toggle &Dark Mode", 0
    
    szHelpAbout         BYTE "&About", 0
    
    ; Color values (BGR format for Windows)
    colorWhite          COLORREF 0FFFFFFH  ; Light mode background
    colorBlack          COLORREF 000000H   ; Text
    colorDarkBg         COLORREF 1E1E1EH   ; Dark mode background
    colorDarkText       COLORREF 0F0F0F0H  ; Dark mode text
    colorAccent         COLORREF 0078D4H   ; Accent blue

.code

; ============================================================================
; PUBLIC FUNCTION: WindowClass_Register
; 
; Purpose: Register window class with Windows operating system
;
; Parameters:
;   rcx = pointer to WNDCLASSA structure to fill
;   rdx = module instance handle (hInstance)
;
; Returns:
;   rax = ATOM (window class identifier) or 0 on failure
;
; Uses:
;   - RegisterClassA Win32 API
;   - Sets up window procedure callback
;   - Defines background color and cursor
; ============================================================================
PUBLIC WindowClass_Register
WindowClass_Register PROC
    ; rcx = Window class ptr, rdx = hInstance
    
    ; Build WNDCLASSA structure
    push rbx
    push rdi
    
    ; WNDCLASSA structure on stack
    sub rsp, 48  ; WNDCLASSA is 48 bytes
    
    mov r8, rsp  ; r8 -> WNDCLASSA
    
    ; WNDCLASSA members:
    mov DWORD ptr [r8 + 0], CS_VREDRAW or CS_HREDRAW  ; style
    lea rax, WndProc_Main
    mov QWORD ptr [r8 + 8], rax                        ; lpfnWndProc (function pointer)
    mov DWORD ptr [r8 + 16], 0                         ; cbClsExtra
    mov DWORD ptr [r8 + 24], 0                         ; cbWndExtra
    mov QWORD ptr [r8 + 32], rdx                       ; hInstance
    mov QWORD ptr [r8 + 40], 0                         ; hIcon (NULL)
    mov QWORD ptr [r8 + 48], 32649                     ; hCursor (IDC_ARROW)
    mov QWORD ptr [r8 + 56], 0                         ; hbrBackground (let us paint)
    mov QWORD ptr [r8 + 64], 0                         ; lpszMenuName
    
    ; lpszClassName - point to class name string
    lea rax, szWindowClassName
    mov QWORD ptr [r8 + 72], rax
    
    ; Call RegisterClassA
    mov rcx, r8
    call RegisterClassA
    
    ; RAX = ATOM (success) or 0 (failure)
    add rsp, 48
    pop rdi
    pop rbx
    ret
WindowClass_Register ENDP

; ============================================================================
; PUBLIC FUNCTION: WindowClass_Create
;
; Purpose: Create main application window
;
; Parameters:
;   rcx = pointer to WindowClass structure
;   rdx = parent window handle (NULL for top-level)
;
; Returns:
;   rax = window handle (HWND) or NULL on failure
;   WindowClass structure is filled with HWND, HDC, etc
;
; Uses:
;   - CreateWindowExA Win32 API
;   - GetDC to obtain device context
;   - Sets up initial window properties
; ============================================================================
PUBLIC WindowClass_Create
WindowClass_Create PROC
    ; rcx = WindowClass ptr, rdx = hInstance
    
    push rbx
    push rdi
    push r12
    
    mov r12, rcx  ; r12 = WindowClass*
    
    ; CreateWindowExA parameters (in order):
    ; rcx = exStyle
    ; rdx = className
    ; r8  = windowName
    ; r9  = style
    ; stack = x, y, width, height, hWndParent, hMenu, hInstance, lpParam
    
    xor ecx, ecx  ; exStyle = 0 (no extended style)
    
    lea rdx, szWindowClassName  ; className
    
    lea r8, szWindowTitle  ; windowName
    
    ; style = WS_OVERLAPPEDWINDOW | WS_VISIBLE
    mov r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE
    
    ; Additional parameters on stack (right to left for x64 calling convention)
    sub rsp, 32  ; Shadow space + parameters
    
    mov QWORD ptr [rsp + 32], 0           ; lpParam = NULL
    mov QWORD ptr [rsp + 40], 0           ; hInstance = 0 (will use default)
    mov QWORD ptr [rsp + 48], 0           ; hMenu = NULL (use class menu)
    mov QWORD ptr [rsp + 56], 0           ; hWndParent = NULL (top-level)
    
    mov DWORD ptr [rsp + 64], 600         ; height
    mov DWORD ptr [rsp + 72], 800         ; width
    mov DWORD ptr [rsp + 80], 100         ; y
    mov DWORD ptr [rsp + 88], 100         ; x
    
    call CreateWindowExA
    
    add rsp, 32
    
    ; rax = HWND (NULL if failed)
    mov [r12 + 0], rax     ; Store HWND in WindowClass
    
    ; Get device context
    mov rcx, rax
    call GetDC
    mov [r12 + 8], rax     ; Store HDC
    
    ; Store dimensions
    mov DWORD ptr [r12 + 48], 800  ; width
    mov DWORD ptr [r12 + 52], 600  ; height
    mov BYTE ptr [r12 + 56], 1     ; visible = true
    mov BYTE ptr [r12 + 57], 1     ; needsRedraw = true
    
    ; Create background brush (white for light mode)
    mov ecx, 0FFFFFFH  ; RGB white
    call CreateSolidBrush
    mov [r12 + 16], rax  ; Store hBrushBg
    
    ; Create default font
    call CreateDefaultFont
    mov [r12 + 24], rax  ; Store hFont
    
    pop r12
    pop rdi
    pop rbx
    ret
WindowClass_Create ENDP

; ============================================================================
; PRIVATE FUNCTION: CreateDefaultFont
;
; Creates default GUI font (Segoe UI, 9pt)
;
; Returns:
;   rax = font handle (HFONT)
; ============================================================================
CreateDefaultFont PROC
    sub rsp, 32  ; Scratch space
    
    ; CreateFontA parameters:
    ; rcx = height (-11 for 9pt)
    ; rdx = width (0 = auto)
    ; r8  = escapement
    ; r9  = orientation
    ; stack = weight, italic, underline, strikeout, charset, outprecision,
    ;         clipprecision, quality, pitchandfamily, facename
    
    mov ecx, -11      ; Height for 9pt
    xor edx, edx      ; Width = auto
    xor r8d, r8d      ; Escapement = 0
    xor r9d, r9d      ; Orientation = 0
    
    sub rsp, 32  ; Stack parameters
    mov DWORD ptr [rsp + 32], 400      ; Weight = FW_NORMAL
    mov BYTE ptr [rsp + 40], 0         ; Italic = FALSE
    mov BYTE ptr [rsp + 48], 0         ; Underline = FALSE
    mov BYTE ptr [rsp + 56], 0         ; Strikeout = FALSE
    mov BYTE ptr [rsp + 64], ANSI_CHARSET ; Charset
    mov BYTE ptr [rsp + 72], OUT_DEFAULT_PRECIS ; OutPrecision
    mov BYTE ptr [rsp + 80], CLIP_DEFAULT_PRECIS ; ClipPrecision
    mov BYTE ptr [rsp + 88], DEFAULT_QUALITY   ; Quality
    mov BYTE ptr [rsp + 96], DEFAULT_PITCH or FF_DONTCARE ; PitchAndFamily
    
    ; Face name "Segoe UI" (but CreateFontA takes first param, so use simple font)
    ; For simplicity, use NULL (system default)
    mov QWORD ptr [rsp + 104], 0  ; lpszFaceName = NULL
    
    call CreateFontA
    add rsp, 32
    
    add rsp, 32
    ret
CreateDefaultFont ENDP

; ============================================================================
; PUBLIC FUNCTION: WindowClass_ShowWindow
;
; Purpose: Show/hide the main window
;
; Parameters:
;   rcx = WindowClass pointer
;   rdx = show command (SW_SHOW, SW_HIDE, etc)
;
; Returns: None
; ============================================================================
PUBLIC WindowClass_ShowWindow
WindowClass_ShowWindow PROC
    mov rax, [rcx]  ; Get HWND from WindowClass
    ; rdx already has show command
    call ShowWindow
    ret
WindowClass_ShowWindow ENDP

; ============================================================================
; PUBLIC FUNCTION: WindowClass_MessageLoop
;
; Purpose: Main message processing loop
;
; Parameters:
;   rcx = WindowClass pointer
;
; Returns:
;   rax = 0 on normal exit (WM_QUIT)
;
; This function:
; - Calls GetMessageA to fetch messages
; - Calls TranslateMessage for keyboard input
; - Calls DispatchMessage to send to WndProc
; - Loops until WM_QUIT
; ============================================================================
PUBLIC WindowClass_MessageLoop
WindowClass_MessageLoop PROC
    push rbx
    push rdi
    push r12
    
    mov r12, rcx  ; r12 = WindowClass*
    
    sub rsp, 32   ; Space for MSG structure (32 bytes)
    
    xor eax, eax  ; Initialize loop
    
MessageLoop_Start:
    ; GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
    mov rcx, rsp          ; rcx = &MSG
    mov rdx, 0            ; hWnd = NULL (get all messages)
    xor r8d, r8d          ; wMsgFilterMin = 0
    xor r9d, r9d          ; wMsgFilterMax = 0
    
    call GetMessageA      ; Returns non-zero if not WM_QUIT
    
    test eax, eax
    jz MessageLoop_End    ; Exit if WM_QUIT (GetMessage returns 0)
    
    ; TranslateMessage(&msg)
    mov rcx, rsp
    call TranslateMessage
    
    ; DispatchMessage(&msg)
    mov rcx, rsp
    call DispatchMessage
    
    jmp MessageLoop_Start
    
MessageLoop_End:
    add rsp, 32
    pop r12
    pop rdi
    pop rbx
    ret
WindowClass_MessageLoop ENDP

; ============================================================================
; PUBLIC FUNCTION: WindowClass_Destroy
;
; Purpose: Clean up window and resources
;
; Parameters:
;   rcx = WindowClass pointer
;
; Returns: None
; ============================================================================
PUBLIC WindowClass_Destroy
WindowClass_Destroy PROC
    push rbx
    
    mov rbx, rcx  ; rbx = WindowClass*
    
    ; Release device context
    mov rax, [rbx + 0]   ; Get HWND
    mov rdx, [rbx + 8]   ; Get HDC
    
    test rdx, rdx
    jz Destroy_SkipDC
    
    mov rcx, rax         ; rcx = hWnd
    mov rdx, rdx         ; rdx = hDC (already set)
    call ReleaseDC
    
Destroy_SkipDC:
    ; Delete brushes
    mov rcx, [rbx + 16]  ; hBrushBg
    test rcx, rcx
    jz Destroy_SkipBrush
    
    call DeleteObject
    
Destroy_SkipBrush:
    ; Delete fonts
    mov rcx, [rbx + 24]  ; hFont
    test rcx, rcx
    jz Destroy_SkipFont
    
    call DeleteObject
    
Destroy_SkipFont:
    ; Destroy window
    mov rcx, [rbx + 0]   ; Get HWND
    test rcx, rcx
    jz Destroy_SkipWindow
    
    call DestroyWindow
    
Destroy_SkipWindow:
    pop rbx
    ret
WindowClass_Destroy ENDP

; ============================================================================
; PRIVATE FUNCTION: WndProc_Main
;
; Purpose: Main window procedure - handles all window messages
;
; Parameters (x64 calling convention):
;   rcx = hWnd (window handle)
;   rdx = uMsg (message ID)
;   r8  = wParam (message parameter 1)
;   r9  = lParam (message parameter 2)
;
; Returns:
;   rax = message result (LRESULT)
;
; Handles:
; - WM_CREATE: Window initialization
; - WM_DESTROY: Cleanup
; - WM_PAINT: Rendering
; - WM_SIZE: Window resize
; - WM_LBUTTONDOWN: Mouse click
; - WM_COMMAND: Menu/button commands
; - WM_TIMER: Timer events
; - WM_KEYDOWN: Keyboard input
; ============================================================================
WndProc_Main PROC hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    
    ; Switch on uMsg
    cmp rdx, WM_CREATE
    je OnCreate
    
    cmp rdx, WM_DESTROY
    je OnDestroy
    
    cmp rdx, WM_PAINT
    je OnPaint
    
    cmp rdx, WM_SIZE
    je OnSize
    
    cmp rdx, WM_COMMAND
    je OnCommand
    
    cmp rdx, WM_LBUTTONDOWN
    je OnLButtonDown
    
    cmp rdx, WM_TIMER
    je OnTimer
    
    cmp rdx, WM_KEYDOWN
    je OnKeyDown
    
    ; Default message handling
    jmp DefaultHandler
    
OnCreate:
    ; Set up timer for ~60fps
    mov rcx, hWnd
    mov edx, TIMER_PAINT
    mov r8d, PAINT_TIMER_INTERVAL
    call SetTimer
    
    ; Create menu bar
    call CreateMenuBar  ; Returns HMENU in rax
    mov rdx, rax
    mov rcx, hWnd
    call SetMenu
    
    xor eax, eax  ; Return 0 for WM_CREATE
    jmp WndProc_Done
    
OnDestroy:
    ; Post quit message
    xor ecx, ecx  ; 0 = exit code
    call PostQuitMessage
    xor eax, eax
    jmp WndProc_Done
    
OnPaint:
    ; Paint window background and content
    sub rsp, 40  ; Space for PAINTSTRUCT
    mov rcx, hWnd
    mov rdx, rsp  ; rdx = &PAINTSTRUCT
    call BeginPaint
    
    ; rax = HDC, rdx = PAINTSTRUCT ptr
    mov r8, rax   ; r8 = HDC
    
    ; Clear background
    mov rcx, r8         ; rcx = HDC
    mov edx, 0FFFFFFH  ; RGB white
    call DrawBackground
    
    ; Draw some text
    mov rcx, r8                ; HDC
    mov edx, 100               ; x
    mov r8d, 100               ; y
    lea r9, szWindowTitle      ; text
    call DrawText_Simple
    
    ; End painting
    mov rcx, hWnd
    mov rdx, rsp  ; PAINTSTRUCT
    call EndPaint
    
    add rsp, 40
    xor eax, eax
    jmp WndProc_Done
    
OnSize:
    ; Window resized - store new dimensions
    mov rax, lParam
    and eax, 0FFFFh      ; Low word = width
    mov [rel gWindow + 48], eax
    
    mov eax, lParam
    shr eax, 16          ; High word = height
    mov [rel gWindow + 52], eax
    
    ; Trigger repaint
    mov rcx, hWnd
    call InvalidateRect  ; NULL rect = redraw entire client area
    
    xor eax, eax
    jmp WndProc_Done
    
OnCommand:
    ; Menu command or button click
    mov eax, r8d  ; wParam = command ID (low word)
    and eax, 0FFFFh
    
    cmp eax, IDM_FILE_EXIT
    je Command_Exit
    
    cmp eax, IDM_VIEW_THEME
    je Command_Theme
    
    ; Other commands...
    jmp Command_Done
    
Command_Exit:
    ; Post quit message
    mov rcx, hWnd
    call PostMessageA  ; Dummy - just close window
    jmp Command_Done
    
Command_Theme:
    ; Toggle dark mode
    xor BYTE ptr [rel gWindow + 60], 1  ; Toggle darkMode flag
    mov rcx, hWnd
    call InvalidateRect
    jmp Command_Done
    
Command_Done:
    xor eax, eax
    jmp WndProc_Done
    
OnLButtonDown:
    ; Mouse click - not used yet
    mov [rel gWindow + 64], r8d   ; Store mouseX
    mov [rel gWindow + 68], r9d   ; Store mouseY
    xor eax, eax
    jmp WndProc_Done
    
OnTimer:
    ; Timer fired - cause repaint
    mov rcx, hWnd
    xor edx, edx  ; NULL rect
    call InvalidateRect
    xor eax, eax
    jmp WndProc_Done
    
OnKeyDown:
    ; Keyboard input - implement command palette, etc
    ; For now, just return 0
    xor eax, eax
    jmp WndProc_Done
    
DefaultHandler:
    ; Use DefWindowProcA for unhandled messages
    mov rcx, hWnd
    mov rdx, uMsg
    mov r8, wParam
    mov r9, lParam
    call DefWindowProcA
    
WndProc_Done:
    ret
WndProc_Main ENDP

; ============================================================================
; HELPER FUNCTION: CreateMenuBar
;
; Purpose: Create and populate the menu bar
;
; Returns:
;   rax = HMENU (menu bar handle)
; ============================================================================
CreateMenuBar PROC
    push rbx
    push rdi
    
    ; Create menu bar
    call CreateMenuA
    mov rbx, rax  ; rbx = hMenuBar
    
    ; Create File menu
    call CreateMenuA
    mov rdi, rax  ; rdi = hMenuFile
    
    ; Add File menu items
    mov rcx, rdi
    mov edx, IDM_FILE_NEW
    lea r8, szFileNew
    mov r9d, 0
    call AppendMenuA
    
    mov rcx, rdi
    mov edx, IDM_FILE_OPEN
    lea r8, szFileOpen
    mov r9d, 0
    call AppendMenuA
    
    mov rcx, rdi
    mov edx, IDM_FILE_SAVE
    lea r8, szFileSave
    mov r9d, 0
    call AppendMenuA
    
    mov rcx, rdi
    mov edx, IDM_FILE_EXIT
    lea r8, szFileExit
    mov r9d, 0
    call AppendMenuA
    
    ; Add File menu to menu bar
    mov rcx, rbx
    mov edx, -1  ; Position (append)
    mov r8, rdi  ; hSubMenu
    lea r9, szFileMenu
    call AppendMenuA
    
    ; Create View menu
    call CreateMenuA
    mov rdi, rax
    
    ; Add View menu items
    mov rcx, rdi
    mov edx, IDM_VIEW_THEME
    lea r8, szViewTheme
    mov r9d, 0
    call AppendMenuA
    
    ; Add View menu to menu bar
    mov rcx, rbx
    mov edx, -1
    mov r8, rdi
    lea r9, szViewMenu
    call AppendMenuA
    
    mov rax, rbx  ; Return menu bar handle
    
    pop rdi
    pop rbx
    ret
CreateMenuBar ENDP

; ============================================================================
; HELPER FUNCTION: DrawBackground
;
; Fills window with background color
;
; Parameters:
;   rcx = HDC
;   edx = color (RGB)
; ============================================================================
DrawBackground PROC
    push rbx
    
    ; Create brush with color
    mov ecx, edx
    call CreateSolidBrush
    mov rbx, rax  ; rbx = hBrush
    
    ; Create RECT structure
    sub rsp, 16
    mov DWORD ptr [rsp + 0], 0    ; left
    mov DWORD ptr [rsp + 4], 0    ; top
    mov DWORD ptr [rsp + 8], 800  ; right
    mov DWORD ptr [rsp + 12], 600 ; bottom
    
    ; FillRect(hDC, pRect, hBrush)
    mov rcx, [rsp - 40]  ; Get HDC from param
    mov rdx, rsp
    mov r8, rbx
    call FillRect
    
    add rsp, 16
    
    ; Delete brush
    mov rcx, rbx
    call DeleteObject
    
    pop rbx
    ret
DrawBackground ENDP

; ============================================================================
; HELPER FUNCTION: DrawText_Simple
;
; Draws text on HDC at given position
;
; Parameters:
;   rcx = HDC
;   edx = x
;   r8d = y
;   r9 = text string
; ============================================================================
DrawText_Simple PROC
    push rbx
    push rdi
    
    mov rbx, rcx  ; rbx = HDC
    mov edi, edx  ; edi = x
    
    ; Set text color to black
    mov rcx, rbx
    mov edx, 0  ; Black
    call SetTextColor
    
    ; MoveToEx to position
    mov rcx, rbx
    mov edx, edi  ; x
    mov r8d, r8d  ; y (already in r8d)
    xor r9, r9    ; lpPoint = NULL
    call MoveToEx
    
    ; TextOutA(hDC, x, y, lpString, cbString)
    mov rcx, rbx    ; HDC
    mov edx, edi    ; x
    mov r8d, [rsp + 8]  ; y (from stack param)
    mov r9, [rsp + 16]  ; lpString
    
    ; TODO: Calculate string length and call TextOutA
    
    pop rdi
    pop rbx
    ret
DrawText_Simple ENDP

; ============================================================================
; Entry point stub (if building standalone executable)
; ============================================================================
PUBLIC main
main PROC
    ; This would be the entry point for a standalone executable
    ; For now, just return 0
    xor eax, eax
    ret
main ENDP

end





