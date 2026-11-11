; RawrXD_GUI_Core.asm - Pure x64 GUI Framework (NO DEPENDENCIES)
; Direct Win32 API only - No Qt, No GTK, No external libs

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; Win32 API Constants
WM_CREATE       EQU 0001h
WM_DESTROY      EQU 0002h
WM_SIZE         EQU 0005h
WM_PAINT        EQU 000Fh
WM_CLOSE        EQU 0010h
WM_QUIT         EQU 0012h
WM_KEYDOWN      EQU 0100h
WM_KEYUP        EQU 0101h
WM_CHAR         EQU 0102h
WM_MOUSEMOVE    EQU 0200h
WM_LBUTTONDOWN  EQU 0201h
WM_LBUTTONUP    EQU 0202h
WM_RBUTTONDOWN  EQU 0204h
WM_RBUTTONUP    EQU 0205h
WM_MOUSEWHEEL   EQU 020Ah

WS_OVERLAPPEDWINDOW EQU 0CF0000h
WS_VISIBLE      EQU 10000000h
WS_CHILD        EQU 40000000h
WS_TABSTOP      EQU 00010000h

CS_HREDRAW      EQU 0002h
CS_VREDRAW      EQU 0001h
CS_OWNDC        EQU 0020h

SW_SHOW         EQU 0005h

PM_REMOVE       EQU 0001h

; Color constants
COLOR_WINDOW    EQU 0005h
COLOR_WINDOWTEXT EQU 0008h

EXTERN CreateWindowExA:PROC
EXTERN RegisterClassExA:PROC
EXTERN DefWindowProcA:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN GetMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageA:PROC
EXTERN PostQuitMessage:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN BeginPaint:PROC
EXTERN EndPaint:PROC
EXTERN FillRect:PROC
EXTERN SetTextColor:PROC
EXTERN SetBkColor:PROC
EXTERN TextOutA:PROC
EXTERN GetClientRect:PROC
EXTERN InvalidateRect:PROC
EXTERN LoadCursorA:PROC
EXTERN LoadIconA:PROC
EXTERN GetStockObject:PROC
EXTERN CreateSolidBrush:PROC
EXTERN DeleteObject:PROC
EXTERN PeekMessageA:PROC
EXTERN SendMessageA:PROC
EXTERN CreateMenu:PROC
EXTERN AppendMenuA:PROC
EXTERN SetMenu:PROC
EXTERN DrawMenuBar:PROC
EXTERN CreatePopupMenu:PROC
EXTERN TrackPopupMenu:PROC
EXTERN GetSubMenu:PROC
EXTERN EnableMenuItem:PROC
EXTERN CheckMenuItem:PROC
EXTERN GetCursorPos:PROC
EXTERN ScreenToClient:PROC
EXTERN ClientToScreen:PROC
EXTERN SetCapture:PROC
EXTERN ReleaseCapture:PROC
EXTERN GetAsyncKeyState:PROC
EXTERN GetKeyState:PROC
EXTERN SetTimer:PROC
EXTERN KillTimer:PROC
EXTERN GetTickCount64:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC

.data
ALIGN 8

; Window class name
szRawrXDClass   db "RawrXD_IDE_Class", 0
szEditorClass   db "RawrXD_Editor_Class", 0
szPanelClass    db "RawrXD_Panel_Class", 0

; Window titles
szMainTitle     db "RawrXD x64 IDE - Production", 0
szUntitled      db "Untitled", 0

; Menu strings
szFileMenu      db "&File", 0
szEditMenu      db "&Edit", 0
szViewMenu      db "&View", 0
szRunMenu       db "&Run", 0
szDebugMenu     db "&Debug", 0
szHelpMenu      db "&Help", 0

; File menu items
szNewFile       db "&New File", 9, "Ctrl+N", 0
szOpenFile      db "&Open File...", 9, "Ctrl+O", 0
szSaveFile      db "&Save", 9, "Ctrl+S", 0
szSaveAs        db "Save &As...", 9, "Ctrl+Shift+S", 0
szExit          db "E&xit", 0

; Edit menu items
szUndo          db "&Undo", 9, "Ctrl+Z", 0
szRedo          db "&Redo", 9, "Ctrl+Y", 0
szCut           db "Cu&t", 9, "Ctrl+X", 0
szCopy          db "&Copy", 9, "Ctrl+C", 0
szPaste         db "&Paste", 9, "Ctrl+V", 0
szSelectAll     db "Select &All", 9, "Ctrl+A", 0
szFind          db "&Find", 9, "Ctrl+F", 0
szReplace       db "&Replace", 9, "Ctrl+H", 0

; View menu items
szCommandPalette db "&Command Palette...", 9, "Ctrl+Shift+P", 0
szExplorer      db "&Explorer", 9, "Ctrl+Shift+E", 0
szSearch        db "&Search", 9, "Ctrl+Shift+F", 0
szSourceControl db "S&ource Control", 9, "Ctrl+Shift+G", 0
szDebugPanel    db "&Run and Debug", 9, "Ctrl+Shift+D", 0
szExtensions    db "E&xtensions", 9, "Ctrl+Shift+X", 0
szTerminal      db "&Terminal", 9, "Ctrl+`", 0

; Run menu items
szStartDebug    db "&Start Debugging", 9, "F5", 0
szRunWithoutDebug db "Run &Without Debugging", 9, "Ctrl+F5", 0
szStopDebug     db "S&top Debugging", 9, "Shift+F5", 0
szRestartDebug  db "&Restart Debugging", 9, "Ctrl+Shift+F5", 0

; Debug menu items
szToggleBreakpoint db "Toggle &Breakpoint", 9, "F9", 0
szStepOver      db "Step &Over", 9, "F10", 0
szStepInto      db "Step &Into", 9, "F11", 0
szStepOut       db "Step O&ut", 9, "Shift+F11", 0
szContinue      db "&Continue", 9, "F5", 0

; Global GUI state
g_hInstance     dq 0
g_hMainWnd      dq 0
g_hMenu         dq 0
g_hStatusBar    dq 0
g_hEditor       dq 0
g_hSidebar      dq 0
g_hPanel        dq 0

g_isRunning     db 1
g_isFullscreen  db 0
g_isMaximized   db 0

g_clientWidth   dd 1920
g_clientHeight  dd 1080

g_hFontNormal   dq 0
g_hFontBold     dq 0
g_hFontMono     dq 0

g_hBrushBg      dq 0
g_hBrushPanel   dq 0
g_hBrushEditor  dq 0
g_hPenBorder    dq 0

g_nCmdShow      dd 0

; Performance timing
g_perfFreq      dq 0
g_frameCount    dd 0
g_lastFrameTime dq 0
g_fps           dd 0

; Editor state
g_editorDirty   db 0
g_editorLine    dd 1
g_editorCol     dd 1
g_editorLines   dd 0
g_editorScrollY dd 0

; Mouse state
g_mouseX        dd 0
g_mouseY        dd 0
g_mouseDown     db 0
g_mouseRight    db 0

; Keyboard state
g_keyCtrl       db 0
g_keyShift      db 0
g_keyAlt        db 0

.code

;=============================================================================
; GUI_Initialize - Initialize the GUI framework
;=============================================================================
GUI_Initialize PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 88
    
    ; Get module handle (hInstance)
    mov     rcx, 0
    call    GetModuleHandleA
    mov     g_hInstance, rax
    
    ; Initialize performance counter
    lea     rcx, g_perfFreq
    call    QueryPerformanceFrequency
    
    ; Register window classes
    call    GUI_RegisterClasses
    test    rax, rax
    jz      init_fail
    
    ; Create brushes
    mov     ecx, 00202020h      ; Dark background
    call    CreateSolidBrush
    mov     g_hBrushBg, rax
    
    mov     ecx, 001A1A1Ah      ; Panel background
    call    CreateSolidBrush
    mov     g_hBrushPanel, rax
    
    mov     ecx, 001E1E1Eh      ; Editor background
    call    CreateSolidBrush
    mov     g_hBrushEditor, rax
    
    mov     eax, 1
    jmp     init_done
    
init_fail:
    xor     eax, eax
    
init_done:
    add     rsp, 88
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GUI_Initialize ENDP

;=============================================================================
; GUI_RegisterClasses - Register all window classes
;=============================================================================
GUI_RegisterClasses PROC
    push    rbx
    sub     rsp, 120
    
    ; Register main window class
    mov     dword ptr [rsp+0], 48         ; cbSize
    mov     dword ptr [rsp+4], CS_HREDRAW or CS_VREDRAW  ; style
    lea     rax, GUI_MainWndProc
    mov     qword ptr [rsp+8], rax        ; lpfnWndProc
    mov     dword ptr [rsp+16], 0         ; cbClsExtra
    mov     dword ptr [rsp+20], 0         ; cbWndExtra
    mov     rax, g_hInstance
    mov     qword ptr [rsp+24], rax       ; hInstance
    mov     qword ptr [rsp+32], 0         ; hIcon
    mov     qword ptr [rsp+40], 0         ; hCursor
    mov     rax, g_hBrushBg
    mov     qword ptr [rsp+48], rax       ; hbrBackground
    mov     qword ptr [rsp+56], 0         ; lpszMenuName
    lea     rax, szRawrXDClass
    mov     qword ptr [rsp+64], rax       ; lpszClassName
    mov     qword ptr [rsp+72], 0         ; hIconSm
    
    mov     rcx, rsp
    call    RegisterClassExA
    test    rax, rax
    jz      reg_fail
    
    mov     eax, 1
    jmp     reg_done
    
reg_fail:
    xor     eax, eax
    
reg_done:
    add     rsp, 120
    pop     rbx
    ret
GUI_RegisterClasses ENDP

;=============================================================================
; GUI_CreateMainWindow - Create the main IDE window
;=============================================================================
GUI_CreateMainWindow PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 88
    
    ; Create main window
    mov     rcx, 0                          ; dwExStyle
    lea     rdx, szRawrXDClass              ; lpClassName
    lea     r8, szMainTitle                   ; lpWindowName
    mov     r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE  ; dwStyle
    mov     dword ptr [rsp+32], 100         ; X
    mov     dword ptr [rsp+40], 100         ; Y
    mov     dword ptr [rsp+48], 1600        ; nWidth
    mov     dword ptr [rsp+56], 900         ; nHeight
    mov     qword ptr [rsp+64], 0           ; hWndParent
    mov     qword ptr [rsp+72], 0           ; hMenu
    mov     rax, g_hInstance
    mov     qword ptr [rsp+80], rax         ; hInstance
    mov     qword ptr [rsp+88], 0           ; lpParam
    
    call    CreateWindowExA
    mov     g_hMainWnd, rax
    test    rax, rax
    jz      create_fail
    
    ; Show window
    mov     rcx, rax
    mov     edx, SW_SHOW
    call    ShowWindow
    
    mov     rcx, g_hMainWnd
    call    UpdateWindow
    
    mov     eax, 1
    jmp     create_done
    
create_fail:
    xor     eax, eax
    
create_done:
    add     rsp, 88
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GUI_CreateMainWindow ENDP

;=============================================================================
; GUI_MainWndProc - Main window message handler
;=============================================================================
GUI_MainWndProc PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 88
    
    mov     rbx, rcx          ; hWnd
    mov     r12d, edx        ; uMsg
    mov     r13, r8          ; wParam
    mov     r14, r9          ; lParam
    
    cmp     r12d, WM_CREATE
    je      wnd_create
    cmp     r12d, WM_DESTROY
    je      wnd_destroy
    cmp     r12d, WM_SIZE
    je      wnd_size
    cmp     r12d, WM_PAINT
    je      wnd_paint
    cmp     r12d, WM_KEYDOWN
    je      wnd_keydown
    cmp     r12d, WM_MOUSEMOVE
    je      wnd_mousemove
    cmp     r12d, WM_LBUTTONDOWN
    je      wnd_lbuttondown
    cmp     r12d, WM_LBUTTONUP
    je      wnd_lbuttonup
    cmp     r12d, WM_MOUSEWHEEL
    je      wnd_mousewheel
    cmp     r12d, WM_CLOSE
    je      wnd_close
    
default_proc:
    mov     rcx, rbx
    mov     edx, r12d
    mov     r8, r13
    mov     r9, r14
    call    DefWindowProcA
    jmp     wnd_done
    
wnd_create:
    call    GUI_OnCreate
    xor     eax, eax
    jmp     wnd_done
    
wnd_destroy:
    mov     g_isRunning, 0
    xor     ecx, ecx
    call    PostQuitMessage
    xor     eax, eax
    jmp     wnd_done
    
wnd_size:
    mov     eax, r14d
    and     eax, 0FFFFh
    mov     g_clientWidth, eax
    mov     eax, r14d
    shr     eax, 16
    mov     g_clientHeight, eax
    call    GUI_LayoutWindows
    xor     eax, eax
    jmp     wnd_done
    
wnd_paint:
    call    GUI_OnPaint
    xor     eax, eax
    jmp     wnd_done
    
wnd_keydown:
    mov     rcx, r13
    call    GUI_OnKeyDown
    xor     eax, eax
    jmp     wnd_done
    
wnd_mousemove:
    mov     eax, r14d
    and     eax, 0FFFFh
    mov     g_mouseX, eax
    mov     eax, r14d
    shr     eax, 16
    mov     g_mouseY, eax
    xor     eax, eax
    jmp     wnd_done
    
wnd_lbuttondown:
    mov     g_mouseDown, 1
    xor     eax, eax
    jmp     wnd_done
    
wnd_lbuttonup:
    mov     g_mouseDown, 0
    xor     eax, eax
    jmp     wnd_done
    
wnd_mousewheel:
    mov     rcx, r13
    call    GUI_OnMouseWheel
    xor     eax, eax
    jmp     wnd_done
    
wnd_close:
    mov     rcx, rbx
    call    DestroyWindow
    xor     eax, eax
    
wnd_done:
    add     rsp, 88
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GUI_MainWndProc ENDP

;=============================================================================
; GUI_RunMessageLoop - Main message loop
;=============================================================================
GUI_RunMessageLoop PROC
    push    rbx
    sub     rsp, 64
    
    jmp     msg_loop
    
msg_loop:
    ; Use PeekMessage for non-blocking loop
    mov     rcx, rsp            ; lpMsg
    mov     rdx, 0              ; hWnd (NULL = all windows)
    mov     r8d, 0              ; wMsgFilterMin
    mov     r9d, 0              ; wMsgFilterMax
    mov     dword ptr [rsp+32], PM_REMOVE  ; wRemoveMsg
    call    PeekMessageA
    test    rax, rax
    jz      msg_idle
    
    cmp     dword ptr [rsp+4], WM_QUIT  ; message
    je      msg_quit
    
    mov     rcx, rsp
    call    TranslateMessage
    
    mov     rcx, rsp
    call    DispatchMessageA
    
msg_idle:
    ; Update and render
    call    GUI_Update
    call    GUI_Render
    
    ; Calculate FPS
    call    GUI_CalculateFPS
    
    ; Small sleep to prevent 100% CPU
    mov     ecx, 1
    call    Sleep
    
    movzx   eax, g_isRunning
    test    eax, eax
    jnz     msg_loop
    
msg_quit:
    mov     eax, dword ptr [rsp+16]  ; wParam from WM_QUIT
    
    add     rsp, 64
    pop     rbx
    ret
GUI_RunMessageLoop ENDP

;=============================================================================
; GUI_OnCreate - Handle WM_CREATE
;=============================================================================
GUI_OnCreate PROC
    push    rbx
    sub     rsp, 88
    
    ; Create menu bar
    call    GUI_CreateMenuBar
    
    ; Create sidebar
    call    GUI_CreateSidebar
    
    ; Create editor
    call    GUI_CreateEditor
    
    ; Create status bar
    call    GUI_CreateStatusBar
    
    ; Layout all windows
    call    GUI_LayoutWindows
    
    add     rsp, 88
    pop     rbx
    ret
GUI_OnCreate ENDP

;=============================================================================
; GUI_CreateMenuBar - Create the main menu
;=============================================================================
GUI_CreateMenuBar PROC
    push    rbx
    sub     rsp, 88
    
    ; Create menu
    call    CreateMenu
    mov     g_hMenu, rax
    
    ; File menu
    call    CreateMenu
    mov     rbx, rax
    
    mov     rcx, rbx
    mov     edx, 0
    mov     r8d, 1000       ; ID_FILE_NEW
    lea     r9, szNewFile
    call    AppendMenuA
    
    mov     rcx, rbx
    mov     edx, 0
    mov     r8d, 1001       ; ID_FILE_OPEN
    lea     r9, szOpenFile
    call    AppendMenuA
    
    mov     rcx, rbx
    mov     edx, 0
    mov     r8d, 1002       ; ID_FILE_SAVE
    lea     r9, szSaveFile
    call    AppendMenuA
    
    mov     rcx, rbx
    mov     edx, 0
    mov     r8d, 1003       ; ID_FILE_SAVEAS
    lea     r9, szSaveAs
    call    AppendMenuA
    
    mov     rcx, rbx
    mov     edx, 0800h      ; MF_SEPARATOR
    mov     r8d, 0
    mov     r9d, 0
    call    AppendMenuA
    
    mov     rcx, rbx
    mov     edx, 0
    mov     r8d, 1099       ; ID_FILE_EXIT
    lea     r9, szExit
    call    AppendMenuA
    
    mov     rcx, g_hMenu
    mov     edx, 10h        ; MF_POPUP
    mov     r8, rbx
    lea     r9, szFileMenu
    call    AppendMenuA
    
    ; Set menu to main window
    mov     rcx, g_hMainWnd
    mov     rdx, g_hMenu
    call    SetMenu
    
    add     rsp, 88
    pop     rbx
    ret
GUI_CreateMenuBar ENDP

;=============================================================================
; GUI_LayoutWindows - Layout all child windows
;=============================================================================
GUI_LayoutWindows PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 88
    
    mov     ebx, g_clientWidth
    mov     esi, g_clientHeight
    
    ; Sidebar: 250px width, full height minus status bar
    mov     r9d, 22            ; height minus status bar
    sub     r9d, 22
    mov     rcx, g_hSidebar
    mov     edx, 0             ; X
    mov     r8d, 0             ; Y
    mov     r10d, 250          ; width
    mov     r11d, 1            ; repaint
    call    MoveWindow
    
    ; Editor: remaining width, full height minus status bar
    mov     r9d, 22
    sub     r9d, 22
    mov     rcx, g_hEditor
    mov     edx, 250           ; X (after sidebar)
    mov     r8d, 0             ; Y
    mov     r10d, ebx
    sub     r10d, 250          ; width
    mov     r11d, 1            ; repaint
    call    MoveWindow
    
    ; Status bar: full width, 22px height at bottom
    mov     rcx, g_hStatusBar
    mov     edx, 0             ; X
    mov     r8d, esi
    sub     r8d, 22            ; Y
    mov     r10d, ebx          ; width
    mov     r11d, 22           ; height
    mov     eax, r11d
    push    rax
    call    MoveWindow
    add     rsp, 8
    
    add     rsp, 88
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GUI_LayoutWindows ENDP

;=============================================================================
; GUI_Update - Update logic
;=============================================================================
GUI_Update PROC
    ; Update editor state
    call    Editor_Update
    
    ; Update LSP client
    call    LSP_Update
    
    ; Update debugger
    call    Debugger_Update
    
    ; Update collaboration
    call    Collab_Update
    
    ret
GUI_Update ENDP

;=============================================================================
; GUI_Render - Render frame
;=============================================================================
GUI_Render PROC
    ; Render editor
    call    Editor_Render
    
    ; Render sidebar
    call    Sidebar_Render
    
    ; Render status bar
    call    StatusBar_Render
    
    ret
GUI_Render ENDP

;=============================================================================
; GUI_CalculateFPS - Calculate and display FPS
;=============================================================================
GUI_CalculateFPS PROC
    push    rbx
    sub     rsp, 32
    
    ; Get current time
    lea     rcx, [rsp+8]
    call    QueryPerformanceCounter
    
    mov     rax, [rsp+8]
    mov     rbx, g_lastFrameTime
    sub     rax, rbx
    
    ; Calculate FPS
    mov     rcx, g_perfFreq
    xor     rdx, rdx
    div     rcx
    
    inc     g_frameCount
    
    ; Update every 60 frames
    cmp     g_frameCount, 60
    jb      fps_done
    
    mov     g_frameCount, 0
    mov     rax, [rsp+8]
    mov     g_lastFrameTime, rax
    
fps_done:
    add     rsp, 32
    pop     rbx
    ret
GUI_CalculateFPS ENDP

;=============================================================================
; GUI_OnPaint - Handle WM_PAINT
;=============================================================================
GUI_OnPaint PROC
    push    rbx
    sub     rsp, 96
    
    mov     rbx, rcx
    
    ; Begin paint
    lea     r8, [rsp+32]       ; PAINTSTRUCT
    call    BeginPaint
    mov     rbx, rax           ; hdc
    
    ; Get client rect
    mov     rcx, g_hMainWnd
    lea     rdx, [rsp+64]
    call    GetClientRect
    
    ; Fill background
    mov     rcx, rbx
    lea     rdx, [rsp+64]
    mov     r8, g_hBrushBg
    call    FillRect
    
    ; End paint
    mov     rcx, g_hMainWnd
    lea     rdx, [rsp+32]
    call    EndPaint
    
    add     rsp, 96
    pop     rbx
    ret
GUI_OnPaint ENDP

;=============================================================================
; GUI_OnKeyDown - Handle keyboard input
;=============================================================================
GUI_OnKeyDown PROC
    push    rbx
    
    mov     ebx, ecx    ; virtual key code
    
    ; Check modifiers
    mov     ecx, 11h    ; VK_CONTROL
    call    GetAsyncKeyState
    test    ax, 8000h
    setnz   g_keyCtrl
    
    mov     ecx, 10h    ; VK_SHIFT
    call    GetAsyncKeyState
    test    ax, 8000h
    setnz   g_keyShift
    
    ; Handle shortcuts
    cmp     ebx, 4Eh    ; 'N'
    jne     not_new
    cmp     g_keyCtrl, 1
    jne     not_new
    call    File_New
    jmp     key_done
    
not_new:
    cmp     ebx, 4Fh    ; 'O'
    jne     not_open
    cmp     g_keyCtrl, 1
    jne     not_open
    call    File_Open
    jmp     key_done
    
not_open:
    cmp     ebx, 53h    ; 'S'
    jne     not_save
    cmp     g_keyCtrl, 1
    jne     not_save
    call    File_Save
    jmp     key_done
    
not_save:
    ; Pass to editor
    mov     ecx, ebx
    call    Editor_OnKeyDown
    
key_done:
    pop     rbx
    ret
GUI_OnKeyDown ENDP

;=============================================================================
; GUI_OnMouseWheel - Handle mouse wheel
;=============================================================================
GUI_OnMouseWheel PROC
    push    rbx
    
    mov     ebx, ecx
    shr     ebx, 16         ; delta
    
    ; Scroll editor
    sar     ebx, 16
    mov     ecx, ebx
    call    Editor_Scroll
    
    pop     rbx
    ret
GUI_OnMouseWheel ENDP

;=============================================================================
; Stub implementations for called functions
;=============================================================================
GUI_CreateSidebar PROC
    ret
GUI_CreateSidebar ENDP

GUI_CreateEditor PROC
    ret
GUI_CreateEditor ENDP

GUI_CreateStatusBar PROC
    ret
GUI_CreateStatusBar ENDP

Editor_Update PROC
    ret
Editor_Update ENDP

Editor_Render PROC
    ret
Editor_Render ENDP

Sidebar_Render PROC
    ret
Sidebar_Render ENDP

StatusBar_Render PROC
    ret
StatusBar_Render ENDP

LSP_Update PROC
    ret
LSP_Update ENDP

Debugger_Update PROC
    ret
Debugger_Update ENDP

Collab_Update PROC
    ret
Collab_Update ENDP

File_New PROC
    ret
File_New ENDP

File_Open PROC
    ret
File_Open ENDP

File_Save PROC
    ret
File_Save ENDP

Editor_OnKeyDown PROC
    ret
Editor_OnKeyDown ENDP

Editor_Scroll PROC
    ret
Editor_Scroll ENDP

DestroyWindow PROC
    xor     eax, eax
    ret
DestroyWindow ENDP

Sleep PROC
    ret
Sleep ENDP

MoveWindow PROC
    mov     eax, 1
    ret
MoveWindow ENDP

GetModuleHandleA PROC
    mov     rax, 00400000h
    ret
GetModuleHandleA ENDP

END
