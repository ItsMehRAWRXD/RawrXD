; ============================================================================
; win32_window_framework_x64.asm
; Pure x64 MASM Win32 Window Framework (no 32-bit includes needed)
; ============================================================================

option casemap:none

; ============================================================================
; CONSTANTS
; ============================================================================

; Window Messages
WM_DESTROY          = 2
WM_PAINT            = 15
WM_SIZE             = 5
WM_COMMAND          = 273
WM_CHAR             = 256
WM_KEYDOWN          = 256
WM_KEYUP            = 257
WM_LBUTTONDOWN      = 513
WM_RBUTTONDOWN      = 516

; Window Styles
WS_OVERLAPPEDWINDOW = 0CF0000h
WS_VISIBLE          = 10000000h

; Class Styles
CS_VREDRAW          = 1
CS_HREDRAW          = 2
CS_DBLCLKS          = 8

; Show Window Constants
SW_SHOW             = 5
SW_HIDE             = 0

; Dialog Box Return Values
IDOK                = 1
IDCANCEL            = 2

; Colors
COLOR_WINDOW        = 5
COLOR_WINDOWTEXT    = 8

; Button Messages
BN_CLICKED          = 0

; MessageBox Styles
MB_OK               = 0
MB_ICONINFORMATION  = 40h

; Menu IDs
IDM_FILE_NEW        = 1001
IDM_FILE_OPEN       = 1002
IDM_FILE_SAVE       = 1003
IDM_FILE_SAVE_AS    = 1004
IDM_FILE_EXIT       = 1005
IDM_EDIT_UNDO       = 2001
IDM_EDIT_REDO       = 2002
IDM_VIEW_THEME      = 3001
IDM_HELP_ABOUT      = 4001

; WNDCLASSEX Structure Offsets (for manual calculations)
; WNDCLASSEX is 80 bytes on x64
WNDCLASSEX_cbSize           = 0
WNDCLASSEX_style            = 4
WNDCLASSEX_lpfnWndProc      = 8
WNDCLASSEX_cbClsExtra       = 16
WNDCLASSEX_cbWndExtra       = 20
WNDCLASSEX_hInstance        = 24
WNDCLASSEX_hIcon            = 32
WNDCLASSEX_hCursor          = 40
WNDCLASSEX_hbrBackground   = 48
WNDCLASSEX_lpszMenuName     = 56
WNDCLASSEX_lpszClassName    = 64
WNDCLASSEX_hIconSm          = 72

; ============================================================================
; EXTERNAL FUNCTIONS (kernel32, user32, gdi32)
; ============================================================================

extern GetModuleHandleA:proc
extern CreateWindowExA:proc
extern ShowWindow:proc
extern UpdateWindow:proc
extern GetMessageA:proc
extern TranslateMessage:proc
extern DispatchMessageA:proc
extern PostQuitMessage:proc
extern DefWindowProcA:proc
extern RegisterClassExA:proc
extern DestroyWindow:proc
extern ExitProcess:proc
extern GetDC:proc
extern ReleaseDC:proc
extern SetEvent:proc
extern CreateEventA:proc
extern WaitForSingleObject:proc
extern GetCurrentThreadId:proc
extern CreateThread:proc
extern LoadIconA:proc
extern LoadCursorA:proc
extern GetStockObject:proc

; ============================================================================
; DATA SECTION
; ============================================================================

.data
    
    ; Window class name
    szClassName     db "RawrXD_Pure_MASM_Window", 0
    szWindowTitle   db "RawrXD Pure MASM IDE", 0
    
    ; Message box text
    szAbout         db "RawrXD Pure MASM IDE", 13, 10, "Built with 100% x64 Assembly", 0
    
    ; Global window handle
    hMainWindow     dq 0
    
    ; WNDCLASSEX structure
    wcex            dq 80                          ; cbSize
                    dq CS_VREDRAW + CS_HREDRAW    ; style
                    dq WndProc_Main                ; lpfnWndProc
                    dq 0                           ; cbClsExtra
                    dq 0                           ; cbWndExtra
                    dq 0                           ; hInstance (filled at runtime)
                    dq 0                           ; hIcon
                    dq 0                           ; hCursor
                    dq COLOR_WINDOW + 1            ; hbrBackground
                    dq 0                           ; lpszMenuName
                    dq szClassName                 ; lpszClassName
                    dq 0                           ; hIconSm
    
    ; Message structure (MSG)
    msg             dd 0, 0, 0, 0, 0, 0, 0, 0     ; hwnd, message, wParam, lParam, time, pt.x, pt.y, lPrivate
    msgSize         = $ - msg

; ============================================================================
; CODE SECTION
; ============================================================================

.code

; ============================================================================
; WndProc_Main - Window Procedure
; rcx = hwnd
; rdx = message
; r8 = wParam
; r9 = lParam
; ============================================================================
WndProc_Main proc
    
    cmp rdx, WM_DESTROY
    je wm_destroy
    
    cmp rdx, WM_COMMAND
    je wm_command
    
    ; Default window procedure
    mov rax, r9         ; lParam
    lea rcx, [DefWindowProcA]
    jmp qword ptr [rcx]

wm_destroy:
    xor ecx, ecx
    call PostQuitMessage
    xor eax, eax
    ret

wm_command:
    xor eax, eax
    ret

WndProc_Main endp

; ============================================================================
; WindowClass_Register - Register window class
; rcx = hInstance
; Returns: TRUE if success, FALSE if failed
; ============================================================================
WindowClass_Register proc
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx        ; rsi = hInstance
    
    ; Set instance in WNDCLASSEX
    lea rax, [wcex]
    mov [rax + 32], rsi ; hInstance at offset 32 in our structure
    
    ; Call RegisterClassExA(&wcex)
    lea rcx, [wcex]
    call RegisterClassExA
    
    add rsp, 32
    pop rsi
    pop rbx
    ret

WindowClass_Register endp

; ============================================================================
; WindowClass_Create - Create main window
; rcx = hInstance
; Returns: hWindow in rax
; ============================================================================
WindowClass_Create proc
    push rbx
    push rsi
    sub rsp, 40
    
    mov rsi, rcx        ; rsi = hInstance
    
    ; CreateWindowExA(
    ;   0,                               ; dwExStyle
    ;   "RawrXD_Pure_MASM_Window",       ; lpClassName
    ;   "RawrXD Pure MASM IDE",          ; lpWindowName
    ;   WS_OVERLAPPEDWINDOW,             ; dwStyle
    ;   100,                             ; x
    ;   100,                             ; y
    ;   800,                             ; nWidth
    ;   600,                             ; nHeight
    ;   NULL,                            ; hWndParent
    ;   NULL,                            ; hMenu
    ;   hInstance,                       ; hInstance
    ;   NULL)                            ; lpParam
    
    xor ecx, ecx                        ; dwExStyle = 0
    lea rdx, [szClassName]              ; lpClassName
    lea r8, [szWindowTitle]             ; lpWindowName
    mov r9d, WS_OVERLAPPEDWINDOW        ; dwStyle
    mov qword ptr [rsp + 32], 100       ; x
    mov qword ptr [rsp + 40], 100       ; y
    mov qword ptr [rsp + 48], 800       ; nWidth
    mov qword ptr [rsp + 56], 600       ; nHeight
    mov qword ptr [rsp + 64], 0         ; hWndParent
    mov qword ptr [rsp + 72], 0         ; hMenu
    mov qword ptr [rsp + 80], rsi       ; hInstance
    mov qword ptr [rsp + 88], 0         ; lpParam
    
    call CreateWindowExA
    
    lea rbx, [hMainWindow]
    mov [rbx], rax      ; Store window handle
    
    add rsp, 40
    pop rsi
    pop rbx
    ret

WindowClass_Create endp

; ============================================================================
; WindowClass_ShowWindow - Show the window
; rcx = hWindow
; rdx = nCmdShow
; ============================================================================
WindowClass_ShowWindow proc
    sub rsp, 32
    call ShowWindow
    call UpdateWindow
    add rsp, 32
    ret

WindowClass_ShowWindow endp

; ============================================================================
; WindowClass_MessageLoop - Main message loop
; ============================================================================
WindowClass_MessageLoop proc
    push rbx
    sub rsp, 32
    
msg_loop:
    ; GetMessage(&msg, NULL, 0, 0)
    lea rcx, [msg]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call GetMessageA
    
    cmp eax, 0
    jle msg_exit
    
    ; TranslateMessage(&msg)
    lea rcx, [msg]
    call TranslateMessage
    
    ; DispatchMessage(&msg)
    lea rcx, [msg]
    call DispatchMessageA
    
    jmp msg_loop

msg_exit:
    add rsp, 32
    pop rbx
    ret

WindowClass_MessageLoop endp

; ============================================================================
; WindowClass_Cleanup - Cleanup window
; ============================================================================
WindowClass_Cleanup proc
    push rbx
    sub rsp, 32
    
    lea rbx, [hMainWindow]
    mov rcx, [rbx]
    call DestroyWindow
    
    add rsp, 32
    pop rbx
    ret

WindowClass_Cleanup endp

; ============================================================================
; WinMain - Entry point
; ============================================================================
WinMain proc
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    sub rsp, 32
    
    ; Get module handle
    xor ecx, ecx
    call GetModuleHandleA
    mov rsi, rax
    
    ; Register window class
    mov rcx, rsi
    call WindowClass_Register
    cmp eax, 0
    je main_error
    
    ; Create window
    mov rcx, rsi
    call WindowClass_Create
    cmp rax, 0
    je main_error
    
    ; Show window
    mov rcx, [hMainWindow]
    mov edx, SW_SHOW
    call WindowClass_ShowWindow
    
    ; Message loop
    call WindowClass_MessageLoop
    
    ; Cleanup
    call WindowClass_Cleanup
    
    xor eax, eax
    jmp main_exit

main_error:
    mov eax, 1

main_exit:
    add rsp, 32
    pop rsi
    pop rbx
    pop rbp
    ret

WinMain endp

; ============================================================================
; Entry point for linker (ENTRY:WinMainCRTStartup)
; ============================================================================
public WinMainCRTStartup
WinMainCRTStartup proc
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call WinMain
    mov ecx, eax
    call ExitProcess
    ret
WinMainCRTStartup endp

end





