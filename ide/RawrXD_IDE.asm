; ============================================================================
; RawrXD_IDE.asm - Native Win32 IDE for RawrXD v15.0.0
; Minimal but functional IDE with editor, console, and agent integration
; ============================================================================

option casemap:none

; Windows API functions
extrn RegisterClassExA:proc
extrn CreateWindowExA:proc
extrn ShowWindow:proc
extrn UpdateWindow:proc
extrn GetMessageA:proc
extrn TranslateMessage:proc
extrn DispatchMessageA:proc
extrn PostQuitMessage:proc
extrn DefWindowProcA:proc
extrn LoadCursorA:proc
extrn GetStockObject:proc
extrn ExitProcess:proc
extrn GetModuleHandleA:proc
extrn GetClientRect:proc
extrn SendMessageA:proc
extrn SetWindowTextA:proc
extrn MessageBoxA:proc
extrn CreateMenu:proc
extrn AppendMenuA:proc
extrn SetMenu:proc
extrn BeginPaint:proc
extrn EndPaint:proc
extrn FillRect:proc
extrn AllocConsole:proc
extrn AttachConsole:proc
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn OutputDebugStringA:proc
extrn GetLastError:proc

; Constants
IDC_ARROW       equ 7F00h
WS_OVERLAPPEDWINDOW equ 0CF0000h
WS_VISIBLE      equ 10000000h
WS_CHILD        equ 40000000h
WS_BORDER       equ 800000h
WS_HSCROLL      equ 100000h
WS_VSCROLL      equ 200000h
WS_TABSTOP      equ 10000h
ES_MULTILINE    equ 4h
ES_AUTOVSCROLL  equ 40h
ES_AUTOHSCROLL  equ 80h
ES_WANTRETURN   equ 1000h
LBS_NOTIFY      equ 1h
LBS_HASSTRINGS  equ 40h
WM_CREATE       equ 1h
WM_DESTROY      equ 2h
WM_SIZE         equ 5h
WM_PAINT        equ 0Fh
WM_CLOSE        equ 10h
WM_COMMAND      equ 111h
WM_SETFOCUS     equ 7h
WM_INITDIALOG   equ 110h
WM_KEYDOWN      equ 100h
WM_CHAR         equ 102h
WM_SETTEXT      equ 0Ch
BN_CLICKED      equ 0
EN_CHANGE       equ 300h
ES_READONLY     equ 800h
MF_STRING       equ 0h
MF_POPUP        equ 10h
SW_SHOWDEFAULT  equ 10
SW_SHOWNORMAL   equ 1
COLOR_WINDOW    equ 5
DT_LEFT         equ 0h
DT_TOP          equ 0h
DT_WORDBREAK    equ 10h
TRANSPARENT     equ 1

; Menu IDs
IDM_FILE_NEW    equ 1001h
IDM_FILE_OPEN   equ 1002h
IDM_FILE_SAVE   equ 1003h
IDM_FILE_EXIT   equ 1004h
IDM_EDIT_CUT    equ 1011h
IDM_EDIT_COPY   equ 1012h
IDM_EDIT_PASTE  equ 1013h
IDM_AGENT_RUN   equ 1021h
IDM_AGENT_BUILD equ 1022h
IDM_HELP_ABOUT  equ 1031h

.data
    ; Window class name
    szClassName     db "RawrXD_IDE_Class", 0
    szAppName       db "RawrXD v15.0.0 - Sovereign IDE", 0
    szEditClass     db "EDIT", 0
    szListBoxClass  db "LISTBOX", 0
    szButtonClass   db "BUTTON", 0
    szStaticClass   db "STATIC", 0
    
    ; Menu strings
    szMenuFile      db "&File", 0
    szMenuNew       db "&New\tCtrl+N", 0
    szMenuOpen      db "&Open...\tCtrl+O", 0
    szMenuSave      db "&Save\tCtrl+S", 0
    szMenuExit      db "E&xit", 0
    szMenuEdit      db "&Edit", 0
    szMenuCut       db "Cu&t\tCtrl+X", 0
    szMenuCopy      db "&Copy\tCtrl+C", 0
    szMenuPaste     db "&Paste\tCtrl+V", 0
    szMenuAgent     db "&Agent", 0
    szMenuRun       db "&Run Agent\tF5", 0
    szMenuBuild     db "&Build\tF7", 0
    szMenuHelp      db "&Help", 0
    szMenuAbout     db "&About", 0
    
    ; UI labels
    szEditorLabel   db "Editor", 0
    szConsoleLabel  db "Console", 0
    szStatusLabel   db "Status: Ready", 0
    szAgentLabel    db "Agent Output", 0
    
    ; About message
    szAboutTitle    db "About RawrXD", 0
    szAboutText     db "RawrXD v15.0.0 - Sovereign IDE", 0Dh, 0Ah
                    db "The Self-Driving Development Environment", 0Dh, 0Ah, 0Dh, 0Ah
                    db "Features:", 0Dh, 0Ah
                    db "- Sovereign Universal Transpiler", 0Dh, 0Ah
                    db "- AI-Powered Agent System", 0Dh, 0Ah
                    db "- Native Win32 Interface", 0Dh, 0Ah
                    db "- SME2 Acceleration Ready", 0Dh, 0Ah, 0Dh, 0Ah
                    db "Build Date: 2026-07-30", 0
    
    ; Status messages
    szStatusReady   db "Ready", 0
    szStatusRunning db "Agent running...", 0
    szStatusBuilding db "Building...", 0
    szStatusDone    db "Done", 0
    
    ; Sample code
    szSampleCode    db "// RawrXD Sovereign PHP", 0Dh, 0Ah
                    db "echo Hello from RawrXD!;", 0Dh, 0Ah, 0
    
    ; Debug log strings
    szDbgBoot       db "[BOOT] RawrXD_IDE starting", 0Dh, 0Ah, 0
    szDbgInit       db "[INIT] GetModuleHandleA OK", 0Dh, 0Ah, 0
    szDbgClass      db "[INIT] RegisterWindowClass OK", 0Dh, 0Ah, 0
    szDbgCreate     db "[INIT] CreateMainWindow OK", 0Dh, 0Ah, 0
    szDbgShow       db "[INIT] ShowWindow OK", 0Dh, 0Ah, 0
    szDbgLoop       db "[LOOP] Entering message loop", 0Dh, 0Ah, 0
    szDbgWmCreate   db "[WND] WM_CREATE received", 0Dh, 0Ah, 0
    szDbgWmSize     db "[WND] WM_SIZE received", 0Dh, 0Ah, 0
    szDbgWmCmd      db "[WND] WM_COMMAND received", 0Dh, 0Ah, 0
    szDbgWmPaint    db "[WND] WM_PAINT received", 0Dh, 0Ah, 0
    szDbgWmDestroy  db "[WND] WM_DESTROY received", 0Dh, 0Ah, 0
    szDbgWmDef      db "[WND] DefWindowProcA called", 0Dh, 0Ah, 0
    szDbgEditor     db "[WND] Creating editor control", 0Dh, 0Ah, 0
    szDbgConsole    db "[WND] Creating console control", 0Dh, 0Ah, 0
    szDbgStatus     db "[WND] Creating status bar", 0Dh, 0Ah, 0
    szDbgExit       db "[EXIT] Exiting message loop", 0Dh, 0Ah, 0
    szDbgCrash      db "[CRASH] Unexpected message in WndProc", 0Dh, 0Ah, 0
    szDbgCreateWin  db "[CREATE] CreateWindowExA called", 0Dh, 0Ah, 0
    szDbgCreateFail db "[CREATE] CreateWindowExA FAILED - GetLastError: ", 0
    szDbgCreateOK   db "[CREATE] CreateWindowExA OK - hWnd: ", 0
    szDbgMenuOK     db "[CREATE] CreateMainMenu OK", 0Dh, 0Ah, 0
    szDbgHexPrefix  db "0x", 0
    szDbgNewline    db 0Dh, 0Ah, 0
    
    ; Stream debug strings
    szOkAttachConsole     db "[INIT] AttachConsole OK", 0Dh, 0Ah, 0
    szErrAttachConsole    db "[INIT] AttachConsole FAILED - Error: 0x", 0
    szWndSize             db "[WND] WM_SIZE dimensions", 0Dh, 0Ah, 0
    szWidthPrefix         db "  Width: 0x", 0
    szHeightPrefix        db "  Height: 0x", 0
    szWndCommand          db "[WND] WM_COMMAND details", 0Dh, 0Ah, 0
    szCmdIdPrefix         db "  Command ID: 0x", 0
    szLogSendMessage      db "[SEND] WM_SETTEXT result: 0x", 0
    szDbgRegClass         db "[INIT] RegisterClassExA atom: 0x", 0
    szDbgChildWin         db "[CREATE] Child window hWnd: 0x", 0
    szDbgPaintHdc         db "[PAINT] BeginPaint hdc: 0x", 0
    
    ; Window handles
    hInstance       dq 0
    hWndMain        dq 0
    hWndEditor      dq 0
    hWndConsole     dq 0
    hWndStatus      dq 0
    hMenu           dq 0
    wcAtom          dd 0            ; window class atom from RegisterClassExA
    
    ; File handling
    szFileName      db 260 dup(0)
    szFileTitle     db 260 dup(0)
    szFileBuffer    db 32768 dup(0)
    
    ; Paint struct
    ps              dd 64 dup(0)

.data?
    ; Uninitialized data
    wc              db 80 dup(?)    ; WNDCLASSEXA
    msg             db 48 dup(?)    ; MSG
    rect            dd 4 dup(?)     ; RECT
    hBrush          dq ?

.code

; ============================================================================
; DebugLog - Print debug message to console and OutputDebugString
; rcx = address of null-terminated string
; ============================================================================
DebugLog PROC
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    
    ; Save string pointer
    mov [rsp + 30h], rcx
    
    ; OutputDebugStringA(msg)
    call OutputDebugStringA
    
    ; GetStdHandle(STD_OUTPUT_HANDLE = -11)
    mov ecx, -11
    call GetStdHandle
    test rax, rax
    jz @f
    
    mov [rsp + 28h], rax        ; hConsole
    mov rcx, [rsp + 30h]        ; msg
    call strlen
    mov r8, rax                 ; nNumberOfBytesToWrite
    mov rcx, [rsp + 28h]        ; hConsole
    mov rdx, [rsp + 30h]        ; lpBuffer
    lea r9, [rsp + 40h]         ; lpNumberOfBytesWritten
    mov qword ptr [rsp + 20h], 0 ; lpOverlapped
    call WriteFile
    
@@:
    mov rsp, rbp
    pop rbp
    ret
DebugLog ENDP

; ============================================================================
; DebugLogHex - Print a 64-bit hex value to debug console
; rcx = value to print
; ============================================================================
DebugLogHex PROC
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    
    mov [rsp + 30h], rcx        ; save value
    
    ; Build hex string on stack (16 hex digits + "0x" prefix)
    ; We'll write from right to left
    lea rdi, [rsp + 40h]        ; buffer (32 bytes)
    mov byte ptr [rdi + 0], '0'
    mov byte ptr [rdi + 1], 'x'
    add rdi, 2
    mov rcx, [rsp + 30h]        ; value
    mov r8, 16                  ; 16 hex digits
    
    ; Convert each nibble
    mov r9, rdi
    add r9, 16                  ; end of buffer
    mov byte ptr [r9], 0        ; null terminator
    dec r9
    
    mov r10, rcx                ; value
    test r10, r10
    jnz dh_loop
    
    ; Value is 0, just print "0x0"
    mov byte ptr [rdi], '0'
    mov byte ptr [rdi + 1], 0
    lea rcx, [rsp + 40h]
    call DebugLog
    jmp dh_done
    
dh_loop:
    mov rcx, r10
    and rcx, 0Fh                ; low nibble
    cmp cl, 10
    jl dh_digit
    add cl, 'A' - 10
    jmp dh_store
dh_digit:
    add cl, '0'
dh_store:
    mov [r9], cl
    dec r9
    shr r10, 4
    test r10, r10
    jnz dh_loop
    
    ; Print from r9+1 to end
    inc r9
    mov rcx, r9
    call DebugLog
    
dh_done:
    mov rsp, rbp
    pop rbp
    ret
DebugLogHex ENDP

; ============================================================================
; strlen - Get length of null-terminated string
; rcx = string pointer
; returns rax = length
; ============================================================================
strlen PROC
    mov rax, rcx
@@:
    cmp byte ptr [rax], 0
    je @f
    inc rax
    jmp @b
@@:
    sub rax, rcx
    ret
strlen ENDP

; ============================================================================
; WinMain - Entry point
; ============================================================================
WinMain PROC
    push rbp
    mov rbp, rsp
    sub rsp, 60h
    
    ; Attach to parent console (PowerShell) for debug output
    mov ecx, -1                 ; ATTACH_PARENT_PROCESS
    call AttachConsole
    test eax, eax
    jnz @f
    
    ; AttachConsole failed - log error
    call GetLastError
    mov r14d, eax
    lea rcx, [szErrAttachConsole]
    call DebugLog
    mov ecx, r14d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    jmp wm_continue
    
@@:
    lea rcx, [szOkAttachConsole]
    call DebugLog
    
wm_continue:
    ; [BOOT] RawrXD_IDE starting
    lea rcx, [szDbgBoot]
    call DebugLog
    
    ; Get module handle
    xor ecx, ecx
    call GetModuleHandleA
    mov [hInstance], rax
    
    ; [INIT] GetModuleHandleA OK
    lea rcx, [szDbgInit]
    call DebugLog
    
    ; Register window class
    call RegisterWindowClass
    test rax, rax
    jz wm_exit
    
    ; [INIT] RegisterWindowClass OK
    lea rcx, [szDbgClass]
    call DebugLog
    
    ; Create main window
    call CreateMainWindow
    test rax, rax
    jz wm_exit
    mov [hWndMain], rax
    
    ; [INIT] CreateMainWindow OK
    lea rcx, [szDbgCreate]
    call DebugLog
    
    ; Show window
    mov rcx, [hWndMain]
    mov edx, SW_SHOWNORMAL
    call ShowWindow
    
    ; [INIT] ShowWindow OK
    lea rcx, [szDbgShow]
    call DebugLog
    
    mov rcx, [hWndMain]
    call UpdateWindow
    
    ; [LOOP] Entering message loop
    lea rcx, [szDbgLoop]
    call DebugLog
    
    ; Message loop
wm_loop:
    lea rcx, [msg]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call GetMessageA
    test rax, rax
    jz wm_done
    
    lea rcx, [msg]
    call TranslateMessage
    
    lea rcx, [msg]
    call DispatchMessageA
    
    jmp wm_loop
    
wm_done:
    ; [EXIT] Exiting message loop
    lea rcx, [szDbgExit]
    call DebugLog
    
    mov eax, dword ptr [msg + 8]     ; wParam from MSG (32-bit in 64-bit struct)
    
wm_exit:
    mov rsp, rbp
    pop rbp
    ret
WinMain ENDP

; ============================================================================
; RegisterWindowClass - Register the main window class
; ============================================================================
RegisterWindowClass PROC
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    ; Zero WNDCLASSEXA structure (80 bytes)
    lea rdi, [wc]
    xor eax, eax
    mov ecx, 20
    rep stosd
    
    ; Fill WNDCLASSEXA
    mov dword ptr [wc + 0], 80        ; cbSize
    mov dword ptr [wc + 4], 3         ; style = CS_HREDRAW | CS_VREDRAW
    lea rax, WndProc
    mov qword ptr [wc + 8], rax   ; lpfnWndProc
    mov dword ptr [wc + 16], 0        ; cbClsExtra
    mov dword ptr [wc + 20], 0        ; cbWndExtra
    mov rax, [hInstance]
    mov qword ptr [wc + 24], rax      ; hInstance
    
    ; Load cursor
    xor ecx, ecx
    mov edx, IDC_ARROW
    call LoadCursorA
    mov qword ptr [wc + 40], rax      ; hCursor
    
    ; Background brush
    mov ecx, COLOR_WINDOW + 1
    call GetStockObject
    mov qword ptr [wc + 48], rax      ; hbrBackground
    
    ; Menu name (none)
    mov qword ptr [wc + 56], 0
    
    ; Class name
    lea rax, [szClassName]
    mov qword ptr [wc + 64], rax      ; lpszClassName
    
    ; Icon (use default application icon)
    mov qword ptr [wc + 32], 0        ; hIcon (will use default)
    mov qword ptr [wc + 72], 0        ; hIconSm
    
    lea rcx, [wc]
    call RegisterClassExA
    
    ; Save the class atom for CreateWindowExA
    mov dword ptr [wcAtom], eax
    
    ; Log the atom
    mov r14d, eax
    lea rcx, [szDbgRegClass]
    call DebugLog
    mov ecx, r14d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    
    mov rsp, rbp
    pop rbp
    ret
RegisterWindowClass ENDP

; ============================================================================
; CreateMainWindow - Create the main IDE window
; ============================================================================
CreateMainWindow PROC
    push rbp
    mov rbp, rsp
    sub rsp, 60h
    
    ; Create menu first
    call CreateMainMenu
    mov [hMenu], rax
    test rax, rax
    jnz @f
    lea rcx, [szDbgCrash]
    call DebugLog
    jmp cmw_fail
@@:
    lea rcx, [szDbgMenuOK]
    call DebugLog
    
    ; CreateWindowEx(0, className, appName, WS_OVERLAPPEDWINDOW,
    ;                CW_USEDEFAULT, CW_USEDEFAULT, 1200, 800,
    ;                NULL, hMenu, hInstance, NULL)
    lea rcx, [szDbgCreateWin]
    call DebugLog
    
    xor ecx, ecx                      ; dwExStyle
    lea rdx, [szClassName]            ; lpClassName (use string, not atom)
    lea r8, [szAppName]               ; lpWindowName
    mov r9d, WS_OVERLAPPEDWINDOW      ; dwStyle
    mov qword ptr [rsp + 20h], 80000000h   ; X = CW_USEDEFAULT
    mov qword ptr [rsp + 28h], 80000000h   ; Y = CW_USEDEFAULT
    mov qword ptr [rsp + 30h], 1200   ; nWidth
    mov qword ptr [rsp + 38h], 800    ; nHeight
    mov qword ptr [rsp + 40h], 0      ; hWndParent
    mov rax, [hMenu]
    mov qword ptr [rsp + 48h], rax    ; hMenu
    mov rax, [hInstance]
    mov qword ptr [rsp + 50h], rax    ; hInstance
    mov qword ptr [rsp + 58h], 0      ; lpParam
    call CreateWindowExA
    
    ; Check result - save error BEFORE any other API calls
    mov r12, rax               ; save HWND
    mov r13d, eax               ; save low part for test
    test r13d, r13d
    jnz cmw_ok
    
    ; Save GetLastError BEFORE calling DebugLog (which calls APIs that clear it)
    call GetLastError
    mov r14d, eax               ; save error code
    
    lea rcx, [szDbgCreateFail]
    call DebugLog
    mov ecx, r14d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    xor rax, rax
    jmp cmw_done
    
cmw_ok:
    lea rcx, [szDbgCreateOK]
    call DebugLog
    mov rcx, r12
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    mov rax, r12
    lea rcx, [szDbgNewline]
    call DebugLog
    ; rax already has hWnd from CreateWindowExA
    
cmw_done:
    mov rsp, rbp
    pop rbp
    ret
    
cmw_fail:
    xor rax, rax
    jmp cmw_done
CreateMainWindow ENDP

; ============================================================================
; CreateMainMenu - Create the application menu
; ============================================================================
CreateMainMenu PROC
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    call CreateMenu
    mov r12, rax          ; hMenu (save in non-volatile)
    
    ; File menu
    call CreateMenu
    mov r13, rax          ; hFileMenu
    
    ; Append file items
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_FILE_NEW
    lea r9, [szMenuNew]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_FILE_OPEN
    lea r9, [szMenuOpen]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_FILE_SAVE
    lea r9, [szMenuSave]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_FILE_EXIT
    lea r9, [szMenuExit]
    call AppendMenuA
    
    ; Add File menu to main menu
    mov rcx, r12
    mov edx, MF_POPUP
    mov r8, r13
    lea r9, [szMenuFile]
    call AppendMenuA
    
    ; Edit menu
    call CreateMenu
    mov r13, rax          ; hEditMenu
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_EDIT_CUT
    lea r9, [szMenuCut]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_EDIT_COPY
    lea r9, [szMenuCopy]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_EDIT_PASTE
    lea r9, [szMenuPaste]
    call AppendMenuA
    
    mov rcx, r12
    mov edx, MF_POPUP
    mov r8, r13
    lea r9, [szMenuEdit]
    call AppendMenuA
    
    ; Agent menu
    call CreateMenu
    mov r13, rax          ; hAgentMenu
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_AGENT_RUN
    lea r9, [szMenuRun]
    call AppendMenuA
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_AGENT_BUILD
    lea r9, [szMenuBuild]
    call AppendMenuA
    
    mov rcx, r12
    mov edx, MF_POPUP
    mov r8, r13
    lea r9, [szMenuAgent]
    call AppendMenuA
    
    ; Help menu
    call CreateMenu
    mov r13, rax          ; hHelpMenu
    
    mov rcx, r13
    mov edx, MF_STRING
    mov r8d, IDM_HELP_ABOUT
    lea r9, [szMenuAbout]
    call AppendMenuA
    
    mov rcx, r12
    mov edx, MF_POPUP
    mov r8, r13
    lea r9, [szMenuHelp]
    call AppendMenuA
    
    mov rax, r12          ; return hMenu
    
    mov rsp, rbp
    pop rbp
    ret
CreateMainMenu ENDP

; ============================================================================
; WndProc - Main window procedure
; ============================================================================
WndProc PROC
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    
    mov [rsp + 28h], rcx      ; hWnd
    mov [rsp + 30h], rdx      ; uMsg
    mov [rsp + 38h], r8       ; wParam
    mov [rsp + 40h], r9       ; lParam
    
    ; Check message type
    cmp edx, WM_CREATE
    je wp_create
    cmp edx, WM_SIZE
    je wp_size
    cmp edx, WM_COMMAND
    je wp_command
    cmp edx, WM_DESTROY
    je wp_destroy
    cmp edx, WM_PAINT
    je wp_paint
    
    ; Default processing
    lea rcx, [szDbgWmDef]
    call DebugLog
    mov rcx, [rsp + 28h]
    mov rdx, [rsp + 30h]
    mov r8, [rsp + 38h]
    mov r9, [rsp + 40h]
    call DefWindowProcA
    jmp wp_done
    
wp_create:
    lea rcx, [szDbgWmCreate]
    call DebugLog
    mov rcx, [rsp + 28h]    ; pass hWnd to OnCreate
    call OnCreate
    jmp wp_return_0
    
wp_size:
    lea rcx, [szDbgWmSize]
    call DebugLog
    lea rcx, [szWidthPrefix]
    call DebugLog
    mov eax, dword ptr [rsp + 40h]
    and eax, 0FFFFh
    mov ecx, eax
    call DebugLogHex
    lea rcx, [szHeightPrefix]
    call DebugLog
    mov eax, dword ptr [rsp + 40h]
    shr eax, 16
    mov ecx, eax
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    call OnSize
    jmp wp_return_0
    
wp_command:
    lea rcx, [szDbgWmCmd]
    call DebugLog
    lea rcx, [szWndCommand]
    call DebugLog
    lea rcx, [szCmdIdPrefix]
    call DebugLog
    mov eax, dword ptr [rsp + 38h]
    and eax, 0FFFFh
    mov ecx, eax
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    call OnCommand
    jmp wp_return_0
    
wp_paint:
    lea rcx, [szDbgWmPaint]
    call DebugLog
    call OnPaint
    jmp wp_return_0
    
wp_destroy:
    lea rcx, [szDbgWmDestroy]
    call DebugLog
    xor ecx, ecx
    call PostQuitMessage
    
wp_return_0:
    xor eax, eax
    
wp_done:
    mov rsp, rbp
    pop rbp
    ret
WndProc ENDP

; ============================================================================
; OnCreate - Handle WM_CREATE
; ============================================================================
OnCreate PROC
    ; rcx = hWnd (parent window handle passed from WndProc)
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    mov r12, rcx             ; parent window (from parameter, NOT from global)
    
    ; Create editor (multiline edit control)
    lea rcx, [szDbgEditor]
    call DebugLog
    xor ecx, ecx              ; dwExStyle
    lea rdx, [szEditClass]    ; lpClassName
    xor r8d, r8d              ; lpWindowName
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or WS_VSCROLL or WS_HSCROLL or ES_MULTILINE or ES_AUTOVSCROLL or ES_AUTOHSCROLL or ES_WANTRETURN
    mov qword ptr [rsp + 20h], 10     ; X
    mov qword ptr [rsp + 28h], 30     ; Y
    mov qword ptr [rsp + 30h], 800    ; nWidth
    mov qword ptr [rsp + 38h], 400    ; nHeight
    mov qword ptr [rsp + 40h], r12    ; hWndParent
    mov qword ptr [rsp + 48h], 1      ; hMenu = ID 1
    mov rax, [hInstance]
    mov qword ptr [rsp + 50h], rax    ; hInstance
    mov qword ptr [rsp + 58h], 0      ; lpParam
    call CreateWindowExA
    mov [hWndEditor], rax
    test rax, rax
    jnz @f
    lea rcx, [szDbgCrash]
    call DebugLog
    jmp oc_editor_done
@@:
    mov r13, rax
    lea rcx, [szDbgChildWin]
    call DebugLog
    mov ecx, r13d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
oc_editor_done:
    
    ; Set sample text
    mov rcx, [hWndEditor]
    mov edx, WM_SETTEXT
    xor r8d, r8d
    lea r9, [szSampleCode]
    call SendMessageA
    mov r13, rax
    lea rcx, [szLogSendMessage]
    call DebugLog
    mov ecx, r13d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    
    ; Create console output (listbox)
    lea rcx, [szDbgConsole]
    call DebugLog
    xor ecx, ecx
    lea rdx, [szEditClass]
    lea r8, [szConsoleLabel]
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or WS_VSCROLL or ES_MULTILINE or ES_READONLY or ES_AUTOVSCROLL
    mov qword ptr [rsp + 20h], 10     ; X
    mov qword ptr [rsp + 28h], 440    ; Y
    mov qword ptr [rsp + 30h], 800    ; nWidth
    mov qword ptr [rsp + 38h], 150    ; nHeight
    mov qword ptr [rsp + 40h], r12
    mov qword ptr [rsp + 48h], 2      ; ID 2
    mov rax, [hInstance]
    mov qword ptr [rsp + 50h], rax
    mov qword ptr [rsp + 58h], 0
    call CreateWindowExA
    mov [hWndConsole], rax
    test rax, rax
    jnz @f
    lea rcx, [szDbgCrash]
    call DebugLog
    jmp oc_console_done
@@:
    mov r13, rax
    lea rcx, [szDbgChildWin]
    call DebugLog
    mov ecx, r13d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
oc_console_done:
    
    ; Set initial console text
    mov rcx, [hWndConsole]
    mov edx, WM_SETTEXT
    xor r8d, r8d
    lea r9, [szStatusReady]
    call SendMessageA
    
    ; Create status bar
    lea rcx, [szDbgStatus]
    call DebugLog
    xor ecx, ecx
    lea rdx, [szStaticClass]
    lea r8, [szStatusLabel]
    mov r9d, WS_CHILD or WS_VISIBLE
    mov qword ptr [rsp + 20h], 10
    mov qword ptr [rsp + 28h], 600
    mov qword ptr [rsp + 30h], 800
    mov qword ptr [rsp + 38h], 20
    mov qword ptr [rsp + 40h], r12
    mov qword ptr [rsp + 48h], 3
    mov rax, [hInstance]
    mov qword ptr [rsp + 50h], rax
    mov qword ptr [rsp + 58h], 0
    call CreateWindowExA
    mov [hWndStatus], rax
    test rax, rax
    jnz @f
    lea rcx, [szDbgCrash]
    call DebugLog
    jmp oc_status_done
@@:
    mov r13, rax
    lea rcx, [szDbgChildWin]
    call DebugLog
    mov ecx, r13d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
oc_status_done:
    
    mov rax, 1        ; success
    
    mov rsp, rbp
    pop rbp
    ret
OnCreate ENDP

; ============================================================================
; OnSize - Handle WM_SIZE
; ============================================================================
OnSize PROC
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    ; Resize editor
    mov rcx, [hWndEditor]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 10
    mov qword ptr [rsp + 28h], 30
    mov qword ptr [rsp + 30h], 800
    mov qword ptr [rsp + 38h], 400
    call SendMessageA
    
    ; Resize console
    mov rcx, [hWndConsole]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 10
    mov qword ptr [rsp + 28h], 440
    mov qword ptr [rsp + 30h], 800
    mov qword ptr [rsp + 38h], 150
    call SendMessageA
    
    ; Resize status
    mov rcx, [hWndStatus]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 10
    mov qword ptr [rsp + 28h], 600
    mov qword ptr [rsp + 30h], 800
    mov qword ptr [rsp + 38h], 20
    call SendMessageA
    
    mov rsp, rbp
    pop rbp
    ret
OnSize ENDP

; ============================================================================
; OnCommand - Handle WM_COMMAND
; ============================================================================
OnCommand PROC
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    mov r12, r8       ; wParam
    
    ; Check menu ID
    cmp r12d, IDM_FILE_NEW
    je cmd_new
    cmp r12d, IDM_FILE_OPEN
    je cmd_open
    cmp r12d, IDM_FILE_SAVE
    je cmd_save
    cmp r12d, IDM_FILE_EXIT
    je cmd_exit
    cmp r12d, IDM_AGENT_RUN
    je cmd_run
    cmp r12d, IDM_AGENT_BUILD
    je cmd_build
    cmp r12d, IDM_HELP_ABOUT
    je cmd_about
    jmp cmd_done
    
cmd_new:
    mov rcx, [hWndEditor]
    mov edx, WM_SETTEXT
    xor r8d, r8d
    lea r9, [szSampleCode]
    call SendMessageA
    jmp cmd_done
    
cmd_open:
    jmp cmd_done
    
cmd_save:
    jmp cmd_done
    
cmd_exit:
    mov rcx, [hWndMain]
    call PostQuitMessage
    jmp cmd_done
    
cmd_run:
    mov rcx, [hWndConsole]
    mov edx, WM_SETTEXT
    xor r8d, r8d
    lea r9, [szStatusRunning]
    call SendMessageA
    jmp cmd_done
    
cmd_build:
    mov rcx, [hWndConsole]
    mov edx, WM_SETTEXT
    xor r8d, r8d
    lea r9, [szStatusBuilding]
    call SendMessageA
    jmp cmd_done
    
cmd_about:
    mov rcx, [hWndMain]
    lea rdx, [szAboutText]
    lea r8, [szAboutTitle]
    mov r9d, 40h      ; MB_OK | MB_ICONINFORMATION
    call MessageBoxA
    
cmd_done:
    mov rsp, rbp
    pop rbp
    ret
OnCommand ENDP

; ============================================================================
; OnPaint - Handle WM_PAINT
; ============================================================================
OnPaint PROC
    push rbp
    mov rbp, rsp
    sub rsp, 80h
    
    mov r12, rcx      ; hWnd
    
    ; BeginPaint
    lea rdx, [ps]
    call BeginPaint
    mov r13, rax      ; hdc
    
    ; Log hdc
    mov r14, rax
    lea rcx, [szDbgPaintHdc]
    call DebugLog
    mov ecx, r14d
    call DebugLogHex
    lea rcx, [szDbgNewline]
    call DebugLog
    
    ; Get client rect
    mov rcx, r12
    lea rdx, [rect]
    call GetClientRect
    
    ; Fill background
    mov ecx, COLOR_WINDOW + 1
    call GetStockObject
    mov r14, rax      ; hBrush
    
    mov rcx, r13
    lea rdx, [rect]
    mov r8, r14
    call FillRect
    
    ; EndPaint
    mov rcx, r12
    lea rdx, [ps]
    call EndPaint
    
    mov rsp, rbp
    pop rbp
    ret
OnPaint ENDP

; ============================================================================
; mainCRTStartup - Entry point
; ============================================================================
mainCRTStartup PROC
    call WinMain
    mov ecx, eax
    call ExitProcess
mainCRTStartup ENDP

end
