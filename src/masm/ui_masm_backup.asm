;==========================================================================
; ui_masm.asm - Pure MASM64 Win32 UI Layer for RawrXD IDE
; ==========================================================================
; Implements all window management, menus, dialogs, and text controls.
; Uses native Win32 APIs (no Qt, no C++).
; Zero dependencies except kernel32.lib, user32.lib, gdi32.lib.
;==========================================================================

option casemap:none

;==========================================================================
; CONSTANTS
;==========================================================================
WM_DESTROY              equ 0002h
WM_COMMAND              equ 0111h
WM_SIZE                 equ 0005h
WM_CREATE               equ 0001h
WM_SETTEXT              equ 000Ch
WM_GETTEXT              equ 000Dh
WM_SETFONT              equ 0030h

WS_OVERLAPPEDWINDOW     equ 00CF0000h
WS_VISIBLE              equ 10000000h
WS_CHILD                equ 40000000h
WS_BORDER               equ 00800000h
WS_VSCROLL              equ 00200000h
WS_HSCROLL              equ 00100000h

ES_MULTILINE            equ 0004h
ES_AUTOVSCROLL          equ 0040h
ES_AUTOHSCROLL          equ 0080h
ES_WANTRETURN           equ 1000h
ES_READONLY             equ 0800h

; Button constants
BS_PUSHBUTTON           equ 0000h
BS_CHECKBOX             equ 0002h
BS_AUTOCHECKBOX         equ 0003h

; ComboBox constants
CBS_DROPDOWNLIST        equ 0003h

CS_VREDRAW              equ 0001h
CS_HREDRAW              equ 0002h

COLOR_BTNFACE           equ 15
COLOR_WINDOW            equ 5

IDC_ARROW               equ 32512
IDI_APPLICATION         equ 32512

SW_SHOWNORMAL           equ 1
CW_USEDEFAULT           equ 80000000h

MB_OK                   equ 00000000h
MB_ICONINFORMATION      equ 00000040h

; Control IDs
IDC_EXPLORER_TREE       equ 1001
IDC_FILE_LIST           equ 1002
IDC_EDITOR              equ 1003
IDC_CHAT_BOX            equ 1004
IDC_INPUT_BOX           equ 1005
IDC_TERMINAL            equ 1006
IDC_AGENT_LIST          equ 1008
IDC_AGENT_CONSOLE       equ 1009
IDC_TAB_CONTROL         equ 1011
IDC_CHAT_SEND_BTN       equ 1012
IDC_MODEL_SELECTOR      equ 1013
IDC_CHK_MAX_MODE        equ 1014
IDC_CHK_THINKING        equ 1015
IDC_CHK_STREAM          equ 1016
IDC_CHK_DEBUG           equ 1017

; Menu IDs
IDM_FILE_OPEN           equ 2001
IDM_FILE_SAVE           equ 2002
IDM_FILE_SAVE_AS        equ 2004
IDM_FILE_EXIT           equ 2005
IDM_CHAT_CLEAR          equ 2006
IDM_SETTINGS_MODEL      equ 2009
IDM_AGENT_TOGGLE        equ 2017

; RichEdit constants
EM_SETSEL               equ 00B1h
EM_REPLACESEL           equ 00C2h
WM_GETTEXTLENGTH        equ 000Eh

; ListBox constants for Explorer
LBS_NOTIFY              equ 0001h
LB_ADDSTRING            equ 0180h
LB_GETCURSEL            equ 0188h
LB_GETTEXT              equ 0189h
LBN_SELCHANGE           equ 0001h
LBN_DBLCLK              equ 0002h

;==========================================================================
; STRUCTURES
;==========================================================================
WndClassExA STRUCT
    cbSize              DWORD ?
    style               DWORD ?
    lpfnWndProc         QWORD ?
    cbClsExtra          DWORD ?
    cbWndExtra          DWORD ?
    hInstance           QWORD ?
    hIcon               QWORD ?
    hCursor             QWORD ?
    hbrBackground       QWORD ?
    lpszMenuName        QWORD ?
    lpszClassName       QWORD ?
    hIconSm             QWORD ?
WndClassExA ENDS

RECT STRUCT
    left                DWORD ?
    top                 DWORD ?
    right               DWORD ?
    bottom              DWORD ?
RECT ENDS

OPENFILENAMEA STRUCT
    lStructSize         DWORD ?
    hwndOwner           QWORD ?
    hInstance           QWORD ?
    lpstrFilter         QWORD ?
    lpstrCustomFilter   QWORD ?
    nMaxCustFilter      DWORD ?
    nFilterIndex        DWORD ?
    lpstrFile           QWORD ?
    nMaxFile            DWORD ?
    lpstrFileTitle      QWORD ?
    nMaxFileTitle       DWORD ?
    lpstrInitialDir     QWORD ?
    lpstrTitle          QWORD ?
    Flags               DWORD ?
    nFileOffset         WORD ?
    nFileExtension      WORD ?
    lpstrDefExt         QWORD ?
    lCustData           QWORD ?
    lpfnHook            QWORD ?
    lpTemplateName      QWORD ?
    pvReserved          QWORD ?
    dwReserved          DWORD ?
    FlagsEx             DWORD ?
OPENFILENAMEA ENDS

;==========================================================================
; EXTERNAL WIN32 APIs
;==========================================================================
EXTERN GetModuleHandleA : PROC
EXTERN RegisterClassExA : PROC
EXTERN CreateWindowExA : PROC
EXTERN ShowWindow : PROC
EXTERN UpdateWindow : PROC
EXTERN GetMessageA : PROC
EXTERN TranslateMessage : PROC
EXTERN DispatchMessageA : PROC
EXTERN PostQuitMessage : PROC
EXTERN DefWindowProcA : PROC
EXTERN LoadCursorA : PROC
EXTERN LoadIconA : PROC
EXTERN GetClientRect : PROC
EXTERN MoveWindow : PROC
EXTERN SendMessageA : PROC
EXTERN MessageBoxA : PROC
EXTERN CreateMenu : PROC
EXTERN CreatePopupMenu : PROC
EXTERN AppendMenuA : PROC
EXTERN SetMenu : PROC
EXTERN DestroyWindow : PROC
EXTERN GetOpenFileNameA : PROC
EXTERN GetSaveFileNameA : PROC
EXTERN CreateFileA : PROC
EXTERN ReadFile : PROC
EXTERN WriteFile : PROC
EXTERN CloseHandle : PROC
EXTERN GetCurrentDirectoryA : PROC
EXTERN FindFirstFileA : PROC
EXTERN FindNextFileA : PROC
EXTERN FindClose : PROC
EXTERN GetLogicalDriveStringsA : PROC
EXTERN SetCurrentDirectoryA : PROC
; duplicates avoided

;==========================================================================
; DATA SEGMENT
;==========================================================================
.data
    szClassName         BYTE "RawrXD_IDE_Class", 0
    szAppName           BYTE "RawrXD Agentic IDE (Pure MASM64)", 0
    szEditClass         BYTE "EDIT", 0
    szStaticClass       BYTE "STATIC", 0
    szListBoxClass      BYTE "LISTBOX", 0
    szRichEditClass     BYTE "RichEdit20A", 0 ; Using A version for simplicity
    
    szMenuFile          BYTE "&File", 0
    szMenuOpen          BYTE "&Open...", 0
    szMenuSave          BYTE "&Save", 0
    szMenuExit          BYTE "E&xit", 0
    szMenuChat          BYTE "&Chat", 0
    szMenuClear         BYTE "&Clear History", 0
    szMenuSettings      BYTE "&Settings", 0
    szMenuModel         BYTE "&AI Model...", 0
    szMenuTools         BYTE "&Tools", 0
    szMenuAgent         BYTE "Agent &Mode", 0
    
    szFilter            BYTE "All Files (*.*)", 0, "*.*", 0, "ASM Files (*.asm)", 0, "*.asm", 0, 0
    empty_str           BYTE 0
    
    ; Button labels
    szSendButton        BYTE "Send", 0
    szButtonClass       BYTE "BUTTON", 0
    szComboClass        BYTE "COMBOBOX", 0
    szModelGPT          BYTE "GPT-4", 0
    szModelClaude       BYTE "Claude-3", 0
    szModelLlama        BYTE "Llama-2", 0
    szChkMaxMode        BYTE "Max Mode", 0
    szChkThinking       BYTE "Thinking", 0
    szChkStream         BYTE "Stream", 0
    szChkDebug          BYTE "Debug", 0
    szWelcomeMsg        BYTE "RawrXD Agentic IDE Ready", 13, 10, "Select a model and type your message below.", 13, 10, 0
    szDrivePrefix       BYTE "[Drive] ", 0
    szDirPrefix         BYTE "[DIR] ", 0
    szBackDir           BYTE "..", 0

.data?
    hInstance           QWORD ?
    hwndMain            QWORD ?
    hwndEditor          QWORD ?
    hwndChat            QWORD ?
    hwndInput           QWORD ?
    hwndTerminal        QWORD ?
    hwndExplorer        QWORD ?
    hMenu               QWORD ?
    hwndSendBtn         QWORD ?
    hwndModelCombo      QWORD ?
    hwndChkMaxMode      QWORD ?
    hwndChkThinking     QWORD ?
    hwndChkStream       QWORD ?
    hwndChkDebug        QWORD ?
    rectClient          RECT <>
    controls_created    QWORD ? ; Flag: 1 if controls exist, 0 if not
    
    szFileName          BYTE 260 DUP (?)
    szSaveName          BYTE 260 DUP (?)
    ofn                 OPENFILENAMEA <>
    sfn                 OPENFILENAMEA <>
    read_buf            BYTE 65536 DUP (?)
    ; moved initialized data to .data
    szExplorerDir       BYTE 260 DUP (?)
    szExplorerPattern   BYTE 260 DUP (?)
    find_data           BYTE 344 DUP (?)
    szSelectedName      BYTE 260 DUP (?)
    szDriveStrings      BYTE 256 DUP (?)  ; Buffer for GetLogicalDriveStringsA
    szTempBuf           BYTE 512 DUP (?)  ; Temp buffer for building strings


;==========================================================================
; CODE SEGMENT
;==========================================================================
.code

;--------------------------------------------------------------------------
; ui_create_main_window
; rcx = hInstance
;--------------------------------------------------------------------------
ui_create_main_window PROC
    push rbp
    mov rbp, rsp
    sub rsp, 112 ; Shadow space + WndClassExA (80 bytes) + alignment

    mov hInstance, rcx

    ; Fill WndClassExA
    mov DWORD PTR [rsp + 32], 80 ; cbSize
    mov DWORD PTR [rsp + 36], CS_HREDRAW or CS_VREDRAW ; style
    lea rax, wnd_proc_main
    mov QWORD PTR [rsp + 40], rax ; lpfnWndProc
    mov DWORD PTR [rsp + 48], 0 ; cbClsExtra
    mov DWORD PTR [rsp + 52], 0 ; cbWndExtra
    mov rax, hInstance
    mov QWORD PTR [rsp + 56], rax ; hInstance
    
    ; Load Icon
    xor rcx, rcx
    mov rdx, IDI_APPLICATION
    call LoadIconA
    mov QWORD PTR [rsp + 64], rax ; hIcon
    
    ; Load Cursor
    xor rcx, rcx
    mov rdx, IDC_ARROW
    call LoadCursorA
    mov QWORD PTR [rsp + 72], rax ; hCursor
    
    mov QWORD PTR [rsp + 80], COLOR_WINDOW + 1 ; hbrBackground
    mov QWORD PTR [rsp + 88], 0 ; lpszMenuName
    lea rax, szClassName
    mov QWORD PTR [rsp + 96], rax ; lpszClassName
    mov QWORD PTR [rsp + 104], 0 ; hIconSm

    lea rcx, [rsp + 32]
    call RegisterClassExA

    ; Create Main Window
    xor rcx, rcx ; dwExStyle
    lea rdx, szClassName ; lpClassName
    lea r8, szAppName ; lpWindowName
    mov r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE ; dwStyle
    
    sub rsp, 64 ; Extra space for stack params
    mov DWORD PTR [rsp + 32], CW_USEDEFAULT ; x
    mov DWORD PTR [rsp + 40], CW_USEDEFAULT ; y
    mov DWORD PTR [rsp + 48], 1200 ; nWidth
    mov DWORD PTR [rsp + 56], 800 ; nHeight
    mov QWORD PTR [rsp + 64], 0 ; hWndParent
    mov QWORD PTR [rsp + 72], 0 ; hMenu
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax ; hInstance
    mov QWORD PTR [rsp + 88], 0 ; lpParam
    
    call CreateWindowExA
    add rsp, 64
    
    mov hwndMain, rax
    
    ; Create Menu
    call ui_create_menu
    mov hMenu, rax
    mov rcx, hwndMain
    mov rdx, hMenu
    call SetMenu

    ; Create Controls
    call ui_create_controls

    mov rax, hwndMain
    leave
    ret
ui_create_main_window ENDP

;--------------------------------------------------------------------------
; ui_create_menu
;--------------------------------------------------------------------------
ui_create_menu PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    call CreateMenu
    mov rbx, rax ; Main Menu

    ; File Menu
    call CreatePopupMenu
    mov rsi, rax
    
    mov rcx, rsi
    xor rdx, rdx
    mov r8, IDM_FILE_OPEN
    lea r9, szMenuOpen
    call AppendMenuA
    
    mov rcx, rsi
    xor rdx, rdx
    mov r8, IDM_FILE_SAVE
    lea r9, szMenuSave
    call AppendMenuA
    
    mov rcx, rsi
    xor rdx, rdx
    mov r8, IDM_FILE_EXIT
    lea r9, szMenuExit
    call AppendMenuA
    
    mov rcx, rbx
    mov rdx, 10h ; MF_POPUP
    mov r8, rsi
    lea r9, szMenuFile
    call AppendMenuA

    ; Chat Menu
    call CreatePopupMenu
    mov rsi, rax
    
    mov rcx, rsi
    xor rdx, rdx
    mov r8, IDM_CHAT_CLEAR
    lea r9, szMenuClear
    call AppendMenuA
    
    mov rcx, rbx
    mov rdx, 10h ; MF_POPUP
    mov r8, rsi
    lea r9, szMenuChat
    call AppendMenuA

    mov rax, rbx
    leave
    ret
ui_create_menu ENDP

;--------------------------------------------------------------------------
; ui_create_controls
;--------------------------------------------------------------------------
ui_create_controls PROC
    push rbp
    mov rbp, rsp
    sub rsp, 96

    ; Explorer (Left side - LISTBOX)
    xor rcx, rcx
    lea rdx, szListBoxClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or LBS_NOTIFY or WS_VSCROLL
    mov DWORD PTR [rsp + 32], 10 ; x
    mov DWORD PTR [rsp + 40], 10 ; y
    mov DWORD PTR [rsp + 48], 240 ; width
    mov DWORD PTR [rsp + 56], 710 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax ; parent
    mov QWORD PTR [rsp + 72], IDC_EXPLORER_TREE ; id
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndExplorer, rax

    ; Editor (Middle)
    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_AUTOVSCROLL or ES_AUTOHSCROLL or WS_VSCROLL or WS_HSCROLL
    mov DWORD PTR [rsp + 32], 260 ; x
    mov DWORD PTR [rsp + 40], 10 ; y
    mov DWORD PTR [rsp + 48], 450 ; width
    mov DWORD PTR [rsp + 56], 500 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax ; parent
    mov QWORD PTR [rsp + 72], IDC_EDITOR ; id
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndEditor, rax

    ; Model Selector ComboBox (Top right, above chat)
    xor rcx, rcx
    lea rdx, szComboClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or CBS_DROPDOWNLIST
    mov DWORD PTR [rsp + 32], 720 ; x
    mov DWORD PTR [rsp + 40], 10 ; y (top of right pane)
    mov DWORD PTR [rsp + 48], 170 ; width (narrow)
    mov DWORD PTR [rsp + 56], 200 ; height (needs to be tall for dropdown)
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_MODEL_SELECTOR
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndModelCombo, rax

    ; Send Button (Top right, next to model selector)
    xor rcx, rcx
    lea rdx, szButtonClass
    lea r8, szSendButton
    mov r9d, WS_CHILD or WS_VISIBLE or BS_PUSHBUTTON
    mov DWORD PTR [rsp + 32], 900 ; x (right of combo)
    mov DWORD PTR [rsp + 40], 10 ; y
    mov DWORD PTR [rsp + 48], 70 ; width
    mov DWORD PTR [rsp + 56], 25 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHAT_SEND_BTN
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndSendBtn, rax

    ; Chat display EDIT (adjusted to below model selector)
    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_READONLY or WS_VSCROLL
    mov DWORD PTR [rsp + 32], 720 ; x
    mov DWORD PTR [rsp + 40], 40 ; y (below model/send)
    mov DWORD PTR [rsp + 48], 450 ; width
    mov DWORD PTR [rsp + 56], 370 ; height (reduced to fit buttons)
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHAT_BOX
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndChat, rax

    ; Input (Bottom right)
    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_WANTRETURN
    
    mov DWORD PTR [rsp + 32], 720 ; x
    mov DWORD PTR [rsp + 40], 420 ; y
    mov DWORD PTR [rsp + 48], 450 ; width
    mov DWORD PTR [rsp + 56], 90 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_INPUT_BOX
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndInput, rax

    ; Checkboxes below input (right side, bottom)
    ; Max Mode checkbox
    xor rcx, rcx
    lea rdx, szButtonClass
    lea r8, szChkMaxMode
    mov r9d, WS_CHILD or WS_VISIBLE or BS_AUTOCHECKBOX
    mov DWORD PTR [rsp + 32], 720 ; x
    mov DWORD PTR [rsp + 40], 520 ; y (below input)
    mov DWORD PTR [rsp + 48], 100 ; width
    mov DWORD PTR [rsp + 56], 20 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHK_MAX_MODE
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndChkMaxMode, rax

    ; Thinking checkbox
    xor rcx, rcx
    lea rdx, szButtonClass
    lea r8, szChkThinking
    mov r9d, WS_CHILD or WS_VISIBLE or BS_AUTOCHECKBOX
    mov DWORD PTR [rsp + 32], 830 ; x (next to Max Mode)
    mov DWORD PTR [rsp + 40], 520 ; y
    mov DWORD PTR [rsp + 48], 90 ; width
    mov DWORD PTR [rsp + 56], 20 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHK_THINKING
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndChkThinking, rax

    ; Stream checkbox
    xor rcx, rcx
    lea rdx, szButtonClass
    lea r8, szChkStream
    mov r9d, WS_CHILD or WS_VISIBLE or BS_AUTOCHECKBOX
    mov DWORD PTR [rsp + 32], 930 ; x
    mov DWORD PTR [rsp + 40], 520 ; y
    mov DWORD PTR [rsp + 48], 80 ; width
    mov DWORD PTR [rsp + 56], 20 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHK_STREAM
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndChkStream, rax

    ; Debug checkbox
    xor rcx, rcx
    lea rdx, szButtonClass
    lea r8, szChkDebug
    mov r9d, WS_CHILD or WS_VISIBLE or BS_AUTOCHECKBOX
    mov DWORD PTR [rsp + 32], 1020 ; x
    mov DWORD PTR [rsp + 40], 520 ; y
    mov DWORD PTR [rsp + 48], 80 ; width
    mov DWORD PTR [rsp + 56], 20 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHK_DEBUG
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndChkDebug, rax

    ; Terminal (Bottom left under Editor)
    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_READONLY or WS_VSCROLL
    mov DWORD PTR [rsp + 32], 260 ; x
    mov DWORD PTR [rsp + 40], 520 ; y
    mov DWORD PTR [rsp + 48], 450 ; width
    mov DWORD PTR [rsp + 56], 200 ; height
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_TERMINAL
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    mov hwndTerminal, rax

    ; Mark controls as created for WM_SIZE handler
    mov QWORD PTR controls_created, 1
    
    ; Add welcome message to chat
    mov rcx, hwndChat
    mov rdx, WM_SETTEXT
    lea r8, szWelcomeMsg
    xor r9, r9
    call SendMessageA
    
    ; Populate model selector with options
    mov rcx, hwndModelCombo
    mov rdx, 0143h ; CB_ADDSTRING
    xor r8, r8
    lea r9, szModelGPT
    call SendMessageA
    
    mov rcx, hwndModelCombo
    mov rdx, 0143h ; CB_ADDSTRING
    xor r8, r8
    lea r9, szModelClaude
    call SendMessageA
    
    mov rcx, hwndModelCombo
    mov rdx, 0143h ; CB_ADDSTRING
    xor r8, r8
    lea r9, szModelLlama
    call SendMessageA
    
    ; Set default selection (first item)
    mov rcx, hwndModelCombo
    mov rdx, 014Eh ; CB_SETCURSEL
    xor r8, r8 ; index 0
    xor r9, r9
    call SendMessageA
    
    ; Add a simple test entry to explorer first
    mov rcx, hwndExplorer
    mov rdx, LB_ADDSTRING
    xor r8, r8
    lea r9, szWelcomeMsg ; Reuse string as test
    call SendMessageA
    
    ; Now safely populate explorer with files from current directory
    ; (wrapped in try-catch equivalent - if it fails, we already have test entry)
    call ui_populate_explorer

    leave
    ret
ui_create_controls ENDP

;--------------------------------------------------------------------------
; wnd_proc_main
;--------------------------------------------------------------------------
; External menu handlers previously used; not needed now

wnd_proc_main PROC
    ; rcx = hwnd, rdx = uMsg, r8 = wParam, r9 = lParam
    push rbp
    mov rbp, rsp
    sub rsp, 48 ; Shadow space

    cmp edx, WM_CREATE
    je on_create
    cmp edx, WM_DESTROY
    je on_destroy
    cmp edx, WM_SIZE
    je on_size
    cmp edx, WM_COMMAND
    je on_command
    
    ; Default: call DefWindowProcA with parameters (rcx, rdx, r8, r9 already set)
    call DefWindowProcA
    leave
    ret

on_create:
    ; Window created - controls will be created after this returns
    ; Do NOT call ui_populate_explorer here - controls don't exist yet
    xor rax, rax
    leave
    ret

on_destroy:
    xor rcx, rcx
    call PostQuitMessage
    xor rax, rax
    leave
    ret

on_size:
    ; Dynamic pane layout on resize
    ; Skip if controls not yet created
    mov rax, controls_created
    test rax, rax
    jz size_done_ret
    
    ; Skip if already processing or no main window
    mov rax, hwndMain
    test rax, rax
    jz size_done_ret
    ; Get client rect
    mov rcx, hwndMain
    lea rdx, rectClient
    call GetClientRect

    ; width = right - left; height = bottom - top
    mov eax, DWORD PTR [rectClient.right]
    sub eax, DWORD PTR [rectClient.left]
    mov r12d, eax ; width
    mov eax, DWORD PTR [rectClient.bottom]
    sub eax, DWORD PTR [rectClient.top]
    mov r13d, eax ; height

    ; constants
    mov r14d, 10      ; margin
    mov r15d, 260     ; explorer width
    mov r10d, 450     ; right column width
    mov r11d, 200     ; terminal height
    mov ebx, 90       ; input height

    ; computed positions
    mov eax, r12d
    sub eax, r10d
    sub eax, r14d
    mov esi, eax      ; rightX

    mov eax, r15d
    add eax, r14d
    add eax, r14d
    mov edi, eax      ; editorX

    mov eax, r12d
    sub eax, r10d
    sub eax, r15d
    sub eax, r14d
    sub eax, r14d
    sub eax, r14d
    sub eax, r14d
    mov ecx, eax      ; editorW

    mov edx, r14d     ; editorY
    mov eax, r13d
    sub eax, r11d
    sub eax, r14d
    sub eax, r14d
    sub eax, r14d
    mov ebp, eax      ; editorH

    ; Move Explorer
    mov rax, hwndExplorer
    test rax, rax
    jz skip_explorer
    mov rcx, rax
    mov edx, r14d
    mov r8d, r14d
    mov r9d, r15d
    sub rsp, 32
    mov eax, r13d
    sub eax, r14d
    sub eax, r14d
    mov DWORD PTR [rsp + 32], eax
    mov DWORD PTR [rsp + 40], 1
    call MoveWindow
    add rsp, 32
skip_explorer:

    ; Move Editor
    mov rax, hwndEditor
    test rax, rax
    jz skip_editor
    mov rcx, rax
    mov edx, edi
    mov r8d, r14d
    mov r9d, ecx
    sub rsp, 32
    mov DWORD PTR [rsp + 32], ebp
    mov DWORD PTR [rsp + 40], 1
    call MoveWindow
    add rsp, 32
skip_editor:

    ; Move Terminal
    mov rax, hwndTerminal
    test rax, rax
    jz skip_terminal
    mov rcx, rax
    mov edx, edi
    mov eax, edx
    add eax, ebp
    add eax, r14d
    mov r8d, eax
    mov r9d, ecx
    sub rsp, 32
    mov DWORD PTR [rsp + 32], 200
    mov DWORD PTR [rsp + 40], 1
    call MoveWindow
    add rsp, 32
skip_terminal:

    ; Move Chat
    mov rax, hwndChat
    test rax, rax
    jz skip_chat
    mov rcx, rax
    mov edx, esi
    mov r8d, r14d
    mov r9d, r10d
    sub rsp, 32
    mov eax, r13d
    sub eax, ebx
    sub eax, r14d
    sub eax, r14d
    sub eax, r14d
    mov DWORD PTR [rsp + 32], eax
    mov DWORD PTR [rsp + 40], 1
    call MoveWindow
    add rsp, 32
skip_chat:

    ; Move Input
    mov rax, hwndInput
    test rax, rax
    jz skip_input
    mov rcx, rax
    mov edx, esi
    mov eax, r13d
    sub eax, ebx
    sub eax, r14d
    sub eax, r14d
    sub eax, r14d
    add eax, r14d
    add eax, r14d
    mov r8d, eax
    mov r9d, r10d
    sub rsp, 32
    mov DWORD PTR [rsp + 32], ebx
    mov DWORD PTR [rsp + 40], 1
    call MoveWindow
    add rsp, 32
skip_input:

size_done_ret:
    xor rax, rax
    leave
    ret

on_command:
    mov eax, r8d ; wParam (low word is ID)
    and eax, 0FFFFh
    
    cmp eax, IDM_FILE_EXIT
    je on_exit
    cmp eax, IDM_FILE_OPEN
    je on_open
    cmp eax, IDM_FILE_SAVE
    je on_save
    cmp eax, IDM_FILE_SAVE_AS
    je on_save_as
    cmp eax, IDM_CHAT_CLEAR
    je on_chat_clear
    ; Send Button
    cmp eax, IDC_CHAT_SEND_BTN
    je on_send_button
    ; Explorer listbox notifications
    cmp eax, IDC_EXPLORER_TREE
    jne cmd_other
    ; HIWORD(wParam) in r8d high word
    mov ebx, r8d
    shr ebx, 16
    cmp ebx, LBN_DBLCLK
    je on_explorer_open
    ; Skip single selection to avoid freezing on every click
    jmp cmd_other
on_explorer_open:
    ; On double-click: open selected file/folder/drive
    mov rcx, hwndExplorer
    mov rdx, LB_GETCURSEL
    xor r8, r8
    xor r9, r9
    call SendMessageA
    cmp eax, 0FFFFFFFFh
    je cmd_other
    ; Get text of selected item into szSelectedName
    mov rcx, hwndExplorer
    mov rdx, LB_GETTEXT
    mov r8d, eax ; index
    lea r9, szSelectedName
    call SendMessageA
    
    ; Check if it's a drive (starts with "[Drive] ")
    lea rsi, szSelectedName
    mov eax, DWORD PTR [rsi]  ; Load first 4 bytes
    cmp eax, 5B447269h  ; "[Dri" in little-endian (reverse bytes)
    jne check_dir
    ; Extract drive letter (after "[Drive] ")
    add rsi, 8  ; Skip "[Drive] "
    ; Drive letter is now at rsi (e.g., "C:\")
    lea rdi, szExplorerDir
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    mov BYTE PTR [rdi + 1], 58  ; ':'
    mov BYTE PTR [rdi + 2], 92  ; '\'
    mov BYTE PTR [rdi + 3], 0
    ; Change to this drive
    lea rcx, szExplorerDir
    call SetCurrentDirectoryA
    ; Refresh explorer
    call ui_populate_explorer
    xor rax, rax
    leave
    ret

check_dir:
    ; Check if it's ".." to go up
    lea rsi, szSelectedName
    mov ax, WORD PTR [rsi]
    cmp ax, 2E2Eh  ; ".."
    jne check_folder
    ; Go up one directory
    call ui_navigate_up
    xor rax, rax
    leave
    ret

check_folder:
    ; Check if it's a directory (starts with "[DIR] ")
    lea rsi, szSelectedName
    mov eax, DWORD PTR [rsi]
    cmp eax, 5B444952h  ; "[DIR" in little-endian (reverse bytes: 52 49 44 5B)
    jne open_file
    ; Extract folder name (after "[DIR] ")
    add rsi, 6  ; Skip "[DIR] "
    ; Build new path: current + \ + foldername
    lea rdi, szTempBuf
    lea rbx, szExplorerDir
nav_cp_cur_dir:
    mov al, BYTE PTR [rbx]
    test al, al
    jz nav_add_slash
    mov BYTE PTR [rdi], al
    inc rbx
    inc rdi
    jmp nav_cp_cur_dir
nav_add_slash:
    ; Check if path already ends with backslash
    cmp BYTE PTR [rdi - 1], 92
    je nav_skip_slash
    mov BYTE PTR [rdi], 92
    inc rdi
nav_skip_slash:
    ; Copy folder name
nav_cp_folder:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    test al, al
    jz nav_set_new_dir
    inc rsi
    inc rdi
    jmp nav_cp_folder
nav_set_new_dir:
    ; Change directory
    lea rcx, szTempBuf
    call SetCurrentDirectoryA
    ; Refresh explorer
    call ui_populate_explorer
    xor rax, rax
    leave
    ret

open_file:
    ; Build full path: szExplorerDir + '\' + szSelectedName -> szFileName
    lea rsi, szExplorerDir
    lea rdi, szFileName
file_copy_dir:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    test al, al
    jz file_add_backslash
    inc rsi
    inc rdi
    jmp file_copy_dir
file_add_backslash:
    ; Check if already ends with backslash
    cmp BYTE PTR [rdi - 1], 92
    je file_copy_filename
    mov BYTE PTR [rdi - 1], 92
file_copy_filename:
    lea rsi, szSelectedName
file_copy_name:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz file_copy_name
    ; Clear editor first
    mov rcx, hwndEditor
    mov rdx, WM_SETTEXT
    xor r8, r8
    lea r9, empty_str
    call SendMessageA
    ; Load file
    call ui_load_selected_file
    xor rax, rax
    leave
    ret

on_send_button:
    ; Get text from input control
    mov rcx, hwndInput
    mov rdx, WM_GETTEXTLENGTH
    xor r8, r8
    xor r9, r9
    call SendMessageA
    test eax, eax
    jz cmd_ret_sb ; Exit if input is empty
    
    ; Get input text into read_buf (reuse buffer)
    mov ecx, eax
    inc ecx ; Include NUL
    mov rcx, hwndInput
    mov rdx, WM_GETTEXT
    mov r8d, ecx
    lea r9, read_buf
    call SendMessageA
    
    ; Append to chat: set selection to end, then insert text
    mov rcx, hwndChat
    mov rdx, EM_SETSEL
    mov r8, -1
    mov r9, -1
    call SendMessageA
    
    ; Append newline + text
    mov rcx, hwndChat
    mov rdx, EM_REPLACESEL
    xor r8, r8
    lea r9, read_buf
    call SendMessageA
    
    ; Clear input
    call ui_clear_input
    
cmd_ret_sb:
    xor rax, rax
    leave
    ret

cmd_other:
    xor rax, rax
    leave
    ret

on_open:
    ; Open file dialog and load into editor
    call ui_open_file_dialog
    test rax, rax
    jz cmd_ret
    call ui_load_selected_file
cmd_ret:
    xor rax, rax
    leave
    ret

on_save:
    call ui_save_file_dialog
    test rax, rax
    jz cmd_ret2
    call ui_save_editor_to_file
cmd_ret2:
    xor rax, rax
    leave
    ret

on_save_as:
    ; Save As follows same flow using save dialog
    call ui_save_file_dialog
    test rax, rax
    jz cmd_ret3
    call ui_save_editor_to_file
cmd_ret3:
    xor rax, rax
    leave
    ret

on_chat_clear:
    ; Clear chat text
    mov rcx, hwndChat
    mov rdx, WM_SETTEXT
    lea r8, empty_str
    xor r9, r9
    call SendMessageA
    xor rax, rax
    leave
    ret

on_exit:
    mov rcx, hwndMain
    call DestroyWindow
    xor rax, rax
    leave
    ret

wnd_proc_main ENDP

;--------------------------------------------------------------------------
; ui_set_main_menu
;--------------------------------------------------------------------------
ui_set_main_menu PROC
    ; rcx = hmenu
    mov rdx, rcx
    mov rcx, hwndMain
    call SetMenu
    ret
ui_set_main_menu ENDP

;--------------------------------------------------------------------------
; ui_create_chat_control
;--------------------------------------------------------------------------
ui_create_chat_control PROC
    ; Return existing handle if created
    mov rax, hwndChat
    test rax, rax
    jnz uc_ret

    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_READONLY or WS_VSCROLL
    sub rsp, 64
    mov DWORD PTR [rsp + 32], 720
    mov DWORD PTR [rsp + 40], 10
    mov DWORD PTR [rsp + 48], 450
    mov DWORD PTR [rsp + 56], 400
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_CHAT_BOX
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    add rsp, 64
    mov hwndChat, rax
uc_ret:
    mov rax, hwndChat
    ret
ui_create_chat_control ENDP

;--------------------------------------------------------------------------
; ui_create_input_control
;--------------------------------------------------------------------------
ui_create_input_control PROC
    mov rax, hwndInput
    test rax, rax
    jnz ui_ret

    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_WANTRETURN
    sub rsp, 64
    mov DWORD PTR [rsp + 32], 720
    mov DWORD PTR [rsp + 40], 420
    mov DWORD PTR [rsp + 48], 450
    mov DWORD PTR [rsp + 56], 90
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_INPUT_BOX
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    add rsp, 64
    mov hwndInput, rax
ui_ret:
    mov rax, hwndInput
    ret
ui_create_input_control ENDP

;--------------------------------------------------------------------------
; ui_create_terminal_control
;--------------------------------------------------------------------------
ui_create_terminal_control PROC
    mov rax, hwndTerminal
    test rax, rax
    jnz ut_ret

    xor rcx, rcx
    lea rdx, szEditClass
    xor r8, r8
    mov r9d, WS_CHILD or WS_VISIBLE or WS_BORDER or ES_MULTILINE or ES_READONLY or WS_VSCROLL
    sub rsp, 64
    mov DWORD PTR [rsp + 32], 10
    mov DWORD PTR [rsp + 40], 520
    mov DWORD PTR [rsp + 48], 700
    mov DWORD PTR [rsp + 56], 200
    mov rax, hwndMain
    mov QWORD PTR [rsp + 64], rax
    mov QWORD PTR [rsp + 72], IDC_TERMINAL
    mov rax, hInstance
    mov QWORD PTR [rsp + 80], rax
    mov QWORD PTR [rsp + 88], 0
    call CreateWindowExA
    add rsp, 64
    mov hwndTerminal, rax
ut_ret:
    mov rax, hwndTerminal
    ret
ui_create_terminal_control ENDP

;--------------------------------------------------------------------------
; ui_open_file_dialog
; Returns 1 on success, 0 otherwise. Path in szFileName.
;--------------------------------------------------------------------------
ui_open_file_dialog PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    mov DWORD PTR [ofn.lStructSize], sizeof OPENFILENAMEA
    mov rax, hwndMain
    mov QWORD PTR [ofn.hwndOwner], rax
    xor rax, rax
    mov QWORD PTR [ofn.hInstance], rax
    lea rax, szFilter
    mov QWORD PTR [ofn.lpstrFilter], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpstrCustomFilter], rax
    mov DWORD PTR [ofn.nMaxCustFilter], 0
    mov DWORD PTR [ofn.nFilterIndex], 1
    lea rax, szFileName
    mov QWORD PTR [ofn.lpstrFile], rax
    mov DWORD PTR [ofn.nMaxFile], 260
    xor rax, rax
    mov QWORD PTR [ofn.lpstrFileTitle], rax
    mov DWORD PTR [ofn.nMaxFileTitle], 0
    xor rax, rax
    mov QWORD PTR [ofn.lpstrInitialDir], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpstrTitle], rax
    mov DWORD PTR [ofn.Flags], 00000800h or 00000004h ; OFN_EXPLORER | OFN_FILEMUSTEXIST
    mov WORD PTR [ofn.nFileOffset], 0
    mov WORD PTR [ofn.nFileExtension], 0
    xor rax, rax
    mov QWORD PTR [ofn.lpstrDefExt], rax
    xor rax, rax
    mov QWORD PTR [ofn.lCustData], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpfnHook], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpTemplateName], rax
    xor rax, rax
    mov QWORD PTR [ofn.pvReserved], rax
    mov DWORD PTR [ofn.dwReserved], 0
    mov DWORD PTR [ofn.FlagsEx], 0

    lea rcx, ofn
    call GetOpenFileNameA
    leave
    ret
ui_open_file_dialog ENDP

;--------------------------------------------------------------------------
; ui_save_file_dialog
; Returns 1 on success, 0 otherwise. Path in szSaveName.
;--------------------------------------------------------------------------
ui_save_file_dialog PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    mov DWORD PTR [sfn.lStructSize], sizeof OPENFILENAMEA
    mov rax, hwndMain
    mov QWORD PTR [sfn.hwndOwner], rax
    xor rax, rax
    mov QWORD PTR [sfn.hInstance], rax
    lea rax, szFilter
    mov QWORD PTR [sfn.lpstrFilter], rax
    xor rax, rax
    mov QWORD PTR [sfn.lpstrCustomFilter], rax
    mov DWORD PTR [sfn.nMaxCustFilter], 0
    mov DWORD PTR [sfn.nFilterIndex], 1
    lea rax, szSaveName
    mov QWORD PTR [sfn.lpstrFile], rax
    mov DWORD PTR [sfn.nMaxFile], 260
    xor rax, rax
    mov QWORD PTR [sfn.lpstrFileTitle], rax
    mov DWORD PTR [sfn.nMaxFileTitle], 0
    xor rax, rax
    mov QWORD PTR [sfn.lpstrInitialDir], rax
    xor rax, rax
    mov QWORD PTR [sfn.lpstrTitle], rax
    mov DWORD PTR [sfn.Flags], 00000800h or 00000002h ; OFN_EXPLORER | OFN_OVERWRITEPROMPT
    mov WORD PTR [sfn.nFileOffset], 0
    mov WORD PTR [sfn.nFileExtension], 0
    xor rax, rax
    mov QWORD PTR [sfn.lpstrDefExt], rax
    xor rax, rax
    mov QWORD PTR [sfn.lCustData], rax
    xor rax, rax
    mov QWORD PTR [sfn.lpfnHook], rax
    xor rax, rax
    mov QWORD PTR [sfn.lpTemplateName], rax
    xor rax, rax
    mov QWORD PTR [sfn.pvReserved], rax
    mov DWORD PTR [sfn.dwReserved], 0
    mov DWORD PTR [sfn.FlagsEx], 0

    lea rcx, sfn
    call GetSaveFileNameA
    leave
    ret
ui_save_file_dialog ENDP

;--------------------------------------------------------------------------
; ui_load_selected_file
; Reads szFileName and appends content to editor.
;--------------------------------------------------------------------------
ui_load_selected_file PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
    lea rcx, szFileName
    mov rdx, 80000000h ; GENERIC_READ
    mov r8d, 00000001h ; FILE_SHARE_READ
    xor r9, r9
    mov DWORD PTR [rsp + 32], 3 ; OPEN_EXISTING
    mov DWORD PTR [rsp + 40], 0
    xor rax, rax
    mov QWORD PTR [rsp + 48], rax
    call CreateFileA
    mov rsi, rax
    cmp rsi, -1
    je ul_done

    ; Read loop
    lea rdi, read_buf
ul_read:
    mov rcx, rsi
    mov rdx, rdi
    mov r8d, 65536
    lea r9, [rsp + 56] ; lpNumberOfBytesRead
    call ReadFile
    test eax, eax
    jz ul_close
    mov eax, DWORD PTR [rsp + 56]
    test eax, eax
    jz ul_close
    
    ; Append chunk to editor via EM_REPLACESEL
    mov rcx, hwndEditor
    mov rdx, EM_SETSEL
    mov r8, -1
    mov r9, -1
    call SendMessageA
    
    mov rcx, hwndEditor
    mov rdx, EM_REPLACESEL
    xor r8, r8
    lea r9, read_buf
    ; EM_REPLACESEL expects NUL-terminated; temporarily add NUL using RIP-safe addressing
    lea rbx, read_buf
    mov BYTE PTR [rbx + rax], 0
    call SendMessageA
    jmp ul_read

ul_close:
    mov rcx, rsi
    call CloseHandle
ul_done:
    leave
    ret
ui_load_selected_file ENDP

;--------------------------------------------------------------------------
; ui_save_editor_to_file
; Writes editor content to szSaveName
;--------------------------------------------------------------------------
ui_save_editor_to_file PROC
    push rbp
    mov rbp, rsp
    sub rsp, 80

    ; Get text length
    mov rcx, hwndEditor
    mov rdx, WM_GETTEXTLENGTH
    xor r8, r8
    xor r9, r9
    call SendMessageA
    mov r12d, eax

    ; Read in chunks using WM_GETTEXT (limited by buffer). We'll do one shot up to 64KB.
    ; If longer, we save first 64KB.
    mov ecx, r12d
    cmp ecx, 65535
    jbe us_len_ok
    mov ecx, 65535
us_len_ok:
    ; WM_GETTEXT expects size including NUL
    lea r9, read_buf
    mov r8d, ecx
    inc r8d
    mov rcx, hwndEditor
    mov rdx, WM_GETTEXT
    call SendMessageA

    ; Create file for write
    lea rcx, szSaveName
    mov rdx, 40000000h ; GENERIC_WRITE
    mov r8d, 00000000h ; FILE_SHARE_NONE
    xor r9, r9
    mov DWORD PTR [rsp + 32], 2 ; CREATE_ALWAYS
    mov DWORD PTR [rsp + 40], 0
    xor rax, rax
    mov QWORD PTR [rsp + 48], rax
    call CreateFileA
    mov rsi, rax
    cmp rsi, -1
    je us_done

    ; Write buffer
    mov rcx, rsi
    lea rdx, read_buf
    mov r8d, eax ; number of chars copied including NUL; write eax-1
    dec r8d
    lea r9, [rsp + 56]
    call WriteFile
    
    mov rcx, rsi
    call CloseHandle

us_done:
    leave
    ret
ui_save_editor_to_file ENDP

;--------------------------------------------------------------------------
; ui_populate_explorer
; Fills explorer listbox with drives or directory contents
;--------------------------------------------------------------------------
ui_populate_explorer PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Clear listbox first
    mov rcx, hwndExplorer
    mov rdx, 0184h  ; LB_RESETCONTENT
    xor r8, r8
    xor r9, r9
    call SendMessageA

    ; Get current directory
    mov rcx, 260
    lea rdx, szExplorerDir
    call GetCurrentDirectoryA

    ; Check if we're at root (length = 3, like "C:\")
    lea rsi, szExplorerDir
    xor ecx, ecx
count_len:
    mov al, BYTE PTR [rsi + rcx]
    test al, al
    jz check_root
    inc ecx
    jmp count_len
check_root:
    cmp ecx, 3
    jle show_drives  ; If "C:\" or shorter, show all drives
    jmp show_contents

show_drives:
    ; Get all logical drives
    mov rcx, 256
    lea rdx, szDriveStrings
    call GetLogicalDriveStringsA
    test eax, eax
    jz show_contents  ; If drive enum fails, show current dir contents instead
    
    ; Parse drive strings (null-separated, double-null terminated)
    lea rsi, szDriveStrings
    xor r15, r15  ; Counter to prevent infinite loop
parse_drives:
    inc r15
    cmp r15, 50  ; Max 50 iterations (safety)
    jge pe_done
    mov al, BYTE PTR [rsi]
    test al, al
    jz pe_done  ; Double-null means end
    
    ; Build display string: "[Drive] C:\"
    lea rdi, szTempBuf
    lea rbx, szDrivePrefix
cp_prefix:
    mov al, BYTE PTR [rbx]
    test al, al
    jz cp_drive_letter
    mov BYTE PTR [rdi], al
    inc rbx
    inc rdi
    jmp cp_prefix
cp_drive_letter:
    ; Copy drive string (e.g., "C:\")
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    mov BYTE PTR [rdi], 0
    inc rsi  ; Skip null terminator
    
    ; Add to listbox
    mov rcx, hwndExplorer
    mov rdx, LB_ADDSTRING
    xor r8, r8
    lea r9, szTempBuf
    call SendMessageA
    jmp parse_drives

show_contents:
    ; Add ".." to go up if not at root
    lea rsi, szExplorerDir
    xor ecx, ecx
count_len2:
    mov al, BYTE PTR [rsi + rcx]
    test al, al
    jz add_parent
    inc ecx
    jmp count_len2
add_parent:
    cmp ecx, 3
    jle skip_parent
    mov rcx, hwndExplorer
    mov rdx, LB_ADDSTRING
    xor r8, r8
    lea r9, szBackDir
    call SendMessageA
skip_parent:

    ; Build pattern: szExplorerDir + "\\*.*"
    lea rsi, szExplorerDir
    lea rdi, szExplorerPattern
cp_pat_dir:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz cp_pat_dir
    ; Check if already ends with backslash
    cmp BYTE PTR [rdi - 2], 92
    je skip_backslash
    mov BYTE PTR [rdi - 1], 92
    inc rdi
skip_backslash:
    mov BYTE PTR [rdi - 1], 42  ; '*'
    mov BYTE PTR [rdi], 46      ; '.'
    mov BYTE PTR [rdi + 1], 42  ; '*'
    mov BYTE PTR [rdi + 2], 0

    ; FindFirstFileA
    lea rcx, szExplorerPattern
    lea rdx, find_data
    call FindFirstFileA
    mov rbx, rax
    cmp rbx, -1
    je pe_done

pe_loop:
    ; cFileName at offset 44 bytes from start of WIN32_FIND_DATAA
    lea rsi, find_data
    lea r14, [rsi + 44]  ; filename pointer
    mov eax, DWORD PTR [rsi + 0]  ; dwFileAttributes
    
    ; Skip "." and ".."
    mov al, BYTE PTR [r14]
    cmp al, 46  ; '.'
    jne check_is_dir
    mov al, BYTE PTR [r14 + 1]
    test al, al
    jz pe_next
    cmp al, 46
    jne check_is_dir
    mov al, BYTE PTR [r14 + 2]
    test al, al
    jz pe_next

check_is_dir:
    ; Check if directory
    mov eax, DWORD PTR [rsi + 0]
    test eax, 00000010h  ; FILE_ATTRIBUTE_DIRECTORY
    jz add_file
    
    ; Build "[DIR] filename"
    lea rdi, szTempBuf
    lea rbx, szDirPrefix
cp_dir_prefix:
    mov al, BYTE PTR [rbx]
    test al, al
    jz cp_dir_name
    mov BYTE PTR [rdi], al
    inc rbx
    inc rdi
    jmp cp_dir_prefix
cp_dir_name:
    mov rsi, r14
cp_dname:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    test al, al
    jz add_dir_item
    inc rsi
    inc rdi
    jmp cp_dname
add_dir_item:
    mov rcx, hwndExplorer
    mov rdx, LB_ADDSTRING
    xor r8, r8
    lea r9, szTempBuf
    call SendMessageA
    jmp pe_next

add_file:
    ; Add file name directly
    mov rcx, hwndExplorer
    mov rdx, LB_ADDSTRING
    xor r8, r8
    mov r9, r14
    call SendMessageA

pe_next:
    mov rcx, rbx
    lea rdx, find_data
    call FindNextFileA
    test eax, eax
    jnz pe_loop

    ; Close handle
    mov rcx, rbx
    call FindClose

pe_done:
    leave
    ret
ui_populate_explorer ENDP

;--------------------------------------------------------------------------
; ui_navigate_up
; Goes up one directory level
;--------------------------------------------------------------------------
ui_navigate_up PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Find last backslash in szExplorerDir
    lea rsi, szExplorerDir
    xor ecx, ecx
    xor edx, edx  ; last backslash position
find_last_slash:
    mov al, BYTE PTR [rsi + rcx]
    test al, al
    jz trim_path
    cmp al, 92  ; '\'
    jne next_char
    mov edx, ecx
next_char:
    inc ecx
    jmp find_last_slash
trim_path:
    ; If edx > 2, we can go up (not at "C:\")
    cmp edx, 2
    jle up_done
    ; Null-terminate at last backslash
    mov BYTE PTR [rsi + rdx], 0
    ; Change directory
    lea rcx, szExplorerDir
    call SetCurrentDirectoryA
    ; Refresh explorer
    call ui_populate_explorer
up_done:
    leave
    ret
ui_navigate_up ENDP

; (legacy main_* handlers removed; not referenced by this module)

;--------------------------------------------------------------------------
; ui_open_text_file_dialog
; Returns rax = pointer to szFileName or 0 if canceled
;--------------------------------------------------------------------------
PUBLIC ui_open_text_file_dialog
ui_open_text_file_dialog PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    mov DWORD PTR [ofn.lStructSize], SIZEOF OPENFILENAMEA
    mov rax, hwndMain
    mov QWORD PTR [ofn.hwndOwner], rax
    xor rax, rax
    mov QWORD PTR [ofn.hInstance], rax
    lea rax, szFilter
    mov QWORD PTR [ofn.lpstrFilter], rax
    mov DWORD PTR [ofn.nFilterIndex], 1
    lea rax, szFileName
    mov QWORD PTR [ofn.lpstrFile], rax
    mov DWORD PTR [ofn.nMaxFile], 260
    xor rax, rax
    mov QWORD PTR [ofn.lpstrFileTitle], rax
    mov DWORD PTR [ofn.nMaxFileTitle], 0
    xor rax, rax
    mov QWORD PTR [ofn.lpstrInitialDir], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpstrTitle], rax
    mov DWORD PTR [ofn.Flags], 00000800h ; OFN_EXPLORER
    mov WORD PTR  [ofn.nFileOffset], 0
    mov WORD PTR  [ofn.nFileExtension], 0
    xor rax, rax
    mov QWORD PTR [ofn.lpstrDefExt], rax
    xor rax, rax
    mov QWORD PTR [ofn.lCustData], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpfnHook], rax
    xor rax, rax
    mov QWORD PTR [ofn.lpTemplateName], rax
    xor rax, rax
    mov QWORD PTR [ofn.pvReserved], rax
    mov DWORD PTR [ofn.dwReserved], 0
    mov DWORD PTR [ofn.FlagsEx], 0

    lea rcx, ofn
    call GetOpenFileNameA
    test eax, eax
    jz cancel_open
    lea rax, szFileName
    leave
    ret
cancel_open:
    xor rax, rax
    leave
    ret
ui_open_text_file_dialog ENDP

;--------------------------------------------------------------------------
; ui_editor_set_text
; rcx = pointer to null-terminated ASCII
;--------------------------------------------------------------------------
PUBLIC ui_editor_set_text
ui_editor_set_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    mov rdx, WM_SETTEXT
    mov r8, rcx
    mov rcx, hwndEditor
    call SendMessageA

    leave
    ret
ui_editor_set_text ENDP

;--------------------------------------------------------------------------
; ui_editor_get_text
; rcx = buffer, rdx = maxlen; returns length
;--------------------------------------------------------------------------
PUBLIC ui_editor_get_text
ui_editor_get_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    mov r8, rdx
    mov r9, rcx
    mov rcx, hwndEditor
    mov rdx, WM_GETTEXT
    call SendMessageA

    leave
    ret
ui_editor_get_text ENDP

; (removed legacy duplicate ui_open_file_dialog; using unified implementation above)

;--------------------------------------------------------------------------
; ui_add_chat_message
; rcx = message string
;--------------------------------------------------------------------------
ui_add_chat_message PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    mov rsi, rcx ; Save message
    
    ; Set selection to end
    mov rcx, hwndChat
    mov rdx, EM_SETSEL
    mov r8, -1
    mov r9, -1
    call SendMessageA
    
    ; Replace selection
    mov rcx, hwndChat
    mov rdx, EM_REPLACESEL
    xor r8, r8
    mov r9, rsi
    call SendMessageA
    
    leave
    ret
ui_add_chat_message ENDP

;--------------------------------------------------------------------------
; ui_show_dialog
; rcx = title, rdx = message
;--------------------------------------------------------------------------
ui_show_dialog PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    mov r8, rcx ; title
    mov rcx, hwndMain
    ; rdx is already message
    mov r9d, MB_OK or MB_ICONINFORMATION
    call MessageBoxA
    
    leave
    ret
ui_show_dialog ENDP

;--------------------------------------------------------------------------
; ui_get_input_text
; rcx = buffer, rdx = maxlen
;--------------------------------------------------------------------------
ui_get_input_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    mov r8, rdx ; maxlen
    mov r9, rcx ; buffer
    mov rcx, hwndInput
    mov rdx, WM_GETTEXT
    call SendMessageA
    
    leave
    ret
ui_get_input_text ENDP

;--------------------------------------------------------------------------
; ui_clear_input
;--------------------------------------------------------------------------
ui_clear_input PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    mov rcx, hwndInput
    mov rdx, WM_SETTEXT
    xor r8, r8
    xor r9, r9
    call SendMessageA
    
    leave
    ret
ui_clear_input ENDP

PUBLIC ui_create_main_window
PUBLIC ui_create_menu
PUBLIC ui_add_chat_message
PUBLIC ui_show_dialog
PUBLIC ui_get_input_text
PUBLIC ui_clear_input
PUBLIC ui_set_main_menu
PUBLIC ui_create_chat_control
PUBLIC ui_create_input_control
PUBLIC ui_create_terminal_control
PUBLIC ui_open_file_dialog
PUBLIC ui_save_file_dialog
PUBLIC ui_load_selected_file
PUBLIC ui_save_editor_to_file
PUBLIC wnd_proc_main

END


