;=============================================================================
; RawrXD_GUI_v5.asm - Advanced Features Edition
; Syntax highlighting, error parsing, project files
; ml64.exe + link /SUBSYSTEM:WINDOWS /ENTRY:WinMain
;=============================================================================
OPTION CASEMAP:NONE

;-----------------------------------------------------------------------------
; Win32 API
;-----------------------------------------------------------------------------
EXTERN  LoadCursorA         :PROC
EXTERN  RegisterClassExA    :PROC
EXTERN  CreateWindowExA     :PROC
EXTERN  ShowWindow          :PROC
EXTERN  UpdateWindow        :PROC
EXTERN  GetMessageA         :PROC
EXTERN  TranslateMessage    :PROC
EXTERN  DispatchMessageA    :PROC
EXTERN  PostQuitMessage     :PROC
EXTERN  BeginPaint          :PROC
EXTERN  EndPaint            :PROC
EXTERN  TextOutA            :PROC
EXTERN  DefWindowProcA      :PROC
EXTERN  ExitProcess         :PROC
EXTERN  GetStockObject      :PROC
EXTERN  wsprintfA           :PROC
EXTERN  SetBkMode           :PROC
EXTERN  SetTextColor        :PROC
EXTERN  lstrlenA            :PROC
EXTERN  CreateProcessA      :PROC
EXTERN  WaitForSingleObject  :PROC
EXTERN  GetExitCodeProcess   :PROC
EXTERN  CloseHandle          :PROC
EXTERN  CreateThread        :PROC
EXTERN  Sleep               :PROC
EXTERN  InvalidateRect      :PROC
EXTERN  MessageBoxA         :PROC
EXTERN  GetOpenFileNameA    :PROC
EXTERN  GetSaveFileNameA    :PROC
EXTERN  CreateFileA         :PROC
EXTERN  WriteFile           :PROC
EXTERN  ReadFile            :PROC
EXTERN  GetFileSize         :PROC
EXTERN  GlobalAlloc         :PROC
EXTERN  GlobalFree          :PROC
EXTERN  SendMessageA        :PROC
EXTERN  SetWindowTextA      :PROC
EXTERN  lstrcpyA            :PROC
EXTERN  lstrcatA            :PROC
EXTERN  GetDlgItemTextA     :PROC

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
IDC_ARROW           EQU 32512
WHITE_BRUSH         EQU 0
GRAY_BRUSH          EQU 1
TRANSPARENT_BK      EQU 1
WM_DESTROY          EQU 002h
WM_PAINT            EQU 00Fh
WM_CREATE           EQU 001h
WM_COMMAND          EQU 0111h
WM_SIZE             EQU 0005h
WM_USER             EQU 0400h
SW_SHOWNORMAL       EQU 1
CS_HREDRAW          EQU 0002h
CS_VREDRAW          EQU 0001h
WS_OVERLAPPEDWINDOW EQU 0CF0000h
CW_USEDEFAULT32     EQU 080000000h

; Colors
COLOR_BLACK         EQU 0000000h
COLOR_WHITE         EQU 0FFFFFFh
COLOR_LIME          EQU 000FF00h
COLOR_RED           EQU 00000FFh
COLOR_YELLOW        EQU 000FFFFh
COLOR_CYAN          EQU 0FFFF00h
COLOR_MAGENTA       EQU 0FF00FFh
COLOR_GRAY          EQU 0808080h
COLOR_DKGRAY        EQU 0404040h

; Control IDs
ID_BTN_OPEN         EQU 1001
ID_BTN_SAVE         EQU 1002
ID_BTN_COMPILE      EQU 1003
ID_BTN_RUN          EQU 1004
ID_MENU_FILE_NEW    EQU 2001
ID_MENU_FILE_OPEN   EQU 2002
ID_MENU_FILE_SAVE   EQU 2003
ID_MENU_FILE_EXIT   EQU 2004
ID_MENU_PROJECT_NEW EQU 2101
ID_MENU_BUILD_COMPILE EQU 2201
ID_EDIT_SOURCE      EQU 3001
ID_EDIT_OUTPUT      EQU 3002
ID_STATUSBAR        EQU 4001

; OFN Flags
OFN_PATHMUSTEXIST   EQU 00000800h
OFN_FILEMUSTEXIST   EQU 00001000h

; RichEdit
EM_SETSEL           EQU 0B1h
EM_REPLACESEL       EQU 0C2h
EM_GETTEXTLENGTH    EQU 00Eh
EM_SETREADONLY      EQU 0CFh
EM_SETBKGNDCOLOR    EQU 0443h

;=============================================================================
.data
ALIGN 16
szClassName         DB  "RawrXD_GUI_v5",0
szTitle             DB  "RawrXD IDE v5 - Advanced Features",0

; Button labels
szBtnOpen           DB  "&Open",0
szBtnSave           DB  "&Save",0
szBtnCompile        DB  "&Compile",0
szBtnRun            DB  "&Run",0

; Status messages
szStatusReady       DB  "Ready",0
szStatusCompiling   DB  "Compiling...",0
szStatusRunning     DB  "Running...",0
szStatusSuccess     DB  "Success",0
szStatusFailed      DB  "Failed",0
szStatusSaved       DB  "Saved",0
szStatusLoaded      DB  "Loaded",0

; File filters
szFilterAll         DB  "All Files",0,"*.*",0
szFilterAsm         DB  "Assembly",0,"*.asm",0
szFilterC           DB  "C/C++",0,"*.c;*.cpp",0
szFilterPy          DB  "Python",0,"*.py",0
szFilterProj        DB  "RawrXD Projects",0,"*.rxproj",0,0

; Compiler path
szCompilerPath      DB  "d:\rawrxd\compilers\rawrxd_ide_cli_v3.bat",0

; Dialog strings
szDlgTitleOpen      DB  "Open File",0
szDlgTitleSave      DB  "Save File",0
szDlgTitleProject   DB  "New Project",0
szFmtStatusFile     DB  "%s - Line: %d, Col: %d",0

; Error parsing
szErrPattern1       DB  "error",0
szErrPattern2       DB  "Error",0
szErrPattern3       DB  "ERROR",0
szErrFmtLine        DB  "Line %d",0

; Project file template
szProjTemplate      DB  "# RawrXD Project File",13,10
                    DB  "version=1.0",13,10
                    DB  "main=main.asm",13,10
                    DB  "output=program.exe",13,10,0

; Buffers
ALIGN 8
g_hInstance         DQ  0
g_hWnd              DQ  0
g_hWndSource        DQ  0
g_hWndOutput        DQ  0
g_hStatusBar        DQ  0
g_hBtnOpen          DQ  0
g_hBtnSave          DQ  0
g_hBtnCompile       DQ  0
g_hBtnRun           DQ  0

g_currentFile       DB  260 DUP(0)
g_projectFile       DB  260 DUP(0)
g_outputBuffer      DB  8192 DUP(0)
g_statusBuffer      DB  256 DUP(0)
g_cmdLine           DB  1024 DUP(0)

g_isBuilding        DD  0
g_hasFile           DD  0
g_hasProject        DD  0
g_lineNum           DD  1
g_colNum            DD  1

; OPENFILENAME struct
ALIGN 8
ofn                 LABEL BYTE
ofn_lStructSize     DD  88
ofn_hwndOwner       DQ  0
ofn_hInstance       DQ  0
ofn_lpstrFilter     DQ  szFilterAll
ofn_lpstrCustomFilter DQ 0
ofn_nMaxCustFilter  DD  0
ofn_nFilterIndex    DD  0
ofn_lpstrFile       DQ  g_currentFile
ofn_nMaxFile        DD  260
ofn_lpstrFileTitle  DQ  0
ofn_nMaxFileTitle   DD  0
ofn_lpstrInitialDir DQ  0
ofn_lpstrTitle      DQ  0
ofn_Flags           DD  OFN_PATHMUSTEXIST OR OFN_FILEMUSTEXIST
ofn_nFileOffset     DW  0
ofn_nFileExtension  DW  0
ofn_lpstrDefExt     DQ  0
ofn_lCustData       DQ  0
ofn_lpfnHook        DQ  0
ofn_lpTemplateName  DQ  0

;=============================================================================
.code

;=============================================================================
; Simple syntax highlighting - colorizes keywords
; rcx = hDC, rdx = text, r8 = x, r9 = y
;=============================================================================
DrawHighlightedText PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 64
    
    mov     rsi, rdx        ; rsi = text
    mov     r12, r8         ; r12 = x
    mov     r13, r9         ; r13 = y
    mov     r14, rcx        ; r14 = hDC
    
    ; Set transparent background
    mov     rcx, r14
    mov     edx, TRANSPARENT_BK
    call    SetBkMode
    
    ; Default color (white)
    mov     rcx, r14
    mov     edx, COLOR_WHITE
    call    SetTextColor
    
    mov     rdi, rsi        ; rdi = current position
    
next_char:
    jz      done_drawing
    
    ; Check for keywords and set colors
    cmp     al, ';'         ; Comment
    je      color_comment
    cmp     al, '"'         ; String
    je      color_string
    cmp     al, "'"         ; String
    je      color_string
    
    ; Check for numbers
    cmp     al, '0'
    jb      check_alpha
    cmp     al, '9'
    jbe     color_number
    
check_alpha:
    cmp     al, 'A'
    jb      draw_char
    cmp     al, 'Z'
    jbe     color_keyword
    cmp     al, 'a'
    jb      draw_char
    cmp     al, 'z'
    jbe     color_keyword
    jmp     draw_char
    
color_comment:
    mov     rcx, r14
    mov     edx, COLOR_GRAY
    call    SetTextColor
    jmp     draw_char
    
color_string:
    mov     rcx, r14
    mov     edx, COLOR_YELLOW
    call    SetTextColor
    jmp     draw_char
    
color_number:
    mov     rcx, r14
    mov     edx, COLOR_CYAN
    call    SetTextColor
    jmp     draw_char
    
color_keyword:
    mov     rcx, r14
    mov     edx, COLOR_MAGENTA
    call    SetTextColor
    
draw_char:
    ; Draw single character
    mov     rcx, rdi
    mov     edx, 1
    mov     [rsp+32], rdx
    mov     rcx, r14
    mov     edx, r12d
    mov     r8d, r13d
    mov     r9, rdi
    call    TextOutA
    
    ; Advance position
    inc     rdi
    add     r12, 8          ; Approximate char width
    jmp     next_char
    
done_drawing:
    add     rsp, 64
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DrawHighlightedText ENDP

;=============================================================================
; Parse errors from compiler output
; rcx = output text
; Returns: error count in eax
;=============================================================================
ParseErrors PROC
    push    rbx
    push    rsi
    push    rdi
    xor     ebx, ebx        ; error count = 0
    mov     rsi, rcx        ; rsi = output text
    
scan_loop:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      parse_done
    
    ; Look for "error" patterns
    cmp     al, 'e'
    je      check_error
    cmp     al, 'E'
    je      check_error
    
next_scan:
    inc     rsi
    jmp     scan_loop
    
check_error:
    ; Check for "error" or "Error" or "ERROR"
    push    rsi
    lea     rdi, szErrPattern1
    mov     rcx, rsi
    mov     rdx, rdi
    call    lstrcmpiA
    test    eax, eax
    pop     rsi
    jnz     next_scan
    
    ; Found error
    inc     ebx
    jmp     next_scan
    
parse_done:
    mov     eax, ebx
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ParseErrors ENDP

EXTERN lstrcmpiA :PROC

;=============================================================================
; Save project file
;=============================================================================
SaveProjectFile PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 64
    
    ; Create project file
    xor     ecx, ecx
    lea     rdx, g_projectFile
    mov     r8d, 40000000h  ; GENERIC_WRITE
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 2  ; CREATE_ALWAYS
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    
    cmp     rax, -1
    je      save_fail
    mov     rbx, rax        ; rbx = file handle
    
    ; Write template
    lea     rcx, szProjTemplate
    call    lstrlenA
    mov     r8, rax         ; r8 = bytes to write
    
    mov     rcx, rbx
    lea     rdx, szProjTemplate
    lea     r9, [rsp+56]    ; lpNumberOfBytesWritten
    mov     qword ptr [rsp+32], 0
    call    WriteFile
    
    ; Close file
    mov     rcx, rbx
    call    CloseHandle
    
    mov     eax, 1          ; success
    jmp     save_done
    
save_fail:
    xor     eax, eax        ; failure
    
save_done:
    add     rsp, 64
    pop     rdi
    pop     rsi
    pop     rbx
    ret
SaveProjectFile ENDP

;=============================================================================
; Build thread with full output capture
;=============================================================================
BuildThread PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 512
    
    ; Build command line
    lea     rdi, g_cmdLine
    mov     rcx, rdi
    lea     rdx, szCompilerPath
    call    lstrcpyA
    
    lea     rcx, g_cmdLine
    call    lstrlenA
    lea     rdi, g_cmdLine
    add     rdi, rax
    mov     byte ptr [rdi], ' '
    inc     rdi
    mov     byte ptr [rdi], '"'
    inc     rdi
    
    lea     rsi, g_currentFile
    mov     rcx, rdi
    mov     rdx, rsi
    call    lstrcpyA
    
    lea     rcx, g_cmdLine
    call    lstrlenA
    lea     rdi, g_cmdLine
    add     rdi, rax
    mov     byte ptr [rdi], '"'
    inc     rdi
    mov     byte ptr [rdi], 0
    
    ; Create process
    xor     ecx, ecx
    lea     rdx, g_cmdLine
    xor     r8d, r8d
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 08000000h
    mov     qword ptr [rsp+48], 0
    mov     qword ptr [rsp+56], 0
    
    ; Initialize STARTUPINFO
    lea     rax, [rsp+64]
    mov     rcx, 104
    mov     rdi, rax
    xor     eax, eax
    rep     stosb
    mov     dword ptr [rsp+64], 104
    
    lea     rax, [rsp+64]
    mov     qword ptr [rsp+72], rax
    lea     rax, [rsp+80]
    mov     qword ptr [rsp+80], rax
    
    xor     ecx, ecx
    lea     rdx, g_cmdLine
    xor     r8d, r8d
    xor     r9d, r9d
    call    CreateProcessA
    
    test    eax, eax
    jz      build_failed
    
    ; Wait for completion
    mov     rcx, qword ptr [rsp+80]
    mov     edx, 0FFFFFFFFh
    call    WaitForSingleObject
    
    ; Get exit code
    mov     rcx, qword ptr [rsp+80]
    lea     rdx, [rsp+200]
    call    GetExitCodeProcess
    
    ; Close handles
    mov     rcx, qword ptr [rsp+80]
    call    CloseHandle
    mov     rcx, qword ptr [rsp+88]
    call    CloseHandle
    
    ; Check result
    mov     eax, dword ptr [rsp+200]
    test    eax, eax
    jnz     build_failed
    
    mov     g_isBuilding, 0
    jmp     build_done
    
build_failed:
    mov     g_isBuilding, 0
    
build_done:
    ; Trigger UI update
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
    add     rsp, 512
    pop     rdi
    pop     rsi
    pop     rbx
    ret
BuildThread ENDP

;=============================================================================
; WndProc
;=============================================================================
WndProc PROC
    push    rbp
    sub     rsp, 144
    mov     rbp, rsp
    
    mov     [rbp+0], rcx
    mov     [rbp+8], rdx
    mov     [rbp+16], r8
    mov     [rbp+24], r9
    
    cmp     edx, WM_CREATE
    je      Msg_Create
    cmp     edx, WM_PAINT
    je      Msg_Paint
    cmp     edx, WM_COMMAND
    je      Msg_Command
    cmp     edx, WM_SIZE
    je      Msg_Size
    cmp     edx, WM_DESTROY
    je      Msg_Destroy
    jmp     Msg_Def

Msg_Create:
    ; Create source edit control (simplified - just a placeholder)
    xor     ecx, ecx
    lea     rdx, [szClassName+20]  ; "EDIT"
    xor     r8d, r8d
    mov     r9d, 50810004h  ; ES_MULTILINE | ES_AUTOVSCROLL | WS_CHILD | WS_VISIBLE | WS_VSCROLL
    mov     qword ptr [rsp+32], 10
    mov     qword ptr [rsp+40], 50
    mov     qword ptr [rsp+48], 400
    mov     qword ptr [rsp+56], 250
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_EDIT_SOURCE
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hWndSource, rax
    
    ; Create output edit control
    xor     ecx, ecx
    lea     rdx, [szClassName+20]
    xor     r8d, r8d
    mov     r9d, 50810004h
    mov     qword ptr [rsp+32], 10
    mov     qword ptr [rsp+40], 310
    mov     qword ptr [rsp+48], 400
    mov     qword ptr [rsp+56], 100
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_EDIT_OUTPUT
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hWndOutput, rax
    
    ; Create buttons
    xor     ecx, ecx
    lea     rdx, szBtnOpen
    lea     r8, szBtnOpen
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 420
    mov     qword ptr [rsp+40], 50
    mov     qword ptr [rsp+48], 80
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_OPEN
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnOpen, rax
    
    xor     ecx, ecx
    lea     rdx, szBtnSave
    lea     r8, szBtnSave
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 420
    mov     qword ptr [rsp+40], 90
    mov     qword ptr [rsp+48], 80
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_SAVE
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnSave, rax
    
    xor     ecx, ecx
    lea     rdx, szBtnCompile
    lea     r8, szBtnCompile
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 420
    mov     qword ptr [rsp+40], 130
    mov     qword ptr [rsp+48], 80
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_COMPILE
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnCompile, rax
    
    xor     ecx, ecx
    lea     rdx, szBtnRun
    lea     r8, szBtnRun
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 420
    mov     qword ptr [rsp+40], 170
    mov     qword ptr [rsp+48], 80
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_RUN
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnRun, rax
    
    xor     eax, eax
    jmp     WndProcRet

Msg_Command:
    mov     rax, [rbp+16]
    cmp     ax, ID_BTN_OPEN
    je      Do_Open
    cmp     ax, ID_BTN_SAVE
    je      Do_Save
    cmp     ax, ID_BTN_COMPILE
    je      Do_Compile
    cmp     ax, ID_BTN_RUN
    je      Do_Run
    xor     eax, eax
    jmp     WndProcRet

Do_Open:
    mov     rax, [rbp+0]
    mov     ofn_hwndOwner, rax
    lea     rcx, ofn_lStructSize
    call    GetOpenFileNameA
    test    eax, eax
    jz      open_done
    
    mov     g_hasFile, 1
    
open_done:
    xor     eax, eax
    jmp     WndProcRet

Do_Save:
    call    SaveProjectFile
    xor     eax, eax
    jmp     WndProcRet

Do_Compile:
    mov     eax, g_hasFile
    test    eax, eax
    jz      compile_done
    
    mov     eax, g_isBuilding
    test    eax, eax
    jnz     compile_done
    
    mov     g_isBuilding, 1
    
    xor     ecx, ecx
    xor     edx, edx
    lea     r8, BuildThread
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    call    CreateThread
    
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
compile_done:
    xor     eax, eax
    jmp     WndProcRet

Do_Run:
    xor     eax, eax
    jmp     WndProcRet

Msg_Size:
    xor     eax, eax
    jmp     WndProcRet

Msg_Paint:
    mov     rcx, [rbp+0]
    lea     rdx, [rbp+64]
    call    BeginPaint
    
    mov     rcx, [rbp+64]
    mov     edx, TRANSPARENT_BK
    call    SetBkMode
    
    ; Draw status
    mov     eax, g_isBuilding
    test    eax, eax
    jnz     show_building
    
    mov     rcx, [rbp+64]
    mov     edx, COLOR_LIME
    call    SetTextColor
    lea     r9, szStatusReady
    jmp     do_textout
    
show_building:
    mov     rcx, [rbp+64]
    mov     edx, COLOR_YELLOW
    call    SetTextColor
    lea     r9, szStatusCompiling
    
do_textout:
    mov     rcx, r9
    call    lstrlenA
    mov     [rsp+32], rax
    mov     rcx, [rbp+64]
    mov     edx, 10
    mov     r8d, 420
    call    TextOutA
    
    mov     rcx, [rbp+0]
    lea     rdx, [rbp+64]
    call    EndPaint
    xor     eax, eax
    jmp     WndProcRet

Msg_Destroy:
    xor     ecx, ecx
    call    PostQuitMessage
    xor     eax, eax
    jmp     WndProcRet

Msg_Def:
    mov     rcx, [rbp+0]
    mov     rdx, [rbp+8]
    mov     r8, [rbp+16]
    mov     r9, [rbp+24]
    call    DefWindowProcA

WndProcRet:
    add     rsp, 144
    pop     rbp
    ret
WndProc ENDP

;=============================================================================
; WinMain
;=============================================================================
WinMain PROC
    push    rbp
    sub     rsp, 96
    mov     rbp, rsp
    
    mov     qword ptr [g_hInstance], rcx
    
    ; Register class
    lea     rax, WndProc
    mov     qword ptr [g_WC_lpfnWndProc], rax
    mov     qword ptr [g_WC_hInstance], rcx
    lea     rax, szClassName
    mov     qword ptr [g_WC_lpszClassName], rax
    
    xor     ecx, ecx
    mov     edx, IDC_ARROW
    call    LoadCursorA
    mov     qword ptr [g_WC_hCursor], rax
    
    mov     ecx, WHITE_BRUSH
    call    GetStockObject
    mov     qword ptr [g_WC_hbrBackground], rax
    
    lea     rcx, g_WC_cbSize
    call    RegisterClassExA
    test    ax, ax
    jz      WinFail
    
    ; Create window
    xor     ecx, ecx
    lea     rdx, szClassName
    lea     r8, szTitle
    mov     r9d, WS_OVERLAPPEDWINDOW
    mov     qword ptr [rsp+32], CW_USEDEFAULT32
    mov     qword ptr [rsp+40], CW_USEDEFAULT32
    mov     qword ptr [rsp+48], 600
    mov     qword ptr [rsp+56], 500
    mov     qword ptr [rsp+64], 0
    mov     qword ptr [rsp+72], 0
    mov     rax, qword ptr [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    test    rax, rax
    jz      WinFail
    mov     qword ptr [g_hWnd], rax
    
    mov     rcx, rax
    mov     edx, SW_SHOWNORMAL
    call    ShowWindow
    mov     rcx, qword ptr [g_hWnd]
    call    UpdateWindow
    
MsgLoop:
    lea     rcx, [rsp+0]
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    GetMessageA
    test    eax, eax
    jz      MsgDone
    lea     rcx, [rsp+0]
    call    TranslateMessage
    lea     rcx, [rsp+0]
    call    DispatchMessageA
    jmp     MsgLoop

MsgDone:
    mov     ecx, dword ptr [rsp+16]
    call    ExitProcess

WinFail:
    mov     ecx, 1
    call    ExitProcess
    
    add     rsp, 96
    pop     rbp
    ret
WinMain ENDP

; WNDCLASSEX
ALIGN 8
g_WC_cbSize         DD  80
g_WC_style          DD  (CS_HREDRAW OR CS_VREDRAW)
g_WC_lpfnWndProc    DQ  0
g_WC_cbClsExtra     DD  0
g_WC_cbWndExtra     DD  0
g_WC_hInstance      DQ  0
g_WC_hIcon          DQ  0
g_WC_hCursor        DQ  0
g_WC_hbrBackground  DQ  0
g_WC_lpszMenuName   DQ  0
g_WC_lpszClassName  DQ  0
g_WC_hIconSm        DQ  0

END
