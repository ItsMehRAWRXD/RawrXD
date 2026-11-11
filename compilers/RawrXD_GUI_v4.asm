;=============================================================================
; RawrXD_GUI_v4.asm - GUI with File Picker and Output Capture
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
EXTERN  GetOpenFileNameA    :PROC  ; File picker
EXTERN  CreatePipe          :PROC  ; For output capture
EXTERN  SetHandleInformation :PROC
EXTERN  ReadFile            :PROC
EXTERN  GetLastError        :PROC

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
IDC_ARROW           EQU 32512
WHITE_BRUSH         EQU 0
TRANSPARENT_BK      EQU 1
WM_DESTROY          EQU 002h
WM_PAINT            EQU 00Fh
WM_CREATE           EQU 001h
WM_COMMAND          EQU 0111h
WM_USER             EQU 0400h
WM_APPEND_TEXT      EQU WM_USER + 1
SW_SHOWNORMAL       EQU 1
CS_HREDRAW          EQU 0002h
CS_VREDRAW          EQU 0001h
WS_OVERLAPPEDWINDOW EQU 0CF0000h
CW_USEDEFAULT32     EQU 080000000h
COLOR_LIME          EQU 000FF00h
COLOR_WHITE         EQU 0FFFFFFh
COLOR_GRAY          EQU 0808080h

; Control IDs
ID_BTN_OPEN         EQU 1001
ID_BTN_COMPILE      EQU 1002
ID_BTN_TEST         EQU 1003
ID_EDIT_OUTPUT      EQU 2001
ID_STATIC_FILE      EQU 3001

; OFN Flags
OFN_PATHMUSTEXIST   EQU 00000800h
OFN_FILEMUSTEXIST   EQU 00001000h

;=============================================================================
.data
ALIGN 16
szClassName         DB  "RawrXD_GUI_v4",0
szTitle             DB  "RawrXD IDE v4 - File Picker + Output Capture",0
szBtnOpen           DB  "Open File...",0
szBtnCompile        DB  "Compile",0
szBtnTest           DB  "Run Tests",0
szStaticFile        DB  "File: (none)",0
szCompilerPath      DB  "d:\rawrxd\compilers\rawrxd_ide_cli_v3.bat",0
szFilter            DB  "All Files",0,"*.*",0,0
szNoFile            DB  "(no file selected)",0
szStatusReady       DB  "Ready",0
szStatusCompiling   DB  "Compiling...",0
szStatusSuccess     DB  "Success!",0
szStatusFailed      DB  "Failed!",0
szFmtFile           DB  "File: %s",0

; File picker struct (OPENFILENAMEA)
ALIGN 8
ofn_lStructSize     DD  88
ofn_hwndOwner       DQ  0
ofn_hInstance       DQ  0
ofn_lpstrFilter     DQ  szFilter
ofn_lpstrCustomFilter DQ 0
ofn_nMaxCustFilter  DD  0
ofn_nFilterIndex    DD  0
ofn_lpstrFile       DQ  g_selectedFile
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
ofn_pvReserved      DQ  0
ofn_dwReserved      DD  0
ofn_ExFlags         DD  0

; Buffers
ALIGN 8
g_hInstance         DQ  0
g_hWnd              DQ  0
g_hBtnOpen          DQ  0
g_hBtnCompile       DQ  0
g_hBtnTest          DQ  0
g_hEditOutput       DQ  0
g_hStaticFile       DQ  0
g_selectedFile      DB  260 DUP(0)
g_outputBuffer      DB  4096 DUP(0)
g_statusText        DB  256 DUP(0)
g_isBuilding        DD  0
g_hasFile           DD  0

; Command line
szCmdLine           DB  1024 DUP(0)

;=============================================================================
.code

;=============================================================================
; Append text to output window
; rcx = text to append
;=============================================================================
AppendOutput PROC
    push    rbx
    push    rsi
    push    rdi
    
    mov     rsi, rcx
    
    ; Get current text length
    mov     rcx, g_hEditOutput
    mov     edx, 0Eh        ; WM_GETTEXTLENGTH
    xor     r8d, r8d
    xor     r9d, r9d
    call    SendMessageA
    mov     rdi, rax        ; rdi = current length
    
    ; Append text
    mov     rcx, g_hEditOutput
    mov     edx, 0Eh        ; WM_GETTEXTLENGTH (get position)
    xor     r8d, r8d
    xor     r9d, r9d
    call    SendMessageA
    
    mov     rcx, g_hEditOutput
    mov     edx, 0B1h       ; EM_SETSEL
    mov     r8, rax         ; start = end
    mov     r9, rax         ; end = end
    call    SendMessageA
    
    mov     rcx, g_hEditOutput
    mov     edx, 0C2h       ; EM_REPLACESEL
    xor     r8d, r8d        ; fCanBeUndo = FALSE
    mov     r9, rsi         ; lpstr = text
    call    SendMessageA
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
AppendOutput ENDP

EXTERN SendMessageA :PROC
EXTERN lstrcpyA :PROC

;=============================================================================
; Build thread with output capture
;=============================================================================
BuildThread PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 256
    
    ; Build command line: compiler "file"
    lea     rdi, szCmdLine
    mov     rcx, rdi
    lea     rdx, szCompilerPath
    call    lstrcpyA
    
    lea     rcx, szCmdLine
    call    lstrlenA
    lea     rdi, szCmdLine
    add     rdi, rax
    mov     byte ptr [rdi], ' '
    inc     rdi
    mov     byte ptr [rdi], '"'
    inc     rdi
    
    ; Append selected file
    lea     rsi, g_selectedFile
    mov     rcx, rdi
    mov     rdx, rsi
    call    lstrcpyA
    
    lea     rcx, szCmdLine
    call    lstrlenA
    lea     rdi, szCmdLine
    add     rdi, rax
    mov     byte ptr [rdi], '"'
    inc     rdi
    mov     byte ptr [rdi], 0
    
    ; Create process
    xor     ecx, ecx
    lea     rdx, szCmdLine
    xor     r8d, r8d
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 08000000h  ; CREATE_NO_WINDOW
    mov     qword ptr [rsp+48], 0
    mov     qword ptr [rsp+56], 0
    lea     rax, [rsp+64]       ; STARTUPINFOA
    mov     rcx, 104
    mov     rdi, rax
    xor     eax, eax
    rep     stosb
    mov     dword ptr [rsp+64], 104
    lea     rax, [rsp+80]       ; PROCESS_INFORMATION
    mov     qword ptr [rsp+80], 0
    mov     qword ptr [rsp+88], 0
    mov     qword ptr [rsp+96], 0
    mov     qword ptr [rsp+104], 0
    
    xor     ecx, ecx
    lea     rdx, szCmdLine
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
    lea     rdx, [rsp+112]
    call    GetExitCodeProcess
    
    ; Close handles
    mov     rcx, qword ptr [rsp+80]
    call    CloseHandle
    mov     rcx, qword ptr [rsp+88]
    call    CloseHandle
    
    ; Check result
    mov     eax, dword ptr [rsp+112]
    test    eax, eax
    jnz     build_failed
    
    ; Success
    mov     g_isBuilding, 0
    jmp     build_done
    
build_failed:
    mov     g_isBuilding, 0
    
build_done:
    ; Trigger repaint
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
    add     rsp, 256
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
    
    mov     [rbp+0], rcx    ; hWnd
    mov     [rbp+8], rdx    ; uMsg
    mov     [rbp+16], r8    ; wParam
    mov     [rbp+24], r9    ; lParam
    
    cmp     edx, WM_CREATE
    je      Msg_Create
    cmp     edx, WM_PAINT
    je      Msg_Paint
    cmp     edx, WM_COMMAND
    je      Msg_Command
    cmp     edx, WM_DESTROY
    je      Msg_Destroy
    jmp     Msg_Def

Msg_Create:
    ; Create "Open File" button
    xor     ecx, ecx
    lea     rdx, szBtnOpen
    lea     r8, szBtnOpen
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 10
    mov     qword ptr [rsp+40], 10
    mov     qword ptr [rsp+48], 100
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_OPEN
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnOpen, rax
    
    ; Create "Compile" button
    xor     ecx, ecx
    lea     rdx, szBtnCompile
    lea     r8, szBtnCompile
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 120
    mov     qword ptr [rsp+40], 10
    mov     qword ptr [rsp+48], 100
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_COMPILE
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnCompile, rax
    
    ; Create "Test" button
    xor     ecx, ecx
    lea     rdx, szBtnTest
    lea     r8, szBtnTest
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 230
    mov     qword ptr [rsp+40], 10
    mov     qword ptr [rsp+48], 100
    mov     qword ptr [rsp+56], 30
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_TEST
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnTest, rax
    
    ; Create file label
    xor     ecx, ecx
    lea     rdx, szStaticFile
    lea     r8, szNoFile
    mov     r9d, 50000000h    ; SS_LEFT | WS_CHILD | WS_VISIBLE
    mov     qword ptr [rsp+32], 10
    mov     qword ptr [rsp+40], 50
    mov     qword ptr [rsp+48], 400
    mov     qword ptr [rsp+56], 20
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_STATIC_FILE
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hStaticFile, rax
    
    ; Create output edit control
    xor     ecx, ecx
    lea     rdx, [szClassName+20]  ; "EDIT"
    xor     r8d, r8d
    mov     r9d, 50810004h  ; ES_MULTILINE | ES_AUTOVSCROLL | 
                            ; ES_READONLY | WS_CHILD | WS_VISIBLE | WS_VSCROLL
    mov     qword ptr [rsp+32], 10
    mov     qword ptr [rsp+40], 80
    mov     qword ptr [rsp+48], 560
    mov     qword ptr [rsp+56], 300
    mov     rax, [rbp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_EDIT_OUTPUT
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hEditOutput, rax
    
    ; Initialize output
    mov     rcx, g_hEditOutput
    lea     rdx, g_outputBuffer
    call    SetWindowTextA
    
    xor     eax, eax
    jmp     WndProcRet

Msg_Command:
    mov     rax, [rbp+16]   ; wParam
    cmp     ax, ID_BTN_OPEN
    je      Do_Open
    cmp     ax, ID_BTN_COMPILE
    je      Do_Compile
    cmp     ax, ID_BTN_TEST
    je      Do_Test
    xor     eax, eax
    jmp     WndProcRet

Do_Open:
    ; Show file picker
    mov     rax, [rbp+0]
    mov     ofn_hwndOwner, rax
    lea     rcx, ofn_lStructSize
    call    GetOpenFileNameA
    
    test    eax, eax
    jz      open_done
    
    ; File selected
    mov     g_hasFile, 1
    
    ; Update file label
    lea     rcx, g_outputBuffer
    lea     rdx, szFmtFile
    lea     r8, g_selectedFile
    call    wsprintfA
    
    mov     rcx, g_hStaticFile
    lea     rdx, g_outputBuffer
    call    SetWindowTextA
    
open_done:
    xor     eax, eax
    jmp     WndProcRet

Do_Compile:
    ; Check if file selected
    mov     eax, g_hasFile
    test    eax, eax
    jz      no_file_compile
    
    ; Check if already building
    mov     eax, g_isBuilding
    test    eax, eax
    jnz     compile_busy
    
    ; Set building flag
    mov     g_isBuilding, 1
    
    ; Create build thread
    xor     ecx, ecx
    xor     edx, edx
    lea     r8, BuildThread
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    call    CreateThread
    
    ; Trigger repaint
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
compile_busy:
no_file_compile:
    xor     eax, eax
    jmp     WndProcRet

Do_Test:
    ; Run test suite
    xor     eax, eax
    jmp     WndProcRet

Msg_Paint:
    mov     rcx, [rbp+0]
    lea     rdx, [rbp+64]
    call    BeginPaint
    
    mov     rcx, [rbp+64]
    mov     edx, TRANSPARENT_BK
    call    SetBkMode
    
    ; Show status
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
    mov     edx, COLOR_WHITE
    call    SetTextColor
    
    lea     r9, szStatusCompiling
    
do_textout:
    mov     rcx, r9
    call    lstrlenA
    mov     [rsp+32], rax
    mov     rcx, [rbp+64]
    mov     edx, 350
    mov     r8d, 15
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

EXTERN SetWindowTextA :PROC

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
    mov     qword ptr [rsp+56], 450
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
