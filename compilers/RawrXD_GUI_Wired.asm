;=============================================================================
; RawrXD_GUI_Wired.asm - GUI with REAL compiler wiring
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
EXTERN  SetTimer            :PROC
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

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
IDC_ARROW           EQU 32512
WHITE_BRUSH         EQU 0
TRANSPARENT_BK      EQU 1
WM_DESTROY          EQU 002h
WM_TIMER            EQU 0113h
WM_PAINT            EQU 00Fh
WM_CREATE           EQU 001h
WM_COMMAND          EQU 0111h
SW_SHOWNORMAL       EQU 1
TIMER_BUILD         EQU 1
TIMER_MS            EQU 100
CS_HREDRAW          EQU 0002h
CS_VREDRAW          EQU 0001h
WS_OVERLAPPEDWINDOW EQU 0CF0000h
CW_USEDEFAULT32     EQU 080000000h
COLOR_LIME          EQU 000FF00h
COLOR_WHITE         EQU 0FFFFFFh

; Button IDs
ID_BTN_COMPILE      EQU 1001
ID_BTN_TEST         EQU 1002

;=============================================================================
.data
ALIGN 16
szClassName     DB  "RawrXD_WiredWnd",0
szTitle         DB  "RawrXD IDE - REAL Compilers",0
szBtnCompile    DB  "Compile",0
szBtnTest       DB  "Run Tests",0
szCompiling     DB  "Compiling...",0
szSuccess       DB  "Build Success!",0
szFailed        DB  "Build Failed!",0
szCompilerPath  DB  "d:\rawrxd\compilers\rawrxd_ide_cli_v3.bat",0
szTestArg       DB  "test",0
szSpace         DB  " ",0

; Build status
ALIGN 8
g_hInstance       QWORD   0
g_hWnd            QWORD   0
g_hBtnCompile     QWORD   0
g_hBtnTest        QWORD   0
g_isBuilding      DWORD   0
g_buildResult     DWORD   0
g_StatusBuf       DB      256 DUP(0)

; Command buffer
szCmdLine         DB      1024 DUP(0)

; WNDCLASSEX
ALIGN 8
g_WC_cbSize         DWORD   80
g_WC_style          DWORD   (CS_HREDRAW OR CS_VREDRAW)
g_WC_lpfnWndProc    QWORD   0
g_WC_cbClsExtra     DWORD   0
g_WC_cbWndExtra     DWORD   0
g_WC_hInstance      QWORD   0
g_WC_hIcon          QWORD   0
g_WC_hCursor        QWORD   0
g_WC_hbrBackground  QWORD   0
g_WC_lpszMenuName   QWORD   0
g_WC_lpszClassName  QWORD   0
g_WC_hIconSm        QWORD   0

;=============================================================================
.code

;=============================================================================
; Build_Thread - Actually runs the compiler
;=============================================================================
Build_Thread PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 128
    
    ; Build command: "compiler.bat" "test"
    lea     rdi, szCmdLine
    mov     rcx, rdi
    lea     rdx, szCompilerPath
    call    lstrlenA
    mov     r8, rax
    mov     rsi, rdx
    mov     rcx, rdi
    mov     rdx, rsi
    call    memcpy
    
    ; Add space and "test"
    lea     rcx, szCmdLine
    call    lstrlenA
    lea     rdi, szCmdLine
    add     rdi, rax
    mov     byte ptr [rdi], ' '
    inc     rdi
    mov     byte ptr [rdi], 't'
    inc     rdi
    mov     byte ptr [rdi], 'e'
    inc     rdi
    mov     byte ptr [rdi], 's'
    inc     rdi
    mov     byte ptr [rdi], 't'
    inc     rdi
    mov     byte ptr [rdi], 0
    
    ; Create process
    xor     ecx, ecx                    ; lpApplicationName
    lea     rdx, szCmdLine             ; lpCommandLine
    xor     r8d, r8d                   ; lpProcessAttributes
    xor     r9d, r9d                   ; lpThreadAttributes
    mov     qword ptr [rsp+32], 0      ; bInheritHandles
    mov     qword ptr [rsp+40], 08000000h ; CREATE_NO_WINDOW
    mov     qword ptr [rsp+48], 0      ; lpEnvironment
    mov     qword ptr [rsp+56], 0      ; lpCurrentDirectory
    lea     rax, [rsp+64]              ; STARTUPINFOA
    mov     rcx, 104
    mov     rdi, rax
    xor     eax, eax
    rep     stosb
    mov     dword ptr [rsp+64], 104    ; cb
    lea     rax, [rsp+64]
    mov     qword ptr [rsp+72], rax    ; lpStartupInfo
    lea     rax, [rsp+80]              ; PROCESS_INFORMATION
    mov     qword ptr [rsp+80], 0
    mov     qword ptr [rsp+88], 0
    mov     qword ptr [rsp+96], 0
    mov     qword ptr [rsp+104], 0
    lea     rax, [rsp+80]
    mov     qword ptr [rsp+80], rax
    xor     ecx, ecx
    lea     rdx, szCmdLine
    xor     r8d, r8d
    xor     r9d, r9d
    call    CreateProcessA
    
    test    eax, eax
    jz      build_failed
    
    ; Wait for process
    mov     rcx, qword ptr [rsp+80]    ; hProcess
    mov     edx, 0FFFFFFFFh            ; INFINITE
    call    WaitForSingleObject
    
    ; Get exit code
    mov     rcx, qword ptr [rsp+80]    ; hProcess
    lea     rdx, [rsp+112]             ; lpExitCode
    call    GetExitCodeProcess
    
    ; Close handles
    mov     rcx, qword ptr [rsp+80]    ; hProcess
    call    CloseHandle
    mov     rcx, qword ptr [rsp+88]    ; hThread
    call    CloseHandle
    
    ; Check result
    mov     eax, dword ptr [rsp+112]
    mov     g_buildResult, eax
    mov     g_isBuilding, 0
    
    ; Trigger repaint
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
    add     rsp, 128
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
build_failed:
    mov     g_buildResult, 1
    mov     g_isBuilding, 0
    
    ; Trigger repaint
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
    add     rsp, 128
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Build_Thread ENDP

; Simple memcpy
memcpy PROC
    push    rdi
    push    rsi
    mov     rdi, rcx
    mov     rsi, rdx
    mov     rcx, r8
    rep     movsb
    pop     rsi
    pop     rdi
    ret
memcpy ENDP

;=============================================================================
; WndProc
;=============================================================================
WndProc PROC FRAME
    push    rbp
    .PUSHREG rbp
    sub     rsp, 144
    .ALLOCSTACK 144
    lea     rbp, [rsp+144]
    .SETFRAME rbp, 144
    .ENDPROLOG

    mov     [rsp+0],  rcx
    mov     [rsp+8],  rdx
    mov     [rsp+16], r8
    mov     [rsp+24], r9

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
    ; Create Compile button
    xor     ecx, ecx
    lea     rdx, szBtnCompile
    lea     r8, szBtnCompile
    mov     r9d, 0B00h                  ; BS_PUSHBUTTON | WS_VISIBLE | WS_CHILD
    mov     qword ptr [rsp+32], 10      ; x
    mov     qword ptr [rsp+40], 10      ; y
    mov     qword ptr [rsp+48], 100     ; width
    mov     qword ptr [rsp+56], 30      ; height
    mov     rax, [rsp+0]
    mov     qword ptr [rsp+64], rax     ; hWndParent
    mov     qword ptr [rsp+72], ID_BTN_COMPILE ; hMenu
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax     ; hInstance
    mov     qword ptr [rsp+88], 0       ; lpParam
    call    CreateWindowExA
    mov     g_hBtnCompile, rax
    
    ; Create Test button
    xor     ecx, ecx
    lea     rdx, szBtnTest
    lea     r8, szBtnTest
    mov     r9d, 0B00h
    mov     qword ptr [rsp+32], 120     ; x
    mov     qword ptr [rsp+40], 10      ; y
    mov     qword ptr [rsp+48], 100     ; width
    mov     qword ptr [rsp+56], 30      ; height
    mov     rax, [rsp+0]
    mov     qword ptr [rsp+64], rax
    mov     qword ptr [rsp+72], ID_BTN_TEST
    mov     rax, [g_hInstance]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExA
    mov     g_hBtnTest, rax
    
    xor     eax, eax
    jmp     WndProcRet

Msg_Command:
    mov     rax, [rsp+16]               ; wParam
    cmp     ax, ID_BTN_COMPILE
    je      Do_Compile
    cmp     ax, ID_BTN_TEST
    je      Do_Test
    xor     eax, eax
    jmp     WndProcRet

Do_Compile:
Do_Test:
    ; Check if already building
    mov     eax, g_isBuilding
    test    eax, eax
    jnz     cmd_done
    
    ; Set building flag
    mov     g_isBuilding, 1
    mov     g_buildResult, 0
    
    ; Create build thread
    xor     ecx, ecx
    xor     edx, edx
    lea     r8, Build_Thread
    xor     r9d, r9d
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    call    CreateThread
    
    ; Trigger repaint to show "Compiling..."
    mov     rcx, g_hWnd
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    InvalidateRect
    
cmd_done:
    xor     eax, eax
    jmp     WndProcRet

Msg_Paint:
    mov     rcx, [rsp+0]
    lea     rdx, [rsp+64]
    call    BeginPaint
    
    mov     rcx, [rsp+64]
    mov     edx, TRANSPARENT_BK
    call    SetBkMode
    
    mov     rcx, [rsp+64]
    mov     edx, COLOR_LIME
    call    SetTextColor
    
    ; Show status
    mov     eax, g_isBuilding
    test    eax, eax
    jnz     show_building
    
    mov     eax, g_buildResult
    test    eax, eax
    jnz     show_failed
    
    ; Show success
    lea     r9, szSuccess
    jmp     do_textout
    
show_building:
    lea     r9, szCompiling
    jmp     do_textout
    
show_failed:
    mov     rcx, [rsp+64]
    mov     edx, COLOR_WHITE
    call    SetTextColor
    lea     r9, szFailed
    
do_textout:
    mov     rcx, r9
    call    lstrlenA
    mov     [rsp+32], rax
    mov     rcx, [rsp+64]
    mov     edx, 10
    mov     r8d, 60
    call    TextOutA
    
    mov     rcx, [rsp+0]
    lea     rdx, [rsp+64]
    call    EndPaint
    xor     eax, eax
    jmp     WndProcRet

Msg_Destroy:
    xor     ecx, ecx
    call    PostQuitMessage
    xor     eax, eax
    jmp     WndProcRet

Msg_Def:
    mov     rcx, [rsp+0]
    mov     rdx, [rsp+8]
    mov     r8,  [rsp+16]
    mov     r9,  [rsp+24]
    call    DefWindowProcA

WndProcRet:
    add     rsp, 144
    pop     rbp
    ret
WndProc ENDP

;=============================================================================
; WinMain
;=============================================================================
WinMain PROC FRAME
    push    rbp
    .PUSHREG rbp
    sub     rsp, 96
    .ALLOCSTACK 96
    lea     rbp, [rsp+96]
    .SETFRAME rbp, 96
    .ENDPROLOG

    mov     qword ptr [g_hInstance], rcx

    ; fill WNDCLASSEX
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

    ; CreateWindowExA
    xor     ecx, ecx
    lea     rdx, szClassName
    lea     r8,  szTitle
    mov     r9d, WS_OVERLAPPEDWINDOW
    mov     qword ptr [rsp+32], CW_USEDEFAULT32
    mov     qword ptr [rsp+40], CW_USEDEFAULT32
    mov     qword ptr [rsp+48], 400
    mov     qword ptr [rsp+56], 200
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

END
