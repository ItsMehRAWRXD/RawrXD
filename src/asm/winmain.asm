; ============================================================================
; winmain.asm - x64 MASM WinMain Entry Point
; ============================================================================
; Provides WinMain for editor_pipeline.exe standalone test
; ============================================================================

option casemap:none

; Win32 API
EXTERN GetModuleHandleA:PROC
EXTERN RegisterClassExA:PROC
EXTERN CreateWindowExA:PROC
EXTERN GetMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageA:PROC
EXTERN PostQuitMessage:PROC
EXTERN DefWindowProcA:PROC
EXTERN LoadCursorA:PROC
EXTERN LoadIconA:PROC
EXTERN GetStockObject:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN PostMessageA:PROC

; External editor functions
EXTERN Editor_Initialize:PROC
EXTERN WndProcInputBridge_WndProc:PROC
EXTERN WndProcInputBridge_Initialize:PROC

; Constants
WS_OVERLAPPEDWINDOW   EQU 0CF0000h
WS_VISIBLE            EQU 10000000h
CW_USEDEFAULT         EQU 80000000h
WM_DESTROY            EQU 2
WM_CREATE             EQU 1
WM_PAINT              EQU 0Fh
WM_KEYDOWN            EQU 100h
WM_CHAR               EQU 102h
IDI_APPLICATION       EQU 32512
IDC_ARROW             EQU 32512
WHITE_BRUSH           EQU 0
SW_SHOW              EQU 5
CS_HREDRAW           EQU 2
CS_VREDRAW           EQU 1

.data

szClassName   BYTE "MASMEditorClass", 0
szWindowTitle BYTE "MASM Editor Pipeline - Standalone Test", 0

; WNDCLASSEX structure (80 bytes)
ALIGN 16
wcSize         DD 80
wcStyle        DD CS_HREDRAW or CS_VREDRAW
wcWndProc      DQ ?
wcClsExtra     DD 0
wcWndExtra     DD 0
wcInstance     DQ ?
wcIcon         DQ ?
wcCursor       DQ ?
wcBackground   DQ ?
wcMenuName     DQ ?
wcClassName    DQ ?
wcIconSm       DQ ?

; MSG structure (56 bytes)
ALIGN 16
msgHwnd        DQ ?
msgMessage     DD ?
msgWParam      DQ ?
msgLParam      DQ ?
msgTime        DD ?
msgPtX         DD ?
msgPtY         DD ?

.data?

hInstance     QWORD ?
hwndMain      QWORD ?

.code

; ============================================================================
; WinMain
; ============================================================================
ALIGN 16
WinMain PROC frame
    
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    ; Save hInstance
    mov     [hInstance], rcx
    mov     rbx, r9            ; nCmdShow
    
    ; Initialize editor
    call    Editor_Initialize
    test    rax, rax
    jz      L_fail
    
    ; Initialize window bridge
    call    WndProcInputBridge_Initialize
    test    rax, rax
    jz      L_fail
    
    ; Setup WNDCLASSEX
    lea     rax, [WndProc]
    mov     [wcWndProc], rax
    mov     rax, [hInstance]
    mov     [wcInstance], rax
    lea     rax, [szClassName]
    mov     [wcClassName], rax
    
    ; Register window class
    lea     rcx, [wcSize]
    call    RegisterClassExA
    test    ax, ax
    jz      L_fail
    
    ; Create window
    xor     rcx, rcx                    ; dwExStyle
    lea     rdx, [szClassName]          ; lpClassName
    lea     r8, [szWindowTitle]          ; lpWindowName
    mov     r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE  ; dwStyle
    sub     rsp, 60h
    mov     dword ptr [rsp + 20h], CW_USEDEFAULT    ; x
    mov     dword ptr [rsp + 28h], CW_USEDEFAULT    ; y
    mov     dword ptr [rsp + 30h], CW_USEDEFAULT    ; nWidth
    mov     dword ptr [rsp + 38h], CW_USEDEFAULT    ; nHeight
    mov     qword ptr [rsp + 40h], 0                 ; hWndParent
    mov     qword ptr [rsp + 48h], 0                 ; hMenu
    mov     rax, [hInstance]
    mov     qword ptr [rsp + 50h], rax              ; hInstance
    mov     qword ptr [rsp + 58h], 0                 ; lpParam
    call    CreateWindowExA
    add     rsp, 60h
    mov     [hwndMain], rax
    test    rax, rax
    jz      L_fail
    
    ; Show window
    mov     rcx, rax
    mov     rdx, rbx            ; nCmdShow
    call    ShowWindow
    
    ; Update window
    mov     rcx, [hwndMain]
    call    UpdateWindow
    
    ; Message loop
L_msgloop:
    lea     rcx, [msgHwnd]
    xor     rdx, rdx
    xor     r8, r8
    xor     r9, r9
    call    GetMessageA
    test    rax, rax
    jz      L_done
    
    lea     rcx, [msgHwnd]
    call    TranslateMessage
    
    lea     rcx, [msgHwnd]
    call    DispatchMessageA
    
    jmp     L_msgloop
    
L_fail:
    xor     rax, rax
    jmp     L_exit
    
L_done:
    mov     rax, [msgWParam]
    
L_exit:
    pop     rbp
    ret

WinMain ENDP

; ============================================================================
; WndProc
; ============================================================================
ALIGN 16
WndProc PROC frame
    
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    ; Check message type
    cmp     edx, WM_DESTROY
    je      L_destroy
    cmp     edx, WM_CREATE
    je      L_create
    cmp     edx, WM_PAINT
    je      L_paint
    cmp     edx, WM_KEYDOWN
    je      L_keydown
    cmp     edx, WM_CHAR
    je      L_char
    
    ; Default processing
    jmp     L_defproc
    
L_create:
    ; Handle WM_CREATE
    xor     rax, rax
    jmp     L_exit
    
L_paint:
    ; Handle WM_PAINT (minimal)
    xor     rax, rax
    jmp     L_exit
    
L_keydown:
    ; Handle WM_KEYDOWN
    xor     rax, rax
    jmp     L_exit
    
L_char:
    ; Handle WM_CHAR
    xor     rax, rax
    jmp     L_exit
    
L_destroy:
    ; Handle WM_DESTROY
    xor     rcx, rcx
    call    PostQuitMessage
    xor     rax, rax
    jmp     L_exit
    
L_defproc:
    ; Call DefWindowProc
    call    DefWindowProcA
    
L_exit:
    pop     rbp
    ret

WndProc ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC WinMain

END
