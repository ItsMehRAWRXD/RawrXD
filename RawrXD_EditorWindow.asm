; RawrXD_EditorWindow.asm - Clean IDE Window with Ghost Engine Integration
; Minimal, compilable MASM64 implementation
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

INCLUDELIB kernel32.lib
INCLUDELIB user32.lib
INCLUDELIB gdi32.lib

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN CreateWindowExA:PROC
EXTERN DefWindowProcA:PROC
EXTERN RegisterClassA:PROC
EXTERN BeginPaint:PROC
EXTERN EndPaint:PROC
EXTERN TextOutA:PROC
EXTERN FillRect:PROC
EXTERN InvalidateRect:PROC
EXTERN PostQuitMessage:PROC
EXTERN ShowWindow:PROC
EXTERN GetMessageA:PROC
EXTERN DispatchMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN SetTextColor:PROC
EXTERN SetBkMode:PROC

; Ghost Engine Bridge
EXTERN IDE_GHOST_RENDER:PROC
EXTERN IDE_GHOST_INIT:PROC

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

g_hwndEditor        dq 0
g_hdc               dq 0
g_client_width      dd 800
g_client_height     dd 600
g_cursor_x          dd 100
g_cursor_y          dd 50
g_char_width        dd 8
g_char_height       dd 16
g_line_num_width    dd 50

szWindowClassName   db "RawrXDEditorClass", 0
szEditorWindowTitle db "RawrXD IDE - Sovereign Ghost Engine", 0
szCursorChar        db "|", 0

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; EditorWindow_WndProc - Main message dispatcher
; rcx = hwnd, edx = msg, r8 = wparam, r9 = lparam
; ==============================================================================
EditorWindow_WndProc PROC
    cmp edx, 15                 ; WM_PAINT
    je OnPaint
    cmp edx, 256                ; WM_KEYDOWN
    je OnKeyDown
    cmp edx, 258                ; WM_CHAR
    je OnChar
    cmp edx, 2                  ; WM_DESTROY
    je OnDestroy
    cmp edx, 5                  ; WM_SIZE
    je OnSize
    jmp DefaultProc

OnPaint:
    call EditorWindow_HandlePaint
    xor eax, eax
    ret

OnKeyDown:
    mov eax, r8d
    call EditorWindow_HandleKeyDown
    xor eax, eax
    ret

OnChar:
    mov eax, r8d
    call EditorWindow_HandleChar
    xor eax, eax
    ret

OnDestroy:
    xor ecx, ecx
    call PostQuitMessage
    xor eax, eax
    ret

OnSize:
    mov eax, r8d
    and eax, 0FFFFh
    mov g_client_width, eax
    mov eax, r8d
    shr eax, 16
    mov g_client_height, eax
    xor eax, eax
    ret

DefaultProc:
    call DefWindowProcA
    ret
EditorWindow_WndProc ENDP

; ==============================================================================
; EditorWindow_HandlePaint - GDI rendering with Ghost Engine overlay
; ==============================================================================
EditorWindow_HandlePaint PROC
    push rbx
    sub rsp, 88                 ; PAINTSTRUCT (72) + shadow space

    mov rbx, rcx                ; Save hwnd
    lea rdx, [rsp]              ; PAINTSTRUCT
    call BeginPaint
    mov g_hdc, rax

    ; Draw white background
    mov rcx, g_hdc
    mov edx, 0FFFFFFh           ; White color
    call SetTextColor
    mov rcx, g_hdc
    mov edx, 1                  ; TRANSPARENT
    call SetBkMode

    ; Draw cursor position text
    mov rcx, g_hdc
    mov edx, g_cursor_x
    mov r8d, g_cursor_y
    lea r9, szCursorChar
    mov dword ptr [rsp+72], 1
    call TextOutA

    ; Render Ghost Engine AI predictions
    mov rcx, rbx
    call IDE_GHOST_RENDER

    ; End paint
    mov rcx, rbx
    lea rdx, [rsp]
    call EndPaint

    add rsp, 88
    pop rbx
    ret
EditorWindow_HandlePaint ENDP

; ==============================================================================
; EditorWindow_HandleKeyDown - Simple cursor movement
; ==============================================================================
EditorWindow_HandleKeyDown PROC
    cmp eax, 37                 ; VK_LEFT
    je HandleLeft
    cmp eax, 39                 ; VK_RIGHT
    je HandleRight
    cmp eax, 38                 ; VK_UP
    je HandleUp
    cmp eax, 40                 ; VK_DOWN
    je HandleDown
    ret

HandleLeft:
    mov eax, g_cursor_x
    sub eax, g_char_width
    mov g_cursor_x, eax
    mov eax, g_cursor_x
    cmp eax, g_line_num_width
    jge InvalidateAfterKey
    mov eax, g_line_num_width
    mov g_cursor_x, eax
    jmp InvalidateAfterKey

HandleRight:
    mov eax, g_cursor_x
    add eax, g_char_width
    mov g_cursor_x, eax
    jmp InvalidateAfterKey

HandleUp:
    mov eax, g_cursor_y
    sub eax, g_char_height
    mov g_cursor_y, eax
    mov eax, g_cursor_y
    cmp eax, 0
    jge InvalidateAfterKey
    mov g_cursor_y, 0
    jmp InvalidateAfterKey

HandleDown:
    mov eax, g_cursor_y
    add eax, g_char_height
    mov g_cursor_y, eax
    jmp InvalidateAfterKey

InvalidateAfterKey:
    mov rcx, g_hwndEditor
    xor edx, edx
    call InvalidateRect
    ret
EditorWindow_HandleKeyDown ENDP

; ==============================================================================
; EditorWindow_HandleChar - Insert character
; ==============================================================================
EditorWindow_HandleChar PROC
    mov eax, g_cursor_x
    add eax, g_char_width
    mov g_cursor_x, eax
    mov rcx, g_hwndEditor
    xor edx, edx
    call InvalidateRect
    ret
EditorWindow_HandleChar ENDP

; ==============================================================================
; EditorWindow_RegisterClass - Register window class
; ==============================================================================
EditorWindow_RegisterClass PROC
    push rbx
    sub rsp, 88                 ; WNDCLASSA (48) + shadow

    lea rbx, [rsp]
    mov dword ptr [rbx], 3      ; style = CS_HREDRAW | CS_VREDRAW
    lea rax, EditorWindow_WndProc
    mov qword ptr [rbx+8], rax  ; lpfnWndProc
    mov dword ptr [rbx+16], 0   ; cbClsExtra
    mov dword ptr [rbx+20], 0   ; cbWndExtra
    mov qword ptr [rbx+24], 0   ; hInstance
    mov qword ptr [rbx+32], 0   ; hIcon
    mov qword ptr [rbx+40], 0   ; hCursor
    mov qword ptr [rbx+48], 0   ; hbrBackground
    mov qword ptr [rbx+56], 0   ; lpszMenuName
    lea rax, szWindowClassName
    mov qword ptr [rbx+64], rax ; lpszClassName

    mov rcx, rbx
    call RegisterClassA

    add rsp, 88
    pop rbx
    ret
EditorWindow_RegisterClass ENDP

; ==============================================================================
; EditorWindow_Create - Create main editor window
; ==============================================================================
EditorWindow_Create PROC
    push rbx
    sub rsp, 72

    call EditorWindow_RegisterClass

    xor ecx, ecx
    lea rdx, szWindowClassName
    lea r8, szEditorWindowTitle
    mov r9d, 0CF0000h           ; WS_OVERLAPPEDWINDOW
    mov dword ptr [rsp], 0      ; x
    mov dword ptr [rsp+4], 0    ; y
    mov dword ptr [rsp+8], 800  ; width
    mov dword ptr [rsp+12], 600 ; height
    mov qword ptr [rsp+16], 0   ; parent
    mov qword ptr [rsp+24], 0   ; menu
    mov qword ptr [rsp+32], 0   ; hInstance
    mov qword ptr [rsp+40], 0   ; param

    call CreateWindowExA
    mov g_hwndEditor, rax

    ; Initialize Ghost Engine for AI predictions
    call IDE_GHOST_INIT

    add rsp, 72
    pop rbx
    ret
EditorWindow_Create ENDP

; ==============================================================================
; EditorWindow_RunMessageLoop - Standard message pump
; ==============================================================================
EditorWindow_RunMessageLoop PROC
    push rbx
    sub rsp, 56                 ; MSG structure (48) + align

MessageLoop:
    lea rcx, [rsp]              ; lpMsg
    xor edx, edx                ; hWnd = NULL
    xor r8d, r8d                ; wMsgFilterMin = 0
    xor r9d, r9d                ; wMsgFilterMax = 0
    call GetMessageA
    test eax, eax
    jz MessageDone

    lea rcx, [rsp]
    call TranslateMessage
    lea rcx, [rsp]
    call DispatchMessageA
    jmp MessageLoop

MessageDone:
    xor eax, eax
    add rsp, 56
    pop rbx
    ret
EditorWindow_RunMessageLoop ENDP

; ==============================================================================
; mainCRTStartup - Entry point for IDE executable
; ==============================================================================
mainCRTStartup PROC
    push rbx
    sub rsp, 40h
    
    ; Create editor window
    call EditorWindow_Create
    test rax, rax
    jz main_exit
    
    ; Show window
    mov rcx, rax
    mov edx, 1                  ; SW_SHOWNORMAL
    call ShowWindow
    
    ; Run message loop
    call EditorWindow_RunMessageLoop
    
main_exit:
    xor ecx, ecx
    call ExitProcess
    
mainCRTStartup ENDP

EXTERN ExitProcess:PROC

; ==============================================================================
; End
; ==============================================================================
end
