; ============================================================================
; RawrXD_TextEditorStandalone.asm
; Standalone entry point for the hardened editor module.
; Hosts one embeddable editor instance in a top-level window and runs the
; message loop.  Used to verify the foundation build.
; ============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

EXTERN GetModuleHandleW:PROC
EXTERN RegisterClassExW:PROC
EXTERN CreateWindowExW:PROC
EXTERN DefWindowProcW:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN GetMessageW:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageW:PROC
EXTERN PostQuitMessage:PROC
EXTERN SetWindowLongPtrW:PROC
EXTERN DestroyWindow:PROC
EXTERN ExitProcess:PROC
EXTERN MessageBoxW:PROC
EXTERN OutputDebugStringW:PROC

EXTERN EditorWindow_Create:PROC
EXTERN RegisterClasses:PROC
EXTERN GetInstance:PROC

WM_CREATE          EQU 1
WM_DESTROY         EQU 2
WS_OVERLAPPEDWINDOW EQU 00CF0000h
WS_VISIBLE         EQU 10000000h
SW_SHOW            EQU 5
CW_USEDEFAULT      EQU 80000000h
COLOR_WINDOWPLUS1  EQU 6
GWLP_USERDATA      EQU -21

.data
align 8
clsMain     dw 'R','a','w','r','X','D',' ','H','a','r','d','e','n','e','d',' ','M','a','i','n',0
errFailed   dw 'R','a','w','r','X','D',' ','e','d','i','t','o','r',' ','i','n','i','t',' ','f','a','i','l','e','d',0
wszTitle    dw 'R','a','w','r','X','D',' ','H','a','r','d','e','n','e','d',' ','E','d','i','t','o','r',0

.code

MainWndProc PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 80
    .allocstack 80
    .endprolog
    mov rbx, rcx                  ; hWnd
    mov [rsp+32], edx             ; uMsg
    mov [rsp+40], r8              ; wParam
    mov [rsp+48], r9              ; lParam
    cmp edx, WM_CREATE
    je wmcreate
    cmp edx, WM_DESTROY
    je wmdestroy
    jmp wmdef
wmcreate:
    call GetInstance
    mov rcx, rax                  ; hInstance
    mov rdx, rbx                  ; hParent
    xor r8d, r8d                  ; x=0
    xor r9d, r9d                  ; y=0
    mov dword ptr [rsp+32], 1000            ; w
    mov dword ptr [rsp+40], 700             ; h
    call EditorWindow_Create
    test rax, rax
    jz wmfail
    mov rcx, rbx
    mov edx, GWLP_USERDATA
    mov r8, rax
    call SetWindowLongPtrW
    xor eax, eax
    jmp wmdone
wmfail:
    mov eax, -1
    jmp wmdone
wmdestroy:
    xor ecx, ecx
    call PostQuitMessage
    xor eax, eax
    jmp wmdone
wmdef:
    mov rcx, rbx
    mov edx, [rsp+32]
    mov r8, [rsp+40]
    mov r9, [rsp+48]
    call DefWindowProcW
wmdone:
    add rsp, 80
    pop rbx
    ret
MainWndProc ENDP

main PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 128
    .allocstack 128
    .endprolog
    call GetInstance
    mov rbx, rax                  ; rbx = hInstance
    mov [rsp+80], rax             ; hInstance
    ; WNDCLASSEXW at [rsp+32] (80 bytes)
    mov dword ptr [rsp+32], 80    ; cbSize
    mov dword ptr [rsp+36], 0     ; style
    lea rax, MainWndProc
    mov [rsp+40], rax             ; lpfnWndProc
    mov rax, [rsp+80]
    mov [rsp+48], rax             ; hInstance
    mov [rsp+56], rbx             ; hIcon
    mov [rsp+64], rbx             ; hCursor
    mov dword ptr [rsp+72], COLOR_WINDOWPLUS1  ; hbrBackground
    mov [rsp+80], rbx             ; lpszMenuName
    lea rax, clsMain
    mov [rsp+88], rax             ; lpszClassName
    mov [rsp+96], rbx             ; hIconSm
    lea rcx, [rsp+32]
    call RegisterClassExW
    test eax, eax
    jz mainfail
    ; Register editor container/gutter classes
    call RegisterClasses
    test eax, eax
    jz mainfail
    ; CreateWindowExW(0, clsMain, wszTitle, WS_OVERLAPPEDWINDOW|WS_VISIBLE,
    ;   CW_USEDEFAULT,CW_USEDEFAULT,900,600, 0,0, hInstance, 0)
    xor ecx, ecx                  ; dwExStyle
    lea rdx, clsMain
    lea r8, wszTitle
    mov r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE
    mov dword ptr [rsp+32], CW_USEDEFAULT   ; X
    mov dword ptr [rsp+40], CW_USEDEFAULT   ; Y
    mov dword ptr [rsp+48], 900             ; nWidth
    mov dword ptr [rsp+56], 600             ; nHeight
    xor rax, rax
    mov [rsp+64], rax             ; hWndParent = 0
    mov [rsp+72], rax             ; hMenu
    mov [rsp+80], rbx             ; hInstance
    mov [rsp+88], rax             ; lpParam
    call CreateWindowExW
    test rax, rax
    jz mainfail
    mov rcx, rax
    mov edx, SW_SHOW
    call ShowWindow
    mov rcx, rax
    call UpdateWindow
loopmsg:
    lea rcx, [rsp+32]             ; MSG at [rsp+32] (48 bytes)
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call GetMessageW
    cmp eax, -1
    je mainfail
    test eax, eax
    jz success
    lea rcx, [rsp+32]
    call TranslateMessage
    lea rcx, [rsp+32]
    call DispatchMessageW
    jmp loopmsg
success:
    mov ecx, dword ptr [rsp+32+16] ; MSG.wParam
    call ExitProcess
mainfail:
    xor ecx, ecx
    lea rdx, errFailed
    lea r8, wszTitle
    mov r9d, 10h
    call MessageBoxW
    mov ecx, 1
    call ExitProcess
    add rsp, 128
    pop rbx
    ret
main ENDP

END