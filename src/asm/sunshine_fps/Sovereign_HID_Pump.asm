; Sovereign_HID_Pump.asm
; Window creation and Message loop pump
; Overrides the base RawInputDevices from Sovereign_HID_RawInput.asm
; with RIDEV_INPUTSINK and our message-only window HWND, so console apps get input.

.data
    RIDEV_INPUTSINK     EQU     00000100h
    wnd_class_name      DB      "SovereignHID", 0

.code
    extern GetModuleHandleA:PROC
    extern RegisterClassExA:PROC
    extern CreateWindowExA:PROC
    extern DefWindowProcA:PROC
    extern PeekMessageA:PROC
    extern TranslateMessage:PROC
    extern DispatchMessageA:PROC

    extern RawInputDevices:BYTE
    extern Sovereign_HID_Process:PROC

; -------------------------------------------------------------------
; Sovereign_Pump_Init
; Creates invisible message sink window, overrides RawInputDevices.
; -------------------------------------------------------------------
Sovereign_Pump_Init PROC
    sub     rsp, 88h

    ; GetModuleHandleA(NULL)
    xor     ecx, ecx
    call    GetModuleHandleA
    mov     rbx, rax                ; hInstance

    ; Register window class
    mov     dword ptr [rsp+20h], 48 ; cbSize
    mov     qword ptr [rsp+28h], rbx; hInstance
    lea     rax, [Sovereign_HID_WndProc]
    mov     qword ptr [rsp+30h], rax; lpfnWndProc
    lea     rax, [wnd_class_name]
    mov     qword ptr [rsp+70h], rax; lpszClassName
    mov     qword ptr [rsp+38h], 0  ; cbClsExtra
    mov     qword ptr [rsp+40h], 0  ; cbWndExtra
    mov     qword ptr [rsp+48h], 0  ; hIcon
    mov     qword ptr [rsp+50h], 0  ; hCursor
    mov     qword ptr [rsp+58h], 0  ; hbrBackground
    mov     qword ptr [rsp+60h], 0  ; lpszMenuName
    mov     qword ptr [rsp+68h], 0  ; hIconSm

    mov     rcx, rsp
    add     rcx, 20h
    call    RegisterClassExA

    ; Create invisible message-only window
    xor     ecx, ecx                ; dwExStyle
    lea     rdx, [wnd_class_name]   ; lpClassName
    xor     r8, r8                  ; lpWindowName
    xor     r9, r9                  ; dwStyle
    mov     qword ptr [rsp+20h], 0  ; X
    mov     qword ptr [rsp+28h], 0  ; Y
    mov     qword ptr [rsp+30h], 0  ; nWidth
    mov     qword ptr [rsp+38h], 0  ; nHeight
    mov     qword ptr [rsp+40h], 0  ; hWndParent = HWND_MESSAGE
    mov     qword ptr [rsp+48h], 0  ; hMenu
    mov     qword ptr [rsp+50h], rbx; hInstance
    mov     qword ptr [rsp+58h], 0  ; lpParam
    call    CreateWindowExA

    ; rax = HWND
    lea     r10, [RawInputDevices]

    ; Mouse is at RawInputDevices + 0
    mov     dword ptr [r10 + 4], RIDEV_INPUTSINK ; dwFlags
    mov     qword ptr [r10 + 8], rax             ; hwndTarget

    ; Keyboard is at RawInputDevices + 16
    mov     dword ptr [r10 + 20], RIDEV_INPUTSINK ; dwFlags
    mov     qword ptr [r10 + 24], rax             ; hwndTarget

    add     rsp, 88h
    ret
Sovereign_Pump_Init ENDP

; -------------------------------------------------------------------
; Sovereign_HID_WndProc
; Processes WM_INPUT messages. Routes to Sovereign_HID_Process.
; -------------------------------------------------------------------
Sovereign_HID_WndProc PROC
    cmp     edx, 0FFh               ; WM_INPUT = 0x00FF
    jne     L_default

    mov     rcx, r9                 ; hRawInput = lParam
    sub rsp, 32
    call    Sovereign_HID_Process
    add rsp, 32

    mov     rax, 0
    ret

L_default:
    jmp     DefWindowProcA
Sovereign_HID_WndProc ENDP

; -------------------------------------------------------------------
; Sovereign_HID_Poll
; Call once per frame from UI thread. Drains message queue.
; -------------------------------------------------------------------
Sovereign_HID_Poll PROC
    sub     rsp, 88h                ; MSG structure (48 bytes) + shadow

L_poll_loop:
    lea     rcx, [rsp+20h]          ; lpMsg
    xor     edx, edx                ; hWnd = NULL
    xor     r8, r8                  ; wMsgFilterMin = 0
    xor     r9, r9                  ; wMsgFilterMax = 0
    mov     dword ptr [rsp+48h], 1  ; PM_REMOVE
    call    PeekMessageA
    test    rax, rax
    jz      L_poll_done

    lea     rcx, [rsp+20h]
    call    TranslateMessage
    lea     rcx, [rsp+20h]
    call    DispatchMessageA
    jmp     L_poll_loop

L_poll_done:
    add     rsp, 88h
    ret
Sovereign_HID_Poll ENDP

PUBLIC  Sovereign_Pump_Init
PUBLIC  Sovereign_HID_Poll

END
