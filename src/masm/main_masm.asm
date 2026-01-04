;==========================================================================
; main_masm.asm - Pure MASM64 RawrXD Main Entry Point
;==========================================================================

option casemap:none

EXTERN GetModuleHandleA : PROC
EXTERN GetMessageA : PROC
EXTERN TranslateMessage : PROC
EXTERN DispatchMessageA : PROC
EXTERN ExitProcess : PROC

EXTERN ui_create_main_window:PROC
EXTERN ui_add_chat_message:PROC

MSG STRUCT
    hwnd        QWORD ?
    message     DWORD ?
    pad1        DWORD ?
    wParam      QWORD ?
    lParam      QWORD ?
    time        DWORD ?
    pt_x        DWORD ?
    pt_y        DWORD ?
    pad2        DWORD ?
MSG ENDS

.data
    szWelcome   BYTE "RawrXD Agentic IDE - Ready", 0

.data?
    hInstance   QWORD ?
    msg         MSG <>

.code

main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    xor rcx, rcx
    call GetModuleHandleA
    mov hInstance, rax

    mov rcx, rax
    call ui_create_main_window
    test rax, rax
    jz exit_app

    lea rcx, szWelcome
    call ui_add_chat_message

msg_loop:
    lea rcx, msg
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call GetMessageA
    test rax, rax
    jz exit_app

    lea rcx, msg
    call TranslateMessage
    lea rcx, msg
    call DispatchMessageA
    jmp msg_loop

exit_app:
    xor rcx, rcx
    call ExitProcess
main ENDP

END

