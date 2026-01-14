;==========================================================================
; main_window_masm.asm - Pure MASM64 Main Window Implementation (ML64-COMPAT)
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

MAIN_WINDOW struct
    hWnd dq ?
    hInstance dq ?
MAIN_WINDOW ends

IDM_FILE_EXIT equ 1005
IDM_HELP_ABOUT equ 1601
MB_OK equ 0
TRUE equ 1
FALSE equ 0

EXTERN CreateMenu:PROC
EXTERN PostQuitMessage:PROC
EXTERN GetMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageA:PROC
EXTERN DestroyWindow:PROC
EXTERN DefWindowProcA:PROC
EXTERN MessageBoxA:PROC
EXTERN hpatch_apply_memory:PROC
EXTERN hpatch_apply_byte:PROC
EXTERN hpatch_apply_server:PROC
EXTERN AgenticEngine_Initialize:PROC
EXTERN agent_init_tools:PROC
EXTERN ml_masm_init:PROC
EXTERN console_log_init:PROC
EXTERN file_log_init:PROC
EXTERN session_manager_init:PROC
EXTERN PaneSystem_HandleResize:PROC

.data
g_mainWindow MAIN_WINDOW <?>
szWindowTitle db "RawrXD IDE",0
szStatusReady db "Ready",0
szAboutMsg db "RawrXD IDE - MASM64",0

.code

MainWindow_Initialize proc
    sub rsp, 40
    mov g_mainWindow.hInstance, rcx
    call CreateMenu
    call hpatch_apply_memory
    call hpatch_apply_byte
    call hpatch_apply_server
    call AgenticEngine_Initialize
    call agent_init_tools
    call ml_masm_init
    call console_log_init
    call file_log_init
    call session_manager_init
    mov rax, TRUE
    add rsp, 40
    ret
MainWindow_Initialize endp

MainWindow_SetStatusMessage proc
    ret
MainWindow_SetStatusMessage endp

MainWindow_HandleMenuCommand proc
    sub rsp, 40
    mov eax, ecx
    cmp eax, IDM_FILE_EXIT
    je handle_exit
    cmp eax, IDM_HELP_ABOUT
    je handle_about
    jmp cmd_done
handle_exit:
    xor rcx, rcx
    call PostQuitMessage
    jmp cmd_done
handle_about:
    mov rcx, g_mainWindow.hWnd
    lea rdx, szAboutMsg
    lea r8, szWindowTitle
    mov r9d, MB_OK
    call MessageBoxA
cmd_done:
    add rsp, 40
    ret
MainWindow_HandleMenuCommand endp

MainWindow_Run proc
    sub rsp, 88
msg_loop:
    lea rcx, [rsp+48]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call GetMessageA
    test rax, rax
    jz exit_loop
    lea rcx, [rsp+48]
    call TranslateMessage
    lea rcx, [rsp+48]
    call DispatchMessageA
    jmp msg_loop
exit_loop:
    mov rax, [rsp+48]
    add rsp, 88
    ret
MainWindow_Run endp

MainWindow_WndProc proc
    sub rsp, 56
    mov [rsp+32], rcx
    mov [rsp+40], rdx
    cmp edx, 111h  ; WM_COMMAND
    je handle_command
    cmp edx, 5     ; WM_SIZE
    je handle_size
    cmp edx, 10h   ; WM_CLOSE
    je handle_close
    cmp edx, 2     ; WM_DESTROY
    je handle_destroy
    jmp default_proc
handle_command:
    mov eax, r8d
    and eax, 0FFFFh
    mov ecx, eax
    call MainWindow_HandleMenuCommand
    xor rax, rax
    add rsp, 56
    ret
handle_size:
    call PaneSystem_HandleResize
    xor rax, rax
    add rsp, 56
    ret
handle_close:
    mov rcx, [rsp+32]
    call DestroyWindow
    xor rax, rax
    add rsp, 56
    ret
handle_destroy:
    xor rcx, rcx
    call PostQuitMessage
    xor rax, rax
    add rsp, 56
    ret
default_proc:
    mov rcx, [rsp+32]
    mov rdx, [rsp+40]
    call DefWindowProcA
    add rsp, 56
    ret
MainWindow_WndProc endp

PUBLIC MainWindow_Initialize
PUBLIC MainWindow_Run
PUBLIC MainWindow_WndProc
PUBLIC MainWindow_SetStatusMessage
PUBLIC MainWindow_HandleMenuCommand
PUBLIC g_mainWindow

end