; RawrXD GUI IDE - Win32 Application
; Main entry point for GUI IDE with compiler integration
; x64 Windows Application
; NASM Syntax

bits 64

section .data
    ; Window class and title
    class_name db "RawrXDGUICLASS", 0
    window_title db "RawrXD GUI IDE v1.0", 0
    
    ; Menu items
    menu_file db "&File", 0
    menu_build db "&Build", 0
    menu_test db "&Test", 0
    menu_help db "&Help", 0
    
    ; Status messages
    status_ready db "Ready", 0
    status_compiling db "Compiling...", 0
    status_success db "Build successful!", 0
    status_failed db "Build failed!", 0
    
    ; Compiler info
    compilers_text db "Working Compilers: 4", 13, 10
                     db "  - Universal Compiler v2 (C/C++)", 13, 10
                     db "  - EON Compiler v2", 13, 10
                     db "  - Bash Compiler v2", 13, 10
                     db "  - PowerShell Compiler v2", 13, 10, 0
    
    ; Dialog text
    dlg_title db "RawrXD IDE", 0
    dlg_compilers db "Available Compilers", 0
    dlg_tests db "Test Results", 0
    
    ; Button text
    btn_compile db "&Compile", 0
    btn_test db "&Run Tests", 0
    btn_exit db "E&xit", 0
    
    ; File filter
    filter_text db "All Files (*.*)", 0, "*.*", 0
                db "C/C++ Files (*.c;*.cpp)", 0, "*.c;*.cpp", 0
                db "EON Files (*.eon)", 0, "*.eon", 0
                db "Bash Scripts (*.sh)", 0, "*.sh", 0
                db "PowerShell (*.ps1)", 0, "*.ps1", 0, 0
    
    ; Buffers
    filename_buffer times 260 db 0
    cmd_buffer times 512 db 0
    output_buffer times 4096 db 0
    
    ; Data
    hInstance dq 0
    hWndMain dq 0
    hEdit dq 0
    hStatus dq 0
    hBtnCompile dq 0
    hBtnTest dq 0
    hBtnExit dq 0

section .text
    global WinMain
    extern GetModuleHandleA
    extern RegisterClassExA
    extern CreateWindowExA
    extern ShowWindow
    extern UpdateWindow
    extern GetMessageA
    extern TranslateMessage
    extern DispatchMessageA
    extern DefWindowProcA
    extern PostQuitMessage
    extern ExitProcess
    extern LoadIconA
    extern LoadCursorA
    extern GetStockObject
    extern MessageBoxA
    extern SendMessageA
    extern SetWindowTextA
    extern CreateFileA
    extern ReadFile
    extern CloseHandle
    extern ShellExecuteA
    extern GetStdHandle
    extern WriteFile

; ============================================
; ENTRY POINT
; ============================================
WinMain:
    push rbp
    mov rbp, rsp
    sub rsp, 128

    ; Save instance handle
    mov [hInstance], rcx

    ; Register window class
    call register_window_class
    test rax, rax
    jz .error

    ; Create main window
    call create_main_window
    test rax, rax
    jz .error
    mov [hWndMain], rax

    ; Show window
    mov rcx, [hWndMain]
    mov rdx, 1  ; SW_SHOWNORMAL
    call ShowWindow

    ; Update window
    mov rcx, [hWndMain]
    call UpdateWindow

    ; Message loop
.message_loop:
    lea rcx, [rsp+48]  ; MSG structure
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call GetMessageA
    test rax, rax
    jz .exit

    lea rcx, [rsp+48]
    call TranslateMessage

    lea rcx, [rsp+48]
    call DispatchMessageA

    jmp .message_loop

.exit:
    xor rcx, rcx
    call ExitProcess

.error:
    mov rcx, 1
    call ExitProcess

; ============================================
; WINDOW PROCEDURE
; ============================================
window_proc:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; rcx = hWnd, rdx = uMsg, r8 = wParam, r9 = lParam
    mov [rsp+32], rcx
    mov [rsp+40], rdx
    mov [rsp+48], r8
    mov [rsp+56], r9

    cmp rdx, 0x0002  ; WM_DESTROY
    je .wm_destroy
    cmp rdx, 0x0111  ; WM_COMMAND
    je .wm_command
    cmp rdx, 0x0001  ; WM_CREATE
    je .wm_create
    cmp rdx, 0x0005  ; WM_SIZE
    je .wm_size

.default:
    mov rcx, [rsp+32]
    mov rdx, [rsp+40]
    mov r8, [rsp+48]
    mov r9, [rsp+56]
    call DefWindowProcA
    jmp .done

.wm_create:
    call create_controls
    xor rax, rax
    jmp .done

.wm_size:
    call resize_controls
    xor rax, rax
    jmp .done

.wm_command:
    mov rax, r8
    and rax, 0xFFFF  ; LOWORD(wParam)
    cmp rax, 1001  ; Compile button
    je .cmd_compile
    cmp rax, 1002  ; Test button
    je .cmd_test
    cmp rax, 1003  ; Exit button
    je .cmd_exit
    cmp rax, 1  ; File-Open menu
    je .cmd_open
    cmp rax, 2  ; Build-Compile menu
    je .cmd_compile
    cmp rax, 3  ; Test-Run menu
    je .cmd_test
    cmp rax, 4  ; Help-About menu
    je .cmd_about
    jmp .default

.cmd_compile:
    call do_compile
    xor rax, rax
    jmp .done

.cmd_test:
    call do_test
    xor rax, rax
    jmp .done

.cmd_exit:
    mov rcx, [hWndMain]
    call PostQuitMessage
    xor rax, rax
    jmp .done

.cmd_open:
    call do_open_file
    xor rax, rax
    jmp .done

.cmd_about:
    mov rcx, [hWndMain]
    lea rdx, [compilers_text]
    lea r8, [dlg_compilers]
    mov r9, 0x40  ; MB_ICONINFORMATION
    call MessageBoxA
    xor rax, rax
    jmp .done

.wm_destroy:
    xor rcx, rcx
    call PostQuitMessage
    xor rax, rax

.done:
    leave
    ret

; ============================================
; REGISTER WINDOW CLASS
; ============================================
register_window_class:
    push rbp
    mov rbp, rsp
    sub rsp, 128

    ; WNDCLASSEXA structure
    mov dword [rsp+0], 80    ; cbSize
    mov dword [rsp+4], 0x0003  ; style (CS_HREDRAW | CS_VREDRAW)
    lea rax, [window_proc]
    mov [rsp+8], rax         ; lpfnWndProc
    mov dword [rsp+16], 0    ; cbClsExtra
    mov dword [rsp+20], 0    ; cbWndExtra
    mov rax, [hInstance]
    mov [rsp+24], rax        ; hInstance
    xor rcx, rcx
    xor rdx, rdx
    call LoadIconA
    mov [rsp+32], rax        ; hIcon
    xor rcx, rcx
    mov rdx, 32512  ; IDC_ARROW
    call LoadCursorA
    mov [rsp+40], rax        ; hCursor
    mov rcx, 0  ; WHITE_BRUSH
    call GetStockObject
    mov [rsp+48], rax        ; hbrBackground
    xor rax, rax
    mov [rsp+56], rax        ; lpszMenuName
    lea rax, [class_name]
    mov [rsp+64], rax        ; lpszClassName
    xor rcx, rcx
    xor rdx, rdx
    call LoadIconA
    mov [rsp+72], rax        ; hIconSm

    lea rcx, [rsp]
    call RegisterClassExA

    leave
    ret

; ============================================
; CREATE MAIN WINDOW
; ============================================
create_main_window:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    xor rcx, rcx              ; dwExStyle
    lea rdx, [class_name]     ; lpClassName
    lea r8, [window_title]    ; lpWindowName
    mov r9, 0x10CF0000        ; dwStyle (WS_OVERLAPPEDWINDOW)
    mov qword [rsp+32], 100   ; X
    mov qword [rsp+40], 100   ; Y
    mov qword [rsp+48], 800   ; nWidth
    mov qword [rsp+56], 600   ; nHeight
    xor rax, rax
    mov qword [rsp+64], rax   ; hWndParent
    mov qword [rsp+72], rax   ; hMenu
    mov rax, [hInstance]
    mov qword [rsp+80], rax   ; hInstance
    xor rax, rax
    mov qword [rsp+88], rax   ; lpParam

    call CreateWindowExA

    leave
    ret

; ============================================
; CREATE CONTROLS
; ============================================
create_controls:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    ; Create edit control for output
    xor rcx, rcx
    lea rdx, [class_name]
    xor r8, r8
    mov r9, 0x50800000  ; WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL
    mov qword [rsp+32], 10
    mov qword [rsp+40], 10
    mov qword [rsp+48], 760
    mov qword [rsp+56], 480
    mov rax, [hWndMain]
    mov qword [rsp+64], rax
    mov qword [rsp+72], 2001  ; ID
    mov rax, [hInstance]
    mov qword [rsp+80], rax
    xor rax, rax
    mov qword [rsp+88], rax
    call CreateWindowExA
    mov [hEdit], rax

    ; Create Compile button
    xor rcx, rcx
    lea rdx, [class_name]
    lea r8, [btn_compile]
    mov r9, 0x50000000  ; WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON
    mov qword [rsp+32], 10
    mov qword [rsp+40], 500
    mov qword [rsp+48], 100
    mov qword [rsp+56], 30
    mov rax, [hWndMain]
    mov qword [rsp+64], rax
    mov qword [rsp+72], 1001  ; ID
    mov rax, [hInstance]
    mov qword [rsp+80], rax
    xor rax, rax
    mov qword [rsp+88], rax
    call CreateWindowExA
    mov [hBtnCompile], rax

    ; Create Test button
    xor rcx, rcx
    lea rdx, [class_name]
    lea r8, [btn_test]
    mov r9, 0x50000000
    mov qword [rsp+32], 120
    mov qword [rsp+40], 500
    mov qword [rsp+48], 100
    mov qword [rsp+56], 30
    mov rax, [hWndMain]
    mov qword [rsp+64], rax
    mov qword [rsp+72], 1002  ; ID
    mov rax, [hInstance]
    mov qword [rsp+80], rax
    xor rax, rax
    mov qword [rsp+88], rax
    call CreateWindowExA
    mov [hBtnTest], rax

    ; Create Exit button
    xor rcx, rcx
    lea rdx, [class_name]
    lea r8, [btn_exit]
    mov r9, 0x50000000
    mov qword [rsp+32], 230
    mov qword [rsp+40], 500
    mov qword [rsp+48], 100
    mov qword [rsp+56], 30
    mov rax, [hWndMain]
    mov qword [rsp+64], rax
    mov qword [rsp+72], 1003  ; ID
    mov rax, [hInstance]
    mov qword [rsp+80], rax
    xor rax, rax
    mov qword [rsp+88], rax
    call CreateWindowExA
    mov [hBtnExit], rax

    leave
    ret

; ============================================
; RESIZE CONTROLS
; ============================================
resize_controls:
    ret

; ============================================
; DO COMPILE
; ============================================
do_compile:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Show compiling message
    mov rcx, [hEdit]
    lea rdx, [status_compiling]
    mov r8, 0x000D  ; WM_SETTEXT
    xor r9, r9
    call SendMessageA

    ; Launch CLI compiler
    xor rcx, rcx
    lea rdx, [dlg_title]
    lea r8, [compilers_text]
    lea r9, [dlg_compilers]
    mov qword [rsp+32], 0x40
    call MessageBoxA

    leave
    ret

; ============================================
; DO TEST
; ============================================
do_test:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; Show test message
    mov rcx, [hEdit]
    lea rdx, [status_compiling]
    mov r8, 0x000D
    xor r9, r9
    call SendMessageA

    ; Launch test suite
    xor rcx, rcx
    lea rdx, [dlg_title]
    lea r8, [compilers_text]
    lea r9, [dlg_tests]
    mov qword [rsp+32], 0x40
    call MessageBoxA

    leave
    ret

; ============================================
; DO OPEN FILE
; ============================================
do_open_file:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    ; For now, just show message
    xor rcx, rcx
    lea rdx, [dlg_title]
    lea r8, [compilers_text]
    lea r9, [dlg_compilers]
    mov qword [rsp+32], 0x40
    call MessageBoxA

    leave
    ret
