; Minimal test to check basic window creation
option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

.data
    app_title BYTE "Test Window",0
    class_name BYTE "TestClass",0

.code
WndProc PROC
    cmp edx, WM_DESTROY
    je destroy
    call DefWindowProcA
    ret
destroy:
    xor rcx, rcx
    call PostQuitMessage
    xor eax, eax
    ret
WndProc ENDP
main PROC
    sub rsp, 40
    
    ; Get instance
    xor rcx, rcx
    call GetModuleHandleA
    mov r12, rax
    
    ; Register class
    sub rsp, 80
    mov DWORD PTR [rsp], 80
    mov DWORD PTR [rsp+4], CS_HREDRAW or CS_VREDRAW
    lea rax, WndProc
    mov QWORD PTR [rsp+8], rax
    mov DWORD PTR [rsp+16], 0
    mov DWORD PTR [rsp+20], 0
    mov QWORD PTR [rsp+24], r12
    mov QWORD PTR [rsp+32], 0
    mov QWORD PTR [rsp+40], 6
    mov QWORD PTR [rsp+48], 0
    lea rax, class_name
    mov QWORD PTR [rsp+56], rax
    mov QWORD PTR [rsp+64], 0
    
    mov rcx, rsp
    call RegisterClassExA
    add rsp, 80
    
    ; Create window
    xor rcx, rcx
    lea rdx, class_name
    lea r8, app_title
    mov r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE
    mov QWORD PTR [rsp+32], CW_USEDEFAULT
    mov QWORD PTR [rsp+40], CW_USEDEFAULT
    mov QWORD PTR [rsp+48], 800
    mov QWORD PTR [rsp+56], 600
    mov QWORD PTR [rsp+64], 0
    mov QWORD PTR [rsp+72], 0
    mov QWORD PTR [rsp+80], r12
    mov QWORD PTR [rsp+88], 0
    call CreateWindowExA
    
    test rax, rax
    jz exit_fail
    
    ; Message loop
    sub rsp, 32
msg_loop:
    mov rcx, rsp
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call GetMessageA
    test eax, eax
    jz msg_exit
    
    mov rcx, rsp
    call TranslateMessage
    mov rcx, rsp
    call DispatchMessageA
    jmp msg_loop
    
msg_exit:
    add rsp, 32
    xor eax, eax
    add rsp, 40
    ret
    
exit_fail:
    mov eax, 1
    add rsp, 40
    ret
main ENDP

END


