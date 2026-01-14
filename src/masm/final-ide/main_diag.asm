; Minimal diagnostic main to isolate crash
option casemap:none
include windows.inc
includelib kernel32.lib
includelib user32.lib

EXTERN GetModuleHandleA:PROC
EXTERN MessageBoxA:PROC
EXTERN ExitProcess:PROC
EXTERN ui_create_main_window:PROC

.data
    msg_test        BYTE "Test: Before ui_create_main_window",0
    msg_ok          BYTE "Test: After ui_create_main_window - SUCCESS",0
    msg_fail        BYTE "Test: ui_create_main_window FAILED or CRASHED",0
    title           BYTE "Diagnostic",0
    h_instance      QWORD 0

.code
PUBLIC main
main PROC
    ; rcx = hInstance
    sub rsp, 32
    
    ; Save instance
    mov h_instance, rcx
    
    ; Show first MessageBox
    xor rcx, rcx
    lea rdx, msg_test
    lea r8, title
    mov r9d, 0
    call MessageBoxA
    
    ; Try to create window
    mov rcx, h_instance
    call ui_create_main_window
    
    ; Show success or failure
    xor rcx, rcx
    lea rdx, msg_ok
    lea r8, title
    mov r9d, 0
    call MessageBoxA
    
    xor eax, eax
    add rsp, 32
    ret
main ENDP
PUBLIC RawrMain
RawrMain EQU main

END




