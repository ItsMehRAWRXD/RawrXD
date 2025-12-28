; Minimal test to identify freeze issue
option casemap:none

includelib kernel32.lib
includelib user32.lib

; Constants
MB_OK equ 0

; External functions
EXTERN MessageBoxA:PROC
EXTERN ExitProcess:PROC

.data
    szTitle BYTE "Test", 0
    szMsg   BYTE "Hello World", 0

.code
main PROC
    sub rsp, 40
    
    ; Simple message box - no console allocation
    xor rcx, rcx
    lea rdx, szMsg
    lea r8, szTitle
    mov r9d, MB_OK
    call MessageBoxA
    
    xor eax, eax
    call ExitProcess
main ENDP

END