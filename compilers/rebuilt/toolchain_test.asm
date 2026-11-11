; Minimal console test
extrn ExitProcess: proc
extrn GetStdHandle: proc
extrn WriteConsoleA: proc

.data
    msg db 'Toolchain test successful', 0Dh, 0Ah
    len equ $ - msg
    written dq ?

.code
mainCRTStartup proc
    sub rsp, 40
    
    ; Get stdout handle
    mov rcx, -11  ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    ; Write message
    mov rcx, rax
    lea rdx, msg
    mov r8, len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
mainCRTStartup endp
end
