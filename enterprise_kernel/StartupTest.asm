; Ultra-minimal test with proper startup
option casemap:none

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

STD_OUTPUT_HANDLE EQU -11

.data
align 8
hStdOut         QWORD 0
bytesWritten    QWORD 0
szHello         BYTE "Hello from MASM x64!", 13, 10, 0

.code
align 8

; Startup entry point - called by OS loader
; Stack is already aligned to 16 bytes by OS
; We just need to preserve it and call our main
mainCRTStartup PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Print hello
    lea rcx, szHello
    call PrintString
    
    ; Exit with code 0
    xor rcx, rcx
    call ExitProcess
    
    ; Should never reach here
    xor rcx, rcx
    call ExitProcess
    
mainCRTStartup ENDP

PrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov r10, rcx
    xor rdx, rdx
    mov r11, r10
PrintString_count_loop:
    cmp byte ptr [r11], 0
    je PrintString_count_done
    inc rdx
    inc r11
    jmp PrintString_count_loop
PrintString_count_done:
    
    test rdx, rdx
    jz PrintString_done
    
    mov rcx, hStdOut
    mov r8, rdx
    mov rdx, r10
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
PrintString_done:
    add rsp, 40h
    pop rbp
    ret
PrintString ENDP

END
