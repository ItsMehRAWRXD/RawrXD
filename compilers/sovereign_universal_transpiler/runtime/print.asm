; print.asm - Native printing for Sovereign Universal Transpiler
; Uses WriteConsoleA (kernel32.dll)

extrn GetStdHandle:proc
extrn WriteFile:proc

.data
    hStdOut       dq 0
    bytes_written dq 0
    STD_OUTPUT_HANDLE equ -11

.code

; RuntimePrintString - Print a string to stdout
; RCX = string pointer
; RDX = string length
RuntimePrintString PROC
    push rbx
    sub rsp, 38h
    
    ; Get stdout handle if not cached
    cmp qword ptr [hStdOut], 0
    jne have_handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOut], rax
have_handle:
    
    mov rbx, rdx            ; save length
    
    ; WriteFile(hStdOut, string, length, &bytesWritten, NULL)
    mov rcx, [hStdOut]
    ; rdx = string pointer (already set)
    mov r8d, ebx            ; length
    lea r9, [bytes_written]
    mov qword ptr [rsp + 20h], 0    ; lpOverlapped = NULL
    call WriteFile
    
    add rsp, 38h
    pop rbx
    ret
RuntimePrintString ENDP

end