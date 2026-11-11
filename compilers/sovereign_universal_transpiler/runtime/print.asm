; print.asm - Native printing for Sovereign Universal Transpiler
; v0.2 - Production: Fixed parameter handling, proper Win64 ABI
; Uses WriteFile (kernel32.dll) for zero-dependency console output

option casemap:none

; Windows API functions
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
; Returns: RAX = 1 on success, 0 on failure
RuntimePrintString PROC
    push rbx
    push rsi
    sub rsp, 28h

    mov rsi, rcx            ; save string pointer (RCX will be clobbered)
    mov rbx, rdx            ; save length

    ; Get stdout handle if not cached
    cmp qword ptr [hStdOut], 0
    jne have_handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOut], rax
    test rax, rax
    jz print_fail
have_handle:

    ; WriteFile(hStdOut, string, length, &bytesWritten, NULL)
    ; Win64 ABI: RCX=hFile, RDX=lpBuffer, R8=nNumberOfBytesToWrite, R9=lpNumberOfBytesWritten
    mov rcx, [hStdOut]      ; hFile
    mov rdx, rsi            ; lpBuffer = string pointer
    mov r8d, ebx            ; nNumberOfBytesToWrite = length
    lea r9, [bytes_written] ; lpNumberOfBytesWritten
    mov qword ptr [rsp + 20h], 0    ; lpOverlapped = NULL
    call WriteFile

    ; RAX = nonzero on success
    test rax, rax
    jz print_fail
    mov rax, 1              ; success
    jmp print_done

print_fail:
    xor rax, rax            ; failure

print_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
RuntimePrintString ENDP

; RuntimePrintChar - Print a single character to stdout
; CL = character
RuntimePrintChar PROC
    push rbx
    sub rsp, 28h

    ; Store char in a buffer
    .data
    char_buf db 0
    .code
    mov [char_buf], cl

    ; Get stdout handle
    cmp qword ptr [hStdOut], 0
    jne have
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOut], rax
have:
    mov rcx, [hStdOut]
    lea rdx, [char_buf]
    mov r8d, 1
    lea r9, [bytes_written]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    add rsp, 28h
    pop rbx
    ret
RuntimePrintChar ENDP

end